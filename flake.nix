{
  description = "Reproducible environment for the evidence-aware baseband CVE dataset";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  inputs.cvelistV5 = {
    url = "git+https://github.com/CVEProject/cvelistV5.git?shallow=1";
    flake = false;
  };

  outputs = { self, nixpkgs, cvelistV5 }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      packagesFor = system:
        let
          pkgs = import nixpkgs { inherit system; };
          python = pkgs.python312.withPackages (ps: [ ps.matplotlib ]);
          enrich = pkgs.writeShellApplication {
            name = "baseband-cve-enrich";
            runtimeInputs = [ python ];
            text = ''
              exec python ${self}/enrich.py "$@"
            '';
          };
          verify = pkgs.writeShellApplication {
            name = "baseband-cve-verify";
            runtimeInputs = [ python ];
            text = ''
              exec python ${self}/verify_outputs.py "$@"
            '';
          };
          fetch = pkgs.writeShellApplication {
            name = "baseband-cve-fetch";
            runtimeInputs = [ python ];
            text = ''
              source_args=(--cve-list-dir ${cvelistV5})
              for arg in "$@"; do
                case "$arg" in
                  --cve-list-dir|--cve-list-dir=*|--cve-list-zip|--cve-list-zip=*)
                    source_args=()
                    break
                    ;;
                esac
              done
              exec python ${self}/fetch_json.py "''${source_args[@]}" "$@"
            '';
          };
          pipeline = pkgs.writeShellApplication {
            name = "baseband-cve-pipeline";
            runtimeInputs = [ python ];
            text = ''
              fetched_dir="''${BASEBAND_CVE_FETCH_DIR:-$PWD/fetched_json}"
              python ${self}/fetch_json.py \
                --cve-list-dir ${cvelistV5} \
                --merge-dir ${self}/no-checked-in-json \
                --output-dir "$fetched_dir" \
                --offline
              exec python ${self}/enrich.py --input-dir "$fetched_dir" "$@"
            '';
          };
        in
        { inherit pkgs python enrich verify fetch pipeline; };
    in
    {
      packages = forAllSystems (system:
        let p = packagesFor system;
        in {
          default = p.pipeline;
          inherit (p) pipeline enrich verify fetch;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.pipeline}/bin/baseband-cve-pipeline";
        };
        pipeline = {
          type = "app";
          program = "${self.packages.${system}.pipeline}/bin/baseband-cve-pipeline";
        };
        enrich = {
          type = "app";
          program = "${self.packages.${system}.enrich}/bin/baseband-cve-enrich";
        };
        verify = {
          type = "app";
          program = "${self.packages.${system}.verify}/bin/baseband-cve-verify";
        };
        fetch = {
          type = "app";
          program = "${self.packages.${system}.fetch}/bin/baseband-cve-fetch";
        };
      });

      devShells = forAllSystems (system:
        let p = packagesFor system;
        in {
          default = p.pkgs.mkShell {
            packages = [ p.python ];
            shellHook = ''
              export MPLCONFIGDIR="''${TMPDIR:-/tmp}/baseband-cve-matplotlib"
              export CVELISTV5_DIR="${cvelistV5}"
            '';
          };
        });

      checks = forAllSystems (system:
        let p = packagesFor system;
        in {
          pipeline = p.pkgs.runCommand "baseband-cve-pipeline-check" {
            nativeBuildInputs = [ p.python ];
          } ''
            export MPLCONFIGDIR="$TMPDIR/matplotlib"
            test -d ${cvelistV5}/cves
            cd ${self}
            python fetch_json.py \
              --cve-list-dir ${cvelistV5} \
              --merge-dir "$TMPDIR/empty-merge" \
              --output-dir "$TMPDIR/fetched_json" \
              --offline
            python enrich.py \
              --input-dir "$TMPDIR/fetched_json" \
              --output "$TMPDIR/generated"
            python verify_outputs.py \
              "$TMPDIR/generated" \
              --input-dir "$TMPDIR/fetched_json"
            touch "$out"
          '';
        });
    };
}
