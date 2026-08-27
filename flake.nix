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
        in
        { inherit pkgs python enrich verify fetch; };
    in
    {
      packages = forAllSystems (system:
        let p = packagesFor system;
        in {
          default = p.enrich;
          inherit (p) enrich verify fetch;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.enrich}/bin/baseband-cve-enrich";
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
            python -m unittest -v test_fetch_json.py
            python enrich.py --output "$TMPDIR/generated"
            python verify_outputs.py "$TMPDIR/generated"
            touch "$out"
          '';
        });
    };
}
