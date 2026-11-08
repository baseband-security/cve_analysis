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
              echo "[pipeline 1/2] Acquiring vendor JSON from the pinned CVE List V5 snapshot"
              python ${self}/fetch_json.py \
                --cve-list-dir ${cvelistV5} \
                --merge-dir ${self}/no-checked-in-json \
                --output-dir "$fetched_dir" \
                --offline
              echo "[pipeline 2/2] Enriching and validating the dataset"
              exec python ${self}/enrich.py --input-dir "$fetched_dir" "$@"
            '';
          };
          serve = pkgs.writeShellApplication {
            name = "baseband-cve-serve";
            runtimeInputs = [ python ];
            text = ''
              exec python ${self}/serve.py "$@"
            '';
          };
          website = pkgs.writeShellApplication {
            name = "baseband-cve-website";
            runtimeInputs = [ pkgs.python312 ];
            text = ''
              data_dir="''${BASEBAND_CVE_OUTPUT_DIR:-$PWD/outputs}"
              exec python ${self}/serve.py --data-dir "$data_dir" "$@"
            '';
          };
          site = pkgs.writeShellApplication {
            name = "baseband-cve-site";
            runtimeInputs = [ python ];
            text = ''
              fetched_dir="''${BASEBAND_CVE_FETCH_DIR:-$PWD/fetched_json}"
              output_dir="''${BASEBAND_CVE_OUTPUT_DIR:-$PWD/outputs}"
              export MPLCONFIGDIR="''${MPLCONFIGDIR:-$PWD/.cache/matplotlib}"
              echo "[Baseband overview 1/3] Acquiring vendor JSON from the pinned CVE List V5 snapshot"
              python ${self}/fetch_json.py \
                --cve-list-dir ${cvelistV5} \
                --merge-dir ${self}/no-checked-in-json \
                --output-dir "$fetched_dir" \
                --offline
              echo "[Baseband overview 2/3] Enriching, plotting, and validating the dataset"
              python ${self}/enrich.py \
                --input-dir "$fetched_dir" \
                --output "$output_dir"
              echo "[Baseband overview 3/3] Starting the local explorer"
              exec python ${self}/serve.py --data-dir "$output_dir" "$@"
            '';
          };
        in
        { inherit pkgs python enrich fetch pipeline serve website site; };
    in
    {
      packages = forAllSystems (system:
        let p = packagesFor system;
        in {
          default = p.pipeline;
          inherit (p) pipeline enrich fetch serve website site;
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
        fetch = {
          type = "app";
          program = "${self.packages.${system}.fetch}/bin/baseband-cve-fetch";
        };
        serve = {
          type = "app";
          program = "${self.packages.${system}.serve}/bin/baseband-cve-serve";
        };
        website = {
          type = "app";
          program = "${self.packages.${system}.website}/bin/baseband-cve-website";
        };
        site = {
          type = "app";
          program = "${self.packages.${system}.site}/bin/baseband-cve-site";
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

    };
}
