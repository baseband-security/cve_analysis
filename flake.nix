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
        { inherit pkgs python enrich verify fetch pipeline serve site; };
    in
    {
      packages = forAllSystems (system:
        let p = packagesFor system;
        in {
          default = p.pipeline;
          inherit (p) pipeline enrich verify fetch serve site;
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
        serve = {
          type = "app";
          program = "${self.packages.${system}.serve}/bin/baseband-cve-serve";
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

      checks = forAllSystems (system:
        let p = packagesFor system;
        in {
          pipeline = p.pkgs.runCommand "baseband-cve-pipeline-check" {
            nativeBuildInputs = [ p.python p.pkgs.nodejs_22 ];
          } ''
            export MPLCONFIGDIR="$TMPDIR/matplotlib"
            export PYTHONPYCACHEPREFIX="$TMPDIR/pycache"
            test -d ${cvelistV5}/cves
            cd ${self}
            python -m py_compile serve.py
            node --check web/app.js
            test -s web/index.html
            test -s web/styles.css
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
            python serve.py \
              --data-dir "$TMPDIR/generated" \
              --host 127.0.0.1 \
              --port 8123 >"$TMPDIR/server.log" 2>&1 &
            server_pid=$!
            python - <<'PY'
            import json
            import time
            import urllib.request

            for attempt in range(20):
                try:
                    with urllib.request.urlopen("http://127.0.0.1:8123/api/health") as response:
                        assert json.load(response)["status"] == "ok"
                    with urllib.request.urlopen("http://127.0.0.1:8123/data/classification_summary.json") as response:
                        assert json.load(response)["included_memory_safety_cves"] == 590
                    with urllib.request.urlopen("http://127.0.0.1:8123/") as response:
                        assert b"Baseband Memory Safety Bugs Overview" in response.read()
                    break
                except OSError:
                    if attempt == 19:
                        raise
                    time.sleep(0.1)
            PY
            kill "$server_pid"
            touch "$out"
          '';
        });
    };
}
