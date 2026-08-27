{
  description = "Reproducible environment for the evidence-aware baseband CVE dataset";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
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
              exec python ${self}/fetch_json.py "$@"
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
            cd ${self}
            python -m unittest -v test_fetch_json.py
            python enrich.py --output "$TMPDIR/generated"
            python verify_outputs.py "$TMPDIR/generated"
            touch "$out"
          '';
        });
    };
}
