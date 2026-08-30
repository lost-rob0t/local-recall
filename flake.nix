{
  description = "Local Recall — local-first encrypted desktop activity recall";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/release-26.05";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      overlays.default = final: prev: {
        local-recall = final.callPackage ./nix/package.nix { };
      };

      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          local-recall = pkgs.callPackage ./nix/package.nix { };
          default = self.packages.${system}.local-recall;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages =
              with pkgs;
              [
                git
                libsodium
                pkg-config
                python314
                shellcheck
                tesseract4
                uv
                xprintidle
                zeromq
                self.packages.${system}.local-recall
              ];

            env = {
              PYTHONDONTWRITEBYTECODE = "1";
              PYTHONHASHSEED = "0";
            };

            shellHook = ''
              echo "Local Recall: Python 3.14 target; run ./scripts/check"
            '';
          };
        }
      );

      nixosModules = {
        local-recall = import ./nix/module.nix;
        default = self.nixosModules.local-recall;
      };

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          package = self.packages.${system}.local-recall;
        }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          vm-test = (import ./nix/vm-test.nix { inherit nixpkgs self system; }).vmTest;
        }
      );
    };
}
