{
  description = "Local Recall development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/release-26.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [
              git
              gnupg
              libsecret
              libsodium
              pkg-config
              python314
              shellcheck
              tesseract4
              uv
              zeromq
            ];

            env = {
              PYTHONDONTWRITEBYTECODE = "1";
              PYTHONHASHSEED = "0";
            };

            shellHook = ''
              echo "Local Recall: Python 3.14 target; run ./scripts/check"
            '';
          };
        });
    };
}
