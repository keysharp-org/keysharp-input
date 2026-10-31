{
  description = "Privileged Linux input broker";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/e5bdc4a41d4c072fe1e3787eaa0320a384741d44";
  inputs.permissions = {
    url = "github:keysharp-org/keysharp-permissions/1fa566406087483c92b059d11d5657cfe3d5ed18";
    flake = false;
  };

  outputs = { self, nixpkgs, permissions }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.callPackage ./nix/package.nix {
            keysharpPermissionsSource = permissions;
          };
          keysharp-input = self.packages.${system}.default;
        });

      nixosModules.default = { config, lib, pkgs, ... }:
        import ./nix/module.nix {
          inherit config lib pkgs;
          defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };
      nixosModules.keysharp-input = self.nixosModules.default;

      checks = forAllSystems (system: {
        package = self.packages.${system}.default;
      });
    };
}
