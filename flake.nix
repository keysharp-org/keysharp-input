{
  description = "Privileged Linux input broker";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/e5bdc4a41d4c072fe1e3787eaa0320a384741d44";
  inputs.permissions = {
    url = "github:keysharp-org/keysharp-permissions/b8f31942dd2c286608d390634a9916bffce55ddf";
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

      nixosModules.default = import ./nix/module.nix;
      nixosModules.keysharp-input = self.nixosModules.default;

      checks = forAllSystems (system: {
        package = self.packages.${system}.default;
      });
    };
}
