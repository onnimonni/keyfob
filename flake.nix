{
  description = "Secure Enclave keys for SSH, git and age, unlocked with Touch ID";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.keyfob;
        keyfob = pkgs.callPackage ./package.nix { };
      });

      homeManagerModules.default = import ./home-manager.nix self;
      darwinModules.default = import ./darwin-module.nix self;

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.swift
            pkgs.swiftpm
            pkgs.age
          ];
        };
      });
    };
}
