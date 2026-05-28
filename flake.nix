{
  description = "Portable DNS resolver in Rust";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages = rec {
          numa = pkgs.callPackage (
            {
              rustPlatform,
              lib,
            }:
              rustPlatform.buildRustPackage {
                pname = "numa";
                version = (lib.importTOML ./Cargo.toml).package.version;
                src = ./.;
                cargoHash = "sha256-yJdSDSi7qSdJG1f74/DCoEUV8TyaRJQ2hwT5wWSkPtg=";
                meta = {
                  description = "Portable DNS resolver in Rust";
                  homepage = "https://numa.rs";
                  license = lib.licenses.mit;
                };
              }
          ) {};
          default = numa;
        };
        apps = rec {
          numa = flake-utils.lib.mkApp {drv = self.packages.${system}.numa;};
          default = numa;
        };
      }
    );
}
