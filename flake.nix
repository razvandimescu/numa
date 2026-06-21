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
                # Per-crate hashes come from Cargo.lock, so there is no aggregate
                # cargoHash to recompute on every dep change. Needs nixpkgs >= the
                # 2026-05-27 importCargoLock->static.crates.io migration (PR #524985)
                # to avoid crates.io/api/v1 403s in the build sandbox.
                cargoLock.lockFile = ./Cargo.lock;
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
