{
  description = "Library for parsing and analyzing DEX files";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    let
      inherit (inputs.nixpkgs) lib;
      inherit (lib) genAttrs;

      eachSystem =
        f: genAttrs lib.systems.flakeExposed (system: f inputs.nixpkgs.legacyPackages.${system});

      # Fenix only exposes outputs for systems where upstream Rust ships
      # binaries. For arches without fenix coverage, we fall back to nixpkgs's
      # bundled rustc.
      hasFenix = system: inputs.fenix.packages ? ${system};
    in
    {
      devShells = eachSystem (
        pkgs:
        let
          inherit (pkgs.stdenv.hostPlatform) system;
          toolchain =
            if hasFenix system then
              (inputs.fenix.packages.${system}.complete.withComponents [
                "cargo"
                "clippy"
                "rust-src"
                "rustc"
                "rustfmt"
                "rust-analyzer"
              ])
            else
              pkgs.rustc;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.cargo-nextest
              pkgs.nixfmt
              pkgs.taplo
              toolchain
            ];
          };
        }
      );
    };
}
