{
  description = "Patches the Jackbox Megapicker to launch games from custom directories, with an ASAR integrity check bypass";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      mkModule = import ./nix/module.nix self;
    in
    {
      packages = forAllSystems (pkgs: rec {
        jackbox_megapicker_patcher = pkgs.callPackage ./nix/package.nix { src = self; };
        default = jackbox_megapicker_patcher;
      });

      apps = forAllSystems (
        pkgs:
        let
          patcher = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        in
        {
          default = {
            type = "app";
            program = "${patcher}/bin/jackbox_megapicker_patcher";
          };
          asar_bypass = {
            type = "app";
            program = "${patcher}/bin/asar_bypass";
          };
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.default ];
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
          ];
        };
      });

      # Declarative per-game path configuration. See the README for usage.
      homeManagerModules.default = mkModule {
        installPath = [
          "home"
          "packages"
        ];
        homeManager = true;
      };
      nixosModules.default = mkModule {
        installPath = [
          "environment"
          "systemPackages"
        ];
        homeManager = false;
      };

      formatter = forAllSystems (pkgs: pkgs.nixpkgs-fmt);
    };
}
