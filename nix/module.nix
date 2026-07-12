self:
{
  installPath,
  homeManager ? false,
}:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.programs.jackbox-megapicker-patcher;

  # Build the argument list for the patcher from the declarative options.
  pathArgs = lib.optional (cfg.megapickerPath != null) (toString cfg.megapickerPath);
  gameArgs = lib.concatLists (
    lib.mapAttrsToList (steamId: gamePath: [
      "--game"
      "${steamId}=${toString gamePath}"
    ]) cfg.games
  );
  # Global launch arguments applied to every game.
  launchArgsFlags = lib.concatMap (arg: [ "--launch-arg" arg ]) cfg.launchArgs;
  # Per-game launch arguments, one `--game-launch-arg <ID>=<ARG>` per argument.
  gameLaunchArgsFlags = lib.concatLists (
    lib.mapAttrsToList (
      steamId: argList: lib.concatMap (arg: [ "--game-launch-arg" "${steamId}=${arg}" ]) argList
    ) cfg.gameLaunchArgs
  );
  toggleArgs =
    (lib.optional cfg.disableAsarPatch "--asar")
    ++ (lib.optional cfg.disableExecutablePatch "--executable");
  allArgs = pathArgs ++ gameArgs ++ launchArgsFlags ++ gameLaunchArgsFlags ++ toggleArgs ++ cfg.extraArgs;

  wrapper = pkgs.writeShellScriptBin "jackbox-megapicker-patch" ''
    exec ${lib.getExe cfg.package} ${lib.escapeShellArgs allArgs} "$@"
  '';

  # --- autoPatch integration (home-manager only) ----------------------------
  # Absolute path to the pre-configured patch command. Its store path changes
  # whenever any patch input changes (game map, launch args, toggles, path), so
  # it doubles as a content token for "is the applied patch up to date?".
  patchExe = lib.getExe' wrapper "jackbox-megapicker-patch";
  megapicker = toString cfg.megapickerPath; # "" when unset; guarded by an assertion
  asarFile = "${megapicker}/resources/app.asar";
  bakFile = "${asarFile}.bak"; # pristine copy the patcher writes on its first run
  stateFile = "${megapicker}/resources/.jbmp-patch-state"; # records the applied token

  patchGuarded = pkgs.writeShellScript "jackbox-megapicker-patch-guarded" ''
    set -eu
    asar=${lib.escapeShellArg asarFile}
    bak=${lib.escapeShellArg bakFile}
    state=${lib.escapeShellArg stateFile}
    want=${lib.escapeShellArg patchExe}
    grep=${pkgs.gnugrep}/bin/grep

    if [ ! -e "$asar" ]; then
      echo "jackbox: $asar not found; nothing to patch"
      exit 0
    fi

    patched=no
    if "$grep" -qa "__jbmpResolveGameDir" "$asar"; then patched=yes; fi

    have=""
    if [ -e "$state" ]; then have="$(cat "$state")"; fi

    if [ "''${JBMP_FORCE:-0}" != 1 ] && [ "$patched" = yes ] && [ "$have" = "$want" ]; then
      echo "jackbox: app.asar already patched and up to date; skipping"
      exit 0
    fi

    if [ "$patched" = yes ]; then
      if [ ! -e "$bak" ]; then
        echo "jackbox: config changed but $bak is missing; refusing to re-patch an already-patched asar" >&2
        echo "jackbox: verify the game files in Steam to restore app.asar, then re-run" >&2
        exit 1
      fi
      echo "jackbox: config changed; restoring pristine app.asar and re-patching (asar only)"
      cp -f "$bak" "$asar"
      ${patchExe} --executable
    else
      echo "jackbox: patching $asar"
      if ! ${patchExe}; then
        echo "jackbox: full patch failed (exe likely already patched); retrying asar only" >&2
        ${patchExe} --executable
      fi
    fi

    printf '%s\n' "$want" > "$state"
    echo "jackbox: patch complete"
  '';
in
{
  options.programs.jackbox-megapicker-patcher = {
    enable = lib.mkEnableOption "the Jackbox Megapicker patcher command";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "jackbox-megapicker-patcher.packages.\${system}.default";
      description = "The patcher package to install and wrap.";
    };

    megapickerPath = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/home/alice/.local/share/Steam/steamapps/common/The Jackbox Megapicker";
      description = ''
        Path to the Jackbox Megapicker install directory. Steam auto-detection is
        disabled in the Nix build, so this must be set for the generated
        `jackbox-megapicker-patch` command to know what to patch.
      '';
    };

    games = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = lib.literalExpression ''
        {
          "3364070" = "/data/jackbox/pack11"; # The Jackbox Party Pack 11
          "2748040" = "/data/jackbox/pack10"; # The Jackbox Party Pack 10
        }
      '';
      description = ''
        Maps each game's Steam ID to the directory it is installed in. Games that
        are not listed here fall back to `<MEGAPICKER>/games/<STEAM_ID>`.
      '';
    };

    launchArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = lib.literalExpression ''[ "-fullscreen" ]'';
      description = ''
        Extra arguments appended to every game's launch command (on top of the
        `-launchTo`/`-jbg.config` arguments the megapicker already passes).
      '';
    };

    gameLaunchArgs = lib.mkOption {
      type = lib.types.attrsOf (lib.types.listOf lib.types.str);
      default = { };
      example = lib.literalExpression ''
        {
          "3364070" = [ "-fullscreen" ]; # The Jackbox Party Pack 11
        }
      '';
      description = ''
        Extra launch arguments for specific games, keyed by Steam ID. Applied on
        top of `launchArgs` for the matching game.
      '';
    };

    patchCommand = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      internal = true;
      default = lib.getExe' wrapper "jackbox-megapicker-patch";
      defaultText = lib.literalExpression "\${wrapper}/bin/jackbox-megapicker-patch";
      description = ''
        Absolute path to the generated, pre-configured `jackbox-megapicker-patch`
        executable. Exposed so callers (e.g. an activation script or a systemd
        unit that re-patches after a Steam update) can invoke it directly.
      '';
    };

    disableAsarPatch = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Pass `--asar` to skip patching `app.asar`.";
    };

    disableExecutablePatch = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Pass `--executable` to skip patching the executable.";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Extra arguments appended to the generated `jackbox-megapicker-patch` command.";
    };

    autoPatch.enable = lib.mkEnableOption ''
      re-patching the megapicker automatically: on every home-manager activation
      and whenever Steam rewrites `app.asar` (watched by a systemd path unit).
      Re-applies the patch when the configuration changes and restores the
      pristine `app.asar` from the backup first when needed. Home-manager only;
      requires `megapickerPath` to be set'';
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge (
      [
        (lib.setAttrByPath installPath [
          wrapper
          cfg.package
        ])
      ]
      # Only the home-manager module emits the activation/systemd wiring.
      ++ lib.optional homeManager (
        lib.mkIf cfg.autoPatch.enable {
          assertions = [
            {
              assertion = cfg.megapickerPath != null;
              message = "programs.jackbox-megapicker-patcher.autoPatch.enable requires megapickerPath to be set.";
            }
          ];

          # Re-apply on every switch. The guard makes this a no-op when the
          # megapicker is absent or already patched and up to date.
          home.activation.jackboxMegapickerPatch = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
            $DRY_RUN_CMD ${patchGuarded} || true
          '';
          # Start the watcher right after a switch; otherwise it stays dead until
          # the next login.
          home.activation.jackboxMegapickerStartPath = lib.hm.dag.entryAfter [ "reloadSystemd" ] ''
            $DRY_RUN_CMD ${pkgs.systemd}/bin/systemctl --user start jackbox-megapicker-patch.path || true
          '';

          systemd.user.services.jackbox-megapicker-patch = {
            Unit.Description = "Patch the Jackbox Megapicker after a Steam update";
            Service = {
              Type = "oneshot";
              ExecStart = "${patchGuarded}";
            };
          };

          # Steam rewrites app.asar when it updates the megapicker, which wipes
          # the patch; re-patch whenever that happens.
          systemd.user.paths.jackbox-megapicker-patch = {
            Unit.Description = "Watch the Jackbox Megapicker app.asar for changes";
            Path = {
              PathChanged = asarFile;
              Unit = "jackbox-megapicker-patch.service";
            };
            Install.WantedBy = [ "default.target" ];
          };
        }
      )
    )
  );
}
