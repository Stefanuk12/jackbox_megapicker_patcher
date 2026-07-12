# Jackbox Megapicker Patcher

Patches the [Jackbox Megapicker](https://store.steampowered.com/app/2828500/The_Jackbox_Megapicker/) to support launching games installed in different directories, includes an ASAR integrity check bypass.

> [!NOTE]
> The ASAR patcher is AI generated, but I did reverse engineer it myself to figure out how to do it.

## How to use

After running the executable, your game should be patched.
From here, you can input the games inside of `{MEGAPICKER_DIRECTORY}/games/{STEAM_ID}/`

- `MEGAPICKER_DIRECTORY` is where you installed the megapicker, for example: `C:\Program Files (x86)\Steam\steamapps\common\The Jackbox Megapicker`
- `STEAM_ID` is the steam ID for each of the packs/standalone games. For example, the ID of Jackbox Pack 11 is `3364070`

### Custom directory per game

Instead of placing every game under `{MEGAPICKER_DIRECTORY}/games/{STEAM_ID}/`, you can point individual
games at any directory with the repeatable `--game <STEAM_ID>=<PATH>` option:

```bash
jackbox_megapicker_patcher --game 3364070=/data/jackbox/pack11 --game 2748040=/data/jackbox/pack10
```

Games that aren't listed keep falling back to `{MEGAPICKER_DIRECTORY}/games/{STEAM_ID}/`. Absolute paths
are recommended, as relative paths are resolved against the megapicker's own directory at launch time.

### Custom launch arguments

You can append extra arguments to the command the megapicker uses to launch a game. Use the repeatable
`--launch-arg <ARG>` option to apply an argument to **every** game, and `--game-launch-arg <STEAM_ID>=<ARG>`
to apply one only to a specific game (on top of any global `--launch-arg` values):

```bash
jackbox_megapicker_patcher \
  --launch-arg -fullscreen \
  --game-launch-arg 3364070=-jbg.config --game-launch-arg 3364070=foo=bar
```

These are added after the arguments the megapicker already passes (`-launchTo …`, `-jbg.config isBundle=false`),
both when launching the game's executable directly and when falling back to `steam://run/…`.

> [!NOTE]
> The asar patcher might be unreliable, so you can manually input the patched the `main.js` file to `.vite/build/main.js` inside the `app.asar` file.
>
> 1. Install [7zip](https://www.7-zip.org/) and [this plugin for it](https://www.tc4shell.com/en/7zip/asar/)
> 2. Run the patcher
> 3. Delete `resources/app.asar` and rename the backup file to `resources/app.asar`
> 4. Open `resources/app.asar` inside of 7zip and navigate to `.vite/build`
> 5. Drag over the `main.js` file inside of `resources/main.js` inside of 7zip, you should be prompted to override
> 6. Override the file and close 7zip

## The code execution cannot proceed because steam_api64.dll was not found

You must install the Steamworks SDK and place the `steam_api64.dll` in the same directory as the executable.

1. Go to [Steamworks SDK Releases](https://partner.steamgames.com/downloads/list)
2. Press "Install latest SDK"
3. Extract the downloaded `.zip` file.
4. You can find the `.dll` within the `./sdk/redistributable_bin/win64` folder inside of the extracted folder

## Usage

```bash
Usage: jackbox_megapicker_patcher.exe [OPTIONS] [PATH]

Arguments:
  [PATH]
          The path to your Steam install of Jackbox Megapicker.

          If not specified, automatically query Steam for the install location.

Options:
  -g, --game <STEAM_ID=PATH>
          Map a game's Steam ID to a specific install directory. Repeatable.

          Format: <STEAM_ID>=<PATH>, e.g. --game 3364070=/games/pack11

          Games not listed here fall back to `<MEGAPICKER>/games/<STEAM_ID>`.

  -L, --launch-arg <ARG>
          Extra argument appended to every game's launch command. Repeatable.

          e.g. --launch-arg -fullscreen

      --game-launch-arg <STEAM_ID=ARG>
          Extra launch argument for a specific game, keyed by Steam ID. Repeatable.

          Format: <STEAM_ID>=<ARG>, e.g. --game-launch-arg 3364070=-fullscreen

          Applied on top of any --launch-arg values for that game.

  -a, --asar
          Disable app.asar patch

  -e, --executable
          Disable executable patch

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## NixOS / Nix flake

The repository is a Nix flake. Steam auto-detection is disabled in the Nix build (it would require
`libsteam_api.so` at runtime), so you always pass the megapicker path explicitly.

Build and run the patcher directly:

```bash
nix run github:<owner>/jackbox_megapicker_patcher -- \
  "/path/to/The Jackbox Megapicker" \
  --game 3364070=/data/jackbox/pack11
```

Or, for local development: `nix build`, `nix develop`.

### Declarative configuration (home-manager / NixOS)

Both a home-manager module (`homeManagerModules.default`) and a NixOS module (`nixosModules.default`) are
exposed. They let you declare each game's directory and generate a pre-configured `jackbox-megapicker-patch`
command. Patching mutates the Steam install in place, so the command is **not** run automatically on rebuild —
you run it yourself after (re)installing the megapicker or adding a game.

```nix
# flake.nix
{
  inputs.jackbox.url = "github:<owner>/jackbox_megapicker_patcher";

  # In your home-manager configuration:
  # imports = [ jackbox.homeManagerModules.default ];
  # (or, system-wide: imports = [ jackbox.nixosModules.default ];)

  programs.jackbox-megapicker-patcher = {
    enable = true;
    megapickerPath = "/home/alice/.local/share/Steam/steamapps/common/The Jackbox Megapicker";
    games = {
      "3364070" = "/data/jackbox/pack11"; # The Jackbox Party Pack 11
      "2748040" = "/data/jackbox/pack10"; # The Jackbox Party Pack 10
    };
    launchArgs = [ "-fullscreen" ]; # applied to every game
    gameLaunchArgs = {
      "3364070" = [ "-jbg.config" "foo=bar" ]; # only Pack 11
    };
  };
}
```

Then run `jackbox-megapicker-patch` (the raw `jackbox_megapicker_patcher` binary is installed too).

To re-apply the patch automatically after Steam updates the megapicker, wire the exposed
`config.programs.jackbox-megapicker-patcher.patchCommand` into a `home.activation` script and a
`systemd.user.path` unit watching `<MEGAPICKER>/resources/app.asar`.
