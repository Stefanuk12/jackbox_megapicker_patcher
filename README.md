# Jackbox Megapicker Patcher

Patches the [Jackbox Megapicker](https://store.steampowered.com/app/2828500/The_Jackbox_Megapicker/) to support launching games installed in different directories, includes an ASAR integrity check bypass.

> [!NOTE]
> The ASAR patcher is AI generated, but I did reverse engineer it myself to figure out how to do it.

## How to use

After running the executable, your game should be patched.
From here, you can input the games inside of `{MEGAPICKER_DIRECTORY}/games/{STEAM_ID}/`

- `MEGAPICKER_DIRECTORY` is where you installed the megapicker, for example: `C:\Program Files (x86)\Steam\steamapps\common\The Jackbox Megapicker`
- `STEAM_ID` is the steam ID for each of the packs/standalone games. For example, the ID of Jackbox Pack 11 is `3364070`

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

1. Go to [https://partner.steamgames.com/downloads/list](Steamworks SDK Releases)
2. You can find the `.dll` within the `./sdk/redistributable_bin/win64` folder inside of the `.zip` file

## Usage

```bash
Usage: jackbox_megapicker_patcher.exe [OPTIONS] [PATH]

Arguments:
  [PATH]
          The path to your Steam install of Jackbox Megapicker.

          If not specified, automatically query Steam for the install location.

Options:
  -a, --asar
          Disable app.asar patch

  -e, --executable
          Disable executable patch

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```
