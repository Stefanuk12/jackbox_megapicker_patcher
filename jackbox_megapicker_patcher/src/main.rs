use std::{collections::BTreeMap, path::{Path, PathBuf}};

use clap::Parser;
use log::{debug, info, warn};
use once_cell::sync::Lazy;
use regex::{Captures, Regex};

mod error;
use error::*;
#[cfg(feature = "steam-autodetect")]
use steamworks::{AppId, Client};

static REQUIRES_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?ms)(\w+?)\s*?=\s*?require\("(node:path|node:fs|child_process)"\)"#).unwrap());
static ENTITLEMENTS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?ms)if\s*?\(!(\w+?)\.entitlements\s*?\|\|\s*?!(\w+?)\.products\s*?\|\|\s*?!(\w+?)\.storage\)\s*?return\s*?null;.*?const.*?];").unwrap());
static INSTALLED_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)\[(\w+)\.steamId\]\s*?=\s*?\{\s*?isInstalled:\s*?(\w+?),\s*?installDir:\s*?(\w+?)\s*?\}").unwrap());
static LAUNCH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?ms)(\w+)\s*?=\s*?`steam://run/\$\{(\w+)\.data\.steamId}// -launchTo \$\{(\w+)\} -jbg\.config isBundle=false`;(.*?)(if\s*?\(await\s*?(\w+)\.)(.+?)!(\w+)\.user(.+?);").unwrap());

/// Patches the [Jackbox Megapicker](https://store.steampowered.com/app/2828500/The_Jackbox_Megapicker/) to support launching games installed in different directories, includes an ASAR integrity check bypass.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// The path to your Steam install of Jackbox Megapicker.
    ///
    /// If not specified, automatically query Steam for the install location.
    path: Option<PathBuf>,

    /// Map a game's Steam ID to a specific install directory. Repeatable.
    ///
    /// Format: <STEAM_ID>=<PATH>, e.g. --game 3364070=/games/pack11
    ///
    /// Games not listed here fall back to `<MEGAPICKER>/games/<STEAM_ID>`.
    #[arg(short, long = "game", value_name = "STEAM_ID=PATH", value_parser = parse_game_mapping)]
    games: Vec<(String, PathBuf)>,

    /// Extra argument appended to every game's launch command. Repeatable.
    ///
    /// e.g. --launch-arg -fullscreen
    #[arg(short = 'L', long = "launch-arg", value_name = "ARG")]
    launch_args: Vec<String>,

    /// Extra launch argument for a specific game, keyed by Steam ID. Repeatable.
    ///
    /// Format: <STEAM_ID>=<ARG>, e.g. --game-launch-arg 3364070=-fullscreen
    ///
    /// Applied on top of any --launch-arg values for that game.
    #[arg(long = "game-launch-arg", value_name = "STEAM_ID=ARG", value_parser = parse_game_launch_arg)]
    game_launch_args: Vec<(String, String)>,

    /// Disable app.asar patch
    #[arg(short, long)]
    asar: bool,

    /// Disable executable patch
    #[arg(short, long)]
    executable: bool
}

/// Parses a `<STEAM_ID>=<PATH>` game mapping from the command line.
fn parse_game_mapping(s: &str) -> std::result::Result<(String, PathBuf), String> {
    let (id, path) = s
        .split_once('=')
        .ok_or_else(|| format!("invalid mapping `{s}`, expected `<STEAM_ID>=<PATH>`"))?;
    let id = id.trim();
    let path = path.trim();
    if id.is_empty() {
        return Err("the Steam ID cannot be empty".to_string());
    }
    if path.is_empty() {
        return Err("the path cannot be empty".to_string());
    }
    Ok((id.to_string(), PathBuf::from(path)))
}

/// Parses a `<STEAM_ID>=<ARG>` per-game launch argument from the command line.
fn parse_game_launch_arg(s: &str) -> std::result::Result<(String, String), String> {
    let (id, arg) = s
        .split_once('=')
        .ok_or_else(|| format!("invalid mapping `{s}`, expected `<STEAM_ID>=<ARG>`"))?;
    let id = id.trim();

    if id.is_empty() {
        return Err("the Steam ID cannot be empty".to_string());
    }
    if arg.is_empty() {
        return Err("the launch argument cannot be empty".to_string());
    }

    Ok((id.to_string(), arg.to_string()))
}

/// Everything the `main.js` patch needs from the command line.
#[derive(Default)]
struct PatchOptions {
    /// Steam ID -> custom install directory.
    games: Vec<(String, PathBuf)>,
    /// Extra launch arguments applied to every game.
    global_launch_args: Vec<String>,
    /// Steam ID -> extra launch arguments for that game.
    per_game_launch_args: BTreeMap<String, Vec<String>>,
}

/// Debug logging to `resources/jbmp_crash.log` when `JBMP_CRASH_LOG` env var is set.
fn debug_crash_handler() -> &'static str {
    if std::env::var_os("JBMP_CRASH_LOG").is_none() {
        return "";
    }
    r#"try{var __jf=require("node:fs"),__jp=require("node:path"),__jl=__jp.join(process.resourcesPath||".","jbmp_crash.log");__jf.writeFileSync(__jl,"jbmp: handler installed\n");var __jw=function(t,e){try{__jf.appendFileSync(__jl,t+": "+String(e&&e.stack||e)+"\n")}catch(_){}};process.on("uncaughtException",function(e){__jw("EXC",e)});process.on("unhandledRejection",function(e){__jw("REJ",e)});}catch(_){}"#
}

/// Prelude that maps steam id to its path.
fn build_injected_prelude(opts: &PatchOptions) -> Result<String> {
    let mut path_map = BTreeMap::new();
    for (id, path) in &opts.games {
        if path.is_relative() {
            warn!("game {id} maps to relative path {path:?}; an absolute path is recommended");
        }
        if path_map.insert(id.clone(), path.to_string_lossy().into_owned()).is_some() {
            warn!("game {id} mapped more than once; using the last path {path:?}");
        }
    }

    let paths_json = serde_json::to_string(&path_map)?;
    let global_json = serde_json::to_string(&opts.global_launch_args)?;
    let per_game_json = serde_json::to_string(&opts.per_game_launch_args)?;
    let handler = debug_crash_handler();

    Ok(format!(
        "{handler}var __jbmpGamePaths={paths_json};\
         function __jbmpResolveGameDir(steamId){{\
             var k=String(steamId);\
             return Object.prototype.hasOwnProperty.call(__jbmpGamePaths,k)?__jbmpGamePaths[k]:`./games/${{k}}`;\
         }}\
         var __jbmpGlobalArgs={global_json};\
         var __jbmpGameArgs={per_game_json};\
         function __jbmpLaunchArgs(steamId){{\
             var k=String(steamId);\
             var e=Object.prototype.hasOwnProperty.call(__jbmpGameArgs,k)?__jbmpGameArgs[k]:[];\
             return __jbmpGlobalArgs.concat(e);\
         }}\n"
    ))
}

/// Make sure we add any code after the directive.
fn leading_directive_end(s: &str) -> Option<usize> {
    let without_bom = s.strip_prefix('\u{feff}').unwrap_or(s);
    let bom_len = s.len() - without_bom.len();
    let trimmed = without_bom.trim_start();
    let ws_len = without_bom.len() - trimmed.len();

    for directive in ["\"use strict\"", "'use strict'"] {
        if trimmed.starts_with(directive) {
            return Some(bom_len + ws_len + directive.len());
        }
    }

    None
}

/// Returns the capture group at index `i` as a string slice.
fn get_capture_str<'a>(caps: &'a Captures<'_>, i: usize) -> &'a str {
    caps.get(i).map(|x| x.as_str()).unwrap_or_default()
}

/// Patches the `main.js` file to allow the launching of custom game directories and launch options.
fn patch_main_js(main: &mut String, opts: &PatchOptions) -> Result<()> {
    // Inject prelude after directive
    let prelude = build_injected_prelude(opts)?;
    match leading_directive_end(main) {
        Some(at) => main.insert_str(at, &format!(";{prelude}")),
        None => main.insert_str(0, &prelude),
    }
    debug!("Injected game directory and launch argument resolvers");

    // Resolve the imports
    let mut node_path = None;
    let mut node_fs = None;
    let mut child_process = None;
    for caps in REQUIRES_RE.captures_iter(main) {
        let var = get_capture_str(&caps, 1).to_string();
        match get_capture_str(&caps, 2) {
            "node:path" => node_path = Some(var),
            "node:fs" => node_fs = Some(var),
            "child_process" => child_process = Some(var),
            _ => {}
        }
    }
    let (Some(node_path), Some(node_fs), Some(child_process)) =
        (node_path, node_fs, child_process)
    else {
        return Err(Error::RequireMatch);
    };
    debug!("Successfully resolved all requires");

    // Trick the application that you own the installed games
    let func_def = ENTITLEMENTS_RE.captures_iter(main).next().ok_or(Error::EntitlementsMatch)?;
    let func_arg = get_capture_str(&func_def, 1);
    let insert_at = func_def.get_match().end();
    main.insert_str(insert_at, &format!("for (const theProduct of {func_arg}.products){{if ({node_fs}.existsSync(__jbmpResolveGameDir(theProduct.steamId))){{{func_arg}.entitlements.appsOwned.push(theProduct.steamId)}}}}"));
    debug!("Patched entitlements");

    // Mark the application as installed, if we do
    let matched = INSTALLED_RE.captures_iter(main).next().ok_or(Error::InstallationMatch)?;
    let game_var = get_capture_str(&matched, 1);
    let insert_at = matched.get(2).unwrap().end();
    main.insert_str(insert_at, &format!("||{node_fs}.existsSync(__jbmpResolveGameDir({game_var}.steamId))"));
    debug!("Patched installation checks");

    // Modify the launch behaviour to use local files
    let captures = LAUNCH_RE.captures_iter(main).next().ok_or(Error::LaunchMatch)?;
    let url_var = get_capture_str(&captures, 1);
    let game_var = get_capture_str(&captures, 2);
    let target_var = get_capture_str(&captures, 3);
    let electron_var = get_capture_str(&captures, 6);
    let user_var = get_capture_str(&captures, 8);
    let range = captures.get(5).unwrap().start()..captures.get_match().end();
    main.replace_range(range, &format!(r#"
        if (!{user_var}.user) return console.warn("No user. Are you logged in?"), {url_var};
        let exePath = null;
        const gameDir = __jbmpResolveGameDir({game_var}.data.steamId);
        const __jbmpExtraArgs = __jbmpLaunchArgs({game_var}.data.steamId);
        try {{
            const findExe = (dir) => {{
                let list;
                try {{
                    list = {node_fs}.readdirSync(dir, {{ withFileTypes: true }});
                }} catch (err) {{
                    return null;
                }}
                for (const entry of list) {{
                    const p = {node_path}.join(dir, entry.name);
                    if (entry.isFile() && /\.exe$/i.test(entry.name) && !/crashpad_handler\.exe$/i.test(entry.name)) return p;
                }}
                return null;
            }};
            exePath = findExe(gameDir);
        }} catch (err) {{ }}
        // If we found an exe path, spawn it directly with arguments so Windows runs the app
        if (exePath && {node_fs}.existsSync(exePath)) {{
            const args = ["-launchTo", {target_var}, "-jbg.config", "isBundle=false"].concat(__jbmpExtraArgs);

            const exePathResolved = {node_path}.resolve(exePath);
            const child = {child_process}.execFile(exePathResolved, args, {{ detached: true, stdio: "ignore", cwd: {node_path}.resolve(gameDir) }});
        }} else {{
            // No exe found; launch via Steam so it handles the app (overlay, cloud, etc.)
            {url_var} = `steam://run/${{{game_var}.data.steamId}}// -launchTo ${{{target_var}}} -jbg.config isBundle=false` + (__jbmpExtraArgs.length ? " " + __jbmpExtraArgs.join(" ") : "");
            await {electron_var}.shell.openExternal({url_var});
        }}
    "#));
    debug!("Patched launch behaviour");

    Ok(())
}

/// Path components of the entry file inside the asar archive.
const MAIN_JS_PATH: &[&str] = &[".vite", "build", "main.js"];

/// Reads a little-endian `u32` (as `usize`) from `bytes` starting at `at`.
fn read_u32_le(bytes: &[u8], at: usize) -> Result<usize> {
    let slice = bytes.get(at..at + 4).ok_or(Error::AsarMalformed)?;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()) as usize)
}

/// Navigates the asar header tree (`{"files": {name: node, ...}}`) to the file
/// entry at `path`, returning a mutable handle to its object.
fn header_entry_mut<'a>(
    header: &'a mut serde_json::Value,
    path: &[&str],
) -> Option<&'a mut serde_json::Map<String, serde_json::Value>> {
    let mut node = header;
    for name in path {
        node = node.get_mut("files")?.get_mut(*name)?;
    }
    node.as_object_mut()
}

/// Recursively shifts the `offset` of every packed file at or beyond `threshold`
/// by `delta`. Unpacked entries have no offset and are left untouched.
fn shift_offsets(node: &mut serde_json::Value, threshold: usize, delta: i64) {
    let Some(map) = node.as_object_mut() else {
        return;
    };

    if let Some(files) = map.get_mut("files").and_then(|f| f.as_object_mut()) {
        for child in files.values_mut() {
            shift_offsets(child, threshold, delta);
        }
    } else if let Some(offset) = map
        .get("offset")
        .and_then(|o| o.as_str())
        .and_then(|s| s.parse::<usize>().ok())
        && offset >= threshold
    {
        let shifted = (offset as i64 + delta) as usize;
        map.insert("offset".to_string(), serde_json::Value::String(shifted.to_string()));
    }
}

/// Lowercase hex encoding of the SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Computes the `@electron/asar` file integrity for `content`
fn file_integrity(content: &[u8], block_size: usize) -> serde_json::Value {
    let block_size = if block_size == 0 { 4 * 1024 * 1024 } else { block_size };
    serde_json::json!({
        "algorithm": "SHA256",
        "hash": sha256_hex(content),
        "blockSize": block_size,
        "blocks": content.chunks(block_size).map(sha256_hex).collect::<Vec<_>>(),
    })
}

/// Builds the asar header framing (a Chromium `Pickle`) around the header JSON
fn build_asar_header(json: &[u8]) -> Vec<u8> {
    let json_size = json.len() as u32;
    let padding = (4 - (json.len() % 4)) % 4;
    let payload = 4 + json_size + padding as u32; // JSON length prefix + JSON + padding
    let header_size = 4 + payload; // includes the payload-size word
    let mut out = Vec::with_capacity(16 + json.len() + padding);

    out.extend_from_slice(&4u32.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&payload.to_le_bytes());
    out.extend_from_slice(&json_size.to_le_bytes());
    out.extend_from_slice(json);
    out.resize(out.len() + padding, 0);
    out
}

/// Handles the entire process of finding and patching the `app.asar` file.
fn patch_asar(app_path: &Path, opts: &PatchOptions) -> Result<()> {
    let resources = app_path.join("resources");
    let asar_file_path = resources.join("app.asar");
    let asar_bytes = std::fs::read(&asar_file_path)?;
    info!("Read app.asar ({} bytes)", asar_bytes.len());

    // Parse the header
    let header_size = read_u32_le(&asar_bytes, 4)?;
    let json_size = read_u32_le(&asar_bytes, 12)?;
    let json_bytes = asar_bytes.get(16..16 + json_size).ok_or(Error::AsarMalformed)?;
    let mut header: serde_json::Value = serde_json::from_slice(json_bytes)?;
    let data_start = header_size + 8;

    // Locate main.js and read its current bytes out of the data section.
    let entry = header_entry_mut(&mut header, MAIN_JS_PATH).ok_or(Error::MainJsNotFound)?;
    let main_offset = entry
        .get("offset")
        .and_then(|o| o.as_str())
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or(Error::MainJsNotFound)?;
    let main_size = entry
        .get("size")
        .and_then(|s| s.as_u64())
        .ok_or(Error::MainJsNotFound)? as usize;
    let block_size = entry
        .get("integrity")
        .and_then(|it| it.get("blockSize"))
        .and_then(|b| b.as_u64())
        .unwrap_or(4 * 1024 * 1024) as usize;
    let main_start = data_start + main_offset;
    let main_end = main_start.checked_add(main_size).ok_or(Error::AsarMalformed)?;
    let mut data = String::from_utf8_lossy(
        asar_bytes.get(main_start..main_end).ok_or(Error::AsarMalformed)?,
    )
    .to_string();
    info!("Retrieved initial main.js data");

    // Patch main.js.
    patch_main_js(&mut data, opts)?;
    info!("Patched main.js");
    let new_bytes = data.as_bytes();
    let delta = new_bytes.len() as i64 - main_size as i64;

    // Also output the patched `main.js` and a backup of the original `app.asar`.
    std::fs::write(resources.join("main.js"), &data)?;
    std::fs::write(resources.join("app.asar.bak"), &asar_bytes)?;

    // Update the header
    shift_offsets(&mut header, main_offset + main_size, delta);
    let entry = header_entry_mut(&mut header, MAIN_JS_PATH).ok_or(Error::MainJsNotFound)?;
    entry.insert("size".to_string(), serde_json::json!(new_bytes.len()));

    // Recompute main.js's integrity hash
    if entry.contains_key("integrity") {
        entry.insert("integrity".to_string(), file_integrity(new_bytes, block_size));
    }

    // Re-frame the header and splice the new main.js into the data section.
    let new_json = serde_json::to_vec(&header)?;
    let mut out = build_asar_header(&new_json);
    out.extend_from_slice(&asar_bytes[data_start..main_start]);
    out.extend_from_slice(new_bytes);
    out.extend_from_slice(&asar_bytes[main_end..]);
    std::fs::write(&asar_file_path, out)?;
    info!("Finalised the asar write");

    Ok(())
}

/// Resolves the Jackbox Megapicker install directory by querying Steam.
#[cfg(feature = "steam-autodetect")]
fn resolve_install_dir() -> Result<PathBuf> {
    let app_id = AppId(2828500);
    let steamworks_client = Client::init_app(app_id)?;
    let apps = steamworks_client.apps();
    let install_dir = apps.app_install_dir(app_id);
    info!("Resolved application installation from Steam as: {install_dir}");
    Ok(PathBuf::from(install_dir))
}

/// Without Steam auto-detection there is no way to find the install directory,
/// so a path must be provided explicitly.
#[cfg(not(feature = "steam-autodetect"))]
fn resolve_install_dir() -> Result<PathBuf> {
    Err(Error::NoPath)
}

fn run() -> Result<()> {
    // Initialise
    env_logger::init();
    let cli = Cli::parse();

    // Attempt to resolve the path to the application, using steamworks if not provided
    let app_path = match cli.path {
        Some(x) => x,
        None => resolve_install_dir()?,
    };

    // Group the repeatable per-game launch arguments by Steam ID, preserving order.
    let mut per_game_launch_args: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (id, arg) in cli.game_launch_args {
        per_game_launch_args.entry(id).or_default().push(arg);
    }
    let opts = PatchOptions {
        games: cli.games,
        global_launch_args: cli.launch_args,
        per_game_launch_args,
    };

    // Patch whatever
    if !cli.executable {
        let executable_path = app_path.join("The Jackbox Megapicker.exe");
        asar_bypass::patch_file(executable_path, None)?;
        info!("Patched executable.");
    }

    if !cli.asar {
        patch_asar(&app_path, &opts)?;
        info!("Patched asar file.")
    }

    // Done!
    info!("Done!");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{patch_main_js, PatchOptions};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// Builds a `PatchOptions` for the tests from a single mapped game plus
    /// global and per-game launch arguments.
    fn opts_with_launch_args() -> PatchOptions {
        PatchOptions {
            games: vec![("3364070".to_string(), PathBuf::from("/data/pack11"))],
            global_launch_args: vec!["-fullscreen".to_string()],
            per_game_launch_args: BTreeMap::from([(
                "3364070".to_string(),
                vec!["-jbg.config".to_string(), "foo=bar".to_string()],
            )]),
        }
    }

    /// A minimal stand-in for the megapicker's bundled `main.js` that exercises
    /// every regex the patcher relies on.
    const SAMPLE: &str = r#""use strict";
const path = require("node:path");
const fs = require("node:fs");
const cp = require("child_process");

function checkEntitlements(user) {
  if (!user.entitlements || !user.products || !user.storage) return null;
  const owned = [
    ...user.entitlements.appsOwned
  ];
  return owned;
}

function markInstalled(game, state, gameDir) {
  state[game.steamId] = { isInstalled: true, installDir: gameDir };
}

async function launch(game, target, electron, user) {
  let url = `steam://run/${game.data.steamId}// -launchTo ${target} -jbg.config isBundle=false`;
  if (await electron.ready.then(x => x) && !user.user) return url;
  return null;
}
"#;

    #[test]
    fn patches_all_sites_and_injects_resolver() {
        let mut main = SAMPLE.to_string();
        patch_main_js(&mut main, &opts_with_launch_args()).expect("patch should succeed");

        // Resolver injected right after the "use strict" directive (which must
        // stay first so the module keeps strict mode), with the mapping embedded.
        assert!(main.starts_with(r#""use strict";var __jbmpGamePaths="#));
        assert!(main.contains(r#""3364070":"/data/pack11""#));

        // Launch arguments embedded (global list and per-game map).
        assert!(main.contains(r#"var __jbmpGlobalArgs=["-fullscreen"];"#));
        assert!(main.contains(r#"var __jbmpGameArgs={"3364070":["-jbg.config","foo=bar"]};"#));

        // All three call sites now route through the resolver.
        assert!(main.contains("existsSync(__jbmpResolveGameDir(theProduct.steamId))"));
        assert!(main.contains("existsSync(__jbmpResolveGameDir(game.steamId))"));
        assert!(main.contains("const gameDir = __jbmpResolveGameDir(game.data.steamId);"));

        // Launch args are resolved once and appended to both launch paths.
        assert!(main.contains("const __jbmpExtraArgs = __jbmpLaunchArgs(game.data.steamId);"));
        assert!(main.contains(r#"["-launchTo", target, "-jbg.config", "isBundle=false"].concat(__jbmpExtraArgs)"#));

        // The hardcoded `./games/${...}` default now lives only in the resolver.
        assert_eq!(main.matches("`./games/${").count(), 1);

        // Optionally dump the patched output so it can be validated with node.
        if let Ok(p) = std::env::var("JBMP_TEST_OUT") {
            std::fs::write(p, &main).unwrap();
        }
    }

    #[test]
    fn empty_options_still_patches() {
        let mut main = SAMPLE.to_string();
        patch_main_js(&mut main, &PatchOptions::default()).expect("patch should succeed");
        assert!(main.contains("var __jbmpGamePaths={};"));
        assert!(main.contains("var __jbmpGlobalArgs=[];"));
        assert!(main.contains("var __jbmpGameArgs={};"));
    }

    /// Returns true if a `node` binary is on PATH, so the JS-execution test can
    /// skip (rather than fail) on machines without Node installed.
    fn node_available() -> bool {
        std::process::Command::new("node")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Runs the patched `main.js` through Node to confirm the injected code is
    /// syntactically valid JavaScript and that the resolver maps IDs correctly.
    /// This catches escaping/template/coercion regressions the string-`contains`
    /// tests above cannot see. Skipped when Node isn't available.
    #[test]
    fn patched_js_parses_and_resolves() {
        if !node_available() {
            eprintln!("skipping patched_js_parses_and_resolves: `node` not found on PATH");
            return;
        }

        let mut main = SAMPLE.to_string();
        patch_main_js(&mut main, &opts_with_launch_args()).expect("patch should succeed");

        let path = std::env::temp_dir().join(format!("jbmp_patched_{}.js", std::process::id()));
        std::fs::write(&path, &main).expect("write temp file");

        // 1. The whole patched module must parse as valid JavaScript.
        let check = std::process::Command::new("node")
            .arg("--check")
            .arg(&path)
            .output()
            .expect("run node --check");
        assert!(
            check.status.success(),
            "patched main.js is not valid JS:\n{}",
            String::from_utf8_lossy(&check.stderr)
        );

        // 2. The injected resolvers must map known IDs (as string or number),
        //    fall back to `./games/<id>` for anything unmapped, and combine
        //    global + per-game launch arguments (per-game only for mapped IDs).
        let eval = std::process::Command::new("node")
            .arg("-e")
            .arg(
                // The patched module is strict (keeps its "use strict"), so
                // eval'd declarations don't leak; capture them via globalThis.
                "var src=require('fs').readFileSync(process.argv[1], 'utf8');\
                 eval(src + ';globalThis.__R=__jbmpResolveGameDir;globalThis.__L=__jbmpLaunchArgs;');\
                 var R=globalThis.__R, L=globalThis.__L;\
                 process.stdout.write(JSON.stringify([\
                     R('3364070'), R(3364070), R(999), L('3364070'), L(999)]));",
            )
            .arg(&path)
            .output()
            .expect("run node -e");
        let _ = std::fs::remove_file(&path);

        assert!(
            eval.status.success(),
            "evaluating patched main.js failed:\n{}",
            String::from_utf8_lossy(&eval.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&eval.stdout),
            r#"["/data/pack11","/data/pack11","./games/999",["-fullscreen","-jbg.config","foo=bar"],["-fullscreen"]]"#
        );
    }

    #[test]
    fn asar_header_framing_roundtrips() {
        use super::{build_asar_header, read_u32_le};
        let json = br#"{"a":1}"#; // 7 bytes -> 1 byte of padding
        let framed = build_asar_header(json);
        let padding = (4 - (json.len() % 4)) % 4;

        assert_eq!(read_u32_le(&framed, 0).unwrap(), 4); // magic word
        let header_size = read_u32_le(&framed, 4).unwrap();
        assert_eq!(read_u32_le(&framed, 12).unwrap(), json.len()); // json_size word
        // The data section begins at header_size + 8, right after JSON + padding.
        assert_eq!(header_size + 8, 16 + json.len() + padding);
        assert_eq!(&framed[16..16 + json.len()], json);
        assert_eq!(framed.len(), 16 + json.len() + padding);
    }

    #[test]
    fn leading_directive_end_finds_use_strict() {
        use super::leading_directive_end;
        // Offset points just after the directive STRING (before any `;`).
        assert_eq!(leading_directive_end(r#""use strict";var a=1"#), Some(12));
        assert_eq!(leading_directive_end("'use strict';x"), Some(12));
        assert_eq!(leading_directive_end(r#"  "use strict" ;"#), Some(14)); // leading ws
        assert_eq!(leading_directive_end("var a=1"), None); // no directive
        assert_eq!(leading_directive_end("\u{feff}\"use strict\";z"), Some(15)); // 3-byte BOM + 12
    }

    #[test]
    fn integrity_matches_known_sha256() {
        use super::{file_integrity, sha256_hex};
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        // Small content -> single block; top-level hash equals blocks[0].
        let it = file_integrity(b"abc", 4 * 1024 * 1024);
        assert_eq!(it["algorithm"], "SHA256");
        assert_eq!(it["hash"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(it["blocks"][0], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(it["blocks"].as_array().unwrap().len(), 1);
        // 5 bytes with a 2-byte block size -> 3 blocks.
        assert_eq!(file_integrity(b"hello", 2)["blocks"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn shift_offsets_moves_only_packed_after_threshold() {
        use super::shift_offsets;
        let mut header = serde_json::json!({
            "files": {
                "main.js": { "size": 100, "offset": "0" },
                "after.js": { "size": 50, "offset": "100" },
                "native.node": { "size": 999, "unpacked": true },
                "sub": { "files": { "deep.js": { "size": 10, "offset": "150" } } }
            }
        });
        // main.js grows by 20; shift everything that starts at/after offset 100.
        shift_offsets(&mut header, 100, 20);

        assert_eq!(header["files"]["main.js"]["offset"], "0"); // below threshold, untouched
        assert_eq!(header["files"]["after.js"]["offset"], "120"); // shifted
        assert_eq!(header["files"]["sub"]["files"]["deep.js"]["offset"], "170"); // nested, shifted
        assert!(header["files"]["native.node"].get("offset").is_none()); // unpacked, no offset
        assert_eq!(header["files"]["native.node"]["unpacked"], true); // flag preserved
    }
}
