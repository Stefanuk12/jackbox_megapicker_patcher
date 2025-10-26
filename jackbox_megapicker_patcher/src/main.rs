use std::{fs::OpenOptions, path::{Path, PathBuf}};

use asar::{AsarReader, AsarWriter};
use clap::Parser;
use log::{debug, info};
use once_cell::sync::Lazy;
use regex::{Captures, Regex};

mod error;
use error::*;
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

    /// Disable app.asar patch
    #[arg(short, long)]
    asar: bool,

    /// Disable executable patch
    #[arg(short, long)]
    executable: bool
}

/// Returns the capture group at index `i` as a string slice.
fn get_capture_str<'a>(caps: &'a Captures<'_>, i: usize) -> &'a str {
    caps.get(i).map(|x| x.as_str()).unwrap_or_default()
}

/// Patches the `main.js` file to allow the launching of custom directories within `./games/{steam_id}`.
fn patch_main_js(main: &mut String) -> Result<()> {
    // Resolve the require names
    let mut node_path = String::new();
    let mut node_fs = String::new();
    let mut child_process = String::new();
    for mat in REQUIRES_RE.captures_iter(&main) {
        match mat.get(2).map(|x| x.as_str()) {
            Some("node:path") => node_path.push_str(get_capture_str(&mat, 1)),
            Some("node:fs") => node_fs.push_str(get_capture_str(&mat, 1)),
            Some("child_process") => child_process.push_str(get_capture_str(&mat, 1)),
            _ => {}
        };
    }

    if node_path.is_empty() || node_fs.is_empty() || child_process.is_empty() {
        return Err(Error::RequireMatch)?;
    }

    debug!("Successfully resolved all requires");

    // Trick the application that you own the installed games
    let func_def = ENTITLEMENTS_RE.captures_iter(&main).next().ok_or(Error::EntitlementsMatch)?;
    let func_arg = get_capture_str(&func_def, 1);
    let insert_at = func_def.get_match().end();
    main.insert_str(insert_at, &format!("for (const theProduct of {func_arg}.products){{if ({node_fs}.existsSync(`./games/${{theProduct.steamId}}`)){{{func_arg}.entitlements.appsOwned.push(theProduct.steamId)}}}}"));
    debug!("Patched entitlements");

    // Mark the application as installed, if we do
    let matched = INSTALLED_RE.captures_iter(&main).next().ok_or(Error::InstallationMatch)?;
    let a = get_capture_str(&matched, 1);
    let n = matched.get(2).unwrap().end();
    main.insert_str(n, &format!("||{node_fs}.existsSync(`./games/${{{a}.steamId}}`)"));
    debug!("Patched installation checks");
    
    // Modify the launch behaviour to use local files
    let captures = LAUNCH_RE.captures_iter(&main).next().ok_or(Error::LaunchMatch)?;
    let s = get_capture_str(&captures, 1);
    let a = get_capture_str(&captures, 2);
    let r = get_capture_str(&captures, 3);
    let u = get_capture_str(&captures, 6);
    let o = get_capture_str(&captures, 8);
    let range = captures.get(5).unwrap().start()..captures.get_match().end();
    main.replace_range(range, &format!(r#"
        if (!{o}.user) return console.warn("No user. Are you logged in?"), {s};
        let exePath = null;
        try {{
            const gameDir = `./games/${{{a}.data.steamId}}`;
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
            const args = ["-launchTo", {r}, "-jbg.config", "isBundle=false"];

            const exePathResolved = {node_path}.resolve(exePath);
            const child = {child_process}.execFile(exePathResolved, args, {{ detached: true, stdio: "ignore", cwd: {node_path}.resolve(`./games/${{{a}.data.steamId}}`) }});
        }} else {{
            // No exe found; launch via Steam so it handles the app (overlay, cloud, etc.)
            {s} = `steam://run/${{{a}.data.steamId}}// -launchTo ${{{r}}} -jbg.config isBundle=false`;
            await {u}.shell.openExternal({s});
        }}
    "#));
    debug!("Patched launch behaviour");

    Ok(())
}

/// Handles the entire process of finding and patching the `app.asar` file.
fn patch_asar(app_path: &Path) -> Result<()> {
    // Read the main asar file
    let resources = app_path.join("resources");
    let asar_file_path = resources.join("app.asar");
    let asar_file = std::fs::read(&asar_file_path)?;
    let asar = AsarReader::new(&asar_file, None)?;
    info!("Successfully opened app.asar");

    // Extract the `main.js` file
    let mainjs_file = PathBuf::from(".vite/build/main.js");
    let mainjs = asar.files().get(&mainjs_file).ok_or(Error::MainJsNotFound)?;
    let mut data = String::from_utf8_lossy(mainjs.data()).to_string();
    info!("Retrieved initial main.js data");

    // Patch the main file
    patch_main_js(&mut data)?;
    info!("Patched main.js");

    // Also output the patched `main.js` file and a backup of the `app.asar` file
    std::fs::write(resources.join("main.js"), &data)?;
    std::fs::write(resources.join("app.asar.bak"), &asar_file)?;

    // Reconstruct the asar with our modified `main.js` file
    let mut writer = AsarWriter::new();
    for (path, file) in asar.files() {
        if *path != mainjs_file {
            writer.write_file(path, file.data(), false)?;
        }
    }
    writer.write_file(mainjs_file, data, false)?;
    
    // Output to file system
    let asar_file_handle = OpenOptions::new().write(true).open(asar_file_path)?;
    writer.finalize(asar_file_handle)?;
    info!("Finalised the asar write");

    Ok(())
}

fn main() -> Result<()> {
    // Initialise
    env_logger::init();
    let cli = Cli::parse();

    // Attempt to resolve the path to the application, using steamworks if not provided
    let app_path = match cli.path {
        Some(x) => x,
        None => {
            let app_id = AppId(2828500);
            let steamworks_client = Client::init_app(app_id)?;
            let apps = steamworks_client.apps();
            let install_dir = apps.app_install_dir(app_id);
            info!("Resolved application installation from Steam as: {install_dir}");
            PathBuf::from(install_dir)
        }
    };

    // Patch whatever
    if !cli.executable {
        let executable_path = app_path.join("The Jackbox Megapicker.exe");
        asar_bypass::patch_file(executable_path, None)?;
        info!("Patched executable.");
    }

    if !cli.asar {
        patch_asar(&app_path)?;
        info!("Patched asar file.")
    }

    // Done!
    info!("Done!");
    Ok(())
}
