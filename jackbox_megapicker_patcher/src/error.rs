#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    AsarBypass(#[from] asar_bypass::Error),
    #[error(transparent)]
    Regex(#[from] regex::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[cfg(feature = "steam-autodetect")]
    #[error(transparent)]
    Steamworks(#[from] steamworks::SteamAPIInitError),

    #[cfg(not(feature = "steam-autodetect"))]
    #[error("no install path provided; pass the path to your Jackbox Megapicker install as an argument")]
    NoPath,
    #[error("the app.asar header is malformed or truncated")]
    AsarMalformed,
    #[error("main.js not found in asar")]
    MainJsNotFound,
    #[error("could not regex match all the requires")]
    RequireMatch,
    #[error("could not regex match the entitlements")]
    EntitlementsMatch,
    #[error("could not regex match the installation check")]
    InstallationMatch,
    #[error("could not regex match the launch behaviour")]
    LaunchMatch,
}

pub type Result<T, E = Error> = core::result::Result<T, E>;