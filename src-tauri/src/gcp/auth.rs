//! Google access tokens from the files `gcloud auth login` leaves behind, without running gcloud: the config directory as gcloud finds it
//! (`CLOUDSDK_CONFIG`, `~/.config/gcloud`, `%APPDATA%\gcloud`), `legacy_credentials/<account>/adc.json` for a named account, the active
//! account's file and then the application default credentials otherwise, and the refresh-token grant against Google's token endpoint.
//! `credentialed_accounts` lists the accounts that have such a file. Only `authorized_user` credentials are read; tokens are cached in
//! memory and zeroed when dropped, and nothing here writes under gcloud's directory.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::ssh::Secret;

/// Google's OAuth 2.0 token endpoint.
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// A cached token is refreshed when less than this of its life remains (gcloud's `RefreshIfAlmostExpire` window).
const REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const ADC_FILE: &str = "application_default_credentials.json";

/// An access token and the Google account it belongs to.
pub struct Token {
    pub value: Secret,
    pub account: String,
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token").field("account", &self.account).field("value", &"<redacted>").finish()
    }
}

/// Where access tokens come from. `account` names a Google account (an email) or asks for the default one. Called from blocking
/// code (the broker's threads, `spawn_blocking` in the engine); may take a network round trip.
pub trait TokenSource: Send + Sync {
    fn access_token(&self, account: Option<&str>) -> Result<Token, AuthError>;
}

/// Why no token could be had. Every text is a sentence for the person; none carries a secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// No credentials file for the account (or no default one) under gcloud's config directory.
    NoCredentials { account: Option<String>, config_dir: PathBuf },
    /// An `authorized_user` file without an `account` email, which the OS Login calls need.
    NoAccount { path: PathBuf },
    /// A credentials file of a kind Lunport does not use (`service_account`, …).
    Unsupported { path: PathBuf, kind: String },
    /// Not JSON, or missing the fields of an `authorized_user` file.
    Malformed { path: PathBuf },
    /// The refresh token was refused (`invalid_grant`): the person signs in again.
    SignInExpired { account: String },
    /// The token service answered with this status.
    Http { status: u16 },
    /// The token service could not be reached, or answered nonsense.
    Network(String),
}

impl AuthError {
    /// Whether trying again later could help: network trouble and server errors, nothing that needs a person or a file.
    pub fn is_retryable(&self) -> bool {
        match self {
            AuthError::Network(_) => true,
            AuthError::Http { status } => *status >= 500,
            _ => false,
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::NoCredentials { account: Some(account), config_dir } => {
                write!(f, "No Google Cloud credentials for {account} were found under {}; run `gcloud auth login {account}`.", config_dir.display())
            }
            AuthError::NoCredentials { account: None, config_dir } => {
                write!(f, "No Google Cloud credentials were found under {}; run `gcloud auth login`.", config_dir.display())
            }
            AuthError::NoAccount { path } => write!(f, "{} names no Google account; name the account in the host's transport.", path.display()),
            AuthError::Unsupported { path, kind } => {
                write!(f, "{} holds {kind} credentials, which Lunport does not use; sign in with `gcloud auth login`.", path.display())
            }
            AuthError::Malformed { path } => write!(f, "{} is not a credentials file Lunport can read.", path.display()),
            AuthError::SignInExpired { account } => {
                write!(f, "Google sign-in for {account} has expired or was revoked; run `gcloud auth login {account}` and connect again.")
            }
            AuthError::Http { status } => write!(f, "Google's token service answered {status}."),
            AuthError::Network(text) => write!(f, "Google's token service could not be reached: {text}."),
        }
    }
}

impl std::error::Error for AuthError {}

/// gcloud's config directory (`core/config.py`, `_GetGlobalConfigDir`): `CLOUDSDK_CONFIG` when set; else `~/.config/gcloud`; on Windows
/// `%APPDATA%\gcloud`, or `<SystemDrive>\gcloud` (`C:` when even that is unset). `var` reads an environment variable.
pub fn config_dir(var: &dyn Fn(&str) -> Option<String>, home: Option<&Path>, windows: bool) -> PathBuf {
    let set = |name: &str| var(name).filter(|value| !value.is_empty());
    if let Some(custom) = set("CLOUDSDK_CONFIG") {
        return PathBuf::from(custom);
    }
    if !windows {
        return home.map(|home| home.join(".config").join("gcloud")).unwrap_or_else(|| PathBuf::from(".config/gcloud"));
    }
    if let Some(appdata) = set("APPDATA") {
        return PathBuf::from(format!("{appdata}\\gcloud"));
    }
    let drive = set("SystemDrive").unwrap_or_else(|| "C:".to_string());
    PathBuf::from(format!("{drive}\\gcloud"))
}

/// The account gcloud is signed in as: `active_config` names a configuration, whose `[core] account` is it. `None` when either file is
/// missing or has no account.
pub fn active_account(config_dir: &Path) -> Option<String> {
    let name = std::fs::read_to_string(config_dir.join("active_config")).ok()?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let text = std::fs::read_to_string(config_dir.join("configurations").join(format!("config_{name}"))).ok()?;
    ini_value(&text, "core", "account")
}

/// `key` under `[section]` of a gcloud properties file (an INI: `[section]` lines, `key = value` lines, `#`/`;` comments).
fn ini_value(text: &str, section: &str, key: &str) -> Option<String> {
    let mut current = "";
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
            current = name.trim();
            continue;
        }
        if current != section {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            if name.trim() == key {
                let value = value.trim();
                return (!value.is_empty()).then(|| value.to_string());
            }
        }
    }
    None
}

/// `<config dir>/legacy_credentials/<account>/adc.json`, with gcloud's spelling of the directory (`core/config.py`,
/// `LegacyCredentialsDir`): colons dropped, and on Windows a dot in front of the device names it reserves.
pub fn legacy_credentials_path(config_dir: &Path, account: &str) -> PathBuf {
    let mut name = if account.is_empty() { "default".to_string() } else { account.replace(':', "") };
    if cfg!(windows) && starts_with_windows_device(&name) {
        name.insert(0, '.');
    }
    config_dir.join("legacy_credentials").join(name).join("adc.json")
}

/// Whether `name` starts with one of the names Windows reserves for devices (`CON.`, `PRN.`, `AUX.`, `NUL.`, in any case), which
/// gcloud's folder for such an account avoids with a dot in front.
fn starts_with_windows_device(name: &str) -> bool {
    const DEVICES: [&str; 4] = ["CON.", "PRN.", "AUX.", "NUL."];
    let upper = name.to_ascii_uppercase();
    DEVICES.iter().any(|device| upper.starts_with(device))
}

/// The account a `legacy_credentials` folder stands for: `legacy_credentials_path`'s spelling run backwards, so on Windows the dot it puts
/// in front of a reserved device name is taken off again. Any other dot is the account's own, and where no dot was put on none is taken off.
fn account_of_folder(folder: &str, windows: bool) -> &str {
    match folder.strip_prefix('.') {
        Some(rest) if windows && starts_with_windows_device(rest) => rest,
        _ => folder,
    }
}

/// The accounts gcloud holds `authorized_user` credentials for, in order of name: each `legacy_credentials/<folder>/adc.json` of that type,
/// the account being the folder as `legacy_credentials_path` spells it. A folder with no such file (a service account, a file that cannot
/// be read, a stray entry) is not listed, and a directory that is not there lists nothing: this is a look at what is on disk, never an
/// error, and it writes nothing. Only each file's `type` is read.
pub fn credentialed_accounts(config_dir: &Path) -> Vec<String> {
    let Ok(folders) = std::fs::read_dir(config_dir.join("legacy_credentials")) else { return Vec::new() };
    let mut accounts: Vec<String> = folders
        .filter_map(Result::ok)
        .filter_map(|folder| {
            let name = folder.file_name().into_string().ok()?;
            is_authorized_user(&folder.path().join("adc.json")).then(|| account_of_folder(&name, cfg!(windows)).to_string())
        })
        .collect();
    accounts.sort();
    accounts
}

/// Whether the file at `path` is an `authorized_user` credentials file. Its text, which holds the refresh token, is zeroed when this
/// returns, and nothing but the `type` is taken out of it.
fn is_authorized_user(path: &Path) -> bool {
    #[derive(serde::Deserialize)]
    struct Kind {
        r#type: Option<String>,
    }
    let Ok(text) = std::fs::read_to_string(path).map(Zeroizing::new) else { return false };
    serde_json::from_str::<Kind>(&text).is_ok_and(|file| file.r#type.as_deref() == Some("authorized_user"))
}

/// The `User-Agent` Lunport sends to Google.
pub fn user_agent() -> String {
    format!("lunport/{}", env!("CARGO_PKG_VERSION"))
}

/// What an `authorized_user` file holds.
struct Credentials {
    account: String,
    client_id: String,
    client_secret: Secret,
    refresh_token: Secret,
}

/// Reads an `authorized_user` file. `requested` is the account the caller asked for, used when an older legacy file carries no `account`.
fn read_credentials(path: &Path, requested: Option<&str>) -> Result<Credentials, AuthError> {
    let malformed = || AuthError::Malformed { path: path.to_path_buf() };
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|_| malformed())?);
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|_| malformed())?;
    let field = |name: &str| json.get(name).and_then(serde_json::Value::as_str).filter(|value| !value.is_empty());
    match field("type") {
        Some("authorized_user") => {}
        Some(kind) => return Err(AuthError::Unsupported { path: path.to_path_buf(), kind: kind.to_string() }),
        None => return Err(malformed()),
    }
    let account = field("account").map(str::to_string).or_else(|| requested.map(str::to_string)).ok_or(AuthError::NoAccount { path: path.to_path_buf() })?;
    Ok(Credentials {
        account,
        client_id: field("client_id").ok_or_else(malformed)?.to_string(),
        client_secret: Zeroizing::new(field("client_secret").ok_or_else(malformed)?.to_string()),
        refresh_token: Zeroizing::new(field("refresh_token").ok_or_else(malformed)?.to_string()),
    })
}

struct Cached {
    token: Secret,
    account: String,
    expires_at: Instant,
}

/// Tokens from gcloud's credential files, refreshed through Google's token endpoint and cached per file.
pub struct FileStore {
    config_dir: PathBuf,
    /// `GOOGLE_APPLICATION_CREDENTIALS`.
    adc_override: Option<PathBuf>,
    token_url: String,
    http: reqwest::blocking::Client,
    cache: Mutex<HashMap<PathBuf, Cached>>,
}

impl FileStore {
    /// The store for this process: gcloud's directory from the environment and the home directory, Google's token endpoint.
    pub fn from_environment() -> FileStore {
        let var = |name: &str| std::env::var(name).ok();
        let home = dirs::home_dir();
        let dir = config_dir(&var, home.as_deref(), cfg!(windows));
        let adc = var("GOOGLE_APPLICATION_CREDENTIALS").filter(|value| !value.is_empty()).map(PathBuf::from);
        FileStore::new(dir, adc, TOKEN_URL)
    }

    pub fn new(config_dir: PathBuf, adc_override: Option<PathBuf>, token_url: &str) -> FileStore {
        let http = reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .user_agent(user_agent())
            .build()
            .expect("the token client builds from fixed options");
        FileStore { config_dir, adc_override, token_url: token_url.to_string(), http, cache: Mutex::new(HashMap::new()) }
    }

    /// The credentials file for `account`: its legacy file; or, for the default, the active account's legacy file, then the ADC override,
    /// then the ADC file. The first that exists decides.
    fn credentials_file(&self, account: Option<&str>) -> Result<PathBuf, AuthError> {
        let missing = || AuthError::NoCredentials { account: account.map(str::to_string), config_dir: self.config_dir.clone() };
        if let Some(account) = account {
            let path = legacy_credentials_path(&self.config_dir, account);
            return path.is_file().then_some(path).ok_or_else(missing);
        }
        let candidates = [
            active_account(&self.config_dir).map(|active| legacy_credentials_path(&self.config_dir, &active)),
            self.adc_override.clone(),
            Some(self.config_dir.join(ADC_FILE)),
        ];
        candidates.into_iter().flatten().find(|path| path.is_file()).ok_or_else(missing)
    }

    /// The refresh-token grant: the access token and how long it lives.
    fn refresh(&self, credentials: &Credentials) -> Result<(Secret, Duration), AuthError> {
        let form = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("client_id", &credentials.client_id)
                .append_pair("client_secret", &credentials.client_secret)
                .append_pair("refresh_token", &credentials.refresh_token)
                .append_pair("grant_type", "refresh_token")
                .finish(),
        );
        let response = self
            .http
            .post(&self.token_url)
            .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form.as_str().to_string())
            .send()
            .map_err(|error| AuthError::Network(describe(&error)))?;
        let status = response.status().as_u16();
        let body = Zeroizing::new(response.text().map_err(|error| AuthError::Network(describe(&error)))?);
        let json: Option<serde_json::Value> = serde_json::from_str(&body).ok();
        if !(200..300).contains(&status) {
            let code = json.as_ref().and_then(|json| json.get("error")).and_then(serde_json::Value::as_str);
            if code == Some("invalid_grant") {
                return Err(AuthError::SignInExpired { account: credentials.account.clone() });
            }
            return Err(AuthError::Http { status });
        }
        let json = json.ok_or_else(|| AuthError::Network("the token service answered with something other than a token".to_string()))?;
        let token = json
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| AuthError::Network("the token service answered without an access token".to_string()))?;
        let expires_in = json.get("expires_in").and_then(serde_json::Value::as_u64).unwrap_or(3600);
        Ok((Zeroizing::new(token.to_string()), Duration::from_secs(expires_in)))
    }

    /// Pretends the token cached for `path` expires at `at` (tests).
    #[cfg(test)]
    pub(crate) fn set_cached_expiry(&self, path: &Path, at: Instant) {
        if let Some(cached) = self.cache.lock().unwrap_or_else(PoisonError::into_inner).get_mut(path) {
            cached.expires_at = at;
        }
    }
}

/// A reqwest error without the URL it carries (the token endpoint is fixed and the text should stay short).
fn describe(error: &reqwest::Error) -> String {
    let text = error.to_string();
    text.split(" for url").next().unwrap_or(&text).trim_end_matches('.').to_string()
}

impl TokenSource for FileStore {
    fn access_token(&self, account: Option<&str>) -> Result<Token, AuthError> {
        let path = self.credentials_file(account)?;
        {
            let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(cached) = cache.get(&path) {
                if cached.expires_at > Instant::now() + REFRESH_MARGIN {
                    return Ok(Token { value: cached.token.clone(), account: cached.account.clone() });
                }
            }
        }
        let credentials = read_credentials(&path, account)?;
        let (token, lifetime) = self.refresh(&credentials)?;
        let account = credentials.account;
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(path, Cached { token: token.clone(), account: account.clone(), expires_at: Instant::now() + lifetime });
        Ok(Token { value: token, account })
    }
}

/// One fixed token, for tests and fakes. The account is the one asked for, or `static@example.com`.
#[cfg(test)]
pub struct StaticToken(pub String);

#[cfg(test)]
impl TokenSource for StaticToken {
    fn access_token(&self, account: Option<&str>) -> Result<Token, AuthError> {
        Ok(Token { value: Zeroizing::new(self.0.clone()), account: account.unwrap_or("static@example.com").to_string() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    fn write(dir: &Path, relative: &str, text: &str) -> PathBuf {
        let path = dir.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }

    fn authorized_user(account: &str, refresh_token: &str) -> String {
        serde_json::json!({
            "account": account,
            "client_id": "cid.apps.googleusercontent.com",
            "client_secret": "csecret",
            "refresh_token": refresh_token,
            "type": "authorized_user",
            "universe_domain": "googleapis.com"
        })
        .to_string()
    }

    /// Google's token endpoint answering one refresh token with one access token.
    fn token_mock(server: &mut mockito::Server, refresh_token: &str, access_token: &str) -> mockito::Mock {
        server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("grant_type".into(), "refresh_token".into()),
                mockito::Matcher::UrlEncoded("refresh_token".into(), refresh_token.into()),
                mockito::Matcher::UrlEncoded("client_id".into(), "cid.apps.googleusercontent.com".into()),
                mockito::Matcher::UrlEncoded("client_secret".into(), "csecret".into()),
            ]))
            .with_header("content-type", "application/json")
            .with_body(serde_json::json!({"access_token": access_token, "expires_in": 3599, "token_type": "Bearer"}).to_string())
            .create()
    }

    fn store(dir: &Path, adc_override: Option<PathBuf>, server: &mockito::Server) -> FileStore {
        FileStore::new(dir.to_path_buf(), adc_override, &format!("{}/token", server.url()))
    }

    #[test]
    fn the_config_dir_follows_gcloud() {
        let custom = |name: &str| (name == "CLOUDSDK_CONFIG").then(|| "/custom/gcloud".to_string());
        assert_eq!(config_dir(&custom, Some(Path::new("/home/f")), false), PathBuf::from("/custom/gcloud"));
        let none = |_: &str| None;
        assert_eq!(config_dir(&none, Some(Path::new("/home/f")), false), PathBuf::from("/home/f/.config/gcloud"));
        let appdata = |name: &str| (name == "APPDATA").then(|| r"C:\Users\f\AppData\Roaming".to_string());
        assert_eq!(config_dir(&appdata, None, true), PathBuf::from(r"C:\Users\f\AppData\Roaming\gcloud"));
        let drive = |name: &str| (name == "SystemDrive").then(|| "D:".to_string());
        assert_eq!(config_dir(&drive, None, true), PathBuf::from(r"D:\gcloud"));
        assert_eq!(config_dir(&none, None, true), PathBuf::from(r"C:\gcloud"));
    }

    #[test]
    fn the_active_account_is_read_from_the_active_configuration() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(active_account(dir.path()), None, "no active_config yet");
        write(dir.path(), "active_config", "prod\n");
        assert_eq!(active_account(dir.path()), None, "the configuration file is missing");
        write(dir.path(), "configurations/config_prod", "# comment\n[core]\naccount = frank@re-tower.com\nproject = knowknow-prod\n\n[compute]\nzone = asia-east1-b\n");
        assert_eq!(active_account(dir.path()), Some("frank@re-tower.com".to_string()));
        write(dir.path(), "configurations/config_prod", "[core]\nproject = knowknow-prod\n[compute]\naccount = not-core@example.com\n");
        assert_eq!(active_account(dir.path()), None, "only [core] account counts");
        assert_eq!(legacy_credentials_path(dir.path(), "a:b@example.com"), dir.path().join("legacy_credentials").join("ab@example.com").join("adc.json"));
    }

    #[test]
    fn credentialed_accounts_lists_user_folders_and_skips_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "legacy_credentials/frank@example.com/adc.json", &authorized_user("frank@example.com", "r1"));
        write(dir.path(), "legacy_credentials/ops@example.com/adc.json", &authorized_user("ops@example.com", "r2"));
        write(dir.path(), "legacy_credentials/robot/adc.json", r#"{"type":"service_account"}"#);
        // gcloud's view, not a route's: `default` (the folder gcloud uses for an empty account) is listed though it is no email address; the
        // Google Cloud command, which knows what a route can name, keeps only the emails (R32).
        write(dir.path(), "legacy_credentials/default/adc.json", &authorized_user("default", "r3"));
        assert_eq!(credentialed_accounts(dir.path()), ["default", "frank@example.com", "ops@example.com"]);
        let missing = dir.path().join("missing");
        assert!(credentialed_accounts(&missing).is_empty()); // Review Focus 4: no gcloud directory is no accounts, not an error
        assert!(!missing.exists(), "listing reads gcloud's directory and creates nothing");
    }

    /// A folder counts only for an `authorized_user` file it holds: a file that is not one, cannot be read, or is not there lists nothing
    /// (never an error), and the application default credentials are not an account of `legacy_credentials`.
    #[test]
    fn credentialed_accounts_skips_every_folder_without_an_authorized_user_file_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        // Written out of order.
        for account in ["zoe@example.com", "ann@example.com", "mia@example.com"] {
            write(dir.path(), &format!("legacy_credentials/{account}/adc.json"), &authorized_user(account, "rt"));
        }
        write(dir.path(), "legacy_credentials/broken@example.com/adc.json", "{not json");
        write(dir.path(), "legacy_credentials/empty@example.com/adc.json", "");
        write(dir.path(), "legacy_credentials/typeless@example.com/adc.json", r#"{"account":"typeless@example.com","refresh_token":"rt"}"#);
        write(dir.path(), "legacy_credentials/numeric@example.com/adc.json", r#"{"type":5}"#);
        write(dir.path(), "legacy_credentials/other@example.com/adc.json", r#"{"type":"external_account"}"#);
        write(dir.path(), "legacy_credentials/no-adc@example.com/.boto", "[Credentials]\n");
        std::fs::create_dir_all(dir.path().join("legacy_credentials/adc-is-a-folder@example.com/adc.json")).unwrap();
        write(dir.path(), "legacy_credentials/stray-file", "not a folder");
        write(dir.path(), "application_default_credentials.json", &authorized_user("adc@example.com", "rt-adc"));
        assert_eq!(credentialed_accounts(dir.path()), ["ann@example.com", "mia@example.com", "zoe@example.com"]);
        // gcloud's directory with nothing signed in.
        let bare = tempfile::tempdir().unwrap();
        assert!(credentialed_accounts(bare.path()).is_empty());
    }

    /// `credentialed_accounts` is `legacy_credentials_path` read backwards: gcloud's Windows spelling of a reserved device name (a dot in
    /// front) is the same account without the dot, and whatever this platform's `legacy_credentials_path` wrote is listed as the account.
    #[test]
    fn the_folder_of_a_reserved_windows_name_is_read_back_as_the_account() {
        assert_eq!(account_of_folder(".con.x@example.com", true), "con.x@example.com");
        assert_eq!(account_of_folder(".NUL.y@example.com", true), "NUL.y@example.com");
        assert_eq!(account_of_folder(".prn.z@example.com", true), "prn.z@example.com");
        assert_eq!(account_of_folder(".Aux.w@example.com", true), "Aux.w@example.com");
        // Any other leading dot belongs to the account, and where no dot was put on, none is taken off.
        assert_eq!(account_of_folder(".dotted@example.com", true), ".dotted@example.com");
        assert_eq!(account_of_folder("frank@example.com", true), "frank@example.com");
        assert_eq!(account_of_folder(".con.x@example.com", false), ".con.x@example.com");
        // The rule both spellings share: a device name and its dot, in any case, at the start.
        assert!(["con.x", "CON.x", "Prn.x", "aux.x", "NUL.x"].iter().all(|name| starts_with_windows_device(name)));
        assert!(!["console@example.com", "con@example.com", "xcon.x", "nul", "com1.x"].iter().any(|name| starts_with_windows_device(name)));

        let dir = tempfile::tempdir().unwrap();
        for account in ["con.x@example.com", "frank@example.com", "nul.ops@example.com"] {
            let path = legacy_credentials_path(dir.path(), account);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, authorized_user(account, "rt")).unwrap();
        }
        assert_eq!(credentialed_accounts(dir.path()), ["con.x@example.com", "frank@example.com", "nul.ops@example.com"]);
    }

    #[test]
    fn a_named_account_reads_its_legacy_file_and_refreshes_a_token() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "legacy_credentials/frank@retower.io/adc.json", &authorized_user("frank@retower.io", "rt-frank"));
        let mut server = mockito::Server::new();
        let mock = token_mock(&mut server, "rt-frank", "ya29.frank");
        let token = store(dir.path(), None, &server).access_token(Some("frank@retower.io")).unwrap();
        assert_eq!((token.account.as_str(), token.value.as_str()), ("frank@retower.io", "ya29.frank"));
        mock.assert();
    }

    #[test]
    fn a_fresh_token_is_cached_until_five_minutes_before_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "legacy_credentials/frank@retower.io/adc.json", &authorized_user("frank@retower.io", "rt-frank"));
        let mut server = mockito::Server::new();
        let mock = token_mock(&mut server, "rt-frank", "ya29.frank").expect(2);
        let store = store(dir.path(), None, &server);
        store.access_token(Some("frank@retower.io")).unwrap();
        store.access_token(Some("frank@retower.io")).unwrap();
        assert!(!mock.matched(), "the second call was answered from the cache");
        store.set_cached_expiry(&path, Instant::now() + Duration::from_secs(4 * 60));
        store.access_token(Some("frank@retower.io")).unwrap();
        mock.assert();
    }

    #[test]
    fn without_an_account_the_active_accounts_legacy_file_then_the_adc_files_are_used() {
        let mut server = mockito::Server::new();
        token_mock(&mut server, "rt-override", "ya29.override");
        token_mock(&mut server, "rt-adc", "ya29.adc");
        token_mock(&mut server, "rt-active", "ya29.active");

        let dir = tempfile::tempdir().unwrap();
        let override_file = write(dir.path(), "elsewhere/creds.json", &authorized_user("override@example.com", "rt-override"));
        write(dir.path(), "application_default_credentials.json", &authorized_user("adc@example.com", "rt-adc"));
        write(dir.path(), "active_config", "default");
        write(dir.path(), "configurations/config_default", "[core]\naccount = frank@re-tower.com\n");
        write(dir.path(), "legacy_credentials/frank@re-tower.com/adc.json", &authorized_user("frank@re-tower.com", "rt-active"));

        // gcloud's active account first, as the editor promises, even when an ADC override and an ADC file exist.
        let token = store(dir.path(), Some(override_file.clone()), &server).access_token(None).unwrap();
        assert_eq!((token.account.as_str(), token.value.as_str()), ("frank@re-tower.com", "ya29.active"));
        std::fs::remove_file(dir.path().join("active_config")).unwrap();
        let token = store(dir.path(), Some(override_file), &server).access_token(None).unwrap();
        assert_eq!((token.account.as_str(), token.value.as_str()), ("override@example.com", "ya29.override"));
        let token = store(dir.path(), None, &server).access_token(None).unwrap();
        assert_eq!((token.account.as_str(), token.value.as_str()), ("adc@example.com", "ya29.adc"));
    }

    #[test]
    fn an_adc_file_without_an_account_email_asks_for_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "application_default_credentials.json",
            r#"{"client_id":"cid.apps.googleusercontent.com","client_secret":"csecret","refresh_token":"rt-anon","type":"authorized_user"}"#,
        );
        let server = mockito::Server::new();
        let error = store(dir.path(), None, &server).access_token(None).unwrap_err();
        assert_eq!(error, AuthError::NoAccount { path: path.clone() });
        assert_eq!(error.to_string(), format!("{} names no Google account; name the account in the host's transport.", path.display()));
        assert!(!error.is_retryable());
    }

    #[test]
    fn a_missing_active_config_or_other_accounts_credentials_give_no_credentials() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "legacy_credentials/other@example.com/adc.json", &authorized_user("other@example.com", "rt-other"));
        let server = mockito::Server::new();
        let store = store(dir.path(), None, &server);
        assert_eq!(store.access_token(None).unwrap_err(), AuthError::NoCredentials { account: None, config_dir: dir.path().to_path_buf() });
        let named = store.access_token(Some("frank@retower.io")).unwrap_err();
        assert_eq!(named, AuthError::NoCredentials { account: Some("frank@retower.io".into()), config_dir: dir.path().to_path_buf() });
        assert!(named.to_string().contains("gcloud auth login frank@retower.io"), "{named}");
        assert!(!named.is_retryable());
    }

    #[test]
    fn invalid_grant_is_sign_in_expired_and_a_5xx_is_retryable() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "legacy_credentials/expired@example.com/adc.json", &authorized_user("expired@example.com", "rt-expired"));
        write(dir.path(), "legacy_credentials/down@example.com/adc.json", &authorized_user("down@example.com", "rt-down"));
        let mut server = mockito::Server::new();
        server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::UrlEncoded("refresh_token".into(), "rt-expired".into()))
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#)
            .create();
        server.mock("POST", "/token").match_body(mockito::Matcher::UrlEncoded("refresh_token".into(), "rt-down".into())).with_status(503).create();
        let store = store(dir.path(), None, &server);
        let expired = store.access_token(Some("expired@example.com")).unwrap_err();
        assert_eq!(expired, AuthError::SignInExpired { account: "expired@example.com".into() });
        assert!(!expired.is_retryable());
        let down = store.access_token(Some("down@example.com")).unwrap_err();
        assert_eq!(down, AuthError::Http { status: 503 });
        assert!(down.is_retryable());
        assert!(!AuthError::Http { status: 400 }.is_retryable());
        assert!(AuthError::Network("timed out".into()).is_retryable());
    }

    #[test]
    fn a_service_account_or_unreadable_file_is_reported_by_path() {
        let dir = tempfile::tempdir().unwrap();
        let service = write(dir.path(), "legacy_credentials/sa@example.com/adc.json", r#"{"type":"service_account","client_email":"sa@example.com","private_key":"-----BEGIN PRIVATE KEY-----"}"#);
        let broken = write(dir.path(), "legacy_credentials/broken@example.com/adc.json", "{not json");
        let server = mockito::Server::new();
        let store = store(dir.path(), None, &server);
        assert_eq!(store.access_token(Some("sa@example.com")).unwrap_err(), AuthError::Unsupported { path: service, kind: "service_account".into() });
        assert_eq!(store.access_token(Some("broken@example.com")).unwrap_err(), AuthError::Malformed { path: broken });
    }

    #[test]
    fn error_texts_are_the_specs_sentences_and_name_no_secret() {
        let dir = PathBuf::from("/d");
        assert_eq!(
            AuthError::NoCredentials { account: Some("frank@retower.io".into()), config_dir: dir.clone() }.to_string(),
            "No Google Cloud credentials for frank@retower.io were found under /d; run `gcloud auth login frank@retower.io`."
        );
        assert_eq!(AuthError::NoCredentials { account: None, config_dir: dir.clone() }.to_string(), "No Google Cloud credentials were found under /d; run `gcloud auth login`.");
        assert_eq!(
            AuthError::SignInExpired { account: "frank@retower.io".into() }.to_string(),
            "Google sign-in for frank@retower.io has expired or was revoked; run `gcloud auth login frank@retower.io` and connect again."
        );
        assert_eq!(AuthError::Http { status: 503 }.to_string(), "Google's token service answered 503.");
        // The file is named as the platform writes its path (`/d\\x.json` on Windows), so the expectation is built the same way.
        let file = dir.join("x.json");
        assert_eq!(
            AuthError::Unsupported { path: file.clone(), kind: "service_account".into() }.to_string(),
            format!("{} holds service_account credentials, which Lunport does not use; sign in with `gcloud auth login`.", file.display())
        );
        assert_eq!(AuthError::Network("timed out".into()).to_string(), "Google's token service could not be reached: timed out.");
        assert_eq!(AuthError::Malformed { path: file.clone() }.to_string(), format!("{} is not a credentials file Lunport can read.", file.display()));
        let token = StaticToken("ya29.secret".into()).access_token(None).unwrap();
        assert_eq!(token.account, "static@example.com");
        assert!(!format!("{token:?}").contains("ya29.secret"), "a token never prints its value");
    }
}
