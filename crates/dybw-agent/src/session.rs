//! What one profile does against the server and the user: API-key login, unlock (online, else from the offline
//! copy), and fetching a fresh `/sync`. The worker calls these and owns the result; nothing here keeps state.
//!
//! The master password and the API key secret live in `Zeroizing` buffers and are dropped right after use. Errors
//! reach the client as the closed [`AgentError`]; the log gets the reason, never a secret.

use std::path::PathBuf;

use dybw_core::api::{ApiError, ApiKey, Client, DeviceInfo, ServerUrls, origin_of, resolve_server_urls};
use dybw_core::crypto::{AwsLcRsa, KdfParams};
use dybw_core::ports::{PortError, Storage};
use dybw_core::profile::{self, CachedSync, ProfileError, UnlockedVault};
use dybw_core::vault::Organizations;
use dybw_native::fsutil::{User, write_private};
use dybw_native::ports::{clock::SystemClock, kdf::BlockingArgon2};
use dybw_native::prompter::{PromptError, one_line};
use dybw_proto::AgentError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::config::{Auth, Profile};
use crate::credentials::Credentials;
use crate::device::device_id_for;
use crate::host::Host;
use crate::paths::ProfilePaths;

/// The server's `DeviceType`: macOS desktop, else Linux desktop.
#[cfg(target_os = "macos")]
const DEVICE_TYPE: u8 = 7;
#[cfg(not(target_os = "macos"))]
const DEVICE_TYPE: u8 = 8;

/// Master password questions per unlock: a wrong one is asked again this many times in all.
const ATTEMPTS: usize = 3;

/// A profile's fixed facts: its settings, where its files are, and who runs the agent.
pub struct Ctx {
    pub profile: Profile,
    pub paths: ProfilePaths,
    pub user: User,
}

impl Ctx {
    /// The ciphertext of the last `/sync`, also the base an offline unlock starts from.
    pub fn cache(&self) -> PathBuf {
        self.paths.cache.join("sync.json")
    }

    /// Unix seconds of the last time the cache was written, which is the last sync.
    pub fn last_sync(&self) -> Option<u64> {
        let modified = std::fs::metadata(self.cache()).and_then(|m| m.modified()).ok()?;
        Some(modified.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs())
    }

    fn storage(&self) -> DirStorage {
        DirStorage(self.paths.state.join("core"))
    }
}

/// The unlocked profile the worker holds: the core's keys and decrypted `/sync`, wiped when it is dropped, and
/// where the server is (no secret), so a sync needs no second look at the configuration.
pub struct Session {
    pub vault: UnlockedVault,
    pub origin: String,
    pub urls: ServerUrls,
}

/// The core's device blobs (KDF pin, security version) as 0600 files in `<state>/core/`.
struct DirStorage(PathBuf);

impl DirStorage {
    fn path(&self, key: &str) -> Result<PathBuf, PortError> {
        let ok = !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b));
        if ok { Ok(self.0.join(key)) } else { Err(PortError("invalid storage key".into())) }
    }
}

fn io(e: std::io::Error) -> PortError {
    PortError(format!("storage: {}", e.kind()))
}

impl Storage for DirStorage {
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, PortError> {
        match std::fs::read(self.path(key)?) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io(e)),
        }
    }

    async fn save(&self, key: &str, data: &[u8]) -> Result<(), PortError> {
        write_private(&self.path(key)?, data).map_err(io)
    }

    async fn remove(&self, key: &str) -> Result<(), PortError> {
        match std::fs::remove_file(self.path(key)?) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io(e)),
            _ => Ok(()),
        }
    }
}

/// KDF parameters as `sync.json` has always stored them (the same file format bwss writes).
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum StoredKdf {
    Pbkdf2 { iterations: u32 },
    Argon2id { iterations: u32, memory_mib: u32, parallelism: u32 },
}

impl From<StoredKdf> for KdfParams {
    fn from(k: StoredKdf) -> Self {
        match k {
            StoredKdf::Pbkdf2 { iterations } => Self::Pbkdf2 { iterations },
            StoredKdf::Argon2id { iterations, memory_mib, parallelism } => {
                Self::Argon2id { iterations, memory_mib, parallelism }
            }
        }
    }
}

/// The KDF the last successful unlock ran: the core's pin (`kdf-pin`) holds exactly it then. The offline unlock of
/// an account without `masterPasswordUnlock` needs it.
// shortcut: reads the core's pin format; use the KDF from `UnlockedVault` once the core reports it.
async fn ran_kdf(storage: &DirStorage) -> Option<StoredKdf> {
    #[derive(Deserialize)]
    struct Pin {
        kdf: u32,
        iterations: u32,
        memory: u32,
        parallelism: u32,
    }
    let pin: Pin = serde_json::from_slice(&storage.load("kdf-pin").await.ok()??).ok()?;
    match pin.kdf {
        0 => Some(StoredKdf::Pbkdf2 { iterations: pin.iterations }),
        1 => Some(StoredKdf::Argon2id {
            iterations: pin.iterations,
            memory_mib: pin.memory,
            parallelism: pin.parallelism,
        }),
        _ => None,
    }
}

/// `sync.json` as read: the ciphertext of the last `/sync`, the KDF of the unlock that wrote it, the account.
#[derive(Deserialize)]
struct Cache {
    #[serde(default)]
    kdf: Option<StoredKdf>,
    email: String,
    sync: Value,
}

/// What `save_cache` writes: `Cache` by reference, so a write never copies the vault.
#[derive(Serialize)]
struct CacheRef<'a> {
    format: u64,
    kdf: Option<StoredKdf>,
    email: &'a str,
    sync: &'a Value,
}

/// The cache of this account; `None` when there is none, it is unreadable, or it is another account's.
fn load_cache(ctx: &Ctx) -> Option<Cache> {
    let raw = match std::fs::read(ctx.cache()) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(profile = %ctx.profile.name, "cannot read the offline copy: {e}");
            return None;
        }
    };
    let cache: Cache = serde_json::from_slice(&raw).ok()?;
    (cache.email == ctx.profile.email).then_some(cache)
}

/// Keeps `sync` for the next offline unlock. A failure is logged: the vault in memory is current either way.
pub(crate) async fn save_cache(ctx: &Ctx, sync: &Value) {
    let kdf = ran_kdf(&ctx.storage()).await;
    let cache = CacheRef { format: 1, kdf, email: &ctx.profile.email, sync };
    let saved = serde_json::to_vec(&cache).map_err(std::io::Error::other).and_then(|b| write_private(&ctx.cache(), &b));
    if let Err(e) = saved {
        tracing::warn!(profile = %ctx.profile.name, "could not write the offline copy: {e}");
    }
}

fn map_api(e: &ApiError) -> AgentError {
    tracing::warn!("server: {e}");
    match e {
        ApiError::Network(_) => AgentError::Network,
        ApiError::Invalid(_) => AgentError::Config,
        _ => AgentError::Server,
    }
}

/// Ask for a secret. A cancel, an empty answer and a timeout are the user's no; anything else is a failed prompt.
async fn ask<H: Host>(host: &H, description: &str, error: Option<&str>) -> Result<Zeroizing<String>, AgentError> {
    match host.password(description, error).await {
        Ok(Some(secret)) if !secret.is_empty() => Ok(secret),
        Ok(_) | Err(PromptError::Timeout) => Err(AgentError::Denied),
        Err(e) => {
            tracing::warn!("prompt: {e}");
            Err(AgentError::Prompt)
        }
    }
}

fn key_of(c: &Credentials) -> ApiKey {
    ApiKey {
        origin: c.identity_origin.clone(),
        client_id: c.client_id.clone(),
        client_secret: Zeroizing::new(c.client_secret.as_str().to_owned()),
    }
}

fn api_auth(ctx: &Ctx) -> Result<(), AgentError> {
    // P4.1 has the API-key flow only; `auth = "password"` (2FA, new-device check) comes later.
    if matches!(ctx.profile.auth, Auth::ApiKey) { Ok(()) } else { Err(AgentError::Config) }
}

fn urls_of(ctx: &Ctx) -> Result<(String, ServerUrls), AgentError> {
    let url = &ctx.profile.server_url;
    let both = origin_of(url).and_then(|origin| Ok((origin, resolve_server_urls(url)?)));
    both.map_err(|e| map_api(&e))
}

/// The stored API key, or `NotLoggedIn` when `dybw login` has not run.
fn stored_key(ctx: &Ctx, origin: &str) -> Result<ApiKey, AgentError> {
    let path = &ctx.paths.credentials;
    if std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Err(AgentError::NotLoggedIn);
    }
    // The error names the file and the rule, never the content.
    let creds = Credentials::load(path, &ctx.user, origin).map_err(|e| {
        tracing::warn!(profile = %ctx.profile.name, "credentials: {e:#}");
        AgentError::Config
    })?;
    Ok(key_of(&creds))
}

fn client<H: Host>(host: &H, ctx: &Ctx, urls: &ServerUrls) -> Result<Client<H::Http, SystemClock>, AgentError> {
    let internal = |what: &str, e: &dyn std::fmt::Display| {
        tracing::warn!(profile = %ctx.profile.name, "{what}: {e}");
        AgentError::Internal
    };
    let http = host.http().map_err(|e| internal("http client", &e))?;
    let identifier = device_id_for(&ctx.paths, ctx.user.uid).map_err(|e| internal("device id", &format!("{e:#}")))?;
    let device = DeviceInfo {
        identifier,
        name: format!("dybw on {}", host.hostname()),
        device_type: DEVICE_TYPE,
        client_name: "dybw".into(),
        client_version: env!("CARGO_PKG_VERSION").into(),
    };
    Client::new(http, SystemClock, urls.clone(), device).map_err(|e| internal("device info", &e))
}

/// Ask for the API key, check it against the server, and store it. Nothing is stored for a key the server refuses
/// or when the server cannot be reached.
pub async fn login<H: Host>(host: &H, ctx: &Ctx) -> Result<(), AgentError> {
    api_auth(ctx)?;
    let (origin, urls) = urls_of(ctx)?;
    let who = format!("dybw profile {} ({})", ctx.profile.name, one_line(&ctx.profile.server_url));
    let client_id = ask(host, &format!("Log in to {who}: API key client_id"), None).await?;
    let client_secret = ask(host, &format!("Log in to {who}: API key client_secret"), None).await?;
    let creds = Credentials { identity_origin: origin, client_id: client_id.as_str().to_owned(), client_secret };
    drop(client_id);
    client(host, ctx, &urls)?.login(&key_of(&creds)).await.map_err(|e| map_api(&e))?;
    creds.store(&ctx.paths.credentials).map_err(|e| {
        tracing::warn!(profile = %ctx.profile.name, "credentials: {e:#}");
        AgentError::Internal
    })
}

/// Why one unlock attempt failed.
enum Refused {
    WrongPassword,
    Failed(AgentError),
}

fn refused(e: ProfileError) -> Refused {
    match e {
        ProfileError::WrongPassword => Refused::WrongPassword,
        ProfileError::Api(e) => Refused::Failed(map_api(&e)),
        ProfileError::Port(e) => {
            tracing::warn!("unlock: {e}");
            Refused::Failed(AgentError::Internal)
        }
        // The core refuses to unlock (weakened KDF, security downgrade, unusable unlock data): what the server
        // offers is not accepted. The text names the problem, never a key.
        e => {
            tracing::warn!("unlock refused: {e}");
            Refused::Failed(AgentError::Server)
        }
    }
}

/// Unlock with the master password from the pinentry: online (login, `/sync`, then the core's checks), and from the
/// offline copy only when the server cannot be reached. A refusal by the server is not "offline".
pub async fn unlock<H: Host>(host: &H, ctx: &Ctx) -> Result<Session, AgentError> {
    api_auth(ctx)?;
    let (origin, urls) = urls_of(ctx)?;
    let key = stored_key(ctx, &origin)?;
    let description = format!("Unlock dybw profile {} ({})", ctx.profile.name, one_line(&ctx.profile.email));
    let mut wrong = None;
    for _ in 0..ATTEMPTS {
        let password = ask(host, &description, wrong).await?;
        match open(host, ctx, &urls, &key, password).await {
            Ok(vault) => return Ok(Session { vault, origin, urls }),
            Err(Refused::WrongPassword) => wrong = Some("Wrong master password."),
            Err(Refused::Failed(e)) => return Err(e),
        }
    }
    Err(AgentError::Denied)
}

async fn open<H: Host>(
    host: &H,
    ctx: &Ctx,
    urls: &ServerUrls,
    key: &ApiKey,
    password: Zeroizing<String>,
) -> Result<UnlockedVault, Refused> {
    let storage = ctx.storage();
    let mut client = client(host, ctx, urls).map_err(Refused::Failed)?;
    let (kdf, rsa, orgs) = (&BlockingArgon2, &AwsLcRsa, &Organizations::None);
    match profile::unlock_vault(&mut client, &storage, key, &ctx.profile.email, password.clone(), kdf, rsa, orgs).await
    {
        Ok(vault) => {
            save_cache(ctx, &vault.sync).await;
            Ok(vault)
        }
        // Only a network that is down: a 4xx or 5xx answer is the server speaking.
        Err(ProfileError::Api(ApiError::Network(why))) => {
            tracing::info!(profile = %ctx.profile.name, "server unreachable ({why}); trying the offline copy");
            let cache = load_cache(ctx).ok_or(Refused::Failed(AgentError::Network))?;
            let cached = CachedSync { sync: cache.sync, prelogin_kdf: cache.kdf.map(Into::into), email: cache.email };
            profile::unlock_vault_cached(cached, &storage, &key.origin, password, kdf, rsa, orgs).await.map_err(refused)
        }
        Err(e) => Err(refused(e)),
    }
}

/// A fresh `/sync` with the stored API key, for the server an unlock opened. The caller installs it, and keeps it
/// with `save_cache`.
pub async fn fetch<H: Host>(host: &H, ctx: &Ctx, origin: &str, urls: &ServerUrls) -> Result<Value, AgentError> {
    let key = stored_key(ctx, origin)?;
    let mut client = client(host, ctx, urls)?;
    client.login(&key).await.map_err(|e| map_api(&e))?;
    client.sync().await.map_err(|e| map_api(&e))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn ctx(dir: &std::path::Path) -> Ctx {
        let profile = Profile {
            name: "work".into(),
            server_url: "https://w.example.org".into(),
            email: "me@example.org".into(),
            auth: Auth::ApiKey,
            lock_timeout: std::time::Duration::ZERO,
            sync_interval: std::time::Duration::ZERO,
            pinentry: "pinentry".into(),
        };
        let paths = ProfilePaths {
            config: dir.join("config.toml"),
            state: dir.join("state"),
            credentials: dir.join("state/credentials"),
            device: dir.join("state/devices/dybw"),
            cache: dir.join("cache"),
        };
        Ctx { profile, paths, user: User { uid: rustix::process::geteuid().as_raw(), groups: None } }
    }

    #[tokio::test]
    async fn the_core_storage_is_private_files_under_valid_keys_only() {
        let dir = tempfile::tempdir().unwrap();
        let storage = ctx(dir.path()).storage();
        assert_eq!(storage.load("k").await.unwrap(), None);
        storage.save("k", b"v").await.unwrap();
        assert_eq!(storage.load("k").await.unwrap(), Some(b"v".to_vec()));
        storage.remove("k").await.unwrap();
        storage.remove("k").await.unwrap();
        for bad in ["", "../x", "a/b", ".hidden"] {
            assert!(storage.save(bad, b"x").await.is_err(), "{bad}");
        }
        // A directory where a blob should be: read and remove fail, and say only what kind of error.
        std::fs::create_dir_all(dir.path().join("state/core/d")).unwrap();
        assert!(storage.load("d").await.unwrap_err().to_string().starts_with("storage: "));
        assert!(storage.remove("d").await.is_err());
    }

    #[tokio::test]
    async fn the_kdf_of_the_last_unlock_is_read_from_the_cores_pin() {
        let dir = tempfile::tempdir().unwrap();
        let storage = ctx(dir.path()).storage();
        assert!(ran_kdf(&storage).await.is_none(), "no pin yet");
        let pin = |kdf: u32| format!(r#"{{"kdf":{kdf},"iterations":3,"memory":64,"parallelism":4,"origin":"o"}}"#);
        storage.save("kdf-pin", pin(1).as_bytes()).await.unwrap();
        let argon = ran_kdf(&storage).await.unwrap();
        assert_eq!(KdfParams::from(argon), KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 });
        storage.save("kdf-pin", pin(0).as_bytes()).await.unwrap();
        assert_eq!(KdfParams::from(ran_kdf(&storage).await.unwrap()), KdfParams::Pbkdf2 { iterations: 3 });
        storage.save("kdf-pin", pin(9).as_bytes()).await.unwrap();
        assert!(ran_kdf(&storage).await.is_none(), "a KDF type this build does not know");
        storage.save("kdf-pin", b"not json").await.unwrap();
        assert!(ran_kdf(&storage).await.is_none(), "an unreadable pin");
    }

    #[tokio::test]
    async fn a_cache_that_cannot_be_written_is_logged_and_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx(dir.path());
        std::fs::write(&ctx.paths.cache, "a file where the directory should be").unwrap();
        save_cache(&ctx, &serde_json::json!({"ciphers": []})).await;
        assert!(load_cache(&ctx).is_none());
        assert_eq!(ctx.last_sync(), None);
    }
}
