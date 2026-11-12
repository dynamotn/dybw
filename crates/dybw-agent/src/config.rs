//! The dybw config file (ADR 0008, profiles §1): the key registry is `dybw-native`'s `resolve`; this adds the
//! choice among profiles.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use dybw_native::config::{read_doc, resolve};
use toml::{Table, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    ApiKey,
    Password,
}

/// One profile with its settings resolved: the profile's own key, else the top level, else the built-in default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub server_url: String,
    pub email: String,
    pub auth: Auth,
    /// Zero means never lock.
    pub lock_timeout: Duration,
    /// Zero means no periodic sync.
    pub sync_interval: Duration,
    /// As written: a program name or an absolute path; see `trust::resolve_pinentry`.
    pub pinentry: String,
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    doc: Table,
    shown: String,
}

impl Config {
    /// Reads the file; a missing file is an empty config (no profile is then defined).
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        Ok(Config { doc: read_doc(path)?.unwrap_or_default(), shown: path.display().to_string() })
    }

    /// The profile `name`, else the file's `default`. The file is validated as a whole, and the profile strictly;
    /// other tools' tables, `[bwss]` included, are not read.
    pub fn profile(&self, name: Option<&str>) -> anyhow::Result<Profile> {
        let mut doc = self.doc.clone();
        // `memory` skips bwss's own `auth` limit; the account is all `resolve` is used for here.
        let mut own = Table::new();
        own.insert("backend".into(), "memory".into());
        if let Some(name) = name {
            own.insert("profile".into(), name.into());
        }
        doc.insert("bwss".into(), Value::Table(own));
        let s = resolve(&doc).with_context(|| self.shown.clone())?;
        let Some(account) = s.account else {
            bail!("no profile: pass -p, set DYBW_PROFILE, or set `default` in {}", self.shown);
        };
        let auth_in = |t: &Table| t.get("auth").and_then(Value::as_str).map(str::to_owned);
        let own = self.doc.get("profiles").and_then(|p| p.get(&account.profile)).and_then(Value::as_table);
        let auth = match own.and_then(auth_in).or_else(|| auth_in(&self.doc)).as_deref() {
            Some("password") => Auth::Password,
            _ => Auth::ApiKey,
        };
        Ok(Profile {
            name: account.profile,
            server_url: account.server_url,
            email: account.email,
            auth,
            lock_timeout: Duration::from_secs(s.lock_timeout_minutes.saturating_mul(60)),
            sync_interval: Duration::from_secs(s.sync_interval_seconds),
            pinentry: s.pinentry,
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use dybw_native::config::{PROFILE_KEYS, TOP_LEVEL_KEYS};

    fn config(text: &str) -> Config {
        Config { doc: toml::from_str(text).unwrap(), shown: "config.toml".into() }
    }

    fn err(text: &str, name: Option<&str>) -> String {
        format!("{:#}", config(text).profile(name).unwrap_err())
    }

    const TWO: &str = "default = \"work\"\nauth = \"password\"\nlock_timeout_minutes = 5\n\
        [profiles.work]\nserver_url = \"https://w.example.org\"\nemail = \"w@example.org\"\n\
        [profiles.home]\nserver_url = \"https://h.example.org\"\nemail = \"h@example.org\"\n\
        auth = \"api-key\"\nlock_timeout_minutes = 0\nsync_interval_seconds = 9\npinentry = \"/bin/sh\"\n";

    #[test]
    fn explicit_profile_beats_default_and_default_beats_nothing() {
        let c = config(TWO);
        assert_eq!(c.profile(None).unwrap().name, "work");
        assert_eq!(c.profile(Some("home")).unwrap().name, "home");
        let e = err("[profiles.a]\nserver_url = \"u\"\nemail = \"e\"\n", None);
        assert!(e.contains("no profile") && e.contains("config.toml"), "{e}");
        assert!(err(TWO, Some("nope")).contains("not defined"));
        assert!(err(TWO, Some("../x")).contains("profile name"));
    }

    #[test]
    fn settings_come_from_the_profile_then_the_top_level_then_the_default() {
        let c = config(TWO);
        let work = c.profile(None).unwrap();
        assert_eq!(
            (work.auth, work.lock_timeout, work.sync_interval, work.pinentry.as_str(), work.email.as_str()),
            (Auth::Password, Duration::from_secs(300), Duration::from_secs(300), "pinentry", "w@example.org")
        );
        let home = c.profile(Some("home")).unwrap();
        assert_eq!(
            (home.auth, home.lock_timeout, home.sync_interval, home.pinentry.as_str(), home.server_url.as_str()),
            (Auth::ApiKey, Duration::ZERO, Duration::from_secs(9), "/bin/sh", "https://h.example.org")
        );
        let bare = config("default = \"a\"\n[profiles.a]\nserver_url = \"u\"\nemail = \"e\"\n").profile(None).unwrap();
        assert_eq!((bare.auth, bare.lock_timeout), (Auth::ApiKey, Duration::from_secs(3600)));
    }

    #[test]
    fn other_tool_tables_are_ignored_even_the_bwss_one() {
        let c = config(&format!("{TWO}[bwss]\nbackend = \"nonsense\"\nprofile = \"home\"\n[other]\nx = 1\n"));
        assert_eq!(c.profile(None).unwrap().name, "work");
    }

    #[test]
    fn every_registry_key_is_accepted_in_its_place_and_refused_elsewhere() {
        let sample = |k: &str| match k {
            "default" => "\"p\"",
            "auth" => "\"api-key\"",
            "pinentry" => "\"pinentry\"",
            "server_url" => "\"u\"",
            "email" => "\"e\"",
            _ => "5",
        };
        let top: String = TOP_LEVEL_KEYS.iter().map(|k| format!("{k} = {}\n", sample(k))).collect();
        let mut own: String = PROFILE_KEYS.iter().map(|k| format!("{k} = {}\n", sample(k))).collect();
        assert_eq!(config(&format!("{top}[profiles.p]\n{own}")).profile(None).unwrap().name, "p");
        for k in TOP_LEVEL_KEYS.iter().filter(|k| !PROFILE_KEYS.contains(k)) {
            let e = err(&format!("[profiles.p]\nserver_url = \"u\"\nemail = \"e\"\n{k} = {}\n", sample(k)), Some("p"));
            assert!(e.contains("top level"), "{k}: {e}");
        }
        for k in PROFILE_KEYS.iter().filter(|k| !TOP_LEVEL_KEYS.contains(k)) {
            let e = err(&format!("{k} = {}\n[profiles.p]\nserver_url = \"u\"\nemail = \"e\"\n", sample(k)), Some("p"));
            assert!(e.contains("belongs in a profile"), "{k}: {e}");
        }
        own.push_str("acl = \"off\"\n");
        assert!(err(&format!("[profiles.p]\n{own}"), Some("p")).contains("acl"));
        assert!(err("acl = \"off\"\n", None).contains("acl"));
        assert!(err("bogus = 1\n", None).contains("unknown key"));
        assert!(err("[profiles.p]\nbogus = 1\nserver_url = \"u\"\nemail = \"e\"\n", Some("p")).contains("unknown key"));
        assert!(err("default = 3\n", None).contains("must be a string"));
        assert!(err("auth = \"sso\"\n", None).contains("auth"));
        assert!(err("lock_timeout_minutes = -1\n", None).contains("negative"));
        assert!(err("pinentry = \"\"\n", None).contains("empty"));
        assert!(err("[profiles.p]\nemail = \"e\"\n", Some("p")).contains("`server_url` is required"));
    }

    #[test]
    fn load_reads_a_file_treats_a_missing_one_as_empty_and_names_a_broken_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert!(format!("{:#}", Config::load(&path).unwrap().profile(None).unwrap_err()).contains("no profile"));
        std::fs::write(&path, TWO).unwrap();
        assert_eq!(Config::load(&path).unwrap().profile(None).unwrap().name, "work");
        std::fs::write(&path, "= broken").unwrap();
        assert!(format!("{:#}", Config::load(&path).unwrap_err()).contains("config.toml"));
        assert!(Config::load(dir.path()).is_err());
    }
}
