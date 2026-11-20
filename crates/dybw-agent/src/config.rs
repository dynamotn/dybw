//! The dybw config file (ADR 0008, profiles §1): the key registry is `dybw-native`'s `resolve`; this adds the
//! choice among profiles.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail, ensure};
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

/// Profile names become directory names under the state and cache dirs, and the file may be synced.
fn check_name(name: &str) -> anyhow::Result<()> {
    let ok =
        (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    ensure!(ok, "profile name {name:?} is not allowed: use 1 to 64 characters of A-Z, a-z, 0-9, `_` and `-`");
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    doc: Table,
    shown: String,
}

impl Config {
    /// Reads the file; a missing file is an empty config (no profile is then defined). Every
    /// `[profiles.*]` section is validated here, used or not.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let doc = read_doc(path)?.unwrap_or_default();
        let config = Config { doc, shown: path.display().to_string() };
        // profiles §1: a misspelt key is always an error, in an unused profile too.
        let names: Vec<String> =
            config.doc.get("profiles").and_then(Value::as_table).into_iter().flat_map(Table::keys).cloned().collect();
        for name in names {
            config.profile(Some(&name))?;
        }
        config.ssh_agent_profiles()?;
        Ok(config)
    }

    /// `[ssh_agent] profiles` (profiles §1 and §8): the profiles whose SSH keys the agent offers, in order; none
    /// without the table. The agent owns the table, so it is checked strictly: no other key, and only defined
    /// profiles.
    pub fn ssh_agent_profiles(&self) -> anyhow::Result<Vec<String>> {
        let shown = &self.shown;
        let Some(table) = self.doc.get("ssh_agent") else { return Ok(Vec::new()) };
        let table = table.as_table().with_context(|| format!("`ssh_agent` in {shown} must be a table"))?;
        if let Some(key) = table.keys().find(|k| *k != "profiles") {
            bail!("unknown key `{key}` in [ssh_agent] in {shown}");
        }
        let Some(list) = table.get("profiles") else { return Ok(Vec::new()) };
        let names = list.as_array().and_then(|a| a.iter().map(|n| n.as_str().map(str::to_owned)).collect());
        let names: Vec<String> =
            names.with_context(|| format!("`profiles` in [ssh_agent] in {shown} must be a list of profile names"))?;
        for name in &names {
            self.profile(Some(name)).context("in [ssh_agent] profiles")?;
        }
        Ok(names)
    }

    /// The profile `name`, else the file's `default`. The file is validated as a whole, and the profile strictly;
    /// other tools' tables, `[bwss]` included, are not read.
    pub fn profile(&self, name: Option<&str>) -> anyhow::Result<Profile> {
        if self.doc.get("bwss").is_some_and(|v| !v.is_table()) {
            bail!("unknown key `bwss` at the top level in {}", self.shown);
        }
        if let Some(name) = name {
            check_name(name)?;
        }
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
        check_name(&account.profile).with_context(|| self.shown.clone())?;
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

    /// How long a `-c` copy stays on the clipboard (a top-level key only; the CLI reads it).
    pub fn clipboard_clear_seconds(&self) -> anyhow::Result<u64> {
        match self.doc.get("clipboard_clear_seconds") {
            None => Ok(DEFAULT_CLIPBOARD_CLEAR_SECONDS),
            Some(v) => v.as_integer().and_then(|n| u64::try_from(n).ok()).with_context(|| {
                format!("`clipboard_clear_seconds` in {} must be a whole number of seconds, not {v}", self.shown)
            }),
        }
    }
}

/// profiles §1.
pub const DEFAULT_CLIPBOARD_CLEAR_SECONDS: u64 = 30;

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
    fn clipboard_clear_seconds_defaults_to_30_and_must_be_a_count() {
        assert_eq!(config("").clipboard_clear_seconds().unwrap(), 30);
        assert_eq!(config("clipboard_clear_seconds = 5").clipboard_clear_seconds().unwrap(), 5);
        for bad in ["clipboard_clear_seconds = -1", "clipboard_clear_seconds = \"5\""] {
            let e = format!("{:#}", config(bad).clipboard_clear_seconds().unwrap_err());
            assert!(e.contains("clipboard_clear_seconds") && e.contains("config.toml"), "{e}");
        }
    }

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
    fn profile_names_are_one_to_64_safe_characters() {
        let long = "a".repeat(65);
        for bad in ["..", "a/b", ".x", "", "a\0b", "a b", long.as_str()] {
            let e = format!("{:#}", config(TWO).profile(Some(bad)).unwrap_err());
            assert!(e.contains("A-Z"), "{bad:?}: {e}");
        }
        for bad in [".x", "a/b", ".."] {
            let e =
                err(&format!("default = \"{bad}\"\n[profiles.\"{bad}\"]\nserver_url = \"u\"\nemail = \"e\"\n"), None);
            assert!(e.contains("A-Z") || e.contains("profile name"), "{bad}: {e}");
        }
        let ok = "default = \"work-2\"\n[profiles.work-2]\nserver_url = \"u\"\nemail = \"e\"\n";
        assert_eq!(config(ok).profile(None).unwrap().name, "work-2");
        assert_eq!(config(&ok.replace("work-2", &"a".repeat(64))).profile(None).unwrap().name.len(), 64);
    }

    #[test]
    fn load_refuses_a_bad_profile_name_even_when_unused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, format!("{TWO}[profiles.\".x\"]\nserver_url = \"u\"\nemail = \"e\"\n")).unwrap();
        assert!(format!("{:#}", Config::load(&path).unwrap_err()).contains("A-Z"));
    }

    #[test]
    fn a_non_table_bwss_is_an_unknown_key_not_overwritten() {
        let e = err(&format!("bwss = 5\n{TWO}"), None);
        assert!(e.contains("unknown key `bwss`"), "{e}");
    }

    #[test]
    fn garbage_bwss_with_password_auth_still_resolves() {
        let c = config(&format!("{TWO}[bwss]\nauth = \"password\"\nbogus = [1]\nprofile = 7\n"));
        let p = c.profile(None).unwrap();
        assert_eq!((p.name.as_str(), p.auth), ("work", Auth::Password));
    }

    #[test]
    fn load_validates_every_profile_even_unused_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, format!("{TWO}[profiles.spare]\nserver_url = \"u\"\nemial = \"e\"\n")).unwrap();
        let e = format!("{:#}", Config::load(&path).unwrap_err());
        assert!(e.contains("unknown key `emial`") && e.contains("spare"), "{e}");
        std::fs::write(&path, format!("{TWO}[profiles.bad]\nx = 1\n")).unwrap();
        assert!(Config::load(&path).is_err());
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
    fn ssh_agent_profiles_are_defined_profiles_and_the_table_is_checked_strictly() {
        assert!(config(TWO).ssh_agent_profiles().unwrap().is_empty());
        assert!(config(&format!("{TWO}[ssh_agent]\n")).ssh_agent_profiles().unwrap().is_empty());
        let both = config(&format!("{TWO}[ssh_agent]\nprofiles = [\"home\", \"work\"]\n"));
        assert_eq!(both.ssh_agent_profiles().unwrap(), ["home", "work"]);
        let e = |extra: &str| format!("{:#}", config(&format!("{TWO}{extra}")).ssh_agent_profiles().unwrap_err());
        let not_table = format!("{:#}", config(&format!("ssh_agent = 1\n{TWO}")).ssh_agent_profiles().unwrap_err());
        assert!(not_table.contains("must be a table"), "{not_table}");
        assert!(e("[ssh_agent]\nprofile = [\"work\"]\n").contains("unknown key `profile` in [ssh_agent]"));
        assert!(e("[ssh_agent]\nprofiles = \"work\"\n").contains("list of profile names"));
        assert!(e("[ssh_agent]\nprofiles = [1]\n").contains("list of profile names"));
        let undefined = e("[ssh_agent]\nprofiles = [\"nope\"]\n");
        assert!(undefined.contains("[ssh_agent] profiles") && undefined.contains("not defined"), "{undefined}");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, format!("{TWO}[ssh_agent]\nprofiles = [\"nope\"]\n")).unwrap();
        assert!(Config::load(&path).is_err(), "checked at load");
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
