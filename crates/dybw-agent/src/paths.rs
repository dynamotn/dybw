//! Where a profile keeps its files (profiles §1): XDG locations, with the XDG defaults on macOS too.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::config::Profile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePaths {
    /// `$XDG_CONFIG_HOME/dybw/config.toml`, shared by every profile.
    pub config: PathBuf,
    /// `$XDG_STATE_HOME/dybw/profiles/<p>`.
    pub state: PathBuf,
    /// `<state>/credentials`.
    pub credentials: PathBuf,
    /// `<state>/policy.json`: the remembered invokers.
    pub policy: PathBuf,
    /// `<state>/devices/dybw`.
    pub device: PathBuf,
    /// `$XDG_CACHE_HOME/dybw/profiles/<p>`.
    pub cache: PathBuf,
}

impl ProfilePaths {
    /// `home` is the validated one from `trust()`, never the raw `HOME`.
    #[cfg(test)]
    pub fn from_env(profile: &Profile, home: &Path) -> Self {
        Self::with(&|var| std::env::var_os(var), home, profile)
    }

    /// The locations for an environment read through `var`. An XDG variable counts only when absolute; the
    /// default is under `home`.
    pub fn with(var: &dyn Fn(&str) -> Option<OsString>, home: &Path, profile: &Profile) -> Self {
        let xdg = |name: &str, fallback: &str| xdg_dir(var, home, name, fallback);
        let state = xdg("XDG_STATE_HOME", ".local/state").join("dybw/profiles").join(&profile.name);
        ProfilePaths {
            config: config_path(var, home),
            credentials: state.join("credentials"),
            policy: state.join("policy.json"),
            device: state.join("devices/dybw"),
            cache: xdg("XDG_CACHE_HOME", ".cache").join("dybw/profiles").join(&profile.name),
            state,
        }
    }
}

fn xdg_dir(var: &dyn Fn(&str) -> Option<OsString>, home: &Path, name: &str, fallback: &str) -> PathBuf {
    var(name).map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| home.join(fallback))
}

/// `$XDG_STATE_HOME/dybw/harnesses.toml`: harnesses to add to the built-in table.
pub fn harnesses_path(var: &dyn Fn(&str) -> Option<OsString>, home: &Path) -> PathBuf {
    xdg_dir(var, home, "XDG_STATE_HOME", ".local/state").join("dybw/harnesses.toml")
}

/// `$XDG_STATE_HOME/dybw/audit.log`: every value request and policy change, for every profile.
pub fn audit_path(var: &dyn Fn(&str) -> Option<OsString>, home: &Path) -> PathBuf {
    xdg_dir(var, home, "XDG_STATE_HOME", ".local/state").join("dybw/audit.log")
}

/// `$XDG_CONFIG_HOME/dybw/config.toml`: the one file every profile shares, known before any profile is.
pub fn config_path(var: &dyn Fn(&str) -> Option<OsString>, home: &Path) -> PathBuf {
    xdg_dir(var, home, "XDG_CONFIG_HOME", ".config").join("dybw/config.toml")
}

#[cfg(test)]
pub(crate) fn test_profile(name: &str) -> Profile {
    Profile {
        name: name.into(),
        server_url: "https://v.example.org".into(),
        email: "e@example.org".into(),
        auth: crate::config::Auth::ApiKey,
        lock_timeout: std::time::Duration::ZERO,
        sync_interval: std::time::Duration::ZERO,
        pinentry: "pinentry".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| OsString::from(v))
    }

    #[test]
    fn xdg_variables_win() {
        let vars = [("XDG_CONFIG_HOME", "/c"), ("XDG_STATE_HOME", "/s"), ("XDG_CACHE_HOME", "/k"), ("HOME", "/raw")];
        let p = ProfilePaths::with(&env(&vars), Path::new("/h"), &test_profile("w"));
        assert_eq!(p.config, Path::new("/c/dybw/config.toml"));
        assert_eq!(p.state, Path::new("/s/dybw/profiles/w"));
        assert_eq!(p.credentials, Path::new("/s/dybw/profiles/w/credentials"));
        assert_eq!(p.policy, Path::new("/s/dybw/profiles/w/policy.json"));
        assert_eq!(harnesses_path(&env(&vars), Path::new("/h")), Path::new("/s/dybw/harnesses.toml"));
        assert_eq!(audit_path(&env(&vars), Path::new("/h")), Path::new("/s/dybw/audit.log"));
        assert_eq!(p.device, Path::new("/s/dybw/profiles/w/devices/dybw"));
        assert_eq!(p.cache, Path::new("/k/dybw/profiles/w"));
    }

    #[test]
    fn defaults_use_the_trusted_home_never_the_raw_one() {
        let vars = [("XDG_CONFIG_HOME", "relative"), ("HOME", "/raw")];
        let p = ProfilePaths::with(&env(&vars), Path::new("/h"), &test_profile("w"));
        assert_eq!(p.config, Path::new("/h/.config/dybw/config.toml"));
        assert_eq!(p.state, Path::new("/h/.local/state/dybw/profiles/w"));
        assert_eq!(p.cache, Path::new("/h/.cache/dybw/profiles/w"));
    }

    #[test]
    fn from_env_reads_the_process_environment() {
        // Only the shape: the environment of the test run is not ours to set.
        let p = ProfilePaths::from_env(&test_profile("w"), Path::new("/h"));
        assert!(p.credentials.ends_with("dybw/profiles/w/credentials"));
    }
}
