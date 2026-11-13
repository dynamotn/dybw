//! Where a profile keeps its files (profiles §1): the XDG layout under the trusted home. No `XDG_*` variable is
//! read: the agent inherits the environment of whoever started it, and that caller must not choose its config,
//! state or cache.

use std::path::{Path, PathBuf};

use crate::config::Profile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePaths {
    /// `<home>/.config/dybw/config.toml`, shared by every profile.
    pub config: PathBuf,
    /// `<home>/.local/state/dybw/profiles/<p>`.
    pub state: PathBuf,
    /// `<state>/credentials`.
    pub credentials: PathBuf,
    /// `<state>/policy.json`: the remembered invokers.
    pub policy: PathBuf,
    /// `<state>/devices/dybw`.
    pub device: PathBuf,
    /// `<home>/.cache/dybw/profiles/<p>`.
    pub cache: PathBuf,
}

impl ProfilePaths {
    /// `home` is the validated one from `trust()`, never the raw `HOME`.
    #[cfg(test)]
    pub fn from_env(profile: &Profile, home: &Path) -> Self {
        Self::with(home, profile)
    }

    /// The locations under `home`.
    pub fn with(home: &Path, profile: &Profile) -> Self {
        let state = home.join(".local/state/dybw/profiles").join(&profile.name);
        ProfilePaths {
            config: config_path(home),
            credentials: state.join("credentials"),
            policy: state.join("policy.json"),
            device: state.join("devices/dybw"),
            cache: home.join(".cache/dybw/profiles").join(&profile.name),
            state,
        }
    }
}

/// `<home>/.local/state/dybw/harnesses.toml`: harnesses to add to the built-in table.
pub fn harnesses_path(home: &Path) -> PathBuf {
    home.join(".local/state/dybw/harnesses.toml")
}

/// `<home>/.local/state/dybw/audit.log`: every value request and policy change, for every profile. Under the
/// trusted home only, never `XDG_STATE_HOME`: the agent inherits the environment of whoever started it, and that
/// caller must not choose where the evidence about it is kept.
pub fn audit_path(home: &Path) -> PathBuf {
    home.join(".local/state/dybw/audit.log")
}

/// `<home>/.config/dybw/config.toml`: the one file every profile shares, known before any profile is.
pub fn config_path(home: &Path) -> PathBuf {
    home.join(".config/dybw/config.toml")
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

    #[test]
    fn everything_is_under_the_trusted_home() {
        // Nothing reads XDG_* or the raw HOME: a caller can set them.
        let p = ProfilePaths::with(Path::new("/h"), &test_profile("w"));
        assert_eq!(p.config, Path::new("/h/.config/dybw/config.toml"));
        assert_eq!(p.state, Path::new("/h/.local/state/dybw/profiles/w"));
        assert_eq!(p.credentials, Path::new("/h/.local/state/dybw/profiles/w/credentials"));
        assert_eq!(p.policy, Path::new("/h/.local/state/dybw/profiles/w/policy.json"));
        assert_eq!(harnesses_path(Path::new("/h")), Path::new("/h/.local/state/dybw/harnesses.toml"));
        assert_eq!(audit_path(Path::new("/h")), Path::new("/h/.local/state/dybw/audit.log"));
        assert_eq!(p.device, Path::new("/h/.local/state/dybw/profiles/w/devices/dybw"));
        assert_eq!(p.cache, Path::new("/h/.cache/dybw/profiles/w"));
    }

    #[test]
    fn from_env_reads_the_process_environment() {
        // Only the shape: the environment of the test run is not ours to set.
        let p = ProfilePaths::from_env(&test_profile("w"), Path::new("/h"));
        assert!(p.credentials.ends_with("dybw/profiles/w/credentials"));
    }
}
