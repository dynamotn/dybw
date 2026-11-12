//! Where a profile keeps its files (profiles §1): XDG locations, with the XDG defaults on macOS too.

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::bail;

use crate::config::Profile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePaths {
    /// `$XDG_CONFIG_HOME/dybw/config.toml`, shared by every profile.
    pub config: PathBuf,
    /// `$XDG_STATE_HOME/dybw/profiles/<p>`.
    pub state: PathBuf,
    /// `<state>/credentials`.
    pub credentials: PathBuf,
    /// `<state>/devices/dybw`.
    pub device: PathBuf,
    /// `$XDG_CACHE_HOME/dybw/profiles/<p>`.
    pub cache: PathBuf,
}

impl ProfilePaths {
    pub fn from_env(profile: &Profile) -> anyhow::Result<Self> {
        Self::with(&|var| std::env::var_os(var), profile)
    }

    /// The locations for an environment read through `var`. An XDG variable counts only when absolute; without
    /// it, `HOME` must be absolute.
    pub fn with(var: &dyn Fn(&str) -> Option<OsString>, profile: &Profile) -> anyhow::Result<Self> {
        let xdg = |name: &str, fallback: &str| -> anyhow::Result<PathBuf> {
            if let Some(p) = var(name).map(PathBuf::from).filter(|p| p.is_absolute()) {
                return Ok(p);
            }
            match var("HOME").map(PathBuf::from).filter(|h| h.is_absolute()) {
                Some(home) => Ok(home.join(fallback)),
                None => bail!("neither {name} nor an absolute HOME is set"),
            }
        };
        let state = xdg("XDG_STATE_HOME", ".local/state")?.join("dybw/profiles").join(&profile.name);
        Ok(ProfilePaths {
            config: xdg("XDG_CONFIG_HOME", ".config")?.join("dybw/config.toml"),
            credentials: state.join("credentials"),
            device: state.join("devices/dybw"),
            cache: xdg("XDG_CACHE_HOME", ".cache")?.join("dybw/profiles").join(&profile.name),
            state,
        })
    }
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
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::path::Path;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| OsString::from(v))
    }

    #[test]
    fn xdg_variables_win() {
        let vars = [("XDG_CONFIG_HOME", "/c"), ("XDG_STATE_HOME", "/s"), ("XDG_CACHE_HOME", "/k"), ("HOME", "/h")];
        let p = ProfilePaths::with(&env(&vars), &test_profile("w")).unwrap();
        assert_eq!(p.config, Path::new("/c/dybw/config.toml"));
        assert_eq!(p.state, Path::new("/s/dybw/profiles/w"));
        assert_eq!(p.credentials, Path::new("/s/dybw/profiles/w/credentials"));
        assert_eq!(p.device, Path::new("/s/dybw/profiles/w/devices/dybw"));
        assert_eq!(p.cache, Path::new("/k/dybw/profiles/w"));
    }

    #[test]
    fn home_gives_the_xdg_defaults_and_a_relative_variable_is_ignored() {
        let vars = [("XDG_CONFIG_HOME", "relative"), ("HOME", "/h")];
        let p = ProfilePaths::with(&env(&vars), &test_profile("w")).unwrap();
        assert_eq!(p.config, Path::new("/h/.config/dybw/config.toml"));
        assert_eq!(p.state, Path::new("/h/.local/state/dybw/profiles/w"));
        assert_eq!(p.cache, Path::new("/h/.cache/dybw/profiles/w"));
    }

    #[test]
    fn no_absolute_home_and_no_variable_is_an_error() {
        let e = ProfilePaths::with(&env(&[("HOME", "rel")]), &test_profile("w")).unwrap_err();
        assert!(e.to_string().contains("HOME"), "{e}");
        assert!(ProfilePaths::with(&env(&[]), &test_profile("w")).is_err());
    }

    #[test]
    fn from_env_reads_the_process_environment() {
        // Only the shape: the environment of the test run is not ours to set.
        if let Ok(p) = ProfilePaths::from_env(&test_profile("w")) {
            assert!(p.credentials.ends_with("dybw/profiles/w/credentials"));
        }
    }
}
