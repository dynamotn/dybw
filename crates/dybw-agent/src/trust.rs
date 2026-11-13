//! The agent's trust anchors (parked from P4.0). The home is this user's in the password database (`dybw-peer`
//! reads it), and must be an absolute, existing directory owned by the agent's uid and not a symlink; a `HOME` that
//! names another directory stops the agent, since whoever started it chose that variable. `PATH` is never read: a
//! bare pinentry name is looked up in a fixed list.

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, bail, ensure};
use dybw_native::config::{Trust, refuse_root};
use dybw_native::fsutil::User;

/// Where a bare `pinentry` name is looked up.
pub const PINENTRY_SEARCH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin";

/// The trust of this process: refuses root and an untrustworthy `HOME`.
pub fn trust() -> anyhow::Result<Trust> {
    let user = crate::current_user().context("cannot tell which user this is")?;
    let exe = std::env::current_exe().and_then(std::fs::canonicalize).context("cannot find this executable")?;
    let passwd = passwd_home(user.uid);
    trust_for(std::env::var_os("HOME"), user, exe, passwd)
}

/// This user's home in the password database, never `HOME`.
///
/// Debug builds only: [`TEST_PASSWD_HOME`] stands in for the database, so the tests can run the agent binary on a
/// home of their own. A release build never reads it.
pub fn passwd_home(uid: u32) -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(home) = std::env::var_os(TEST_PASSWD_HOME) {
        return Some(home.into());
    }
    dybw_peer::home_of(uid)
}

/// The variable a debug build takes as the password database's home (see [`passwd_home`]).
pub const TEST_PASSWD_HOME: &str = "DYBW_TEST_PASSWD_HOME";

/// The trust for `user`, whose home in the password database is `passwd`; `home_var` is the `HOME` this process got.
fn trust_for(home_var: Option<OsString>, user: User, exe: PathBuf, passwd: Option<PathBuf>) -> anyhow::Result<Trust> {
    use std::os::unix::fs::MetadataExt;
    refuse_root(&user)?;
    let Some(home) = passwd else {
        bail!("this user has no home directory in the password database");
    };
    let shown = home.display();
    let real = |p: &std::path::Path| std::fs::canonicalize(p).ok();
    if let Some(var) = home_var.map(PathBuf::from)
        && (real(&var).is_none() || real(&var) != real(&home))
    {
        bail!(
            "HOME {} is not this user's home {shown} (password database): whoever started the agent chose it; \
             start it with the real HOME",
            var.display()
        );
    }
    let meta = std::fs::symlink_metadata(&home).with_context(|| format!("HOME {shown}"))?;
    ensure!(!meta.file_type().is_symlink(), "HOME {shown} is a symbolic link");
    ensure!(meta.is_dir(), "HOME {shown} is not a directory");
    ensure!(meta.uid() == user.uid, "HOME {shown} is not owned by this user");
    let home = std::fs::canonicalize(&home).context(format!("HOME {shown}"))?;
    Ok(Trust { search: Some(PINENTRY_SEARCH.into()), user, exe: Some(exe), home: Some(home) })
}

/// The canonical path of a trusted pinentry, resolved once at start; hand it on as the program name afterwards.
pub fn resolve_pinentry(trust: &Trust, pinentry: &str) -> anyhow::Result<String> {
    Ok(trust.check(pinentry)?.0.to_string_lossy().into_owned())
}

/// `resolve_pinentry` for this process's own trust: what `dybw doctor` shows of a profile's pinentry.
pub fn pinentry_of(pinentry: &str) -> anyhow::Result<String> {
    resolve_pinentry(&trust()?, pinentry)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn me() -> User {
        crate::current_user().unwrap()
    }

    /// `home` is both `HOME` and the password database's home.
    fn try_home(home: Option<&std::path::Path>) -> anyhow::Result<Trust> {
        let var = home.map(|h| h.as_os_str().to_owned());
        trust_for(var, me(), PathBuf::from("/x/bin/dybw-agent"), home.map(PathBuf::from))
    }

    fn err(home: Option<&std::path::Path>) -> String {
        format!("{:#}", try_home(home).unwrap_err())
    }

    #[test]
    fn a_good_home_is_kept_and_path_is_never_the_search() {
        let dir = tempfile::tempdir().unwrap();
        let t = try_home(Some(dir.path())).unwrap();
        assert_eq!(t.home, Some(std::fs::canonicalize(dir.path()).unwrap()));
        assert_eq!(t.search, Some(OsString::from(PINENTRY_SEARCH)));
        assert_eq!(t.user, me());
    }

    #[test]
    fn home_comes_from_the_password_database_and_a_different_home_variable_stops_the_agent() {
        let (real, other) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let start = |var: Option<&std::path::Path>| {
            trust_for(var.map(|v| v.as_os_str().to_owned()), me(), PathBuf::new(), Some(real.path().into()))
        };
        // Unset, or the same directory under another spelling: the database's home.
        let canonical = Some(std::fs::canonicalize(real.path()).unwrap());
        assert_eq!(start(None).unwrap().home, canonical);
        assert_eq!(start(Some(&real.path().join("."))).unwrap().home, canonical);
        // Whoever started the agent pointed HOME elsewhere (or nowhere): refused, naming both.
        // A database home that is not there.
        let gone = trust_for(None, me(), PathBuf::new(), Some(real.path().join("gone"))).unwrap_err();
        assert!(format!("{gone:#}").contains("HOME"), "{gone:#}");
        for var in [other.path().to_owned(), real.path().join("missing"), PathBuf::from("relative")] {
            let e = format!("{:#}", start(Some(&var)).unwrap_err());
            assert!(e.contains("password database") && e.contains(&*var.to_string_lossy()), "{e}");
        }
    }

    #[test]
    fn home_must_be_known_present_a_real_directory_and_ours() {
        let dir = tempfile::tempdir().unwrap();
        assert!(err(None).contains("password database"));
        assert!(err(Some(&dir.path().join("missing"))).contains("HOME"));
        let file = dir.path().join("file");
        std::fs::write(&file, "").unwrap();
        assert!(err(Some(&file)).contains("not a directory"));
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(err(Some(&link)).contains("symbolic link"));
        let stranger = User { uid: std::fs::metadata(dir.path()).unwrap().uid().wrapping_add(1), groups: None };
        let e = trust_for(Some(dir.path().into()), stranger, PathBuf::new(), Some(dir.path().into())).unwrap_err();
        assert!(format!("{e:#}").contains("not owned"), "{e:#}");
    }

    #[test]
    fn root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = User { uid: 0, groups: None };
        assert!(trust_for(Some(dir.path().into()), root, PathBuf::new(), Some(dir.path().into())).is_err());
    }

    #[test]
    fn trust_reads_this_process() {
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let expected = trust_for(std::env::var_os("HOME"), me(), exe.clone(), passwd_home(me().uid));
        let got = trust();
        assert_eq!(got.is_ok(), expected.is_ok());
        let seen: Vec<_> =
            got.into_iter().map(|t| (t.exe, t.user, t.search, t.home.is_some_and(|h| h.is_absolute()))).collect();
        let want = (Some(exe), me(), Some(OsString::from(PINENTRY_SEARCH)), true);
        assert!(seen.iter().all(|s| *s == want));
    }

    #[test]
    fn the_pinentry_of_this_process_is_refused_when_missing() {
        assert!(pinentry_of("dybw-no-such-pinentry").is_err());
    }

    #[test]
    fn pinentry_resolves_against_the_fixed_list_only() {
        let dir = tempfile::tempdir().unwrap();
        let t = try_home(Some(dir.path())).unwrap();
        let e = format!("{:#}", resolve_pinentry(&t, "dybw-no-such-pinentry").unwrap_err());
        assert!(e.contains("not found in PATH"), "{e}");
        // A program this user could replace is refused, a system one is accepted as its canonical path.
        let mine = dir.path().join("pinentry");
        std::fs::write(&mine, "").unwrap();
        assert!(resolve_pinentry(&t, mine.to_str().unwrap()).is_err());
        let sh = resolve_pinentry(&t, "/bin/sh").unwrap();
        assert!(sh.ends_with("sh") && PathBuf::from(&sh).is_absolute());
        assert_eq!(resolve_pinentry(&t, &sh).unwrap(), sh);
    }
}
