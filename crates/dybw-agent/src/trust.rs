//! The agent's trust anchors (parked from P4.0). `HOME` is taken only when it is an absolute, existing directory
//! owned by the agent's uid and not a symlink, since there is no passwd lookup without `unsafe`. `PATH` is never
//! read: a bare pinentry name is looked up in a fixed list.

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
    trust_for(std::env::var_os("HOME"), user, exe)
}

fn trust_for(home: Option<OsString>, user: User, exe: PathBuf) -> anyhow::Result<Trust> {
    use std::os::unix::fs::MetadataExt;
    refuse_root(&user)?;
    let Some(home) = home.map(PathBuf::from).filter(|h| h.is_absolute()) else {
        bail!("HOME is not set to an absolute path");
    };
    let shown = home.display();
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn me() -> User {
        crate::current_user().unwrap()
    }

    fn try_home(home: Option<&std::path::Path>) -> anyhow::Result<Trust> {
        trust_for(home.map(|h| h.as_os_str().to_owned()), me(), PathBuf::from("/x/bin/dybw-agent"))
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
    fn home_must_be_absolute_present_a_real_directory_and_ours() {
        let dir = tempfile::tempdir().unwrap();
        assert!(err(None).contains("absolute"));
        assert!(err(Some(std::path::Path::new("relative"))).contains("absolute"));
        assert!(err(Some(&dir.path().join("missing"))).contains("HOME"));
        let file = dir.path().join("file");
        std::fs::write(&file, "").unwrap();
        assert!(err(Some(&file)).contains("not a directory"));
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(err(Some(&link)).contains("symbolic link"));
        let stranger = User { uid: std::fs::metadata(dir.path()).unwrap().uid().wrapping_add(1), groups: None };
        let e = trust_for(Some(dir.path().into()), stranger, PathBuf::new()).unwrap_err();
        assert!(format!("{e:#}").contains("not owned"), "{e:#}");
    }

    #[test]
    fn root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = User { uid: 0, groups: None };
        assert!(trust_for(Some(dir.path().into()), root, PathBuf::new()).is_err());
    }

    #[test]
    fn trust_reads_this_process() {
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let expected = trust_for(std::env::var_os("HOME"), me(), exe.clone());
        let got = trust();
        assert_eq!(got.is_ok(), expected.is_ok());
        let seen: Vec<_> =
            got.into_iter().map(|t| (t.exe, t.user, t.search, t.home.is_some_and(|h| h.is_absolute()))).collect();
        let want = (Some(exe), me(), Some(OsString::from(PINENTRY_SEARCH)), true);
        assert!(seen.iter().all(|s| *s == want));
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
