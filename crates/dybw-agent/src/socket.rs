//! The agent socket (D6): where it lives, who may reach it, and when an old one may be replaced.

use std::ffi::OsString;
use std::fs::DirBuilder;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};

/// `$XDG_RUNTIME_DIR/dybw`, else `$TMPDIR/dybw-<uid>` (`/tmp` when `TMPDIR` is unset): a directory only this user
/// may use, so the socket inside needs no path-based trust.
pub fn socket_dir(var: &dyn Fn(&str) -> Option<OsString>, uid: u32) -> PathBuf {
    let absolute = |name: &str| var(name).map(PathBuf::from).filter(|p| p.is_absolute());
    match absolute("XDG_RUNTIME_DIR") {
        Some(runtime) => runtime.join("dybw"),
        None => absolute("TMPDIR").unwrap_or_else(|| "/tmp".into()).join(format!("dybw-{uid}")),
    }
}

/// Create `dir` 0700 if it is missing, then require that it is a real directory (not a symlink), owned by `uid`
/// and closed to group and others.
fn ensure_dir(dir: &Path, uid: u32) -> anyhow::Result<()> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != ErrorKind::AlreadyExists => return Err(e).context(format!("create {}", dir.display())),
        _ => {}
    }
    let meta = std::fs::symlink_metadata(dir).context(format!("stat {}", dir.display()))?;
    let shown = dir.display();
    ensure!(!meta.file_type().is_symlink(), "{shown} is a symbolic link");
    ensure!(meta.is_dir(), "{shown} is not a directory");
    ensure!(meta.uid() == uid, "{shown} is not owned by this user");
    ensure!(meta.mode() & 0o077 == 0, "{shown} is open to other users (mode {:o})", meta.mode() & 0o777);
    Ok(())
}

/// Bind `dir/agent.sock`. A live agent on it is refused and left alone; a socket nobody answers on is
/// replaced; anything else at that path is refused.
pub fn bind(dir: &Path, uid: u32) -> anyhow::Result<UnixListener> {
    ensure_dir(dir, uid)?;
    let path = dir.join("agent.sock");
    // A stat error other than "missing" falls through to the bind, which then fails on its own.
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        ensure!(meta.file_type().is_socket() && meta.uid() == uid, "{} is not this user's socket", path.display());
        ensure!(UnixStream::connect(&path).is_err(), "dybw-agent is already running on {}", path.display());
        std::fs::remove_file(&path).context(format!("remove stale {}", path.display()))?;
    }
    let listener = UnixListener::bind(&path).context(format!("bind {}", path.display()))?;
    std::fs::set_permissions(&path, PermissionsExt::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn err(r: anyhow::Result<UnixListener>) -> String {
        format!("{:#}", r.unwrap_err())
    }

    /// A short base path: a socket path is limited to about 100 bytes.
    fn base() -> tempfile::TempDir {
        tempfile::Builder::new().prefix("d").tempdir_in("/tmp").unwrap()
    }

    #[test]
    fn the_directory_follows_xdg_runtime_dir_then_tmpdir() {
        let env = |pairs: &'static [(&str, &str)]| {
            move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| OsString::from(v))
        };
        assert_eq!(socket_dir(&env(&[("XDG_RUNTIME_DIR", "/run/u/1")]), 7), PathBuf::from("/run/u/1/dybw"));
        assert_eq!(socket_dir(&env(&[("TMPDIR", "/var/t")]), 7), PathBuf::from("/var/t/dybw-7"));
        assert_eq!(socket_dir(&env(&[("XDG_RUNTIME_DIR", "run"), ("TMPDIR", "t")]), 7), PathBuf::from("/tmp/dybw-7"));
    }

    #[test]
    fn a_new_directory_is_0700_and_the_socket_0600() {
        let base = base();
        let dir = base.path().join("dybw");
        let _listener = bind(&dir, me()).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(dir.join("agent.sock")).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn the_directory_must_be_ours_closed_and_real() {
        let base = base();
        let dir = base.path().join("dybw");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o755)).unwrap();
        assert!(err(bind(&dir, me())).contains("open to other users"));
        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o700)).unwrap();
        assert!(err(bind(&dir, me() + 1)).contains("not owned"));
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(err(bind(&link, me())).contains("symbolic link"));
        let file = base.path().join("file");
        std::fs::write(&file, "").unwrap();
        assert!(err(bind(&file, me())).contains("not a directory"));
        assert!(err(bind(&base.path().join("a/b/c"), me())).contains("create"));
    }

    #[test]
    fn a_live_agent_is_refused_and_keeps_its_socket() {
        let base = base();
        let dir = base.path().join("dybw");
        let live = bind(&dir, me()).unwrap();
        assert!(err(bind(&dir, me())).contains("already running"));
        // The first agent still owns the path and still accepts.
        let client = UnixStream::connect(dir.join("agent.sock")).unwrap();
        live.set_nonblocking(false).unwrap();
        assert!(live.accept().is_ok());
        drop(client);
    }

    #[test]
    fn a_stale_socket_is_replaced_and_a_stranger_at_the_path_is_not() {
        let base = base();
        let dir = base.path().join("dybw");
        drop(bind(&dir, me()).unwrap());
        assert!(dir.join("agent.sock").exists(), "closing a listener leaves the file behind");
        let _fresh = bind(&dir, me()).unwrap();

        let other = base.path().join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::set_permissions(&other, PermissionsExt::from_mode(0o700)).unwrap();
        std::fs::write(other.join("agent.sock"), "").unwrap();
        assert!(err(bind(&other, me())).contains("not this user's socket"));
        let dir_as_sock = base.path().join("third");
        std::fs::create_dir_all(dir_as_sock.join("agent.sock/x")).unwrap();
        std::fs::set_permissions(&dir_as_sock, PermissionsExt::from_mode(0o700)).unwrap();
        assert!(err(bind(&dir_as_sock, me())).contains("not this user's socket"));
    }
}
