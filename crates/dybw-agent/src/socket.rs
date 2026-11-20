//! The agent socket (D6): where it lives, who may reach it, and when an old one may be replaced.

use std::ffi::OsString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use rustix::fs::{FlockOperation, flock};

/// `$XDG_RUNTIME_DIR/dybw`, else `$TMPDIR/dybw-<uid>` (`/tmp` when `TMPDIR` is unset): a directory only this user
/// may use, so the socket inside needs no path-based trust.
pub fn socket_dir(var: &dyn Fn(&str) -> Option<OsString>, uid: u32) -> PathBuf {
    let absolute = |name: &str| var(name).map(PathBuf::from).filter(|p| p.is_absolute());
    match absolute("XDG_RUNTIME_DIR") {
        Some(runtime) => runtime.join("dybw"),
        None => absolute("TMPDIR").unwrap_or_else(|| "/tmp".into()).join(format!("dybw-{uid}")),
    }
}

/// Create `dir` 0700 if it is missing, then [`check_dir`] it.
pub fn ensure_dir(dir: &Path, uid: u32) -> anyhow::Result<()> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != ErrorKind::AlreadyExists => return Err(e).context(format!("create {}", dir.display())),
        _ => {}
    }
    check_dir(dir, uid)
}

/// Require that `dir` is a real directory (not a symlink), owned by `uid` and closed to group and others.
pub fn check_dir(dir: &Path, uid: u32) -> anyhow::Result<()> {
    let meta = std::fs::symlink_metadata(dir).context(format!("stat {}", dir.display()))?;
    let shown = dir.display();
    ensure!(!meta.file_type().is_symlink(), "{shown} is a symbolic link");
    ensure!(meta.is_dir(), "{shown} is not a directory");
    ensure!(meta.uid() == uid, "{shown} is not owned by this user");
    ensure!(meta.mode() & 0o077 == 0, "{shown} is open to other users (mode {:o})", meta.mode() & 0o777);
    Ok(())
}

/// Bind `dir/agent.sock`. The returned file holds `dir/agent.lock` and must be kept for the life of the process:
/// while one agent holds it, a second refuses to start, whatever state the socket is in. With the lock taken, a
/// socket nobody refuses or misses is stale and replaced; a live one, a stranger, or an unclear connect error
/// is refused and left alone.
pub fn bind(dir: &Path, uid: u32) -> anyhow::Result<(UnixListener, File)> {
    ensure_dir(dir, uid)?;
    let lock_path = dir.join("agent.lock");
    let lock = OpenOptions::new().create(true).append(true).mode(0o600).open(&lock_path);
    let lock = lock.context(format!("open {}", lock_path.display()))?;
    ensure!(
        flock(&lock, FlockOperation::NonBlockingLockExclusive).is_ok(),
        "dybw-agent is already running (the lock {} is held)",
        lock_path.display()
    );
    let listener = listen(&dir.join("agent.sock"), uid)?;
    Ok((listener, lock))
}

/// Bind `dir/ssh-agent.sock` (the SSH agent, profiles §8) as [`bind`] binds `agent.sock`, under the lock `bind`
/// returned: only the agent holding it may replace a stale SSH socket.
pub fn bind_ssh(dir: &Path, uid: u32, _lock: &File) -> anyhow::Result<UnixListener> {
    listen(&dir.join("ssh-agent.sock"), uid)
}

/// Bind `path` 0600, replacing a stale socket of `uid` there; the caller holds the lock.
fn listen(path: &Path, uid: u32) -> anyhow::Result<UnixListener> {
    // A stat error other than "missing" falls through to the bind, which then fails on its own.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        ensure!(meta.file_type().is_socket() && meta.uid() == uid, "{} is not this user's socket", path.display());
        match UnixStream::connect(path) {
            Ok(_) => bail!("dybw-agent is already running on {}", path.display()),
            Err(e) => ensure!(
                matches!(e.kind(), ErrorKind::ConnectionRefused | ErrorKind::NotFound),
                "cannot tell whether {} is stale ({e}); not removing it",
                path.display()
            ),
        }
        std::fs::remove_file(path).context(format!("remove stale {}", path.display()))?;
    }
    let listener = UnixListener::bind(path).context(format!("bind {}", path.display()))?;
    std::fs::set_permissions(path, PermissionsExt::from_mode(0o600))?;
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

    fn err(r: anyhow::Result<(UnixListener, File)>) -> String {
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
        let (live, _lock) = bind(&dir, me()).unwrap();
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

    #[test]
    fn the_lock_alone_keeps_a_second_agent_out_even_without_a_socket_file() {
        let base = base();
        let dir = base.path().join("dybw");
        let _first = bind(&dir, me()).unwrap();
        std::fs::remove_file(dir.join("agent.sock")).unwrap();
        assert!(err(bind(&dir, me())).contains("lock"));
        assert!(!dir.join("agent.sock").exists(), "the refused agent created nothing");
    }

    #[test]
    fn a_live_socket_of_an_agent_without_the_lock_is_still_refused() {
        let base = base();
        let dir = base.path().join("dybw");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o700)).unwrap();
        let _foreign = UnixListener::bind(dir.join("agent.sock")).unwrap();
        assert!(err(bind(&dir, me())).contains("already running on"));
        assert!(dir.join("agent.sock").exists());
    }

    #[test]
    fn the_ssh_socket_is_0600_next_to_the_agent_socket_and_follows_the_same_stale_rule() {
        let base = base();
        let dir = base.path().join("dybw");
        let (_agent, lock) = bind(&dir, me()).unwrap();
        let ssh = bind_ssh(&dir, me(), &lock).unwrap();
        assert_eq!(std::fs::metadata(dir.join("ssh-agent.sock")).unwrap().mode() & 0o777, 0o600);
        assert!(format!("{:#}", bind_ssh(&dir, me(), &lock).unwrap_err()).contains("already running on"));
        drop(ssh);
        let _fresh = bind_ssh(&dir, me(), &lock).unwrap();
    }

    #[test]
    fn only_refused_or_missing_counts_as_stale() {
        let false = crate::skipped_as_root(crate::ROOT_BYPASSES) else { return };
        let base = base();
        let dir = base.path().join("dybw");
        drop(bind(&dir, me()).unwrap());
        let sock = dir.join("agent.sock");
        // Connecting to it now fails with "permission denied": not a sign that nobody is there.
        std::fs::set_permissions(&sock, PermissionsExt::from_mode(0o000)).unwrap();
        assert!(err(bind(&dir, me())).contains("cannot tell"));
        assert!(sock.exists(), "an unclear socket is not unlinked");
    }
}
