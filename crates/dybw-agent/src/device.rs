//! The device id of a profile (profiles §3): one UUID, generated once, kept in `devices/dybw`.

use std::io::{ErrorKind, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, bail, ensure};
use dybw_native::fsutil::{User, write_private};

use crate::paths::ProfilePaths;

pub fn device_id(paths: &ProfilePaths) -> anyhow::Result<String> {
    device_id_for(paths, User::current().context("cannot tell which user this is")?.uid)
}

fn device_id_for(paths: &ProfilePaths, uid: u32) -> anyhow::Result<String> {
    if let Some(id) = read(&paths.device, uid)? {
        return Ok(id);
    }
    let id = uuid::Uuid::new_v4().to_string();
    // The private-write helper makes a whole file under a name of its own; the link is the create-if-absent
    // step, so two first starts cannot replace each other's id.
    let tmp = paths.device.with_extension(format!("new{}", std::process::id()));
    let shown = || paths.device.display().to_string();
    write_private(&tmp, id.as_bytes()).with_context(shown)?;
    let linked = std::fs::hard_link(&tmp, &paths.device);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(shown),
    }
    // Whoever linked first won: read back what the file holds.
    read(&paths.device, uid)?.with_context(|| format!("{} vanished", paths.device.display()))
}

/// The stored id: `None` when there is no file; an error for a link, a file that is not ours or not a UUID.
fn read(path: &Path, uid: u32) -> anyhow::Result<Option<String>> {
    let shown = path.display();
    let link = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| shown.to_string()),
    };
    ensure!(!link.file_type().is_symlink(), "{shown} is a symbolic link; the device id must be a regular file");
    ensure!(link.is_file(), "{shown} is not a regular file");
    let mut file = std::fs::File::open(path).with_context(|| shown.to_string())?;
    let meta = file.metadata()?;
    ensure!((meta.dev(), meta.ino()) == (link.dev(), link.ino()), "{shown} changed while it was read");
    ensure!(meta.uid() == uid, "{shown} is not owned by this user");
    let mut text = String::new();
    file.read_to_string(&mut text).with_context(|| shown.to_string())?;
    let id = text.trim();
    if uuid::Uuid::parse_str(id).is_err() {
        bail!("{shown} does not hold a device id (a UUID); remove it to get a new one");
    }
    Ok(Some(id.to_owned()))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn paths(dir: &Path) -> ProfilePaths {
        ProfilePaths::with(&|_| None, dir, &crate::paths::test_profile("p"))
    }

    fn mine(p: &ProfilePaths) -> u32 {
        std::fs::metadata(p.device.parent().unwrap()).unwrap().uid()
    }

    fn err(p: &ProfilePaths) -> String {
        format!("{:#}", device_id(p).unwrap_err())
    }

    #[test]
    fn generated_once_private_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let id = device_id(&p).unwrap();
        assert_eq!(uuid::Uuid::parse_str(&id).unwrap().to_string(), id);
        assert_eq!(std::fs::metadata(&p.device).unwrap().mode() & 0o777, 0o600);
        assert_eq!(device_id(&p).unwrap(), id);
        // No temporary file is left behind.
        assert_eq!(std::fs::read_dir(p.device.parent().unwrap()).unwrap().count(), 1);
    }

    #[test]
    fn a_first_write_that_lost_the_race_returns_the_winners_id() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let winner = device_id(&p).unwrap();
        // The loser saw no file, then the winner linked its own: the link fails and the read-back wins.
        let tmp = p.device.with_extension(format!("new{}", std::process::id()));
        write_private(&tmp, b"x").unwrap();
        assert_eq!(std::fs::hard_link(&tmp, &p.device).unwrap_err().kind(), ErrorKind::AlreadyExists);
        std::fs::remove_file(&tmp).unwrap();
        assert_eq!(device_id_for(&p, mine(&p)).unwrap(), winner);
    }

    #[test]
    fn a_bad_file_is_an_error_that_names_the_file_not_the_content() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        device_id(&p).unwrap();
        for bad in ["", " \n", "s3cr3t-not-a-uuid"] {
            std::fs::write(&p.device, bad).unwrap();
            let e = err(&p);
            assert!(e.contains("devices/dybw") && !e.contains("s3cr3t"), "{e}");
        }
        std::fs::remove_file(&p.device).unwrap();
        std::fs::create_dir(&p.device).unwrap();
        assert!(err(&p).contains("not a regular file"));
        std::fs::remove_dir(&p.device).unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, uuid::Uuid::new_v4().to_string()).unwrap();
        std::os::unix::fs::symlink(&target, &p.device).unwrap();
        assert!(err(&p).contains("symbolic link"));
    }

    #[test]
    fn a_file_of_another_user_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        device_id(&p).unwrap();
        let e = format!("{:#}", device_id_for(&p, mine(&p).wrapping_add(1)).unwrap_err());
        assert!(e.contains("not owned"), "{e}");
    }

    #[test]
    fn an_unwritable_place_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let blocked = paths(&dir.path().join("f/x"));
        std::fs::write(dir.path().join("f"), "x").unwrap();
        assert!(err(&blocked).contains("devices/dybw"));
        // The file exists but cannot be read.
        let p = paths(dir.path());
        device_id(&p).unwrap();
        std::fs::set_permissions(&p.device, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
        assert!(err(&p).contains("devices/dybw"));
    }
}
