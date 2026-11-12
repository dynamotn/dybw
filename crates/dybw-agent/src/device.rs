//! The device id of a profile (profiles §3): one UUID, generated once, kept in `devices/dybw`.

use std::io::ErrorKind;

use anyhow::Context;
use dybw_native::fsutil::write_private;

use crate::paths::ProfilePaths;

pub fn device_id(paths: &ProfilePaths) -> anyhow::Result<String> {
    match std::fs::read_to_string(&paths.device) {
        Ok(s) if !s.trim().is_empty() => return Ok(s.trim().to_owned()),
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| paths.device.display().to_string()),
    }
    let id = uuid::Uuid::new_v4().to_string();
    write_private(&paths.device, id.as_bytes()).with_context(|| paths.device.display().to_string())?;
    Ok(id)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn paths(dir: &std::path::Path) -> ProfilePaths {
        let vars = dir.as_os_str().to_owned();
        ProfilePaths::with(&|_| Some(vars.clone()), &crate::paths::test_profile("p")).unwrap()
    }

    #[test]
    fn generated_once_private_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let id = device_id(&p).unwrap();
        assert_eq!(uuid::Uuid::parse_str(&id).unwrap().to_string(), id);
        assert_eq!(std::fs::metadata(&p.device).unwrap().mode() & 0o777, 0o600);
        assert_eq!(device_id(&p).unwrap(), id);
    }

    #[test]
    fn an_empty_file_is_replaced_and_an_unreadable_one_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        std::fs::create_dir_all(&p.device).unwrap();
        // A directory cannot be read as a file: the error names the path and nothing is overwritten.
        assert!(format!("{:#}", device_id(&p).unwrap_err()).contains("devices/dybw"));
        std::fs::remove_dir(&p.device).unwrap();
        std::fs::write(&p.device, " \n").unwrap();
        assert!(!device_id(&p).unwrap().is_empty());
        // A path that cannot be written names where.
        let blocked = paths(&dir.path().join("dybw/profiles/p/credentials/x"));
        std::fs::create_dir_all(dir.path().join("dybw/profiles/p")).unwrap();
        std::fs::write(dir.path().join("dybw/profiles/p/credentials"), "f").unwrap();
        assert!(format!("{:#}", device_id(&blocked).unwrap_err()).contains("devices/dybw"));
    }
}
