//! A profile's API key (ported from bwss): a TOML file bound to the identity origin it was entered for.

use std::path::Path;

use anyhow::{Context, bail, ensure};
use dybw_native::fsutil::{User, write_private};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    /// `scheme://host[:port]` of the identity server the key may be sent to.
    pub identity_origin: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("identity_origin", &self.identity_origin)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

impl Credentials {
    /// Reads the key: a regular file owned by `user`, mode 0600, saved for `origin`.
    pub fn load(path: &Path, user: &User, origin: &str) -> anyhow::Result<Credentials> {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;

        let shown = path.display();
        let link = std::fs::symlink_metadata(path).with_context(|| format!("{shown} (run `dybw login`)"))?;
        if link.file_type().is_symlink() {
            bail!("{shown} is a symbolic link; the API key must be a regular file");
        }
        if !link.is_file() {
            bail!("{shown} is not a regular file");
        }
        let mut file = std::fs::File::open(path).with_context(|| shown.to_string())?;
        let meta = file.metadata()?;
        // The file opened is the one checked above, not a link swapped in.
        ensure!((meta.dev(), meta.ino()) == (link.dev(), link.ino()), "{shown} changed while it was read");
        if meta.uid() != user.uid {
            bail!("{shown} is owned by uid {}, not by this user", meta.uid());
        }
        if meta.mode() & 0o077 != 0 {
            bail!("{shown} must not be readable by others (chmod 600)");
        }
        let mut text = Zeroizing::new(String::new());
        file.read_to_string(&mut text).with_context(|| shown.to_string())?;
        let creds: Credentials = parse_secret_toml(&text, path)?;
        if creds.identity_origin != origin {
            bail!(
                "the API key in {shown} was saved for {}, and the profile's server is now {origin}; \
                 it is not sent there: run `dybw login` again",
                creds.identity_origin
            );
        }
        Ok(creds)
    }

    pub fn store(&self, path: &Path) -> anyhow::Result<()> {
        let text = Zeroizing::new(toml::to_string(self)?);
        write_private(path, text.as_bytes()).with_context(|| path.display().to_string())
    }
}

/// Parses a file that holds a secret. A TOML error quotes the source line, so it is never passed on: only the
/// path, the position, and the name of a missing key (one of ours). An unknown key is not named: it could be a
/// pasted secret.
fn parse_secret_toml<T: serde::de::DeserializeOwned>(text: &str, path: &Path) -> anyhow::Result<T> {
    let e = match toml::from_str::<T>(text) {
        Ok(value) => return Ok(value),
        Err(e) => e,
    };
    let message = e.message();
    let missing = message.strip_prefix("missing field `").and_then(|rest| rest.split('`').next());
    let what = match missing {
        Some(key) => format!("missing key `{key}`"),
        None if message.starts_with("unknown field") => "an unknown key".to_owned(),
        None => "not valid TOML for this file".to_owned(),
    };
    let at = e.span().map(|span| {
        let before = text.get(..span.start).unwrap_or_default();
        let line = before.matches('\n').count() + 1;
        let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
        format!(" (line {line}, column {column})")
    });
    bail!("{}: {what}{}", path.display(), at.unwrap_or_default())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use toml::Table;

    const ORIGIN: &str = "https://identity.example.org";

    fn creds() -> Credentials {
        Credentials {
            identity_origin: ORIGIN.into(),
            client_id: "cid".into(),
            client_secret: Zeroizing::new("csecret".into()),
        }
    }

    fn me(path: &Path) -> User {
        User { uid: std::fs::metadata(path).unwrap().uid(), groups: None }
    }

    fn load_err(path: &Path, user: &User, origin: &str) -> String {
        format!("{:#}", Credentials::load(path, user, origin).unwrap_err())
    }

    #[test]
    fn debug_is_redacted() {
        let shown = format!("{:?}", creds());
        assert!(shown.contains("cid") && shown.contains("<redacted>") && !shown.contains("csecret"), "{shown}");
    }

    #[test]
    fn saved_credentials_load_for_their_origin_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles/p/credentials");
        creds().store(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777, 0o700);
        let c = Credentials::load(&path, &me(&path), ORIGIN).unwrap();
        assert_eq!((c.client_id.as_str(), c.client_secret.as_str()), ("cid", "csecret"));
        let e = load_err(&path, &me(&path), "https://identity.evil.example");
        assert!(e.contains(ORIGIN) && e.contains("identity.evil.example") && e.contains("dybw login"), "{e}");
        assert!(!e.contains("csecret"), "{e}");
    }

    #[test]
    fn credentials_must_be_private_owned_and_not_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials");
        assert!(load_err(&path, &User { uid: 1, groups: None }, ORIGIN).contains("dybw login"));
        creds().store(&path).unwrap();
        let user = me(&path);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_err(&path, &user, ORIGIN).contains("chmod 600"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let stranger = User { uid: user.uid.wrapping_add(1), groups: None };
        assert!(load_err(&path, &stranger, ORIGIN).contains("owned"));

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_err(&link, &user, ORIGIN).contains("symbolic link"));

        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        assert!(load_err(&sub, &user, ORIGIN).contains("regular file"));

        std::fs::write(&path, "client_id = \"no origin\"\n").unwrap();
        assert!(Credentials::load(&path, &user, ORIGIN).is_err());
    }

    #[test]
    fn unreadable_or_unwritable_credentials_say_where() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials");
        creds().store(&path).unwrap();
        let user = me(&path);
        std::fs::write(&path, b"client_secret = \"\xff\xfe\"\n").unwrap();
        let e = load_err(&path, &user, ORIGIN);
        assert!(e.contains(&path.display().to_string()) && e.contains("UTF-8"), "{e}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(load_err(&path, &user, ORIGIN).contains(&path.display().to_string()));

        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, "x").unwrap();
        let target = blocker.join("profiles/p/credentials");
        let e = format!("{:#}", creds().store(&target).unwrap_err());
        assert!(e.contains(&target.display().to_string()), "{e}");
        assert_eq!(std::fs::read_to_string(&blocker).unwrap(), "x");
    }

    #[test]
    fn credentials_have_exactly_three_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials");
        creds().store(&path).unwrap();
        let user = me(&path);
        let full = std::fs::read_to_string(&path).unwrap();
        let saved: Table = toml::from_str(&full).unwrap();
        let mut keys: Vec<&str> = saved.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["client_id", "client_secret", "identity_origin"]);

        std::fs::write(&path, format!("{full}extra = 1\n")).unwrap();
        let e = load_err(&path, &user, ORIGIN);
        assert!(e.contains("an unknown key") && !e.contains("extra"), "{e}");
        std::fs::write(&path, "identity_origin = \"https://identity.example.org\"\nclient_id = \"cid\"\n").unwrap();
        assert!(load_err(&path, &user, ORIGIN).contains("missing key `client_secret`"));
    }

    #[test]
    fn a_broken_file_never_shows_its_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials");
        creds().store(&path).unwrap();
        let user = me(&path);
        for text in [
            "identity_origin = \"https://identity.example.org\"\nclient_id = \"cid\"\nclient_secret = \"s3cr3t-leak\n",
            "client_secret = 's3cr3t-leak' 'more'\n",
            "client_secret = \"s3cr3t-leak\"\nclient_secret = \"s3cr3t-leak\"\n",
            "identity_origin = 1\nclient_id = \"s3cr3t-leak\"\nclient_secret = \"x\"\n",
            "s3cr3t-leak = 1\n",
        ] {
            std::fs::write(&path, text).unwrap();
            let e = load_err(&path, &user, ORIGIN);
            assert!(!e.contains("s3cr3t") && e.contains(&path.display().to_string()), "{e}");
        }
        std::fs::write(&path, "client_secret = \"s3cr3t-leak\n").unwrap();
        assert!(load_err(&path, &user, ORIGIN).contains("line 1"));
    }
}
