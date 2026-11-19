//! `rbw config show/set/unset` on the dybw config file (profiles §1): rbw's keys are mapped onto the keys of the
//! profile. The file is edited line by line so its comments, order and other tables stay as they are.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use dybw_proto::Op;
use toml_edit::{DocumentMut, Item, Table, TableLike, Value};

use crate::{Env, Fail, ask, doctor, no_home, pinentry_text};

fn log(e: impl std::fmt::Display) -> Fail {
    Fail::Log(e.to_string())
}

fn config_file(env: &Env) -> Result<PathBuf, Fail> {
    Ok(dybw_agent::paths::config_path(&doctor::home_of(env).ok_or_else(no_home)?))
}

/// The profile of the settings: the one named, else the file's `default`.
pub fn show(env: &Env, profile: Option<&str>, out: &mut dyn Write) -> Result<u8, Fail> {
    let config = dybw_agent::config::Config::load(&config_file(env)?).map_err(|e| log(format!("{e:#}")))?;
    let p = config.profile(profile).map_err(|e| log(format!("{e:#}")))?;
    // rbw's field order; the settings dybw has no use for are null.
    let text = |s: &str| serde_json::Value::from(s).to_string();
    writeln!(
        out,
        "{{\n  \"email\": {},\n  \"sso_id\": null,\n  \"base_url\": {},\n  \"identity_url\": null,\n  \"ui_url\": null,\n  \
         \"notifications_url\": null,\n  \"lock_timeout\": {},\n  \"sync_interval\": {},\n  \"pinentry\": {},\n  \
         \"client_cert_path\": null\n}}",
        text(&p.email),
        text(&p.server_url),
        p.lock_timeout.as_secs(),
        p.sync_interval.as_secs(),
        text(&p.pinentry),
    )?;
    Ok(0)
}

/// Why rbw's key cannot be set in a dybw profile, if it cannot.
fn unsupported(key: &str) -> Option<&'static str> {
    match key {
        "sso_id" => Some("dybw logs in with an API key only, there is no SSO"),
        "identity_url" => Some("dybw derives the identity URL from `base_url`; set `base_url`"),
        "ui_url" => Some("dybw has no web vault URL setting"),
        "notifications_url" => Some("dybw has no notifications URL setting"),
        "client_cert_path" => Some("dybw has no client certificate setting"),
        _ => None,
    }
}

fn refuse(key: &str) -> Fail {
    unsupported(key).map_or_else(
        || Fail::Log(format!("invalid config key: {key}")),
        |why| Fail::Log(format!("`{key}` is not supported: {why}")),
    )
}

/// `base_url` picks the server the API key is sent to and `pinentry` the program that asks for the master password:
/// a script or an AI harness must not move either through the shim.
fn needs_terminal(env: &Env, key: &str) -> Result<(), Fail> {
    if matches!(key, "base_url" | "pinentry") && !env.stdin_tty {
        return Err(log("changing base_url/pinentry needs an interactive terminal"));
    }
    Ok(())
}

pub fn set(env: &Env, profile: Option<&str>, key: &str, value: &str, err: &mut dyn Write) -> Result<u8, Fail> {
    needs_terminal(env, key)?;
    let change = match key {
        "email" => Some(("email", Value::from(value))),
        "base_url" => Some(("server_url", Value::from(value))),
        "lock_timeout" => {
            let secs: u64 = value.parse().map_err(|e| log(format!("failed to parse value for lock_timeout: {e}")))?;
            if secs == 0 {
                // rbw logs this and saves the file as it was.
                let _ = writeln!(err, "ERROR: lock_timeout must be greater than 0");
                None
            } else {
                Some(("lock_timeout_minutes", Value::from(i64::try_from(secs.div_ceil(60)).unwrap_or(i64::MAX))))
            }
        }
        // 0 is "no periodic sync", as in rbw.
        "sync_interval" => {
            let secs: u64 = value.parse().map_err(|e| log(format!("failed to parse value for sync_interval: {e}")))?;
            Some(("sync_interval_seconds", Value::from(i64::try_from(secs).map_err(log)?)))
        }
        "pinentry" => {
            pinentry_text(value).map_err(|e| log(format!("pinentry {value:?} is not trusted: {e}")))?;
            Some(("pinentry", Value::from(value)))
        }
        _ => return Err(refuse(key)),
    };
    if let Some((profile_key, value)) = change {
        edit(env, profile, profile_key, Some(value), err)?;
    }
    stop_agent(env)
}

pub fn unset(env: &Env, profile: Option<&str>, key: &str, err: &mut dyn Write) -> Result<u8, Fail> {
    needs_terminal(env, key)?;
    let profile_key = match key {
        "lock_timeout" => "lock_timeout_minutes",
        "pinentry" => "pinentry",
        "email" | "base_url" => {
            return Err(log(format!("`{key}` cannot be unset: a dybw profile needs it; set a new value instead")));
        }
        // rbw cannot unset `sync_interval` either.
        "sync_interval" => return Err(log("invalid config key: sync_interval")),
        _ => return Err(refuse(key)),
    };
    edit(env, profile, profile_key, None, err)?;
    stop_agent(env)
}

/// The agent reads the file when it starts: stop it so the next command sees the change (as rbw does).
fn stop_agent(env: &Env) -> Result<u8, Fail> {
    ask(env, Op::StopAgent, false).map(|_| 0)
}

/// Set (`Some`) or remove (`None`) `key` in the profile's section, and say what changed.
fn edit(env: &Env, profile: Option<&str>, key: &str, value: Option<Value>, err: &mut dyn Write) -> Result<u8, Fail> {
    let path = config_file(env)?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(log(format!("cannot read {}: {e}", path.display()))),
    };
    let mut doc: DocumentMut = text.parse().map_err(|e| log(format!("cannot parse {}: {e}", path.display())))?;
    let named = profile.map(str::to_owned).or_else(|| doc.get("default").and_then(Item::as_str).map(str::to_owned));
    let name = named.clone().unwrap_or_else(|| "default".into());
    let mut shown = vec![];
    if named.is_none() && value.is_some() {
        put(doc.as_table_mut(), None, "default", Value::from(name.as_str()), &mut shown);
    }
    let broken = |what: &str| log(format!("cannot edit {}: {what} is not a table", path.display()));
    match value {
        Some(v) => {
            let profiles = doc.entry("profiles").or_insert_with(|| {
                let mut t = Table::new();
                t.set_implicit(true);
                Item::Table(t)
            });
            let profiles = profiles.as_table_like_mut().ok_or_else(|| broken("`profiles`"))?;
            let own = profiles.entry(&name).or_insert(Item::Table(Table::new()));
            let own = own.as_table_like_mut().ok_or_else(|| broken(&format!("`profiles.{name}`")))?;
            put(own, Some(&name), key, v, &mut shown);
        }
        None => {
            let own = doc.get_mut("profiles").and_then(Item::as_table_like_mut).and_then(|p| p.get_mut(&name));
            if let Some(own) = own.and_then(Item::as_table_like_mut)
                && let Some(old) = own.remove(key)
            {
                shown.push(format!("[profiles.{name}] - {key} = {}", item_text(&old)));
            }
        }
    }
    if shown.is_empty() {
        let _ = writeln!(err, "{}: nothing to change", path.display());
        return Ok(0);
    }
    write_file(&path, &doc.to_string())?;
    let _ = writeln!(err, "{}\n{}", path.display(), shown.join("\n"));
    Ok(0)
}

fn item_text(item: &Item) -> String {
    item.as_value().map_or_else(String::new, |v| v.to_string().trim().to_owned())
}

/// Set `key` in `table` (`profile`: the profile it is the table of; `None`: the top level), keeping the comment
/// after an old value, and note a change.
fn put(table: &mut dyn TableLike, profile: Option<&str>, key: &str, mut new: Value, shown: &mut Vec<String>) {
    let place = profile.map_or("top level".to_owned(), |p| format!("[profiles.{p}]"));
    let new_text = format!("{key} = {}", new.to_string().trim());
    let old = table.get(key).and_then(Item::as_value);
    if let Some(old) = old {
        if old.to_string().trim() == new.to_string().trim() {
            return;
        }
        shown.push(format!("{place} - {key} = {}", old.to_string().trim()));
        *new.decor_mut() = old.decor().clone();
    }
    table.insert(key, Item::Value(new));
    shown.push(format!("{place} + {new_text}"));
}

/// Write beside the file and rename over it. An existing file keeps its permissions and a symlink (chezmoi's) stays
/// a symlink: the target is replaced. Missing directories are made 0700. The temporary file never outlives a failure.
fn write_file(path: &Path, text: &str) -> Result<(), Fail> {
    let path = &std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    let mode = std::fs::metadata(path).map_or(0o600, |m| m.permissions().mode() & 0o777);
    let tmp = path.with_extension("toml.new");
    let write = || -> std::io::Result<()> {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path.parent().unwrap_or(path))?;
        let _ = std::fs::remove_file(&tmp);
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;
        // The umask may have narrowed the mode: say it outright.
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(text.as_bytes())?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        log(format!("cannot write {}: {e}", path.display()))
    })
}
