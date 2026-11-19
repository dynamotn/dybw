//! `rbw config show/set/unset` on the dybw config file (profiles §1): rbw's keys are mapped onto the keys of the
//! profile. The file is edited line by line so its comments, order and other tables stay as they are.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use dybw_proto::Op;
use toml::{Table, Value};

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
    let text = |s: &str| Value::String(s.into()).to_string();
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

pub fn set(env: &Env, profile: Option<&str>, key: &str, value: &str, err: &mut dyn Write) -> Result<u8, Fail> {
    let change = match key {
        "email" => Some(("email", Value::String(value.into()))),
        "base_url" => Some(("server_url", Value::String(value.into()))),
        "lock_timeout" => {
            let secs: u64 = value.parse().map_err(|e| log(format!("failed to parse value for lock_timeout: {e}")))?;
            if secs == 0 {
                // rbw logs this and saves the file as it was.
                let _ = writeln!(err, "ERROR: lock_timeout must be greater than 0");
                None
            } else {
                Some(("lock_timeout_minutes", Value::Integer(i64::try_from(secs.div_ceil(60)).unwrap_or(i64::MAX))))
            }
        }
        // 0 is "no periodic sync", as in rbw.
        "sync_interval" => {
            let secs: u64 = value.parse().map_err(|e| log(format!("failed to parse value for sync_interval: {e}")))?;
            Some(("sync_interval_seconds", Value::Integer(i64::try_from(secs).map_err(log)?)))
        }
        "pinentry" => {
            pinentry_text(value).map_err(|e| log(format!("pinentry {value:?} is not trusted: {e}")))?;
            Some(("pinentry", Value::String(value.into())))
        }
        _ => return Err(refuse(key)),
    };
    if let Some((profile_key, value)) = change {
        edit(env, profile, profile_key, Some(value), err)?;
    }
    stop_agent(env)
}

pub fn unset(env: &Env, profile: Option<&str>, key: &str, err: &mut dyn Write) -> Result<u8, Fail> {
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
    let doc: Table = toml::from_str(&text).map_err(|e| log(format!("cannot parse {}: {e}", path.display())))?;
    let named = profile.map(str::to_owned).or_else(|| doc.get("default").and_then(Value::as_str).map(str::to_owned));
    let name = named.clone().unwrap_or_else(|| "default".into());
    let mut lines = Lines(text.lines().map(str::to_owned).collect());
    let mut shown = vec![];
    if named.is_none() && value.is_some() {
        lines.put("", "default", &Value::String(name.clone()), &mut shown);
    }
    let section = format!("profiles.{name}");
    match &value {
        Some(v) => lines.put(&section, key, v, &mut shown),
        None => lines.remove(&section, key, &mut shown),
    }
    if shown.is_empty() {
        let _ = writeln!(err, "{}: nothing to change", path.display());
        return Ok(0);
    }
    let new = lines.0.join("\n") + "\n";
    toml::from_str::<Table>(&new).map_err(|e| log(format!("the edit would break {}: {e}", path.display())))?;
    write_file(&path, &new)?;
    let _ = writeln!(err, "{}\n{}", path.display(), shown.join("\n"));
    Ok(0)
}

/// Write beside the file and rename over it; an existing file keeps its permissions.
fn write_file(path: &Path, text: &str) -> Result<(), Fail> {
    let mode = std::fs::metadata(path).map_or(0o600, |m| m.permissions().mode() & 0o777);
    let tmp = path.with_extension("toml.new");
    let write = || -> std::io::Result<()> {
        std::fs::create_dir_all(path.parent().unwrap_or(path))?;
        let _ = std::fs::remove_file(&tmp);
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;
        file.write_all(text.as_bytes())?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| log(format!("cannot write {}: {e}", path.display())))
}

/// The lines of the file. shortcut: a header is a line that starts with `[` and keys are bare, one per line, which is
/// how this tool and the docs write the file; a profile written any other way is not found, and a new section is made.
pub(crate) struct Lines(pub(crate) Vec<String>);

fn is_header(line: &str) -> bool {
    line.trim_start().starts_with('[')
}

fn header_is(line: &str, section: &str) -> bool {
    let name = line.trim_start().strip_prefix('[').and_then(|r| r.split(']').next()).map(str::trim);
    let quoted = section.split_once('.').map(|(a, b)| format!("{a}.\"{b}\""));
    name.is_some_and(|n| n == section || quoted.as_deref() == Some(n))
}

fn is_key(line: &str, key: &str) -> bool {
    line.trim_start().strip_prefix(key).is_some_and(|rest| rest.trim_start().starts_with('='))
}

impl Lines {
    /// The body of a section as a range of line indexes (`""`: the top level, before the first header).
    fn body(&self, section: &str) -> Option<std::ops::Range<usize>> {
        let first =
            |from: usize| self.0.iter().skip(from).position(|l| is_header(l)).map_or(self.0.len(), |p| p + from);
        if section.is_empty() {
            return Some(0..first(0));
        }
        let at = self.0.iter().position(|l| header_is(l, section))?;
        Some(at + 1..first(at + 1))
    }

    /// The lines of a body with their indexes.
    fn lines(&self, body: &std::ops::Range<usize>) -> impl Iterator<Item = (usize, &String)> {
        self.0.iter().enumerate().skip(body.start).take(body.len())
    }

    pub(crate) fn put(&mut self, section: &str, key: &str, value: &Value, shown: &mut Vec<String>) {
        let new = format!("{key} = {value}");
        let place = if section.is_empty() { "top level".to_owned() } else { format!("[{section}]") };
        let Some(body) = self.body(section) else {
            if self.0.last().is_some_and(|l| !l.trim().is_empty()) {
                self.0.push(String::new());
            }
            self.0.push(format!("[{section}]"));
            self.0.push(new.clone());
            shown.push(format!("{place} + {new}"));
            return;
        };
        if let Some(line) = self.0.iter_mut().skip(body.start).take(body.len()).find(|l| is_key(l, key)) {
            if line.trim() != new {
                shown.push(format!("{place} - {}\n{place} + {new}", line.trim()));
                *line = new;
            }
            return;
        }
        // After the last line with something on it, so a trailing blank line stays a separator.
        let at =
            self.lines(&body).filter(|(_, l)| !l.trim().is_empty()).map(|(i, _)| i + 1).last().unwrap_or(body.start);
        self.0.insert(at, new.clone());
        if self.0.get(at + 1).is_some_and(|l| is_header(l)) {
            self.0.insert(at + 1, String::new());
        }
        shown.push(format!("{place} + {new}"));
    }

    fn remove(&mut self, section: &str, key: &str, shown: &mut Vec<String>) {
        let found = self.body(section).and_then(|b| self.lines(&b).find(|(_, l)| is_key(l, key)).map(|(i, _)| i));
        if let Some(at) = found {
            shown.push(format!("[{section}] - {}", self.0.remove(at).trim()));
        }
    }
}
