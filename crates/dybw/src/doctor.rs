//! `dybw doctor`: what is wrong on this machine, in the order a person would look. It reads and asks; it changes
//! nothing and never starts the agent. Exit 0 when every check passes (warnings do not count), 1 otherwise.

use std::io::Write;
use std::path::PathBuf;

use dybw_agent::caller::Caller;
use dybw_agent::config::Config;
use dybw_agent::paths::{ProfilePaths, audit_path, config_path};
use dybw_agent::policy::Store;
use dybw_agent::{audit, socket};
use dybw_proto::{Op, Reply};

use crate::{Env, escape};

struct Report<'a> {
    out: &'a mut dyn Write,
    failed: bool,
}

impl Report<'_> {
    fn line(&mut self, tag: &str, what: &str, detail: &str) -> std::io::Result<()> {
        writeln!(self.out, "[{tag}] {what}: {}", escape(detail))
    }

    fn ok(&mut self, what: &str, detail: &str) -> std::io::Result<()> {
        self.line("ok", what, detail)
    }

    fn problem(&mut self, what: &str, detail: &str) -> std::io::Result<()> {
        self.failed = true;
        self.line("problem", what, detail)
    }
}

/// `HOME` when it is an absolute path.
pub fn home_of(env: &Env) -> Option<PathBuf> {
    (env.var)("HOME").map(PathBuf::from).filter(|h| h.is_absolute())
}

/// Run every check. `me` is what this process would be taken for as a caller of the agent, and `pinentry` resolves a
/// profile's pinentry the way the agent does.
pub fn run(
    env: &Env,
    profile: Option<&str>,
    me: Option<Caller>,
    pinentry: &dyn Fn(&str) -> Result<String, String>,
    out: &mut dyn Write,
) -> std::io::Result<u8> {
    let mut r = Report { out, failed: false };
    if let Some(Caller::Ai { harness, .. }) = me {
        let note = format!(
            "this runs under the AI harness {harness}; its sandbox must not be able to reach the agent socket or the \
             state directories, and a value request from here is denied"
        );
        r.line("warning", "caller", &note)?;
    }
    sockets(env, &mut r)?;
    let Some(home) = home_of(env) else {
        r.problem("home", "HOME is not set to an absolute path")?;
        return Ok(1);
    };
    match Config::load(&config_path(&env.var, &home)) {
        Err(e) => r.problem("config", &format!("{e:#}"))?,
        Ok(config) => {
            r.ok("config", &config_path(&env.var, &home).display().to_string())?;
            profile_checks(env, &config, profile, &home, pinentry, &mut r)?;
        }
    }
    let path = audit_path(&env.var, &home);
    let shown = path.display();
    match audit::read(&path, env.uid) {
        Ok(log) if log.skipped == 0 => r.ok("audit log", &format!("{shown}, {} lines", log.entries.len()))?,
        Ok(log) => r.problem("audit log", &format!("{shown}: {} lines are not entries", log.skipped))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => r.ok("audit log", &format!("{shown}, none yet"))?,
        Err(e) => {
            let note = format!("{shown}: {e}; nothing is recorded until it is fixed (requests are still answered)");
            r.problem("audit log", &note)?;
        }
    }
    Ok(u8::from(r.failed))
}

/// The socket directory, and whether the agent behind it answers.
fn sockets(env: &Env, r: &mut Report<'_>) -> std::io::Result<()> {
    let dir = socket::socket_dir(&env.var, env.uid);
    let shown = dir.display().to_string();
    match std::fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            r.ok("socket directory", &format!("{shown}, made on first use"))?;
        }
        _ => match socket::check_dir(&dir, env.uid) {
            Ok(()) => r.ok("socket directory", &shown)?,
            Err(e) => r.problem("socket directory", &format!("{e:#}"))?,
        },
    }
    match crate::client::call(env, Op::Status { profile: None }, false) {
        Ok(None) => r.ok("agent", "not running (it starts on first use)"),
        Ok(Some(Reply::Status { agent_version, .. })) if agent_version == env!("CARGO_PKG_VERSION") => {
            r.ok("agent", &format!("running, version {agent_version}"))
        }
        Ok(Some(Reply::Status { agent_version, .. })) => {
            let note = format!("version {agent_version}, dybw is {}: run `dybw agent stop`", env!("CARGO_PKG_VERSION"));
            r.problem("agent", &note)
        }
        Ok(Some(Reply::Error { error })) => r.problem("agent", &format!("running, but answers with an error: {error}")),
        Ok(Some(_)) => r.problem("agent", "running, but the reply does not fit the request"),
        Err(e) => r.problem("agent", &e.to_string()),
    }
}

/// The profile in use: its pinentry and its policy file.
fn profile_checks(
    env: &Env,
    config: &Config,
    profile: Option<&str>,
    home: &std::path::Path,
    pinentry: &dyn Fn(&str) -> Result<String, String>,
    r: &mut Report<'_>,
) -> std::io::Result<()> {
    let profile = match config.profile(profile) {
        Ok(p) => p,
        Err(e) => return r.problem("profile", &format!("{e:#}")),
    };
    r.ok("profile", &profile.name)?;
    match pinentry(&profile.pinentry) {
        Ok(path) => r.ok("pinentry", &path)?,
        Err(e) => r.problem("pinentry", &format!("{}: {e}", profile.pinentry))?,
    }
    let file = ProfilePaths::with(&env.var, home, &profile).policy;
    let shown = file.display();
    match Store::new(&file, env.uid).read() {
        Ok(entries) => r.ok("policy", &format!("{shown}, {} entries", entries.len())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => r.ok("policy", &format!("{shown}, none yet")),
        // Every grant is ignored while this lasts, and policy changes are refused (a write must not drop a deny).
        Err(e) => {
            let note = format!("{shown}: {e}; fix its mode or owner, or remove it (the grants are asked again)");
            r.problem("policy", &note)
        }
    }
}
