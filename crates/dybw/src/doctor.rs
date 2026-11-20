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

pub(crate) struct Report<'a> {
    pub(crate) out: &'a mut dyn Write,
    pub(crate) failed: bool,
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

/// This user's home in the password database: where the agent keeps its files, whatever `HOME` says.
pub fn home_of(env: &Env) -> Option<PathBuf> {
    env.home.clone()
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
        r.problem("home", "this user has no home directory in the password database")?;
        return Ok(1);
    };
    // The agent refuses to start under a HOME that is not the user's home.
    let real = |p: &std::path::Path| std::fs::canonicalize(p).ok();
    if let Some(var) = (env.var)("HOME").map(PathBuf::from)
        && (real(&var).is_none() || real(&var) != real(&home))
    {
        let note = format!(
            "HOME {} is not your home {} (password database): the agent will not start",
            var.display(),
            home.display()
        );
        r.problem("home", &note)?;
    }
    match Config::load(&config_path(&home)) {
        Err(e) => r.problem("config", &format!("{e:#}"))?,
        Ok(config) => {
            r.ok("config", &config_path(&home).display().to_string())?;
            profile_checks(env, &config, profile, &home, pinentry, &mut r)?;
            ssh_checks(env, &config, &mut r)?;
        }
    }
    let path = audit_path(&home);
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

/// The SSH agent: its socket, and, when `[ssh_agent]` lists profiles, which are unlocked, how many keys are offered,
/// how many listings were asked for, and whether `SSH_AUTH_SOCK` points at it.
fn ssh_checks(env: &Env, config: &Config, r: &mut Report<'_>) -> std::io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let path = socket::socket_dir(&env.var, env.uid).join("ssh-agent.sock");
    let shown = path.display().to_string();
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            r.ok("ssh agent socket", &format!("{shown}, made when the agent starts"))?;
        }
        Ok(m) if m.file_type().is_socket() && m.uid() == env.uid && m.mode() & 0o777 == 0o600 => {
            let listening = std::os::unix::net::UnixStream::connect(&path).is_ok();
            let state = if listening { "listening" } else { "not listening (the agent is not running)" };
            r.ok("ssh agent socket", &format!("{shown}, mode 0600, {state}"))?;
        }
        _ => r.problem("ssh agent socket", &format!("{shown} is not a socket of yours with mode 0600"))?,
    }
    // Checked when the config was loaded.
    let names = config.ssh_agent_profiles().unwrap_or_default();
    if names.is_empty() {
        return r.ok("ssh agent", "[ssh_agent] lists no profiles: it offers no keys");
    }
    match crate::client::call(env, Op::SshList, false) {
        Ok(None) => r.ok("ssh agent", &format!("profiles {}; the agent is not running", names.join(", ")))?,
        Ok(Some(Reply::SshKeys { keys, profiles, lists })) => {
            let state = |unlocked| if unlocked { "unlocked" } else { "locked" };
            let profiles: Vec<String> =
                profiles.iter().map(|p| format!("{} ({})", p.name, state(p.unlocked))).collect();
            let note = format!(
                "profiles {}; {} keys offered; {lists} key listings since the agent started",
                profiles.join(", "),
                keys.len()
            );
            r.ok("ssh agent", &note)?;
        }
        Ok(Some(Reply::Error { error })) => r.problem("ssh agent", &format!("answers with an error: {error}"))?,
        Ok(Some(_)) => r.problem("ssh agent", "the reply does not fit the request")?,
        Err(e) => r.problem("ssh agent", &e.to_string())?,
    }
    match (env.var)("SSH_AUTH_SOCK") {
        Some(sock) if std::path::Path::new(&sock) == path => r.ok("SSH_AUTH_SOCK", &shown),
        other => {
            let now = other.map_or_else(|| "unset".to_owned(), |s| s.to_string_lossy().into_owned());
            r.line("warning", "SSH_AUTH_SOCK", &format!("is {now}; set it to {shown} to use dybw's SSH agent"))
        }
    }
}

/// Local unlock (ADR 0006): a PIN is bound to the machine fingerprint, so one that cannot be read means no PIN.
pub(crate) fn local_unlock(machine: Result<String, dybw_peer::Error>, r: &mut Report<'_>) -> std::io::Result<()> {
    match machine {
        Ok(_) => r.ok(
            "local unlock",
            "the machine fingerprint is readable; `dybw unlock add pin` sets a PIN, `dybw unlock list` shows it",
        ),
        Err(e) => {
            let note = format!("the machine fingerprint cannot be read ({e}): no PIN can be set or used");
            r.line("warning", "local unlock", &note)
        }
    }
}

/// The `login` protector (ADR 0006, Linux): enrolled or not; when it is, whether the user keyring `pam_bwss` writes to
/// can be read, and when a login password handed over last unlocked the profile (`handover`: `None` without an agent).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn login_unlock(
    file: &std::path::Path,
    keyring: Result<(), dybw_peer::Error>,
    handover: &dyn Fn() -> Option<Option<u64>>,
    r: &mut Report<'_>,
) -> std::io::Result<()> {
    if !file.exists() {
        return r.ok("login unlock", "none; with pam_bwss installed, `dybw unlock add login` sets one");
    }
    r.ok("login unlock", &format!("{}, bound to this device", file.display()))?;
    match keyring {
        Ok(()) => r.ok("keyring", "the user keyring is readable")?,
        Err(e) => {
            let note = format!("the user keyring cannot be read ({e}): no login password reaches the agent");
            r.problem("keyring", &note)?;
        }
    }
    let note = match handover() {
        None => "the agent is not running".to_owned(),
        Some(None) => "none since the agent started".to_owned(),
        Some(Some(t)) => format!("at unix time {t}"),
    };
    r.ok("last handover", &note)
}

/// When the agent last unlocked `profile` by a login password: `None` when no agent answers.
#[cfg(target_os = "linux")]
fn handover(env: &Env, profile: &str) -> Option<Option<u64>> {
    let status = crate::client::call(env, Op::Status { profile: Some(profile.to_owned()) }, false).ok().flatten();
    let Some(Reply::Status { profiles, .. }) = status else { return None };
    Some(profiles.first().and_then(|p| p.login_handover))
}

/// The profile in use: its pinentry, local unlock and its policy file.
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
    local_unlock(dybw_peer::machine_id(), r)?;
    #[cfg(target_os = "linux")]
    {
        let file = ProfilePaths::with(home, &profile).unlock.join("login");
        login_unlock(&file, dybw_peer::keyring::readable(), &|| handover(env, &profile.name), r)?;
    }
    let file = ProfilePaths::with(home, &profile).policy;
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
