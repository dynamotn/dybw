//! The dybw agent. P4.1 builds it up: the config layer first, then the socket server and the vault session.

pub mod agent;
pub mod audit;
pub mod caller;
pub mod config;
pub mod credentials;
pub mod device;
#[cfg(any(target_os = "linux", test))]
pub mod handover;
pub mod hardening;
pub mod host;
pub mod paths;
pub mod policy;
pub mod pwgen;
pub mod rbw_view;
pub mod read;
pub mod server;
pub mod session;
pub mod socket;
pub mod ssh;
pub mod ssh_agent;
pub mod trust;
pub mod worker;

#[cfg(test)]
mod biometric_tests;
#[cfg(test)]
mod flow_tests;
#[cfg(test)]
mod pin_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod rbw_tests;
#[cfg(test)]
mod read_tests;
#[cfg(test)]
mod write_tests;

use std::sync::Arc;

use dybw_proto::PROTOCOL_VERSION;

/// `User::current()`. On macOS dybw-native probes with a temp file named by pid and nanoseconds, which collides when
/// tests call it in parallel; tests take this lock so they never do.
pub(crate) fn current_user() -> std::io::Result<dybw_native::fsutil::User> {
    #[cfg(test)]
    static PROBE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[cfg(test)]
    let _serial = PROBE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    dybw_native::fsutil::User::current()
}

/// Tests only, why a test is skipped under root: root bypasses the permission check it needs refused.
#[cfg(test)]
pub(crate) const ROOT_BYPASSES: &str = "root bypasses the permission check it needs refused";
/// Tests only, why a test is skipped under root: it checks the rules for an ordinary user, and the agent refuses root.
#[cfg(test)]
pub(crate) const ROOT_REFUSED: &str = "the agent refuses root (root_is_refused); this checks an ordinary user's rules";

/// Tests only: true under root, after saying on stderr which test is skipped and `why`. GitLab's `rust` image runs
/// jobs as root.
#[cfg(test)]
pub(crate) fn skipped_as_root(why: &str) -> bool {
    let root = rustix::process::geteuid().is_root();
    let test = std::thread::current().name().unwrap_or("a test").to_owned();
    eprint!("{}", if root { format!("skipped {test} under root: {why}\n") } else { String::new() });
    root
}

/// The line `dybw-agent` prints at start.
pub fn banner() -> String {
    format!("dybw-agent {} (protocol {PROTOCOL_VERSION})", env!("CARGO_PKG_VERSION"))
}

#[cfg(all(feature = "test-home", not(debug_assertions)))]
compile_error!("the `test-home` feature is for tests only and must not be built in release");

/// Start the agent and serve until `StopAgent`, SIGTERM or SIGINT.
pub fn run() -> anyhow::Result<()> {
    run_on(None)
}

/// Tests only (feature `test-home`): `run()` with the password database's home taken from
/// [`trust::TEST_PASSWD_HOME`], so the agent binary can be tested on a home of its own.
#[cfg(feature = "test-home")]
pub fn run_test_home() -> anyhow::Result<()> {
    run_on(std::env::var_os(trust::TEST_PASSWD_HOME).map(Into::into))
}

/// The exit status for what `run` returned; an error is printed first.
pub fn exit_code(result: anyhow::Result<()>) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dybw-agent: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[expect(clippy::expect_used, reason = "`trust()` always sets the home")]
fn run_on(passwd: Option<std::path::PathBuf>) -> anyhow::Result<()> {
    // First, before any other work: nothing may attach to the agent and read its memory.
    eprint!("{}", hardening::report(&hardening::harden()));
    init_logging();
    let trust = trust::trust_on(passwd)?;
    let home = trust.home.clone().expect("trust() sets the home");
    let var = |name: &str| std::env::var_os(name);
    let config = config::Config::load(&paths::config_path(&home))?;
    let ssh_profiles = config.ssh_agent_profiles()?;
    let touch_id = config.touch_id_confirm()?;
    let user = trust.user.clone();
    let dir = socket::socket_dir(&var, user.uid);
    // The lock file stays held until the process ends.
    let (listener, lock) = socket::bind(&dir, user.uid)?;
    let ssh_listener = socket::bind_ssh(&dir, user.uid, &lock)?;
    let harnesses = caller::Harnesses::load(&paths::harnesses_path(&home));
    // The companion CLI: the `dybw` next to this executable.
    let companion = trust.exe.as_deref().and_then(|exe| std::fs::canonicalize(exe.with_file_name("dybw")).ok());
    let resolver = Arc::new(caller::Resolver::new(Arc::new(dybw_peer::Os), harnesses).with_companion(companion));
    let audit = Arc::new(audit::FileAudit::new(&paths::audit_path(&home), user.uid));
    let agent = Arc::new(agent::Agent::new(config, home, user, real_spawn(trust, touch_id), resolver, audit));
    let confirm = Arc::new(ssh_agent::Confirm(agent.clone()));
    let ssh = Arc::new(ssh_agent::SshAgent::new(agent.clone(), ssh_profiles, confirm));
    let _ = agent.ssh.set(Arc::downgrade(&ssh));
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let served = runtime.block_on(server::serve(agent, listener, Some((ssh_listener, ssh)), stop_signal()));
    drop(lock);
    served.map_err(anyhow::Error::from)
}

/// Workers with the real host: the HTTP port, the trusted pinentry of their profile, and Touch ID for confirmations
/// unless `[agent] touch_id_confirm = false`.
fn real_spawn(trust: dybw_native::config::Trust, touch_id: bool) -> agent::Spawn {
    Box::new(move |ctx| {
        let host = host::RealHost::new(trust.clone(), &ctx.profile.pinentry, touch_id);
        worker::Worker::spawn(host, ctx)
    })
}

/// Log to stderr, `info` by default and `RUST_LOG` to change it. Log lines carry metadata only: profile names, op
/// kinds and decisions, never a request body or a value.
fn init_logging() {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::filter::LevelFilter;
    let filter = EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
}

/// Resolves on SIGTERM or SIGINT.
async fn stop_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => Ok(()),
        interrupt = tokio::signal::ctrl_c() => interrupt,
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use dybw_native::config::Trust;
    use dybw_native::fsutil::User;
    use dybw_proto::Reply;

    #[tokio::test]
    async fn real_workers_are_started_with_the_real_host() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        std::fs::write(&file, "[profiles.work]\nserver_url = \"https://w.example.org\"\nemail = \"w@example.org\"\n")
            .unwrap();
        let profile = crate::config::Config::load(&file).unwrap().profile(Some("work")).unwrap();
        let paths = crate::paths::ProfilePaths::with(dir.path(), &profile);
        let user = User { uid: rustix::process::geteuid().as_raw(), groups: None };
        let trust = Trust { search: Some("/usr/bin:/bin".into()), user: user.clone(), exe: None, home: None };
        let worker = super::real_spawn(trust, false)(crate::session::Ctx {
            profile,
            paths,
            user,
            audit: std::sync::Arc::new(crate::policy::NoAudit),
        });
        let status = worker.call(crate::worker::Cmd::Status, std::time::Instant::now()).await;
        assert!(matches!(status, Reply::Status { .. }));
        worker.stop(std::time::Instant::now()).await;
        // Stopping again is harmless.
        worker.stop(std::time::Instant::now()).await;
        assert!(!worker.is_alive());
    }

    #[test]
    fn banner_names_version_and_protocol() {
        assert_eq!(super::banner(), format!("dybw-agent {} (protocol 1)", env!("CARGO_PKG_VERSION")));
    }
}
