//! The dybw agent. P4.1 builds it up: the config layer first, then the socket server and the vault session.

pub mod agent;
pub mod audit;
pub mod caller;
pub mod config;
pub mod credentials;
pub mod device;
pub mod hardening;
pub mod host;
pub mod paths;
pub mod policy;
pub mod read;
pub mod server;
pub mod session;
pub mod socket;
pub mod trust;
pub mod worker;

#[cfg(test)]
mod flow_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod read_tests;

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

/// The line `dybw-agent` prints at start.
pub fn banner() -> String {
    format!("dybw-agent {} (protocol {PROTOCOL_VERSION})", env!("CARGO_PKG_VERSION"))
}

/// Start the agent and serve until `StopAgent`, SIGTERM or SIGINT.
#[expect(clippy::expect_used, reason = "`trust()` always sets the home")]
pub fn run() -> anyhow::Result<()> {
    // First, before any other work: nothing may attach to the agent and read its memory.
    eprint!("{}", hardening::report(&hardening::harden()));
    init_logging();
    let trust = trust::trust()?;
    let home = trust.home.clone().expect("trust() sets the home");
    let var = |name: &str| std::env::var_os(name);
    let config = config::Config::load(&paths::config_path(&home))?;
    let user = trust.user.clone();
    // The lock file stays held until the process ends.
    let (listener, _lock) = socket::bind(&socket::socket_dir(&var, user.uid), user.uid)?;
    let harnesses = caller::Harnesses::load(&paths::harnesses_path(&home));
    // The companion CLI: the `dybw` next to this executable.
    let companion = trust.exe.as_deref().and_then(|exe| std::fs::canonicalize(exe.with_file_name("dybw")).ok());
    let resolver = Arc::new(caller::Resolver::new(Arc::new(dybw_peer::Os), harnesses).with_companion(companion));
    let audit = Arc::new(audit::FileAudit::new(&paths::audit_path(&home), user.uid));
    let agent = Arc::new(agent::Agent::new(config, home, user, real_spawn(trust), resolver, audit));
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(server::serve(agent, listener, stop_signal())).map_err(anyhow::Error::from)
}

/// Workers with the real host: the HTTP port and the trusted pinentry of their profile.
fn real_spawn(trust: dybw_native::config::Trust) -> agent::Spawn {
    Box::new(move |ctx| {
        let host = host::RealHost::new(trust.clone(), &ctx.profile.pinentry);
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
        let worker = super::real_spawn(trust)(crate::session::Ctx {
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
