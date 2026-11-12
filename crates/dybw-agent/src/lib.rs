//! The dybw agent. P4.1 builds it up: the config layer first, then the socket server and the vault session.

pub mod agent;
pub mod config;
pub mod credentials;
pub mod device;
pub mod hardening;
pub mod paths;
pub mod server;
pub mod socket;
pub mod trust;
pub mod worker;

use std::sync::Arc;

use dybw_proto::PROTOCOL_VERSION;

/// The line `dybw-agent` prints at start.
pub fn banner() -> String {
    format!("dybw-agent {} (protocol {PROTOCOL_VERSION})", env!("CARGO_PKG_VERSION"))
}

/// Start the agent and serve until `StopAgent`, SIGTERM or SIGINT.
#[expect(clippy::expect_used, reason = "`trust()` always sets the home")]
pub fn run() -> anyhow::Result<()> {
    init_logging();
    eprint!("{}", hardening::report(&hardening::harden()));
    let trust = trust::trust()?;
    let home = trust.home.expect("trust() sets the home");
    let var = |name: &str| std::env::var_os(name);
    let config = config::Config::load(&paths::config_path(&var, &home))?;
    let uid = trust.user.uid;
    // The lock file stays held until the process ends.
    let (listener, _lock) = socket::bind(&socket::socket_dir(&var, uid), uid)?;
    let agent = Arc::new(agent::Agent::new(config, home, uid, Box::new(var)));
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(server::serve(agent, listener, stop_signal())).map_err(anyhow::Error::from)
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
mod tests {
    #[test]
    fn banner_names_version_and_protocol() {
        assert_eq!(super::banner(), format!("dybw-agent {} (protocol 1)", env!("CARGO_PKG_VERSION")));
    }
}
