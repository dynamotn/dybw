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
// `rustfmt::skip`: one long line keeps the error path of `?` from being the last, uncoverable, region of its line.
#[rustfmt::skip]
#[expect(clippy::expect_used, reason = "`trust()` always sets the home")]
pub fn run() -> anyhow::Result<()> {
    eprint!("{}", hardening::report(&hardening::harden()));
    let trust = trust::trust()?;
    let home = trust.home.expect("trust() sets the home");
    let var = |name: &str| std::env::var_os(name);
    let config = config::Config::load(&paths::config_path(&var, &home))?;
    let uid = trust.user.uid;
    let listener = socket::bind(&socket::socket_dir(&var, uid), uid)?;
    let agent = Arc::new(agent::Agent::new(config, home, uid, Box::new(var)));
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?; let stop = async { tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} } };
        server::serve(agent, listener, stop).await
    }).map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    #[test]
    fn banner_names_version_and_protocol() {
        assert_eq!(super::banner(), format!("dybw-agent {} (protocol 1)", env!("CARGO_PKG_VERSION")));
    }
}
