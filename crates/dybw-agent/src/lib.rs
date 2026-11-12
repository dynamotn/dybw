//! The dybw agent. P4.1 builds it up: the config layer first, then the socket server and the vault session.

pub mod config;
pub mod credentials;
pub mod device;
pub mod paths;
pub mod trust;

use dybw_proto::PROTOCOL_VERSION;

/// The line `dybw-agent` prints at start.
pub fn banner() -> String {
    format!("dybw-agent {} (protocol {PROTOCOL_VERSION})", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn banner_names_version_and_protocol() {
        assert_eq!(super::banner(), format!("dybw-agent {} (protocol 1)", env!("CARGO_PKG_VERSION")));
    }
}
