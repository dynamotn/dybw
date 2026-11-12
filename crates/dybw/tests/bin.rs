#![expect(clippy::expect_used, reason = "tests")]

use std::process::Command;

fn dybw(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dybw")).args(args).output().expect("run dybw")
}

#[test]
fn version_flag_prints_the_version() {
    let out = dybw(&["--version"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("dybw {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn no_arguments_exits_zero() {
    assert!(dybw(&[]).status.success());
}
