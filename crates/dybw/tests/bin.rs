#![expect(clippy::expect_used, reason = "tests")]

use std::process::Command;

fn dybw(args: &[&str]) -> std::process::Output {
    // An empty runtime directory: no agent answers there, and none may be started from the test binary's folder.
    let dir = tempfile::Builder::new().prefix("d").tempdir_in("/tmp").expect("tempdir");
    Command::new(env!("CARGO_BIN_EXE_dybw"))
        .args(args)
        .env("XDG_RUNTIME_DIR", dir.path())
        .env_remove("DYBW_PROFILE")
        .output()
        .expect("run dybw")
}

#[test]
fn version_flag_prints_the_version() {
    let out = dybw(&["--version"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("dybw {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn no_arguments_is_a_usage_error() {
    assert_eq!(dybw(&[]).status.code(), Some(1));
}

#[test]
fn unlocked_without_an_agent_exits_1_silently() {
    let out = dybw(&["unlocked"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty() && out.stderr.is_empty());
}

#[test]
fn the_clipboard_clearer_reads_its_job_from_stdin_and_refuses_an_empty_one() {
    let out = dybw(&["__clear-clipboard"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&out.stderr), "dybw: not a clipboard job\n");
}
