#![expect(clippy::expect_used, reason = "tests")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use dybw_proto::{Op, Reply, Request, Response, decode_response, encode};

fn agent(home: &std::path::Path, runtime: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_dybw-agent"))
        .env("HOME", home)
        .env("XDG_RUNTIME_DIR", runtime)
        .env_remove("XDG_CONFIG_HOME")
        .stderr(Stdio::null())
        .spawn()
        .expect("start dybw-agent")
}

/// Connect once the agent is listening; a short socket path keeps clear of the sun_path limit.
fn connect(runtime: &std::path::Path) -> UnixStream {
    let socket = runtime.join("dybw/agent.sock");
    let start = Instant::now();
    loop {
        match UnixStream::connect(&socket) {
            Ok(s) => return s,
            Err(e) => assert!(start.elapsed() < Duration::from_secs(20), "agent never answered: {e}"),
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn ask(runtime: &std::path::Path, op: Op) -> Reply {
    let mut s = connect(runtime);
    s.write_all(&encode(&Request::new(op)).expect("encode")).expect("send");
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("read");
    let (Response { reply, .. }, _) = decode_response(&buf).expect("frame").expect("complete");
    reply
}

fn dirs() -> (tempfile::TempDir, tempfile::TempDir) {
    let home = tempfile::tempdir().expect("home");
    let runtime = tempfile::Builder::new().prefix("d").tempdir_in("/tmp").expect("runtime");
    (home, runtime)
}

#[test]
fn prints_banner_and_exits_zero() {
    let out = Command::new(env!("CARGO_BIN_EXE_dybw-agent")).arg("--version").output().expect("run dybw-agent");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{}\n", dybw_agent::banner()));
}

#[test]
fn an_untrusted_home_stops_it_with_a_message() {
    let out = Command::new(env!("CARGO_BIN_EXE_dybw-agent")).env("HOME", "relative").output().expect("run");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("HOME"));
}

#[test]
fn stop_agent_ends_it_cleanly_and_a_second_agent_is_refused() {
    let (home, runtime) = dirs();
    let mut first = agent(home.path(), runtime.path());
    assert!(matches!(ask(runtime.path(), Op::Status { profile: None }), Reply::Error { .. }), "no profile defined");
    let second = agent(home.path(), runtime.path()).wait().expect("wait second");
    assert!(!second.success(), "a second agent must refuse");
    assert!(matches!(ask(runtime.path(), Op::StopAgent), Reply::Done), "the first still answers");
    assert!(first.wait().expect("wait").success());
}

fn ends_on(signal: &str) {
    let (home, runtime) = dirs();
    let mut child = agent(home.path(), runtime.path());
    drop(connect(runtime.path()));
    let pid = child.id().to_string();
    assert!(Command::new("kill").args([signal, &pid]).status().expect("kill").success());
    assert!(child.wait().expect("wait").success());
}

#[test]
fn sigterm_ends_it_cleanly() {
    ends_on("-TERM");
}

#[test]
fn sigint_ends_it_cleanly() {
    ends_on("-INT");
}

fn fails_with(home: &std::path::Path, runtime: &std::path::Path, text: &str) {
    let out = Command::new(env!("CARGO_BIN_EXE_dybw-agent"))
        .env("HOME", home)
        .env("XDG_RUNTIME_DIR", runtime)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .expect("run");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains(text), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn a_bad_config_or_socket_directory_stops_it_before_serving() {
    let (home, runtime) = dirs();
    let config = home.path().join(".config/dybw");
    std::fs::create_dir_all(&config).expect("config dir");
    std::fs::write(config.join("config.toml"), "not = [valid\n").expect("config");
    fails_with(home.path(), runtime.path(), "config.toml");
    std::fs::remove_file(config.join("config.toml")).expect("remove");
    // The runtime dir is a file, so `dybw` cannot be created inside it.
    let file = runtime.path().join("file");
    std::fs::write(&file, "").expect("file");
    fails_with(home.path(), &file, "create");
}

#[test]
fn the_config_comes_from_the_trusted_home_not_from_xdg_config_home() {
    let (home, runtime) = dirs();
    // A starter points XDG_CONFIG_HOME at a config of its own: it is never read.
    let elsewhere = tempfile::tempdir().expect("xdg");
    std::fs::create_dir_all(elsewhere.path().join("dybw")).expect("dir");
    std::fs::write(elsewhere.path().join("dybw/config.toml"), "not = [valid\n").expect("config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dybw-agent"))
        .env("HOME", home.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_CONFIG_HOME", elsewhere.path())
        .stderr(Stdio::null())
        .spawn()
        .expect("start dybw-agent");
    assert!(matches!(ask(runtime.path(), Op::StopAgent), Reply::Done));
    assert!(child.wait().expect("wait").success());
}
