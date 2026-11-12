#![expect(clippy::expect_used, reason = "tests")]

#[test]
fn prints_banner_and_exits_zero() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_dybw-agent")).output().expect("run dybw-agent");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{}\n", dybw_agent::banner()));
}
