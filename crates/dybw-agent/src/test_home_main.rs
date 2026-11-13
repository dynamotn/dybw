//! `dybw-agent` for the tests (feature `test-home`): the password database's home comes from
//! `DYBW_TEST_PASSWD_HOME`. Never shipped: the feature refuses a build without debug assertions.

fn main() -> std::process::ExitCode {
    dybw_agent::exit_code(dybw_agent::run_test_home())
}
