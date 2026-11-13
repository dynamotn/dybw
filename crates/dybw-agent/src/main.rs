use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("{}", dybw_agent::banner());
        return ExitCode::SUCCESS;
    }
    dybw_agent::exit_code(dybw_agent::run())
}
