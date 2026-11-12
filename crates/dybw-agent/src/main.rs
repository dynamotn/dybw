use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("{}", dybw_agent::banner());
        return ExitCode::SUCCESS;
    }
    match dybw_agent::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dybw-agent: {e:#}");
            ExitCode::FAILURE
        }
    }
}
