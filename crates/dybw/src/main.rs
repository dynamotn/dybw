use clap::Parser;

/// Command line client for the dybw agent.
// TODO(P4.4): dispatch on argv[0] here (the git-credential and ssh-askpass personalities) before parsing.
#[derive(Parser)]
#[command(version)]
struct Cli {}

fn main() {
    let Cli {} = Cli::parse();
}
