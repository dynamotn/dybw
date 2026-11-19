//! `-c`: the value goes to the clipboard marked as secret (in this process: it already passed the agent's gate), and a
//! detached `dybw __clear-clipboard` clears it after `clipboard_clear_seconds` if it still holds it. The clearer gets
//! the delay and the clipboard token on its stdin: its argv and environment carry neither, and nothing carries the
//! value.

use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

pub use dybw_peer::clipboard::{Error, Token};
use zeroize::Zeroizing;

/// The hidden subcommand the clearer runs.
pub const CLEAR_COMMAND: &str = "__clear-clipboard";

type CopyFn = Box<dyn Fn(&[u8]) -> Result<Token, Error>>;
type ClearFn = Box<dyn Fn(&Token) -> Result<bool, Error>>;
type SpawnFn = Box<dyn Fn(&str) -> io::Result<()>>;

/// The clipboard and the clearer as the CLI uses them; tests swap them.
pub struct Clip {
    pub copy: CopyFn,
    pub clear: ClearFn,
    /// Start the clearer with this job on its stdin.
    pub spawn: SpawnFn,
    pub sleep: Box<dyn Fn(Duration)>,
    /// The clearer reads its job (from stdin).
    pub job: Box<dyn Fn() -> io::Result<Zeroizing<String>>>,
}

impl Clip {
    pub fn real() -> Clip {
        Clip {
            copy: Box::new(dybw_peer::clipboard::copy),
            clear: Box::new(dybw_peer::clipboard::clear_if_unchanged),
            spawn: Box::new(|job| spawn_clearer(&std::env::current_exe()?, job)),
            sleep: Box::new(std::thread::sleep),
            job: Box::new(|| io::read_to_string(io::stdin()).map(Zeroizing::new)),
        }
    }
}

/// Start `program __clear-clipboard` in a process group of its own (a Ctrl-C at the shell does not stop it), detached
/// from the terminal, with `job` on its stdin.
pub fn spawn_clearer(program: &Path, job: &str) -> io::Result<()> {
    let mut child = Command::new(program)
        .arg(CLEAR_COMMAND)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    child.stdin.take().map_or(Ok(()), |mut stdin| stdin.write_all(job.as_bytes()))
}

/// `<seconds> <token>`: what the clearer needs.
pub fn job(seconds: u64, token: &Token) -> String {
    format!("{seconds} {}\n", token.encode())
}

pub fn parse_job(text: &str) -> Option<(Duration, Token)> {
    let (seconds, token) = text.trim_end().split_once(' ')?;
    Some((Duration::from_secs(seconds.parse().ok()?), Token::decode(token)?))
}
