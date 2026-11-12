//! The connection to the agent: one request per connection, the reply read into wiped memory, and the agent
//! started on demand.

use std::ffi::OsString;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use dybw_proto::{FrameError, MAX_FRAME, Op, Reply, Request, decode_response, encode};
use zeroize::Zeroizing;

/// How long a started agent has to bind its socket.
pub const START_WAIT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(50);

/// How the CLI reads its environment; tests swap it.
pub type VarFn = Box<dyn Fn(&str) -> Option<OsString>>;

/// Everything the CLI takes from the machine; tests swap it.
pub struct Env {
    pub var: VarFn,
    pub uid: u32,
    /// The directory of the running `dybw`: the only place `dybw-agent` is looked for.
    pub exe_dir: Option<PathBuf>,
    pub start_wait: Duration,
}

impl Env {
    pub fn real() -> Env {
        Env {
            var: Box::new(|name| std::env::var_os(name)),
            uid: rustix::process::geteuid().as_raw(),
            exe_dir: std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from)),
            start_wait: START_WAIT,
        }
    }

    fn socket(&self) -> PathBuf {
        dybw_agent::socket::socket_dir(&self.var, self.uid).join("agent.sock")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the agent closed the connection (is it a different version? try `dybw agent stop`)")]
    Closed,
    #[error("cannot start the agent: {0}")]
    Start(String),
    #[error("cannot talk to the agent: {0}")]
    Io(#[from] std::io::Error),
    #[error("the agent sent an invalid reply: {0}")]
    Frame(#[from] FrameError),
}

/// Send `op` and read the reply. `Ok(None)`: no agent runs and `autostart` is off.
pub fn call(env: &Env, op: Op, autostart: bool) -> Result<Option<Reply>, Error> {
    let Some(mut stream) = connect(env, autostart)? else { return Ok(None) };
    stream.write_all(&encode(&Request::new(op))?)?;
    read_reply(&mut stream).map(Some)
}

fn connect(env: &Env, autostart: bool) -> Result<Option<UnixStream>, Error> {
    let sock = env.socket();
    match UnixStream::connect(&sock) {
        Ok(s) => Ok(Some(s)),
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
            if autostart {
                start(env).map(Some)
            } else {
                Ok(None)
            }
        }
        Err(e) => Err(Error::Start(format!("cannot connect to {}: {e}", sock.display()))),
    }
}

/// Spawn `dybw-agent` from next to this executable (never from `PATH`), detached, and wait for its socket.
fn start(env: &Env) -> Result<UnixStream, Error> {
    let Some(dir) = &env.exe_dir else { return Err(Error::Start("cannot locate the dybw executable".into())) };
    let bin = dir.join("dybw-agent");
    let mut child = Command::new(&bin)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| Error::Start(format!("{}: {e}; install dybw-agent next to dybw", bin.display())))?;
    let deadline = Instant::now() + env.start_wait;
    let sock = env.socket();
    loop {
        if let Ok(stream) = UnixStream::connect(&sock) {
            return Ok(stream);
        }
        if let Ok(Some(status)) = child.try_wait() {
            // It may have lost a race to another agent that is now answering.
            return UnixStream::connect(&sock)
                .map_err(|_| Error::Start(format!("the agent exited at start ({status})")));
        }
        if Instant::now() >= deadline {
            return Err(Error::Start(format!("no answer on {} after {:?}", sock.display(), env.start_wait)));
        }
        std::thread::sleep(POLL);
    }
}

/// The whole reply frame, read into memory that is wiped when it drops.
fn read_reply(stream: &mut UnixStream) -> Result<Reply, Error> {
    let eof = |e: std::io::Error| if e.kind() == ErrorKind::UnexpectedEof { Error::Closed } else { e.into() };
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).map_err(eof)?;
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len).into());
    }
    let mut frame = Zeroizing::new(vec![0u8; 4 + len]);
    let (head, body) = frame.split_at_mut(4);
    head.copy_from_slice(&header);
    stream.read_exact(body).map_err(eof)?;
    // The frame is complete by construction, so `None` (incomplete) cannot happen.
    let (response, _) = decode_response(&frame)?.ok_or(Error::Closed)?;
    Ok(response.reply)
}
