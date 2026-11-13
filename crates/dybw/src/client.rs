//! The connection to the agent: one request per connection, the reply read into wiped memory, and the agent
//! started on demand.

use std::cell::RefCell;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use dybw_proto::{FrameError, MAX_FRAME, Op, Reply, Request, decode_response, encode};
use zeroize::Zeroizing;

/// How long a started agent has to bind its socket.
pub const START_WAIT: Duration = Duration::from_secs(5);
/// How long the socket is still awaited after the started agent exited.
const EXIT_GRACE: Duration = Duration::from_secs(1);
const POLL: Duration = Duration::from_millis(50);

/// How the CLI reads its environment; tests swap it.
pub type VarFn = Box<dyn Fn(&str) -> Option<OsString>>;

/// Everything the CLI takes from the machine; tests swap it.
pub struct Env {
    pub var: VarFn,
    pub uid: u32,
    /// This user's home in the password database (never `HOME`): where the agent keeps its files.
    pub home: Option<PathBuf>,
    /// The directory of the running `dybw`: the only place `dybw-agent` is looked for.
    pub exe_dir: Option<PathBuf>,
    pub start_wait: Duration,
    /// The log of the agent this process started, once it has started one.
    pub started_log: RefCell<Option<PathBuf>>,
}

impl Env {
    pub fn real() -> Env {
        let uid = rustix::process::geteuid().as_raw();
        Env {
            var: Box::new(|name| std::env::var_os(name)),
            uid,
            home: dybw_agent::trust::passwd_home(uid),
            exe_dir: exe_dir_of(std::env::current_exe()),
            start_wait: START_WAIT,
            started_log: RefCell::new(None),
        }
    }

    fn dir(&self) -> PathBuf {
        dybw_agent::socket::socket_dir(&self.var, self.uid)
    }

    fn socket(&self) -> PathBuf {
        self.dir().join("agent.sock")
    }
}

/// The real directory of an executable path: symlinks resolved, which macOS' `current_exe` does not do.
pub(crate) fn exe_dir_of(exe: std::io::Result<PathBuf>) -> Option<PathBuf> {
    let real = std::fs::canonicalize(exe.ok()?).ok()?;
    real.parent().map(PathBuf::from)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the agent closed the connection (is it a different version? try `dybw agent stop`)")]
    Closed,
    #[error("unsafe socket directory: {0}")]
    Dir(String),
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
    stream.write_all(&encode(&Request::new(op))?).map_err(gone)?;
    read_reply(&mut stream).map(Some)
}

/// A write or read the agent cut off: the same hint as a closed connection.
pub(crate) fn gone(e: std::io::Error) -> Error {
    match e.kind() {
        ErrorKind::UnexpectedEof | ErrorKind::BrokenPipe | ErrorKind::ConnectionReset => Error::Closed,
        _ => e.into(),
    }
}

/// The socket directory must be the agent's own kind of directory before anything is sent into it. `false`: it
/// does not exist (and `autostart` is off, so it stays that way).
fn check_dir(env: &Env, autostart: bool) -> Result<bool, Error> {
    let (dir, uid) = (env.dir(), env.uid);
    let checked = if autostart {
        dybw_agent::socket::ensure_dir(&dir, uid)
    } else {
        match std::fs::symlink_metadata(&dir) {
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
            _ => dybw_agent::socket::check_dir(&dir, uid),
        }
    };
    checked.map(|()| true).map_err(|e| Error::Dir(format!("{e:#}")))
}

fn connect(env: &Env, autostart: bool) -> Result<Option<UnixStream>, Error> {
    if !check_dir(env, autostart)? {
        return Ok(None);
    }
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

/// The agent's log file next to its socket: owner only, appended to, never through a symlink.
fn open_log(path: &PathBuf) -> Result<File, Error> {
    let flags = rustix::fs::OFlags::NOFOLLOW.bits() as i32;
    let file = OpenOptions::new().create(true).append(true).mode(0o600).custom_flags(flags).open(path);
    file.map_err(|e| Error::Start(format!("cannot open the agent log {}: {e}", path.display())))
}

/// Spawn `dybw-agent` from next to this executable (never from `PATH`), detached, its output in the log file,
/// and wait for its socket.
fn start(env: &Env) -> Result<UnixStream, Error> {
    let Some(dir) = &env.exe_dir else { return Err(Error::Start("cannot locate the dybw executable".into())) };
    let bin = dir.join("dybw-agent");
    let log_path = env.dir().join("agent.log");
    let log = open_log(&log_path)?;
    let mut child = Command::new(&bin)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .process_group(0)
        .spawn()
        .map_err(|e| Error::Start(format!("{}: {e}; install dybw-agent next to dybw", bin.display())))?;
    *env.started_log.borrow_mut() = Some(log_path.clone());
    let deadline = Instant::now() + env.start_wait;
    let sock = env.socket();
    // When the agent exits at once it may have lost the start race to one that is about to answer.
    let mut exited = None;
    loop {
        if let Ok(stream) = UnixStream::connect(&sock) {
            return Ok(stream);
        }
        if exited.is_none()
            && let Ok(Some(status)) = child.try_wait()
        {
            exited = Some((status, (Instant::now() + EXIT_GRACE).min(deadline)));
        }
        let (limit, what) = match exited {
            Some((status, limit)) => (limit, format!("the agent exited at start ({status})")),
            None => (deadline, format!("no answer on {} after {:?}", sock.display(), env.start_wait)),
        };
        if Instant::now() >= limit {
            return Err(Error::Start(format!("{what}; see {}", log_path.display())));
        }
        std::thread::sleep(POLL);
    }
}

/// The whole reply frame, read into memory that is wiped when it drops.
fn read_reply(stream: &mut UnixStream) -> Result<Reply, Error> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).map_err(gone)?;
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len).into());
    }
    let mut frame = Zeroizing::new(vec![0u8; 4 + len]);
    let (head, body) = frame.split_at_mut(4);
    head.copy_from_slice(&header);
    stream.read_exact(body).map_err(gone)?;
    // The frame is complete by construction, so `None` (incomplete) cannot happen.
    let (response, _) = decode_response(&frame)?.ok_or(Error::Closed)?;
    Ok(response.reply)
}
