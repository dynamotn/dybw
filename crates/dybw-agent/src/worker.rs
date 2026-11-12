//! One worker thread per profile: a `current_thread` runtime plus a `LocalSet` owns the profile's state (the
//! unlocked vault, which is not `Send`), and the rest of the agent reaches it through a `Send` [`Worker`] handle.
//!
//! Task 4 and 5 extend [`Cmd`] and `handle`; nothing else about the handle changes.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dybw_proto::{AgentError, ProfileStatus, Reply};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::config::Profile;

/// What a profile worker is asked to do.
#[derive(Debug)]
#[non_exhaustive]
pub enum Cmd {
    Status,
    /// Drop the keys now.
    Lock,
    /// Lock when the profile has been idle for its lock timeout. Does not count as use.
    IdleCheck,
    /// Lock and end the thread.
    Exit,
    /// Test only: put a vault in the slot.
    #[cfg(test)]
    Install,
    /// Test only: panic inside the command task.
    #[cfg(test)]
    Panic,
    /// Test only: panic in the worker loop itself, which ends the thread.
    #[cfg(test)]
    Crash,
}

/// The unlocked vault of a profile. Task 4 replaces the body with the core's `UnlockedVault`; the slot owns it
/// and dropping it is what wipes the keys.
pub struct UnlockedVault {
    _key: Zeroizing<Vec<u8>>,
}

struct Msg {
    cmd: Cmd,
    /// The agent's monotonic clock at the request.
    now: Instant,
    reply: oneshot::Sender<Reply>,
}

#[derive(Default)]
struct State {
    slot: Option<UnlockedVault>,
    last_used: Option<Instant>,
}

/// The `Send` handle to a profile's worker thread.
pub struct Worker {
    tx: mpsc::UnboundedSender<Msg>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

fn internal() -> Reply {
    Reply::Error { error: AgentError::Internal }
}

impl Worker {
    pub fn spawn(profile: &Profile, credentials: PathBuf) -> Worker {
        let (tx, rx) = mpsc::unbounded_channel();
        let (name, timeout) = (profile.name.clone(), profile.lock_timeout);
        let thread = std::thread::spawn(move || run(name, credentials, timeout, rx));
        Worker { tx, thread: std::sync::Mutex::new(Some(thread)) }
    }

    /// Run `cmd` on the worker. A worker that panicked or died answers `Internal`, so a profile never hangs.
    pub async fn call(&self, cmd: Cmd, now: Instant) -> Reply {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Msg { cmd, now, reply }).is_err() {
            return internal();
        }
        rx.await.unwrap_or_else(|_| internal())
    }

    /// False once the worker thread is gone.
    pub fn is_alive(&self) -> bool {
        !self.tx.is_closed()
    }

    /// Lock, end the thread and wait for it: the keys are gone when this returns.
    pub async fn stop(&self, now: Instant) {
        self.call(Cmd::Exit, now).await;
        let thread = self.thread.lock().ok().and_then(|mut t| t.take());
        // A panicked thread has already dropped its state while unwinding.
        let _ = thread.map(std::thread::JoinHandle::join);
    }
}

#[expect(clippy::expect_used, reason = "a worker without a runtime is a dead worker, which `call` reports as Internal")]
fn run(name: String, credentials: PathBuf, timeout: Duration, mut rx: mpsc::UnboundedReceiver<Msg>) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().expect("worker runtime");
    let local = tokio::task::LocalSet::new();
    let state = Rc::new(RefCell::new(State::default()));
    rt.block_on(local.run_until(async {
        while let Some(Msg { cmd, now, reply }) = rx.recv().await {
            let exit = matches!(cmd, Cmd::Exit);
            #[cfg(test)]
            let crash = matches!(cmd, Cmd::Crash);
            let task =
                tokio::task::spawn_local(handle(state.clone(), name.clone(), credentials.clone(), timeout, cmd, now));
            // A panic in the task leaves the slot in an unknown state: wipe it and answer Internal.
            let out = task.await.unwrap_or_else(|_| {
                state.borrow_mut().slot = None;
                internal()
            });
            #[cfg(test)]
            assert!(!crash, "worker crash for a test");
            let _ = reply.send(out);
            if exit {
                break;
            }
        }
    }));
}

async fn handle(
    state: Rc<RefCell<State>>,
    name: String,
    credentials: PathBuf,
    timeout: Duration,
    cmd: Cmd,
    now: Instant,
) -> Reply {
    let mut st = state.borrow_mut();
    if !matches!(cmd, Cmd::Status | Cmd::IdleCheck) {
        st.last_used = Some(now);
    }
    match cmd {
        Cmd::Status => Reply::Status {
            agent_version: env!("CARGO_PKG_VERSION").into(),
            profiles: vec![ProfileStatus {
                profile: name,
                logged_in: credentials.exists(),
                unlocked: st.slot.is_some(),
            }],
        },
        Cmd::IdleCheck => {
            let idle = now.saturating_duration_since(st.last_used.unwrap_or(now));
            if !timeout.is_zero() && idle >= timeout {
                st.slot = None;
                tracing::info!(profile = %name, "locked after idle");
            }
            Reply::Done
        }
        Cmd::Lock | Cmd::Exit => {
            st.slot = None;
            Reply::Done
        }
        #[cfg(test)]
        Cmd::Install => {
            st.slot = Some(UnlockedVault { _key: Zeroizing::new(vec![7; 32]) });
            Reply::Done
        }
        #[cfg(test)]
        Cmd::Panic => {
            st.slot = Some(UnlockedVault { _key: Zeroizing::new(vec![7; 32]) });
            panic!("task panic for a test");
        }
        #[cfg(test)]
        Cmd::Crash => Reply::Done,
    }
}
