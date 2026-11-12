//! One worker thread per profile: a `current_thread` runtime plus a `LocalSet` owns the profile's state (the
//! unlocked vault, which is not `Send`), and the rest of the agent reaches it through a `Send` [`Worker`] handle.
//!
//! The loop never waits on a command. Quick ones (`Status`, `IdleCheck`, `Lock`, `Exit`) run inline; the long ones
//! (login, unlock, sync, and what Task 5 adds) each run in a task of their own that the loop tracks, so a `Lock`
//! is never queued behind a pinentry or the network and cancels what is in flight. The state is behind a `RefCell`
//! that is never borrowed across an await.
//!
//! The reads reach the unlocked vault under a short `shared.state.borrow()` (`state.slot` is `Some(Session)` while
//! unlocked, `Session::vault` is the core's `UnlockedVault`). `list` and `search` are quick. `get` and `history`
//! are long: find the item by its summary, drop the borrow, wait for the user's confirmation (the value gate),
//! and only then borrow again to open it. A `Lock` aborts the task at its next await, so nothing is opened or
//! returned after it.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dybw_core::profile::UnlockedVault;
use dybw_native::prompter::one_line;
use dybw_proto::{AgentError, Field, ProfileStatus, Reply, Select};
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use crate::host::Host;
use crate::read::{self, Found, Lookup};
use crate::session::{self, Ctx, Session};

/// How long `stop` waits for the thread: a worker that cannot end is left behind, and the process exit ends it.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// What a profile worker is asked to do.
#[derive(Debug)]
#[non_exhaustive]
pub enum Cmd {
    Status,
    /// Ask for the API key and store it.
    Login,
    /// Ask for the master password and unlock; answers `Done` at once when already unlocked.
    Unlock,
    /// Fetch `/sync` now.
    Sync,
    /// Drop the keys now, and cancel whatever is in flight.
    Lock,
    /// Lock when the profile has been idle for its lock timeout. Does not count as use.
    IdleCheck,
    /// The names (and optionally users, folders, types) of every item.
    List {
        fields: Vec<Field>,
        folder: Option<String>,
    },
    /// `List` for the items whose name or user has `term`.
    Search {
        term: String,
        folder: Option<String>,
        fields: Vec<Field>,
    },
    /// A value of one item, after the user confirmed (names of custom fields need no confirmation).
    Get {
        find: Lookup,
        select: Select,
    },
    /// The previous passwords of one item, after the user confirmed.
    History {
        find: Lookup,
    },
    /// Lock and end the thread.
    Exit,
    /// Test only: how many items this worker has opened.
    #[cfg(test)]
    Opens,
    /// Test only: panic inside a command task.
    #[cfg(test)]
    Panic,
    /// Test only: panic in the worker loop itself, which ends the thread.
    #[cfg(test)]
    Crash,
}

/// The commands that wait on the user or the network.
enum Long {
    Login,
    Unlock,
    Sync,
    /// `Some` is a `get`, `None` the password history.
    Read(Lookup, Option<Select>),
    #[cfg(test)]
    Panic,
}

struct Msg {
    cmd: Cmd,
    /// The agent's monotonic clock at the request.
    now: Instant,
    reply: oneshot::Sender<Reply>,
}

#[derive(Default)]
struct State {
    slot: Option<Session>,
    last_used: Option<Instant>,
    /// The latest agent time any message carried: "now" for work that finishes later.
    seen: Option<Instant>,
    next_id: u64,
    /// The long commands running now, cancelled by a lock.
    inflight: HashMap<u64, AbortHandle>,
}

#[derive(Default)]
struct Shared {
    state: RefCell<State>,
    /// One login, unlock or sync at a time; a second waits (a periodic sync skips).
    op: tokio::sync::Mutex<()>,
    /// One confirmation on the screen at a time: a second request waits for the first answer.
    asking: tokio::sync::Mutex<()>,
}

/// The `Send` handle to a profile's worker thread.
pub struct Worker {
    tx: mpsc::UnboundedSender<Msg>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

fn error(error: AgentError) -> Reply {
    Reply::Error { error }
}

fn internal() -> Reply {
    error(AgentError::Internal)
}

fn outcome(result: Result<(), AgentError>) -> Reply {
    result.map_or_else(error, |()| Reply::Done)
}

impl Worker {
    pub fn spawn<H: Host>(host: H, ctx: Ctx) -> Worker {
        let (tx, rx) = mpsc::unbounded_channel();
        let thread = std::thread::spawn(move || run(host, ctx, rx));
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

    /// Lock, end the thread and wait for it, for at most [`STOP_TIMEOUT`]: the keys are gone when this returns.
    pub async fn stop(&self, now: Instant) {
        let ended = async {
            self.call(Cmd::Exit, now).await;
            let thread = self.thread.lock().ok().and_then(|mut t| t.take());
            if let Some(thread) = thread {
                // A panicked thread has already dropped its state while unwinding; the join is off the runtime.
                let _ = tokio::task::spawn_blocking(move || thread.join()).await;
            }
        };
        let _ = tokio::time::timeout(STOP_TIMEOUT, ended).await;
    }
}

#[expect(clippy::expect_used, reason = "a worker without a runtime is a dead worker, which `call` reports as Internal")]
fn run<H: Host>(host: H, ctx: Ctx, mut rx: mpsc::UnboundedReceiver<Msg>) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("worker runtime");
    let local = tokio::task::LocalSet::new();
    let (host, ctx, shared) = (Rc::new(host), Rc::new(ctx), Rc::new(Shared::default()));
    let period = ctx.profile.sync_interval;
    rt.block_on(local.run_until(async {
        // No periodic sync (zero) still wakes up now and then, to do nothing: one loop shape for both.
        let every = if period.is_zero() { Duration::from_secs(3600) } else { period };
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    if msg.is_none_or(|msg| on_msg(&shared, &host, &ctx, msg)) {
                        break;
                    }
                }
                _ = tick.tick() => {
                    if periodic_due(&shared, period) {
                        spawn(&shared, &host, &ctx, Long::Sync, None);
                    }
                }
            }
        }
        lock(&shared);
    }));
}

/// A periodic sync is for an unlocked profile with an interval: a locked one has nothing to sync.
fn periodic_due(shared: &Shared, period: Duration) -> bool {
    !period.is_zero() && shared.state.borrow().slot.is_some()
}

/// Handle one message; true when the worker must end.
fn on_msg<H: Host>(shared: &Rc<Shared>, host: &Rc<H>, ctx: &Rc<Ctx>, Msg { cmd, now, reply }: Msg) -> bool {
    {
        let mut st = shared.state.borrow_mut();
        st.seen = Some(now);
        if !matches!(cmd, Cmd::Status | Cmd::IdleCheck) {
            st.last_used = Some(now);
        }
    }
    let long = match cmd {
        Cmd::Status => return quick(reply, status(shared, ctx)),
        Cmd::IdleCheck => {
            idle_check(shared, ctx, now);
            return quick(reply, Reply::Done);
        }
        Cmd::Lock => {
            lock(shared);
            return quick(reply, Reply::Done);
        }
        Cmd::List { fields, folder } => {
            let list = |v: &UnlockedVault| Ok(read::list(v, &fields, folder.as_deref(), None));
            return quick(reply, with_vault(shared, list).unwrap_or_else(error));
        }
        Cmd::Search { term, folder, fields } => {
            let search = |v: &UnlockedVault| Ok(read::list(v, &fields, folder.as_deref(), Some(&term)));
            return quick(reply, with_vault(shared, search).unwrap_or_else(error));
        }
        Cmd::Get { find, select } => Long::Read(find, Some(select)),
        Cmd::History { find } => Long::Read(find, None),
        #[cfg(test)]
        Cmd::Opens => {
            return quick(reply, Reply::Value { value: dybw_proto::Secret::new(read::OPENS.get().to_string()) });
        }
        Cmd::Exit => {
            lock(shared);
            let _ = reply.send(Reply::Done);
            return true;
        }
        Cmd::Login => Long::Login,
        Cmd::Unlock => Long::Unlock,
        Cmd::Sync => Long::Sync,
        #[cfg(test)]
        Cmd::Panic => Long::Panic,
        #[cfg(test)]
        Cmd::Crash => panic!("worker crash for a test"),
    };
    spawn(shared, host, ctx, long, Some(reply));
    false
}

fn quick(reply: oneshot::Sender<Reply>, answer: Reply) -> bool {
    let _ = reply.send(answer);
    false
}

fn status(shared: &Shared, ctx: &Ctx) -> Reply {
    Reply::Status {
        agent_version: env!("CARGO_PKG_VERSION").into(),
        profiles: vec![ProfileStatus {
            profile: ctx.profile.name.clone(),
            logged_in: ctx.paths.credentials.exists(),
            unlocked: shared.state.borrow().slot.is_some(),
            last_sync: ctx.last_sync(),
        }],
    }
}

fn idle_check(shared: &Shared, ctx: &Ctx, now: Instant) {
    let timeout = ctx.profile.lock_timeout;
    let idle = {
        let st = shared.state.borrow();
        st.slot.is_some().then(|| now.saturating_duration_since(st.last_used.unwrap_or(now)))
    };
    if !timeout.is_zero() && idle.is_some_and(|idle| idle >= timeout) {
        lock(shared);
        tracing::info!(profile = %ctx.profile.name, "locked after idle");
    }
}

/// Drop the keys and cancel every command in flight (at its next await).
fn lock(shared: &Shared) {
    let mut st = shared.state.borrow_mut();
    for (_, task) in st.inflight.drain() {
        task.abort();
    }
    st.slot = None;
}

/// Run a long command in a task of its own, and answer from a second one. `reply` is `None` for the periodic
/// sync, which is no use of the profile and has no one to answer.
fn spawn<H: Host>(shared: &Rc<Shared>, host: &Rc<H>, ctx: &Rc<Ctx>, long: Long, reply: Option<oneshot::Sender<Reply>>) {
    let id = {
        let mut st = shared.state.borrow_mut();
        st.next_id += 1;
        st.next_id
    };
    let work = tokio::task::spawn_local(run_long(shared.clone(), host.clone(), ctx.clone(), long, reply.is_some()));
    shared.state.borrow_mut().inflight.insert(id, work.abort_handle());
    let shared = shared.clone();
    tokio::task::spawn_local(async move {
        let answer = match work.await {
            Ok(answer) => answer,
            Err(e) if e.is_cancelled() => error(AgentError::Locked),
            // A panic leaves the slot in an unknown state: wipe it.
            Err(_) => {
                shared.state.borrow_mut().slot = None;
                internal()
            }
        };
        shared.state.borrow_mut().inflight.remove(&id);
        if let Some(reply) = reply {
            let _ = reply.send(answer);
        }
    });
}

async fn run_long<H: Host>(shared: Rc<Shared>, host: Rc<H>, ctx: Rc<Ctx>, long: Long, wait: bool) -> Reply {
    match long {
        Long::Login => {
            // One pinentry at a time: a second login waits for the first.
            let _op = shared.op.lock().await;
            outcome(session::login(&*host, &ctx).await)
        }
        Long::Unlock => unlock(&shared, &*host, &ctx).await,
        Long::Sync => sync(&shared, &*host, &ctx, wait).await,
        Long::Read(find, select) => get(&shared, &*host, &ctx, find, select).await,
        #[cfg(test)]
        Long::Panic => panic!("task panic for a test"),
    }
}

/// Run `f` on the unlocked vault; `Locked` when there is none.
fn with_vault<T>(shared: &Shared, f: impl FnOnce(&UnlockedVault) -> Result<T, AgentError>) -> Result<T, AgentError> {
    let st = shared.state.borrow();
    f(&st.slot.as_ref().ok_or(AgentError::Locked)?.vault)
}

/// What the confirmation says is asked: the profile, the item's name and what is read, each on one line.
fn ask_text(ctx: &Ctx, found: &Found, select: Option<&Select>) -> String {
    let tidy = |s: &str| one_line(s).chars().take(80).collect::<String>();
    let what = match select {
        Some(Select::Field(name)) => format!("its field \"{}\"", tidy(name)),
        Some(Select::Full) => "the full item (every value)".to_owned(),
        Some(Select::Raw) => "the raw item as JSON".to_owned(),
        Some(_) => "its main value (password, notes, number or public key)".to_owned(),
        None => "its password history".to_owned(),
    };
    format!("dybw profile {}: allow reading {what} of the item \"{}\"?", ctx.profile.name, tidy(&found.name))
}

/// `get` and `history`: find the item from its summary (a missing or ambiguous one ends here, with no prompt), get
/// the user's yes (the value gate: a no or a timeout is `Denied`, and nothing was opened), and only then open the
/// item, build the reply and drop it. A lock during the wait cancels this task.
async fn get<H: Host>(shared: &Shared, host: &H, ctx: &Ctx, find: Lookup, select: Option<Select>) -> Reply {
    let found = match with_vault(shared, |v| read::find(v, &find)) {
        Ok(found) => found,
        Err(e) => return error(e),
    };
    // Names of custom fields are not values: no prompt.
    if !matches!(select, Some(Select::ListFields)) {
        if found.reprompt {
            // Until P4.3 can ask for the master password again, a reprompt item gives no value and no question.
            tracing::warn!(profile = %ctx.profile.name, id = %found.id, "value request denied: the item needs a reprompt (P4.3)");
            return error(AgentError::Denied);
        }
        let _one_at_a_time = shared.asking.lock().await;
        let answer = session::confirm(host, &ask_text(ctx, &found, select.as_ref())).await;
        tracing::info!(profile = %ctx.profile.name, id = %found.id, allowed = answer.is_ok(), "value request");
        if let Err(e) = answer {
            return error(e);
        }
    }
    let read = |v: &UnlockedVault| match &select {
        Some(select) => read::value(v, &found.id, select),
        None => read::history(v, &found.id),
    };
    with_vault(shared, read).unwrap_or_else(error)
}

async fn unlock<H: Host>(shared: &Shared, host: &H, ctx: &Ctx) -> Reply {
    let _op = shared.op.lock().await;
    if shared.state.borrow().slot.is_some() {
        return Reply::Done;
    }
    match session::unlock(host, ctx).await {
        Ok(session) => {
            let mut st = shared.state.borrow_mut();
            // The idle timeout runs from the answer, not from a request that waited on the user.
            st.last_used = st.seen;
            st.slot = Some(session);
            Reply::Done
        }
        Err(e) => error(e),
    }
}

/// Fetch `/sync`, keep it as the offline copy and show it to the vault. `wait` is false for the periodic sync, which
/// skips a round when another operation is running. A lock cancels this task, so no wait or fetch outlives the keys.
async fn sync<H: Host>(shared: &Shared, host: &H, ctx: &Ctx, wait: bool) -> Reply {
    let target = shared.state.borrow().slot.as_ref().map(|s| (s.origin.clone(), s.urls.clone()));
    let Some((origin, urls)) = target else { return error(AgentError::Locked) };
    let _op = if wait {
        shared.op.lock().await
    } else {
        match shared.op.try_lock() {
            Ok(op) => op,
            Err(_) => return Reply::Done,
        }
    };
    let sync = match session::fetch(host, ctx, &origin, &urls).await {
        Ok(sync) => sync,
        Err(e) => {
            if !wait {
                tracing::warn!(profile = %ctx.profile.name, "periodic sync failed: {e}");
            }
            return error(e);
        }
    };
    session::save_cache(ctx, &sync).await;
    if let Some(session) = shared.state.borrow_mut().slot.as_mut() {
        session.vault.sync = sync;
    }
    Reply::Done
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_locked_profile_or_one_without_an_interval_has_no_periodic_sync() {
        let shared = Shared::default();
        assert!(!periodic_due(&shared, Duration::from_secs(300)), "locked");
        assert!(!periodic_due(&shared, Duration::ZERO), "no interval");
    }
}
