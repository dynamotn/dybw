//! One worker thread per profile: a `current_thread` runtime plus a `LocalSet` owns the profile's state (the
//! unlocked vault, which is not `Send`), and the rest of the agent reaches it through a `Send` [`Worker`] handle.
//!
//! The loop never waits on a command. Quick ones (`Status`, `IdleCheck`, `Lock`, `Exit`) run inline; the long ones
//! (login, unlock, sync, the value reads and the writes) each run in a task of their own that the loop tracks, so a
//! `Lock` is never queued behind a pinentry or the network and cancels what is in flight. The state is behind a
//! `RefCell` that is never borrowed across an await.
//!
//! The reads reach the unlocked vault under a short `shared.state.borrow()` (`state.slot` is `Some(Session)` while
//! unlocked, `Session::vault` is the core's `UnlockedVault`). `list` and `search` are quick. `get`, `history` and
//! `code` are long: find the item by its summary, drop the borrow, wait for the user's confirmation (the value gate)
//! and the master password of an item that asks for a reprompt, and only then borrow again to open it. A `Lock`
//! aborts the task at its next await, so nothing is opened or returned after it. The writes are in `worker/write.rs`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dybw_core::profile::UnlockedVault;
use dybw_core::totp::TotpKey;
use dybw_native::prompter::one_line;
use dybw_proto::{AgentError, Field, PolicyAction, PolicyEntry, PolicyRule, ProfileStatus, Reply, Secret, Select};
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use crate::caller::{Caller, Scope, hash_of, interpreter, launcher};
use crate::host::Host;
use crate::policy::{self, Access, AuditEvent, Decision, Store, Verdict};
use crate::read::{self, Found, Lookup};
use crate::session::{self, Ctx, Session};
use crate::ssh::{self, Key, SshError};
use crate::ssh_agent::SignContext;

mod sign;
mod write;
pub use write::Write;

/// Is the peer still the process that asked? Asked again once the user has answered.
#[derive(Clone)]
pub struct Recheck(std::sync::Arc<dyn Fn() -> bool + Send + Sync>);

impl Recheck {
    pub fn new(f: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(f))
    }

    fn holds(&self) -> bool {
        (self.0)()
    }
}

impl std::fmt::Debug for Recheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Recheck")
    }
}

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
    /// A value of one item, once the caller policy allows it (a grant, or the user's yes). `rbw`: in rbw's view, with
    /// the clock a TOTP field's code is made at.
    Get {
        find: Lookup,
        select: Select,
        rbw: Option<Now>,
        caller: Caller,
        still: Recheck,
    },
    /// The previous passwords of one item, under the same rule.
    History {
        find: Lookup,
        caller: Caller,
        still: Recheck,
    },
    /// The TOTP code of one item, at the time it is made, under the same rule.
    Code {
        find: Lookup,
        next: bool,
        now: Now,
        caller: Caller,
        still: Recheck,
    },
    /// A change of the vault: confirmed every time, refused to an AI-class or unknown caller.
    Write {
        write: Write,
        caller: Caller,
        still: Recheck,
    },
    /// Show the caller policy, or change it (the user confirms, and an AI-class caller cannot).
    Policy {
        action: PolicyAction,
        caller: Caller,
        still: Recheck,
    },
    /// rbw's `purge`: once the user confirms, lock and delete the local copy of the vault.
    Purge {
        caller: Caller,
        still: Recheck,
    },
    /// The SSH keys of the unlocked vault ([`ssh::keys`]), sent on the channel; a locked profile sends nothing. Not a
    /// use of the profile: SSH clients list the keys on every connection.
    SshKeys(oneshot::Sender<Vec<Key>>),
    /// [`ssh::sign`] in the unlocked vault, its result sent on `out`; a locked profile sends nothing. The caller has
    /// authorized it.
    SshSign {
        id: String,
        blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
        out: oneshot::Sender<Result<Vec<u8>, SshError>>,
    },
    /// The user's decision on one SSH signature (profiles §8): `Done` allows it. Asked through the pinentry unless
    /// this very client process holds an "always" for this key.
    SshConfirm {
        caller: Caller,
        key: Key,
        ctx: SignContext,
    },
    /// Unlock for an SSH signature, the question naming its client (`why`). A client that cancelled such an unlock
    /// is refused without a question until the profile unlocks.
    SshUnlock {
        caller: Caller,
        why: String,
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
    /// A value request, and whose request it is.
    Read(Lookup, Read, Caller, Recheck),
    Write(Write, Caller, Recheck),
    Policy(PolicyAction, Caller, Recheck),
    Purge(Caller, Recheck),
    SshConfirm(Caller, Key, SignContext),
    SshUnlock(Caller, String),
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
    /// Per-process grants ([`Scope::Process`]): callers, with their process identity, the user said "always" for.
    /// Memory only, dropped by a lock. A grant whose process exited can never match again (a new process has
    /// another start time or image); shortcut: it stays until the lock, at most [`MAX_HELD`] of them.
    held: Vec<Caller>,
    /// SSH "always" answers: a client process (its caller, with pid, start and image), a key's blob, and whether it
    /// was for a login (`true`) or for data. Memory only, dropped by a lock; at most [`MAX_HELD`].
    ssh_held: Vec<(Caller, Vec<u8>, bool)>,
    /// SSH clients that cancelled an unlock this profile asked for them: not asked again until it unlocks.
    ssh_declined: Vec<Caller>,
    /// How many SSH signatures each client (a process; the class for a caller with no pid) was refused by the user:
    /// past [`sign::MAX_NOES`] it is asked nothing more until the profile locks or unlocks. At most [`MAX_HELD`].
    ssh_noes: Vec<(Caller, u8)>,
}

/// Most per-process grants kept; the oldest goes first.
const MAX_HELD: usize = 64;

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
        if !matches!(cmd, Cmd::Status | Cmd::IdleCheck | Cmd::SshKeys(_)) {
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
        Cmd::SshKeys(out) => {
            if let Ok(keys) = with_vault(shared, |v| Ok(ssh::keys(&v.sync, v.keys.user()))) {
                let _ = out.send(keys);
            }
            return quick(reply, Reply::Done);
        }
        Cmd::SshSign { id, blob, data, flags, out } => {
            let sign = |v: &UnlockedVault| Ok(ssh::sign(&v.sync, v.keys.user(), &id, &blob, &data, flags));
            if let Ok(signed) = with_vault(shared, sign) {
                let _ = out.send(signed);
            }
            return quick(reply, Reply::Done);
        }
        Cmd::Get { find, select, rbw, caller, still } => {
            let read = match rbw {
                Some(now) => Read::Rbw { select, now },
                None => Read::Get(select),
            };
            Long::Read(find, read, caller, still)
        }
        Cmd::History { find, caller, still } => Long::Read(find, Read::History, caller, still),
        Cmd::Code { find, next, now, caller, still } => Long::Read(find, Read::Code { next, now }, caller, still),
        Cmd::Write { write, caller, still } => Long::Write(write, caller, still),
        Cmd::Policy { action, caller, still } => Long::Policy(action, caller, still),
        Cmd::Purge { caller, still } => Long::Purge(caller, still),
        Cmd::SshConfirm { caller, key, ctx } => Long::SshConfirm(caller, key, ctx),
        Cmd::SshUnlock { caller, why } => Long::SshUnlock(caller, why),
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
    st.held.clear();
    st.ssh_held.clear();
    st.ssh_noes.clear();
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
        Long::Unlock => unlock(&shared, &*host, &ctx, None).await,
        Long::Sync => sync(&shared, &*host, &ctx, wait).await,
        Long::Read(find, read, caller, still) => get(&shared, &*host, &ctx, &caller, &still, find, read).await,
        Long::Write(change, caller, still) => write::write(&shared, &*host, &ctx, &caller, &still, change).await,
        Long::Policy(action, caller, still) => change_policy(&shared, &*host, &ctx, &caller, &still, action).await,
        Long::Purge(caller, still) => purge(&shared, &*host, &ctx, &caller, &still).await,
        Long::SshConfirm(caller, key, sign) => sign::confirm(&shared, &*host, &ctx, &caller, &key, &sign).await,
        Long::SshUnlock(caller, why) => sign::unlock(&shared, &*host, &ctx, &caller, &why).await,
        #[cfg(test)]
        Long::Panic => panic!("task panic for a test"),
    }
}

/// Run `f` on the unlocked vault; `Locked` when there is none.
fn with_vault<T>(shared: &Shared, f: impl FnOnce(&UnlockedVault) -> Result<T, AgentError>) -> Result<T, AgentError> {
    let st = shared.state.borrow();
    f(&st.slot.as_ref().ok_or(AgentError::Locked)?.vault)
}

/// What the confirmation says: the profile, who asks and by which command, what is read of which item, each on one
/// line; and when "always" is for this process only, that.
fn ask_text(ctx: &Ctx, caller: &Caller, found: &Found, read: &Read, remember: Scope) -> String {
    let (command, what) = match (read, read.select()) {
        (_, Some(Select::Field(name))) => ("get", format!("its field \"{}\"", tidy(name))),
        (_, Some(Select::Full)) => ("get", "the full item (every value)".to_owned()),
        (_, Some(Select::Raw)) => ("get", "the raw item as JSON".to_owned()),
        (_, Some(Select::EditText)) => ("edit", "its current password and notes, to edit them".to_owned()),
        (_, Some(_)) => ("get", "its main value (password, notes, number or public key)".to_owned()),
        (Read::History, None) => ("history", "its password history".to_owned()),
        (_, None) => ("code", "a TOTP code".to_owned()),
    };
    let scope = if remember == Scope::Process { " [always (this process only)]" } else { "" };
    format!(
        "dybw profile {}: allow {} (dybw {command}) to read {what} of the item {}?{scope}",
        ctx.profile.name,
        policy::who(caller),
        item_text(found)
    )
}

/// The item a question is about, told apart from any other of the same name: its name, user, folder or
/// organization, and the start of its id.
pub(crate) fn item_text(found: &Found) -> String {
    let user = found.user.as_deref().map_or_else(|| "no user".to_owned(), |u| format!("user {}", quoted(u)));
    let place = match (&found.org, &found.folder) {
        (Some(org), _) => format!("organization item {}", quoted(org)),
        (None, Some(folder)) => format!("folder {}", quoted(folder)),
        (None, None) => "no folder".to_owned(),
    };
    let id: String = found.id.chars().take(8).collect();
    format!("{} ({user}, {place}, id {})", quoted(&found.name), tidy(&id))
}

/// `s` [`tidy`] in double quotes, with its own quotes and backslashes escaped: a name cannot close the quote and
/// fake what follows it.
pub(crate) fn quoted(s: &str) -> String {
    format!("\"{}\"", tidy(s).replace('\\', "\\\\").replace('"', "\\\""))
}

/// `s` on one line, cut for a question.
fn tidy(s: &str) -> String {
    one_line(s).chars().take(80).collect()
}

/// What a value request reads.
#[derive(Debug, Clone)]
pub enum Read {
    Get(Select),
    /// `Get` in rbw's view (the `rbw` shim); `now` is the clock a TOTP field's code is made at.
    Rbw {
        select: Select,
        now: Now,
    },
    History,
    /// The TOTP code at the time it is made; with `next`, the next one when fewer than [`NEXT_UNDER`] seconds are
    /// left.
    Code {
        next: bool,
        now: Now,
    },
}

impl Read {
    /// What a `get` selects, in either view.
    pub(crate) fn select(&self) -> Option<&Select> {
        match self {
            Read::Get(select) | Read::Rbw { select, .. } => Some(select),
            Read::History | Read::Code { .. } => None,
        }
    }
}

/// The agent's clock, read when a code is made rather than when its request came in: the user may have taken a
/// while to answer.
#[derive(Clone)]
pub struct Now(pub std::sync::Arc<dyn crate::agent::Clock>);

impl std::fmt::Debug for Now {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Now")
    }
}

/// `dybw code --next` waits for the next code when the current one has fewer seconds left than this (profiles §7).
pub const NEXT_UNDER: u64 = 5;

/// What a request reads: the whole item, its raw JSON and the history are never covered by a grant.
fn access_of(read: &Read) -> Access {
    match (read, read.select()) {
        (Read::History, _) | (_, Some(Select::Full | Select::Raw | Select::EditText)) => Access::Whole,
        _ => Access::Value,
    }
}

/// The op, and for `get` what was selected: the kind only, never a field name.
pub(crate) fn op_of(read: &Read) -> (&'static str, Option<&'static str>) {
    match (read, read.select()) {
        (Read::History, _) => ("history", None),
        (_, Some(Select::Field(_))) => ("get", Some("field")),
        (_, Some(Select::Full)) => ("get", Some("full")),
        (_, Some(Select::Raw)) => ("get", Some("raw")),
        (_, Some(Select::ListFields)) => ("get", Some("list-fields")),
        (_, Some(Select::EditText)) => ("edit", Some("current")),
        (_, Some(Select::Password)) => ("get", Some("password")),
        (_, None) => ("code", None),
    }
}

fn audit(
    ctx: &Ctx,
    caller: &Caller,
    (op, kind): (&'static str, Option<&'static str>),
    item: Option<&str>,
    verdict: Verdict,
) {
    tracing::info!(profile = %ctx.profile.name, op, item, ?verdict, "caller policy");
    ctx.audit.record(AuditEvent {
        time: std::time::SystemTime::now(),
        profile: ctx.profile.name.clone(),
        caller: caller.clone(),
        op,
        kind,
        item: item.map(str::to_owned),
        verdict,
        ssh: None,
    });
}

/// The policy's answer for a value request, and the user's when it is asked. One question on the screen at a time
/// (`asking`), each naming its own caller: nothing the user says to one is reused for another. The entries are read
/// again once this request has the screen, so a grant made while it waited counts, and a request never prompts for
/// what is already allowed or denied.
async fn gate<H: Host>(
    shared: &Shared,
    host: &H,
    ctx: &Ctx,
    caller: &Caller,
    found: &Found,
    read: &Read,
) -> Result<(), AgentError> {
    let op = op_of(read);
    let store = Store::new(&ctx.paths.policy, ctx.user.uid);
    let decide = || {
        let held = shared.state.borrow().held.clone();
        policy::decide(caller, &store.load(), &held, access_of(read))
    };
    let mut decision = decide();
    let _screen = if matches!(decision, Decision::Confirm { .. }) {
        let screen = shared.asking.lock().await;
        decision = decide();
        Some(screen)
    } else {
        None
    };
    let (verdict, result) = match decision {
        Decision::Allow => (Verdict::Granted, Ok(())),
        Decision::Deny => (Verdict::Denied, Err(AgentError::Denied)),
        Decision::Confirm { remember: scope } => {
            let text = ask_text(ctx, caller, found, read, scope);
            match session::confirm(host, &text, scope != Scope::Never).await {
                Ok(true) => (remember(shared, ctx, &store, caller, scope), Ok(())),
                Ok(false) => (Verdict::Confirmed, Ok(())),
                Err(e) => (Verdict::Declined, Err(e)),
            }
        }
    };
    audit(ctx, caller, op, Some(&found.id), verdict);
    result
}

/// Keep the grant "always" asks for: in memory for this process, or in the policy file. A failed write still lets
/// this one request through (the user said yes), and is logged.
fn remember(shared: &Shared, ctx: &Ctx, store: &Store, caller: &Caller, scope: Scope) -> Verdict {
    if scope == Scope::Process {
        let held = &mut shared.state.borrow_mut().held;
        if held.len() >= MAX_HELD {
            held.remove(0);
        }
        held.push(caller.clone());
        return Verdict::Remembered;
    }
    // "Always" is only offered for a caller that has a grant; for any other it is just a yes.
    let Some(entry) = policy::grant_for(caller) else { return Verdict::Confirmed };
    match store.set(entry) {
        Ok(()) => Verdict::Remembered,
        Err(e) => {
            tracing::warn!(profile = %ctx.profile.name, "the grant was not saved: {e}");
            Verdict::Confirmed
        }
    }
}

/// The master password again, for an item that asks for it (ADR 0025), checked here against the unlocked user key and
/// never sent anywhere. No grant satisfies it. A wrong password is `Denied`, a cancel or a timeout the user's no; each
/// is audited. The caller holds the screen (`asking`).
async fn reprompt<H: Host>(
    shared: &Shared,
    host: &H,
    ctx: &Ctx,
    caller: &Caller,
    found: &Found,
    op: (&'static str, Option<&'static str>),
) -> Result<(), AgentError> {
    let account = |s: &Session| {
        let part = |k: &str| s.vault.sync.get(k).cloned().unwrap_or_default();
        (s.origin.clone(), serde_json::json!({ "profile": part("profile"), "userDecryption": part("userDecryption") }))
    };
    let target = shared.state.borrow().slot.as_ref().map(|s| (account(s), s.vault.user_key_id()));
    let Some(((origin, account), unlocked)) = target else { return Err(AgentError::Locked) };
    let description = format!(
        "dybw profile {}: the item {} asks for the master password again (dybw {} by {})",
        ctx.profile.name,
        item_text(found),
        op.0,
        policy::who(caller)
    );
    let (verdict, why) = match session::ask(host, "Master password:", &description, None).await {
        Err(e) => (Verdict::Declined, e),
        Ok(password) => match session::key_id_of(ctx, &origin, account, password).await {
            Ok(Some(id)) if id == unlocked => {
                audit(ctx, caller, op, Some(&found.id), Verdict::Reprompted);
                return Ok(());
            }
            Ok(_) => (Verdict::Denied, AgentError::Denied),
            Err(e) => (Verdict::Failed, e),
        },
    };
    tracing::warn!(profile = %ctx.profile.name, id = %found.id, "the reprompt was not passed: {why}");
    audit(ctx, caller, op, Some(&found.id), verdict);
    Err(why)
}

/// `get`, `history` and `code`: find the item from its summary (a missing or ambiguous one ends here, with no
/// prompt), pass the caller policy (a no or a timeout is `Denied`, and nothing was opened), then the reprompt of an
/// item that asks for one, check the item is still the one asked about, and only then open it, build the reply and
/// drop it. A lock during a wait cancels this task.
async fn get<H: Host>(
    shared: &Shared,
    host: &H,
    ctx: &Ctx,
    caller: &Caller,
    still: &Recheck,
    find: Lookup,
    read: Read,
) -> Reply {
    let found = match with_vault(shared, |v| read::find(v, &find)) {
        Ok(found) => found,
        Err(e) => return error(e),
    };
    if found.hidden && shows_password(&read) {
        tracing::warn!(profile = %ctx.profile.name, id = %found.id, "denied: the organization hides this item's password");
        audit(ctx, caller, op_of(&read), Some(&found.id), Verdict::Denied);
        return error(AgentError::Denied);
    }
    // Field names are names (ADR 0012): no question for any caller, but a reprompt item still asks for the master
    // password, which is never asked on behalf of an AI agent or an unidentified caller.
    let names = matches!(read.select(), Some(Select::ListFields));
    if names && found.reprompt && matches!(caller, Caller::Ai { .. } | Caller::Unknown { .. }) {
        audit(ctx, caller, op_of(&read), Some(&found.id), Verdict::Denied);
        return error(AgentError::Denied);
    }
    if !names && let Err(e) = gate(shared, host, ctx, caller, &found, &read).await {
        return error(e);
    }
    if found.reprompt {
        let _screen = shared.asking.lock().await;
        if let Err(e) = reprompt(shared, host, ctx, caller, &found, op_of(&read)).await {
            return error(e);
        }
    }
    // The user may have taken a while: the peer must still be the one that asked, before anything is opened.
    if !still.holds() {
        tracing::warn!(profile = %ctx.profile.name, id = %found.id, "the caller changed while the user was asked");
        audit(ctx, caller, op_of(&read), Some(&found.id), Verdict::Denied);
        return error(AgentError::Denied);
    }
    // A hidden-type custom field is hidden with the password. It is checked only now, after the user's yes, as
    // ruled in P4.3: an unconfirmed caller learns nothing from the refusal (no oracle on field types).
    let rbw = matches!(read, Read::Rbw { .. });
    if found.hidden
        && let Some(Select::Field(name)) = read.select()
        && with_vault(shared, |v| same_item(ctx, v, &found).and_then(|()| read::hidden_field(v, &found.id, name, rbw)))
            .unwrap_or(true)
    {
        tracing::warn!(profile = %ctx.profile.name, id = %found.id, "denied: the organization hides this field");
        audit(ctx, caller, op_of(&read), Some(&found.id), Verdict::Denied);
        return error(AgentError::Denied);
    }
    if let Read::Code { next, now } = read {
        let key = with_vault(shared, |v| same_item(ctx, v, &found).and_then(|()| read::totp(v, &found.id)));
        return match key {
            Ok(key) => code(&key, &now, next).await,
            Err(e) => error(e),
        };
    }
    let open = |v: &UnlockedVault| {
        same_item(ctx, v, &found)?;
        match &read {
            Read::Get(select) => read::value(v, &found.id, select),
            Read::Rbw { select, now } => {
                let at = now.0.wall().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                read::rbw_value(v, &found.id, found.folder.as_deref(), select, at)
            }
            _ => read::history(v, &found.id),
        }
    };
    let reply = with_vault(shared, open).unwrap_or_else(error);
    if names && matches!(reply, Reply::FieldNames { .. }) {
        audit(ctx, caller, op_of(&read), Some(&found.id), Verdict::Listed);
    }
    reply
}

/// Whether `read` gives a login's password, TOTP key or history, or the whole item (which holds them).
fn shows_password(read: &Read) -> bool {
    match (read, read.select()) {
        (Read::Get(Select::Field(name)), _) => name == "password" || name == "totp",
        (Read::Rbw { select: Select::Field(name), .. }, _) => crate::rbw_view::login_secret(name),
        (_, Some(Select::ListFields)) => false,
        _ => true,
    }
}

/// The user answered about `found`: it must still be the same item (a sync may have run meanwhile).
fn same_item(ctx: &Ctx, v: &UnlockedVault, found: &Found) -> Result<(), AgentError> {
    let now = read::find(v, &Lookup { needle: found.id.clone(), user: None, folder: None, ignorecase: false });
    if now.as_ref().ok() == Some(found) {
        return Ok(());
    }
    tracing::warn!(profile = %ctx.profile.name, id = %found.id, "the item changed while the user was asked");
    Err(AgentError::Denied)
}

/// The code at the agent's wall time now (after any wait on the user); with `next`, when fewer than [`NEXT_UNDER`]
/// seconds of it are left, the next one once its
/// period has started (a lock meanwhile cancels the wait).
async fn code(key: &TotpKey, now: &Now, next: bool) -> Reply {
    let at = now.0.wall().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let mut code = key.generate(at.as_secs());
    if next && code.seconds_remaining() < NEXT_UNDER {
        let start = at.as_secs() + code.seconds_remaining();
        tokio::time::sleep(Duration::from_secs(start).saturating_sub(at)).await;
        code = key.generate(start);
    }
    Reply::Code { code: Secret::new(code.code().to_owned()), seconds_left: code.seconds_remaining() }
}

/// An absolute path as the policy keys it: canonical when the file exists.
fn policy_path(path: &str) -> Option<String> {
    let path = std::path::Path::new(path);
    let key =
        if path.is_absolute() { std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned()) } else { return None };
    key.to_str().map(str::to_owned)
}

/// A change of the policy, planned before the user is asked.
enum Change {
    Set(PolicyEntry),
    Forget(String),
}

impl Change {
    /// What the question says is done, on one line.
    fn sentence(&self) -> String {
        let tidy = |s: &str| policy::shown(s, 120);
        let target = |e: &PolicyEntry| match (&e.script, e.detached) {
            (Some(script), _) => format!("{} running {}", tidy(&e.exe), tidy(script)),
            (None, true) => format!("{} when run detached (parent exited)", tidy(&e.exe)),
            (None, false) => tidy(&e.exe),
        };
        match self {
            Change::Set(e) if e.rule == PolicyRule::Allow => format!("always allow reading values for {}", target(e)),
            Change::Set(e) => format!("always refuse reading values for {}", target(e)),
            Change::Forget(invoker) => format!("forget what is remembered for {}", tidy(invoker)),
        }
    }
}

/// What a change asks for, before its paths are looked at.
enum Asked {
    Set { invoker: String, script: Option<String>, rule: PolicyRule, detached: bool },
    Forget(String),
}

fn plan(asked: Asked) -> Result<Change, AgentError> {
    let bad = |why: &str| {
        tracing::warn!("policy: {why}");
        AgentError::Config
    };
    match asked {
        Asked::Set { invoker, script, rule, detached } => {
            let exe = policy_path(&invoker).ok_or_else(|| bad("the executable must be an absolute path"))?;
            let script = script.map(|s| policy_path(&s).ok_or_else(|| bad("the script must be an absolute path")));
            let script = script.transpose()?;
            // An allow that could never match, or would cover what a launcher runs, is refused, not stored (a deny of
            // the same target is fine). A script's grant lasts for its process only, so none is ever written.
            if rule == PolicyRule::Allow {
                let path = std::path::Path::new(&exe);
                if script.is_some() || interpreter(path) {
                    return Err(bad("an interpreter or shell, or a script, is remembered per process only"));
                }
                if launcher(path) {
                    return Err(bad("a launcher, multiplexer or terminal runs anything: it cannot be remembered"));
                }
            }
            // A deny is by path; an allow is for the program as it is now.
            let hash = match rule {
                PolicyRule::Allow => hash_of(std::path::Path::new(&exe)).map_err(|w| bad(&w))?,
                PolicyRule::Deny => String::new(),
            };
            Ok(Change::Set(PolicyEntry { exe, script, hash, rule, detached: detached && rule == PolicyRule::Allow }))
        }
        Asked::Forget(invoker) => Ok(Change::Forget(policy_path(&invoker).unwrap_or(invoker))),
    }
}

/// `dybw policy`. `show` names no secret and is open to every class. A change is refused for an AI-class or an
/// unknown caller, and needs the user's yes in the pinentry like any value.
async fn change_policy<H: Host>(
    shared: &Shared,
    host: &H,
    ctx: &Ctx,
    caller: &Caller,
    still: &Recheck,
    action: PolicyAction,
) -> Reply {
    let store = Store::new(&ctx.paths.policy, ctx.user.uid);
    let (op, asked) = match action {
        PolicyAction::Show => return Reply::Policy { entries: store.load() },
        PolicyAction::Allow { invoker, script, detached } => {
            ("policy-allow", Asked::Set { invoker, script, rule: PolicyRule::Allow, detached })
        }
        PolicyAction::Deny { invoker, script } => {
            ("policy-deny", Asked::Set { invoker, script, rule: PolicyRule::Deny, detached: false })
        }
        PolicyAction::Forget { invoker } => ("policy-forget", Asked::Forget(invoker)),
    };
    if !matches!(caller, Caller::Invoker { .. }) {
        audit(ctx, caller, (op, None), None, Verdict::Denied);
        return error(AgentError::Denied);
    }
    let change = match plan(asked) {
        Ok(change) => change,
        Err(e) => return error(e),
    };
    let _screen = shared.asking.lock().await;
    let text = format!(
        "dybw profile {}: {} asks to {} (dybw policy). Do it?",
        ctx.profile.name,
        policy::who(caller),
        change.sentence()
    );
    if let Err(e) = session::confirm(host, &text, false).await {
        audit(ctx, caller, (op, None), None, Verdict::Declined);
        return error(e);
    }
    if !still.holds() {
        audit(ctx, caller, (op, None), None, Verdict::Denied);
        return error(AgentError::Denied);
    }
    let done = match &change {
        Change::Set(entry) => store.set(entry.clone()),
        Change::Forget(invoker) => store.forget(invoker).map(|_| ()),
    };
    audit(ctx, caller, (op, None), None, if done.is_ok() { Verdict::Confirmed } else { Verdict::Failed });
    done.map_or_else(
        |e| {
            tracing::warn!(profile = %ctx.profile.name, "the policy was not saved: {e}");
            internal()
        },
        |()| Reply::Done,
    )
}

/// rbw's `purge`: refused to a caller the policy refuses, then confirmed by the user every time (no grant counts).
/// After the yes it waits for any login, unlock, sync or write in flight, drops the keys (whatever still waits on
/// the user finds the profile locked) and deletes the profile's copy of the vault. The API key, the device id, the
/// policy and the core's pins stay: a pin deleted here would let the server lower the KDF unnoticed at the next unlock.
async fn purge<H: Host>(shared: &Shared, host: &H, ctx: &Ctx, caller: &Caller, still: &Recheck) -> Reply {
    let op = ("purge", None);
    let store = Store::new(&ctx.paths.policy, ctx.user.uid);
    if policy::decide(caller, &store.load(), &[], Access::Write) == Decision::Deny {
        audit(ctx, caller, op, None, Verdict::Denied);
        return error(AgentError::Denied);
    }
    {
        let _screen = shared.asking.lock().await;
        let text = format!(
            "dybw profile {}: allow {} (rbw purge) to lock the profile and delete its local copy of the vault? (asked \
             every time)",
            ctx.profile.name,
            policy::who(caller)
        );
        if let Err(e) = session::confirm(host, &text, false).await {
            audit(ctx, caller, op, None, Verdict::Declined);
            return error(e);
        }
    }
    if !still.holds() {
        audit(ctx, caller, op, None, Verdict::Denied);
        return error(AgentError::Denied);
    }
    let _op = shared.op.lock().await;
    {
        let mut st = shared.state.borrow_mut();
        st.slot = None;
        st.held.clear();
        st.ssh_held.clear();
    }
    let removed = match std::fs::remove_dir_all(&ctx.paths.cache) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    };
    if let Err(e) = removed {
        tracing::warn!(profile = %ctx.profile.name, "the local copy was not deleted: {}", e.kind());
        audit(ctx, caller, op, None, Verdict::Failed);
        return internal();
    }
    audit(ctx, caller, op, None, Verdict::Confirmed);
    Reply::Done
}

/// `why`: what asks for the unlock, when not the user ([`session::unlock`]).
async fn unlock<H: Host>(shared: &Shared, host: &H, ctx: &Ctx, why: Option<&str>) -> Reply {
    // Every read starts here: an unlocked profile must not wait behind a sync or another unlock.
    if shared.state.borrow().slot.is_some() {
        return Reply::Done;
    }
    let _op = shared.op.lock().await;
    // Another unlock may have finished while this one waited for its turn.
    if shared.state.borrow().slot.is_some() {
        return Reply::Done;
    }
    match session::unlock(host, ctx, why).await {
        Ok(session) => {
            let mut st = shared.state.borrow_mut();
            st.ssh_declined.clear();
            st.ssh_noes.clear();
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
    install(shared, ctx, sync).await;
    Reply::Done
}

/// Keep a fresh `/sync` as the offline copy and show it to the vault.
async fn install(shared: &Shared, ctx: &Ctx, sync: serde_json::Value) {
    session::save_cache(ctx, &sync).await;
    // A lock cancels the task that runs this, so the slot is there; if it is not, there is no vault to show it to.
    shared.state.borrow_mut().slot.as_mut().map(|session| session.vault.sync = sync).unwrap_or_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_question_tells_apart_two_items_of_the_same_name() {
        let item = |user: Option<&str>, folder: Option<&str>, org: Option<&str>, id: &str| Found {
            id: id.into(),
            name: "GitHub".into(),
            user: user.map(Into::into),
            folder: folder.map(Into::into),
            org: org.map(Into::into),
            reprompt: false,
            hidden: false,
        };
        let mine = item_text(&item(Some("me"), Some("Dev"), None, "0b3c6f0e-6a3e-4c55-9a59-1c2d3e4f5a6b"));
        let theirs = item_text(&item(None, Some("Dev"), Some("Acme"), "9f00aa11-0000-4000-8000-000000000000"));
        assert_eq!(mine, "\"GitHub\" (user \"me\", folder \"Dev\", id 0b3c6f0e)");
        assert_eq!(theirs, "\"GitHub\" (no user, organization item \"Acme\", id 9f00aa11)");
        assert_eq!(item_text(&item(None, None, None, "x1")), "\"GitHub\" (no user, no folder, id x1)");
        // A name cannot fake the suffix: its quotes and backslashes are escaped.
        let mut fake = item(None, None, Some("Acme"), "9f00aa11");
        fake.name = r#"GitHub" (user "me", folder "Dev", id 0b3c6f0e)"#.into();
        fake.user = Some(r"a\".into());
        assert_eq!(
            item_text(&fake),
            r#""GitHub\" (user \"me\", folder \"Dev\", id 0b3c6f0e)" (user "a\\", organization item "Acme", id 9f00aa11)"#
        );
    }

    #[test]
    fn a_write_prints_its_selectors_only() {
        let find = Lookup { needle: "n".into(), user: None, folder: None, ignorecase: false };
        assert!(format!("{:?}", Write::Remove { find }).starts_with("Remove { find: Lookup { needle: \"n\""));
        assert_eq!(format!("{:?}", Now(std::sync::Arc::new(crate::agent::SystemClock))), "Now");
    }

    #[test]
    fn a_recheck_answers_and_prints_without_its_closure() {
        let still = Recheck::new(|| true);
        assert!(still.holds());
        assert_eq!(format!("{still:?}"), "Recheck");
    }

    #[test]
    fn a_locked_profile_or_one_without_an_interval_has_no_periodic_sync() {
        let shared = Shared::default();
        assert!(!periodic_due(&shared, Duration::from_secs(300)), "locked");
        assert!(!periodic_due(&shared, Duration::ZERO), "no interval");
    }

    #[test]
    fn the_audit_names_what_was_selected_but_never_a_field() {
        let kinds: Vec<_> = [
            Read::History,
            Read::Code { next: true, now: Now(std::sync::Arc::new(crate::agent::SystemClock)) },
            Read::Get(Select::Password),
            Read::Get(Select::Field("secret field".into())),
            Read::Get(Select::Full),
            Read::Get(Select::Raw),
            Read::Get(Select::ListFields),
        ]
        .iter()
        .map(op_of)
        .collect();
        let want = [
            ("history", None),
            ("code", None),
            ("get", Some("password")),
            ("get", Some("field")),
            ("get", Some("full")),
            ("get", Some("raw")),
            ("get", Some("list-fields")),
        ];
        assert_eq!(kinds, want);
    }
}
