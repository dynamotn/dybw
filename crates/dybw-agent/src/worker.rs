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
use dybw_proto::{AgentError, Field, PolicyAction, PolicyEntry, PolicyRule, ProfileStatus, Reply, Select};
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use crate::caller::{Caller, hash_of};
use crate::host::Host;
use crate::policy::{self, Access, AuditEvent, Decision, Store, Verdict};
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
    /// A value of one item, once the caller policy allows it (a grant, or the user's yes).
    Get {
        find: Lookup,
        select: Select,
        caller: Caller,
    },
    /// The previous passwords of one item, under the same rule.
    History {
        find: Lookup,
        caller: Caller,
    },
    /// Show the caller policy, or change it (the user confirms, and an AI-class caller cannot).
    Policy {
        action: PolicyAction,
        caller: Caller,
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
    /// `Some` is a `get`, `None` the password history; whose request it is.
    Read(Lookup, Option<Select>, Caller),
    Policy(PolicyAction, Caller),
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
        Cmd::Get { find, select, caller } => Long::Read(find, Some(select), caller),
        Cmd::History { find, caller } => Long::Read(find, None, caller),
        Cmd::Policy { action, caller } => Long::Policy(action, caller),
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
        Long::Read(find, select, caller) => get(&shared, &*host, &ctx, &caller, find, select).await,
        Long::Policy(action, caller) => change_policy(&shared, &*host, &ctx, &caller, action).await,
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
/// line.
fn ask_text(ctx: &Ctx, caller: &Caller, found: &Found, select: Option<&Select>) -> String {
    let tidy = |s: &str| one_line(s).chars().take(80).collect::<String>();
    let (command, what) = match select {
        Some(Select::Field(name)) => ("get", format!("its field \"{}\"", tidy(name))),
        Some(Select::Full) => ("get", "the full item (every value)".to_owned()),
        Some(Select::Raw) => ("get", "the raw item as JSON".to_owned()),
        Some(Select::ListFields) => ("get", "the field names".to_owned()),
        Some(_) => ("get", "its main value (password, notes, number or public key)".to_owned()),
        None => ("history", "its password history".to_owned()),
    };
    format!(
        "dybw profile {}: allow {} (dybw {command}) to read {what} of the item \"{}\"?",
        ctx.profile.name,
        policy::who(caller),
        tidy(&found.name)
    )
}

fn audit(ctx: &Ctx, caller: &Caller, op: &'static str, item: Option<&str>, verdict: Verdict) {
    tracing::info!(profile = %ctx.profile.name, op, item, ?verdict, "caller policy");
    ctx.audit.record(AuditEvent {
        time: std::time::SystemTime::now(),
        profile: ctx.profile.name.clone(),
        caller: caller.clone(),
        op,
        item: item.map(str::to_owned),
        verdict,
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
    select: Option<&Select>,
) -> Result<(), AgentError> {
    let op = if select.is_some() { "get" } else { "history" };
    let store = Store::new(&ctx.paths.policy, ctx.user.uid);
    let mut decision = policy::decide(caller, &store.load(), Access::Value);
    let _screen = if matches!(decision, Decision::Confirm { .. }) {
        let screen = shared.asking.lock().await;
        decision = policy::decide(caller, &store.load(), Access::Value);
        Some(screen)
    } else {
        None
    };
    let (verdict, result) = match decision {
        Decision::Allow => (Verdict::Granted, Ok(())),
        Decision::Deny => (Verdict::Denied, Err(AgentError::Denied)),
        Decision::Confirm { rememberable } => {
            match session::confirm(host, &ask_text(ctx, caller, found, select), rememberable).await {
                Ok(true) => (remember(ctx, &store, caller), Ok(())),
                Ok(false) => (Verdict::Confirmed, Ok(())),
                Err(e) => (Verdict::Declined, Err(e)),
            }
        }
    };
    audit(ctx, caller, op, Some(&found.id), verdict);
    result
}

/// Store the grant "always" asks for. A failed write still lets this one request through (the user said yes), and
/// is logged.
fn remember(ctx: &Ctx, store: &Store, caller: &Caller) -> Verdict {
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

/// `get` and `history`: find the item from its summary (a missing or ambiguous one ends here, with no prompt), pass
/// the caller policy (a no or a timeout is `Denied`, and nothing was opened), check the item is still the one asked
/// about, and only then open it, build the reply and drop it. A lock during the wait cancels this task.
async fn get<H: Host>(
    shared: &Shared,
    host: &H,
    ctx: &Ctx,
    caller: &Caller,
    find: Lookup,
    select: Option<Select>,
) -> Reply {
    let found = match with_vault(shared, |v| read::find(v, &find)) {
        Ok(found) => found,
        Err(e) => return error(e),
    };
    // TODO(core): field_names, a names-only decrypt; until then `--list-fields` opens the whole item, so it is a
    // value request like any other.
    if found.reprompt {
        // Until P4.3 can ask for the master password again, a reprompt item gives no value and no question, and
        // no grant satisfies it.
        tracing::warn!(profile = %ctx.profile.name, id = %found.id, "value request denied: the item needs a reprompt (P4.3)");
        let op = if select.is_some() { "get" } else { "history" };
        audit(ctx, caller, op, Some(&found.id), Verdict::Denied);
        return error(AgentError::Denied);
    }
    if let Err(e) = gate(shared, host, ctx, caller, &found, select.as_ref()).await {
        return error(e);
    }
    let read = |v: &UnlockedVault| {
        // The user answered about this item: it must still be the same one (a sync may have run meanwhile).
        let now = read::find(v, &Lookup { needle: found.id.clone(), user: None, folder: None, ignorecase: false });
        if now.as_ref().ok() != Some(&found) {
            tracing::warn!(profile = %ctx.profile.name, id = %found.id, "the item changed while the user was asked");
            return Err(AgentError::Denied);
        }
        match &select {
            Some(select) => read::value(v, &found.id, select),
            None => read::history(v, &found.id),
        }
    };
    with_vault(shared, read).unwrap_or_else(error)
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
        let tidy = |s: &str| one_line(s).chars().take(120).collect::<String>();
        let target = |e: &PolicyEntry| match &e.script {
            Some(script) => format!("{} running {}", tidy(&e.exe), tidy(script)),
            None => tidy(&e.exe),
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
    Set { invoker: String, script: Option<String>, rule: PolicyRule },
    Forget(String),
}

fn plan(asked: Asked) -> Result<Change, AgentError> {
    let bad = |why: &str| {
        tracing::warn!("policy: {why}");
        AgentError::Config
    };
    match asked {
        Asked::Set { invoker, script, rule } => {
            let exe = policy_path(&invoker).ok_or_else(|| bad("the executable must be an absolute path"))?;
            let script = script.map(|s| policy_path(&s).ok_or_else(|| bad("the script must be an absolute path")));
            let script = script.transpose()?;
            // A deny is by path; an allow is for the program as it is now.
            let hash = match rule {
                PolicyRule::Allow => {
                    hash_of(std::path::Path::new(script.as_deref().unwrap_or(&exe))).map_err(|w| bad(&w))?
                }
                PolicyRule::Deny => String::new(),
            };
            Ok(Change::Set(PolicyEntry { exe, script, hash, rule }))
        }
        Asked::Forget(invoker) => Ok(Change::Forget(policy_path(&invoker).unwrap_or(invoker))),
    }
}

/// `dybw policy`. `show` names no secret and is open to every class. A change is refused for an AI-class or an
/// unknown caller, and needs the user's yes in the pinentry like any value.
async fn change_policy<H: Host>(shared: &Shared, host: &H, ctx: &Ctx, caller: &Caller, action: PolicyAction) -> Reply {
    let store = Store::new(&ctx.paths.policy, ctx.user.uid);
    let (op, asked) = match action {
        PolicyAction::Show => return Reply::Policy { entries: store.load() },
        PolicyAction::Allow { invoker, script } => {
            ("policy-allow", Asked::Set { invoker, script, rule: PolicyRule::Allow })
        }
        PolicyAction::Deny { invoker, script } => {
            ("policy-deny", Asked::Set { invoker, script, rule: PolicyRule::Deny })
        }
        PolicyAction::Forget { invoker } => ("policy-forget", Asked::Forget(invoker)),
    };
    if !matches!(caller, Caller::Invoker { .. }) {
        audit(ctx, caller, op, None, Verdict::Denied);
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
        audit(ctx, caller, op, None, Verdict::Declined);
        return error(e);
    }
    let done = match &change {
        Change::Set(entry) => store.set(entry.clone()),
        Change::Forget(invoker) => store.forget(invoker).map(|_| ()),
    };
    audit(ctx, caller, op, None, Verdict::Confirmed);
    done.map_or_else(
        |e| {
            tracing::warn!(profile = %ctx.profile.name, "the policy was not saved: {e}");
            internal()
        },
        |()| Reply::Done,
    )
}

async fn unlock<H: Host>(shared: &Shared, host: &H, ctx: &Ctx) -> Reply {
    // Every read starts here: an unlocked profile must not wait behind a sync or another unlock.
    if shared.state.borrow().slot.is_some() {
        return Reply::Done;
    }
    let _op = shared.op.lock().await;
    // Another unlock may have finished while this one waited for its turn.
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
