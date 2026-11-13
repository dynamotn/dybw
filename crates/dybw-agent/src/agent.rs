//! The agent's shared state: the config, the per-profile workers, the clocks and the lock rules.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use dybw_native::fsutil::User;
use dybw_proto::{AgentError, Op, Reply, Target};
use tokio::sync::Notify;
use tokio::task::JoinSet;

use crate::caller::{Caller, Resolved, Resolver};
use crate::config::{Config, Profile};
use crate::paths::ProfilePaths;
use crate::policy::{Audit, AuditEvent, Verdict};
use crate::read::Lookup;
use crate::session::Ctx;
use crate::worker::op_of;
use crate::worker::{Cmd, Recheck, Worker};

/// How often the idle and sleep checks run.
pub const TICK: Duration = Duration::from_secs(30);
/// Wall time may run this much ahead of monotonic time between two ticks before it counts as a suspend.
pub const SLEEP_SLACK: Duration = Duration::from_secs(60);
/// How long a client has to send its request.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a shutdown lets connections in flight finish before it cancels them: a request may be waiting on a
/// pinentry or the network.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Starts the worker of a profile: the real host in the agent, a fake in tests.
pub type Spawn = Box<dyn Fn(Ctx) -> Worker + Send + Sync>;

/// The two clocks; tests drive them by hand so nothing sleeps.
pub trait Clock: Send + Sync {
    fn wall(&self) -> SystemTime;
    /// Does not advance while the machine sleeps (macOS and Linux).
    fn mono(&self) -> Instant;
}

/// The kind of an op for the log: never its contents.
fn kind(op: &Op) -> &'static str {
    match op {
        Op::Status { .. } => "status",
        Op::Login { .. } => "login",
        Op::Unlock { .. } => "unlock",
        Op::Lock { .. } => "lock",
        Op::Sync { .. } => "sync",
        Op::List { .. } => "list",
        Op::Search { .. } => "search",
        Op::Get { .. } => "get",
        Op::History { .. } => "history",
        Op::Policy { .. } => "policy",
        Op::StopAgent => "stop_agent",
        _ => "other",
    }
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }
    fn mono(&self) -> Instant {
        Instant::now()
    }
}

pub struct Agent {
    pub(crate) config: Config,
    pub(crate) home: PathBuf,
    pub(crate) user: User,
    /// The uid every peer must have.
    pub(crate) uid: u32,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) read_timeout: Duration,
    pub(crate) drain_timeout: Duration,
    spawn: Spawn,
    /// Who is asking: the peer's invoker, an AI class or nobody we can name.
    pub(crate) resolver: Arc<Resolver>,
    audit: Arc<dyn Audit>,
    /// Test hook: the guard announces on `.0` that it reached the post-suspend lock, and waits for `.1` first.
    #[cfg(test)]
    pub(crate) lock_gate: Option<(Arc<Notify>, Arc<Notify>)>,
    workers: Mutex<HashMap<String, Arc<Worker>>>,
    /// Held for a whole guard run, so a request that arrives while a suspend is being handled waits for the locks.
    last_tick: tokio::sync::Mutex<(SystemTime, Instant)>,
    pub(crate) stop: Notify,
    /// Set by `shutdown`: no worker starts after it.
    closed: AtomicBool,
}

impl Agent {
    pub fn new(
        config: Config,
        home: PathBuf,
        user: User,
        spawn: Spawn,
        resolver: Arc<Resolver>,
        audit: Arc<dyn Audit>,
    ) -> Agent {
        let clock = Arc::new(SystemClock);
        let last_tick = tokio::sync::Mutex::new((clock.wall(), clock.mono()));
        Agent {
            config,
            home,
            uid: user.uid,
            user,
            clock,
            read_timeout: READ_TIMEOUT,
            drain_timeout: DRAIN_TIMEOUT,
            spawn,
            resolver,
            audit,
            #[cfg(test)]
            lock_gate: None,
            workers: Mutex::default(),
            last_tick,
            stop: Notify::new(),
            closed: AtomicBool::new(false),
        }
    }

    /// The live workers; a poisoned lock means a panic elsewhere, and the map is still sound.
    fn live(&self) -> Vec<Arc<Worker>> {
        let workers = self.workers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        workers.values().cloned().collect()
    }

    /// The worker of a profile, started on first use and again after it died (its keys died with it).
    /// `None` once `shutdown` has begun.
    fn worker(&self, profile: &Profile) -> Option<Arc<Worker>> {
        let mut workers = self.workers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.closed.load(Ordering::SeqCst) {
            return None;
        }
        if let Some(w) = workers.get(&profile.name).filter(|w| w.is_alive()) {
            return Some(w.clone());
        }
        let paths = ProfilePaths::with(&self.home, profile);
        let w = Arc::new((self.spawn)(Ctx {
            profile: profile.clone(),
            paths,
            user: self.user.clone(),
            audit: self.audit.clone(),
        }));
        workers.insert(profile.name.clone(), w.clone());
        Some(w)
    }

    #[cfg(test)]
    pub(crate) fn worker_count(&self) -> usize {
        self.workers.lock().map(|w| w.len()).unwrap_or_default()
    }

    /// Answer one request from `who`. Anything not yet served answers `Internal`. `StopAgent` only answers `Done`: the
    /// connection handler notifies the stop once that reply is written.
    ///
    /// A request that reads a value or touches the policy is checked twice against the peer's identity taken at
    /// connect time: here before anything is asked, and in the worker once the user has answered, before anything is
    /// opened or written (a pid reused while the user was being asked must not receive what was granted).
    pub async fn dispatch_for(&self, op: Op, who: &Resolved) -> Reply {
        // Do not wait for the tick: a request right after a wake or past the idle timeout finds the profile locked.
        self.guard().await;
        tracing::info!(op = kind(&op), "request");
        let sensitive = match &op {
            Op::Get { profile, select, .. } => Some((kind(&op), op_of(Some(select)).1, profile.clone())),
            Op::History { profile, .. } | Op::Policy { profile, .. } => Some((kind(&op), None, profile.clone())),
            _ => None,
        };
        let logged = sensitive.clone().filter(|_| !matches!(op, Op::Policy { .. })).or_else(|| match &op {
            Op::List { profile, .. } | Op::Search { profile, .. } => Some((kind(&op), None, profile.clone())),
            _ => None,
        });
        // An AI-class caller is never given a value: refuse before any unlock, so it cannot raise a password prompt.
        if let Some(s) = sensitive.clone()
            && matches!(who.caller, Caller::Ai { .. })
            && matches!(op, Op::Get { .. } | Op::History { .. })
        {
            return self.deny(who, s, "an AI-class caller asked for a value: denied");
        }
        if let Some(s) = sensitive.clone()
            && !self.resolver.recheck(who)
        {
            return self.deny(who, s, "the caller changed while it was being served: denied");
        }
        // The worker checks the peer again once the user has answered, right before it opens anything; and once more
        // here, right before a value is handed back to be written.
        let reply = self.serve(op, who).await;
        let holds_value = matches!(
            reply,
            Reply::Value { .. }
                | Reply::Full { .. }
                | Reply::Raw { .. }
                | Reply::FieldNames { .. }
                | Reply::History { .. }
        );
        if let Some(s) = sensitive
            && holds_value
            && !self.resolver.recheck(who)
        {
            return self.deny(who, s, "the caller changed while it was being served: denied");
        }
        self.log_unvetted(who, logged, &reply);
        reply
    }

    /// Audit and answer `Denied` for a sensitive request.
    fn deny(
        &self,
        who: &Resolved,
        (op, what, profile): (&'static str, Option<&'static str>, Option<String>),
        why: &str,
    ) -> Reply {
        tracing::warn!(op, "{why}");
        let profile = self.config.profile(profile.as_deref()).map(|p| p.name).unwrap_or_default();
        self.audit.record(AuditEvent {
            time: SystemTime::now(),
            profile,
            caller: who.caller.clone(),
            op,
            kind: what,
            item: None,
            verdict: Verdict::Denied,
        });
        Reply::Error { error: AgentError::Denied }
    }

    /// Every read request of an AI-class or unknown caller leaves a line, also the ones that never reach a decision
    /// (a lookup that failed, a list): `listed`, or `failed` with no needle and no candidates. Decisions on a value
    /// are already recorded by the worker; invoker-class requests are recorded only as decisions.
    fn log_unvetted(
        &self,
        who: &Resolved,
        request: Option<(&'static str, Option<&'static str>, Option<String>)>,
        reply: &Reply,
    ) {
        let Some((op, kind, profile)) = request else { return };
        if !matches!(who.caller, Caller::Ai { .. } | Caller::Unknown { .. }) {
            return;
        }
        let verdict = match reply {
            Reply::Items { .. } => Verdict::Listed,
            Reply::Error { error } if !matches!(error, AgentError::Denied | AgentError::Prompt) => Verdict::Failed,
            _ => return,
        };
        let profile = self.config.profile(profile.as_deref()).map(|p| p.name).unwrap_or_default();
        self.audit.record(AuditEvent {
            time: SystemTime::now(),
            profile,
            caller: who.caller.clone(),
            op,
            kind,
            item: None,
            verdict,
        });
    }

    async fn serve(&self, op: Op, who: &Resolved) -> Reply {
        let caller = || who.caller.clone();
        let (resolver, resolved) = (self.resolver.clone(), who.clone());
        let still = || {
            Recheck::new({
                let (resolver, resolved) = (resolver.clone(), resolved.clone());
                move || resolver.recheck(&resolved)
            })
        };
        match op {
            Op::StopAgent => Reply::Done,
            Op::Status { profile } => self.on_profile(profile.as_deref(), Cmd::Status).await,
            Op::Login { profile } => self.on_profile(profile.as_deref(), Cmd::Login).await,
            Op::Unlock { profile } => self.on_profile(profile.as_deref(), Cmd::Unlock).await,
            Op::Sync { target: Target::Profile(name) } => self.on_unlocked(Some(&name), Cmd::Sync).await,
            Op::Sync { target: Target::All } => self.sync_all().await,
            Op::Lock { target: Target::Profile(name) } => self.on_profile(Some(&name), Cmd::Lock).await,
            Op::Lock { target: Target::All } => {
                self.each(|| Cmd::Lock).await;
                Reply::Done
            }
            Op::List { profile, fields, folder } => {
                self.on_unlocked(profile.as_deref(), Cmd::List { fields, folder }).await
            }
            Op::Search { profile, term, folder, fields } => {
                self.on_unlocked(profile.as_deref(), Cmd::Search { term, folder, fields }).await
            }
            Op::Get { profile, needle, user, folder, ignorecase, select } => {
                let find = Lookup { needle, user, folder, ignorecase };
                self.on_unlocked(profile.as_deref(), Cmd::Get { find, select, caller: caller(), still: still() }).await
            }
            Op::History { profile, needle, user, folder } => {
                let find = Lookup { needle, user, folder, ignorecase: false };
                self.on_unlocked(profile.as_deref(), Cmd::History { find, caller: caller(), still: still() }).await
            }
            // The policy needs no unlocked vault.
            Op::Policy { profile, action } => {
                self.on_profile(profile.as_deref(), Cmd::Policy { action, caller: caller(), still: still() }).await
            }
            _ => Reply::Error { error: AgentError::Internal },
        }
    }

    /// Test only: a request from the stock invoker ([`testing::invoker`]).
    #[cfg(test)]
    pub(crate) async fn dispatch(&self, op: Op) -> Reply {
        self.dispatch_as(op, testing::invoker()).await
    }

    /// Test only: a request from `caller`, whose peer is the fake tree's.
    #[cfg(test)]
    pub(crate) async fn dispatch_as(&self, op: Op, caller: crate::caller::Caller) -> Reply {
        self.dispatch_for(op, &Resolved::fixed(caller, testing::peer())).await
    }

    /// Test only: how many items the profile's worker has opened.
    #[cfg(test)]
    pub(crate) async fn opens(&self, profile: &str) -> usize {
        let Reply::Value { value } = self.on_profile(Some(profile), Cmd::Opens).await else { return usize::MAX };
        value.expose().parse().unwrap_or(usize::MAX)
    }

    async fn on_profile(&self, name: Option<&str>, cmd: Cmd) -> Reply {
        match self.config.profile(name) {
            Ok(profile) => match self.worker(&profile) {
                Some(worker) => worker.call(cmd, self.clock.mono()).await,
                None => Reply::Error { error: AgentError::Internal },
            },
            Err(e) => {
                // The text names the file and the key, never a value.
                tracing::warn!("{e:#}");
                Reply::Error { error: AgentError::Config }
            }
        }
    }

    /// Unlock on first need (profiles.md section 4): the same flow as `dybw unlock`, then `cmd`. A failed or cancelled
    /// unlock is the answer, so nothing after it (lookup, confirmation, opening) runs.
    async fn on_unlocked(&self, name: Option<&str>, cmd: Cmd) -> Reply {
        match self.on_profile(name, Cmd::Unlock).await {
            Reply::Done => self.on_profile(name, cmd).await,
            failed => failed,
        }
    }

    /// Sync every profile that is unlocked; a locked one has nothing to sync. The first real failure is the answer.
    async fn sync_all(&self) -> Reply {
        let mut first = Reply::Done;
        for w in self.live() {
            match w.call(Cmd::Sync, self.clock.mono()).await {
                Reply::Error { error: AgentError::Locked } | Reply::Done => {}
                failed if first == Reply::Done => first = failed,
                _ => {}
            }
        }
        first
    }

    async fn each(&self, cmd: impl Fn() -> Cmd) {
        for w in self.live() {
            w.call(cmd(), self.clock.mono()).await;
        }
    }

    /// The 30 s tick; see [`Agent::guard`].
    pub async fn tick(&self) {
        self.guard().await;
    }

    /// Lock everything after a suspend (wall time ran ahead of monotonic time since the last check), else lock
    /// the profiles that have been idle past their timeout. Runs on every tick and before every request.
    async fn guard(&self) {
        let mut last = self.last_tick.lock().await;
        let (wall, mono) = (self.clock.wall(), self.clock.mono());
        let (last_wall, last_mono) = std::mem::replace(&mut *last, (wall, mono));
        let wall_step = wall.duration_since(last_wall).unwrap_or_default();
        let mono_step = mono.saturating_duration_since(last_mono);
        if wall_step.saturating_sub(mono_step) > SLEEP_SLACK {
            tracing::info!("suspend detected, locking every profile");
            #[cfg(test)]
            if let Some((reached, release)) = &self.lock_gate {
                reached.notify_one();
                release.notified().await;
            }
            self.each(|| Cmd::Lock).await;
        } else {
            self.each(|| Cmd::IdleCheck).await;
        }
    }

    /// Lock every profile and end its thread, so the keys are gone when this returns.
    pub async fn shutdown(&self) {
        let workers = {
            let mut map = self.workers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            self.closed.store(true, Ordering::SeqCst);
            std::mem::take(&mut *map)
        };
        // Together, so the bound on each stop is the bound on all of them.
        let mut stops = JoinSet::new();
        for w in workers.into_values() {
            let now = self.clock.mono();
            stops.spawn(async move { w.stop(now).await });
        }
        while stops.join_next().await.is_some() {}
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
pub(crate) mod testing {
    use super::*;
    use crate::credentials::Credentials;
    use crate::host::fake::{Answer, FakeHost, PASSWORD};
    use crate::policy::Audit;
    use crate::worker::Worker;
    use zeroize::Zeroizing;

    /// Both clocks start at the real now and move only when told to.
    pub struct FakeClock(Mutex<(SystemTime, Instant)>);

    impl FakeClock {
        pub fn advance(&self, wall: Duration, mono: Duration) {
            let mut t = self.0.lock().unwrap();
            *t = (t.0 + wall, t.1 + mono);
        }
    }

    impl FakeClock {
        pub fn set_wall(&self, wall: SystemTime) {
            self.0.lock().unwrap().0 = wall;
        }
    }

    impl Clock for FakeClock {
        fn wall(&self) -> SystemTime {
            self.0.lock().unwrap().0
        }
        fn mono(&self) -> Instant {
            self.0.lock().unwrap().1
        }
    }

    /// Every profile has the vector's email, since it is the salt of the vector's master key.
    pub const CONFIG: &str = "default = \"work\"\n\
        [profiles.work]\nserver_url = \"https://w.example.org\"\nemail = \"pbkdf2@vectors.invalid\"\nlock_timeout_minutes = 5\n\
        [profiles.home]\nserver_url = \"https://h.example.org\"\nemail = \"pbkdf2@vectors.invalid\"\nlock_timeout_minutes = 0\n\
        [profiles.fast]\nserver_url = \"https://f.example.org\"\nemail = \"pbkdf2@vectors.invalid\"\nlock_timeout_minutes = 0\nsync_interval_seconds = 1\n\
        [profiles.org]\nserver_url = \"https://o.example.org\"\nemail = \"org@vectors.invalid\"\n\
        [profiles.pw]\nserver_url = \"https://p.example.org\"\nemail = \"pbkdf2@vectors.invalid\"\nauth = \"password\"\n\
        [profiles.plain]\nserver_url = \"http://plain.example.org\"\nemail = \"pbkdf2@vectors.invalid\"\n";

    pub fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// The stock caller: a named script run by a named program, so it can be remembered.
    pub fn invoker() -> crate::caller::Caller {
        crate::caller::Caller::Invoker {
            exe: "/usr/local/bin/mytool".into(),
            script: Some("/opt/scripts/backup.sh".into()),
            hash: "h1".into(),
            relative: false,
        }
    }

    /// The `dybw` process every fake connection comes from.
    pub fn peer() -> dybw_peer::Peer {
        dybw_peer::Peer { pid: 100, uid: me(), token: dybw_peer::Token::plain(0, 100) }
    }

    /// Records every decision.
    #[derive(Default)]
    pub struct Recorder(Mutex<Vec<AuditEvent>>);

    impl Recorder {
        pub fn events(&self) -> Vec<AuditEvent> {
            self.0.lock().unwrap().clone()
        }
    }

    impl Audit for Recorder {
        fn record(&self, event: AuditEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    pub struct Rig {
        pub agent: Arc<Agent>,
        pub clock: Arc<FakeClock>,
        pub host: FakeHost,
        /// The process table the resolver reads: `peer()` is in it.
        pub tree: Arc<dybw_peer::Fake>,
        pub audit: Arc<Recorder>,
    }

    /// An agent over [`CONFIG`], with the fake clock, the scripted host, a fake process table and every path under
    /// `dir`.
    pub fn rig(dir: &std::path::Path) -> Rig {
        rig_with(dir, |tree| tree)
    }

    /// `rig` with the resolver reading the process table through `wrap`.
    pub fn rig_with(
        dir: &std::path::Path,
        wrap: impl FnOnce(Arc<dybw_peer::Fake>) -> Arc<dyn dybw_peer::ProcessSource>,
    ) -> Rig {
        let file = dir.join("config.toml");
        std::fs::write(&file, CONFIG).unwrap();
        let host = FakeHost::new();
        let spawn: Spawn = Box::new({
            let host = host.clone();
            move |ctx| Worker::spawn(host.clone(), ctx)
        });
        let tree = Arc::new(dybw_peer::Fake::default());
        tree.set_peer(peer());
        tree.add(100, process(100));
        let resolver = Arc::new(Resolver::new(wrap(tree.clone()), crate::caller::Harnesses::default()));
        let audit = Arc::new(Recorder::default());
        let user = User { uid: me(), groups: None };
        let config = Config::load(&file).unwrap();
        let mut agent = Agent::new(config, dir.to_owned(), user, spawn, resolver, audit.clone());
        let clock = Arc::new(FakeClock(Mutex::new((SystemTime::now(), Instant::now()))));
        agent.clock = clock.clone();
        Rig { agent: Arc::new(agent), clock, host, tree, audit }
    }

    /// The process `peer()` names, started as `start`.
    pub fn process(start: u64) -> dybw_peer::Process {
        dybw_peer::Process {
            exe: "/usr/local/bin/dybw".into(),
            ppid: 1,
            start,
            image: Vec::new(),
            argv: None,
            env: None,
            cwd: None,
            started: None,
            exe_uuid: None,
        }
    }

    pub fn agent_world(dir: &std::path::Path) -> (Arc<Agent>, Arc<FakeClock>, FakeHost) {
        let Rig { agent, clock, host, .. } = rig(dir);
        (agent, clock, host)
    }

    pub fn agent(dir: &std::path::Path) -> (Arc<Agent>, Arc<FakeClock>) {
        let (agent, clock, _) = agent_world(dir);
        (agent, clock)
    }

    /// The stored API key of a profile, as `dybw login` leaves it.
    pub fn seed_credentials(agent: &Agent, profile: &str) {
        let p = agent.config.profile(Some(profile)).unwrap();
        let paths = ProfilePaths::with(&agent.home, &p);
        let creds = Credentials {
            identity_origin: dybw_core::api::origin_of(&p.server_url).unwrap(),
            client_id: "user.0000".into(),
            client_secret: Zeroizing::new("secret".into()),
        };
        creds.store(&paths.credentials).unwrap();
    }

    /// Log in (the key file), then unlock with the vector's master password.
    pub async fn unlock(agent: &Agent, host: &FakeHost, profile: &str) {
        seed_credentials(agent, profile);
        host.answer(Answer::Text(PASSWORD));
        let reply = agent.dispatch(Op::Unlock { profile: Some(profile.into()) }).await;
        assert_eq!(reply, Reply::Done);
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::host::fake::FakeHost;
    use dybw_proto::ProfileStatus;
    use tokio::sync::Notify;

    const MIN: Duration = Duration::from_secs(60);

    async fn unlocked(agent: &Agent, profile: &str) -> bool {
        let status = agent.dispatch(Op::Status { profile: Some(profile.into()) }).await;
        format!("{status:?}").contains("unlocked: true")
    }

    async fn install(agent: &Agent, host: &FakeHost, profile: &str) {
        unlock(agent, host, profile).await;
        assert!(unlocked(agent, profile).await);
    }

    #[tokio::test]
    async fn status_names_the_profile_and_sees_the_credentials_file() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, _) = agent(dir.path());
        assert_eq!(agent.worker_count(), 0, "workers start on first use");
        let status = agent.dispatch(Op::Status { profile: None }).await;
        assert_eq!(
            status,
            Reply::Status {
                agent_version: env!("CARGO_PKG_VERSION").into(),
                profiles: vec![ProfileStatus {
                    profile: "work".into(),
                    logged_in: false,
                    unlocked: false,
                    last_sync: None
                }],
            }
        );
        assert_eq!(agent.worker_count(), 1);
        seed_credentials(&agent, "work");
        let status = agent.dispatch(Op::Status { profile: Some("work".into()) }).await;
        assert!(format!("{status:?}").contains("logged_in: true"));
    }

    #[tokio::test]
    async fn config_errors_unserved_ops_and_stop_are_answered() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, _) = agent(dir.path());
        let nope = Op::Status { profile: Some("nope".into()) };
        assert_eq!(agent.dispatch(nope).await, Reply::Error { error: AgentError::Config });
        assert_eq!(agent.dispatch(Op::Unknown).await, Reply::Error { error: AgentError::Internal });
        assert_eq!(agent.dispatch(Op::StopAgent).await, Reply::Done);
        // Only the connection handler stops the agent, after the reply is written.
        let stopped = tokio::time::timeout(Duration::from_millis(50), agent.stop.notified()).await;
        assert!(stopped.is_err(), "dispatch must not notify the stop itself");
    }

    #[test]
    fn the_log_names_the_kind_of_an_op_and_never_its_contents() {
        let ops = [
            Op::Status { profile: None },
            Op::Login { profile: None },
            Op::Unlock { profile: None },
            Op::Lock { target: Target::All },
            Op::Sync { target: Target::All },
            Op::List { profile: None, fields: vec![], folder: None },
            Op::Search { profile: None, term: "t".into(), folder: None, fields: vec![] },
            Op::Get {
                profile: None,
                needle: "n".into(),
                user: None,
                folder: None,
                ignorecase: false,
                select: dybw_proto::Select::Password,
            },
            Op::History { profile: None, needle: "n".into(), user: None, folder: None },
            Op::StopAgent,
            Op::Unknown,
        ];
        let kinds: Vec<_> = ops.iter().map(kind).collect();
        assert_eq!(
            kinds,
            ["status", "login", "unlock", "lock", "sync", "list", "search", "get", "history", "stop_agent", "other"]
        );
    }

    #[tokio::test]
    async fn lock_wipes_one_profile_or_all() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, _, host) = agent_world(dir.path());
        install(&agent, &host, "work").await;
        install(&agent, &host, "home").await;
        assert_eq!(agent.dispatch(Op::Lock { target: Target::Profile("work".into()) }).await, Reply::Done);
        assert!(!unlocked(&agent, "work").await && unlocked(&agent, "home").await);
        install(&agent, &host, "work").await;
        assert_eq!(agent.dispatch(Op::Lock { target: Target::All }).await, Reply::Done);
        assert!(!unlocked(&agent, "work").await && !unlocked(&agent, "home").await);
    }

    #[tokio::test]
    async fn a_profile_idle_past_its_timeout_locks_and_a_never_profile_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, clock, host) = agent_world(dir.path());
        install(&agent, &host, "work").await; // 5 minutes
        install(&agent, &host, "home").await; // never
        clock.advance(4 * MIN, 4 * MIN);
        agent.tick().await;
        assert!(unlocked(&agent, "work").await, "not idle long enough");
        clock.advance(2 * MIN, 2 * MIN);
        agent.tick().await;
        assert!(!unlocked(&agent, "work").await, "idle for 6 minutes");
        assert!(unlocked(&agent, "home").await, "timeout 0 never locks");
    }

    #[tokio::test]
    async fn a_request_restarts_the_idle_clock_but_status_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, clock, host) = agent_world(dir.path());
        install(&agent, &host, "work").await;
        clock.advance(4 * MIN, 4 * MIN);
        // An unlock of an unlocked profile asks nothing and is a use of it, at minute 4.
        assert_eq!(agent.dispatch(Op::Unlock { profile: Some("work".into()) }).await, Reply::Done);
        clock.advance(2 * MIN, 2 * MIN);
        assert!(unlocked(&agent, "work").await, "used 2 minutes ago");
        clock.advance(4 * MIN, 4 * MIN);
        assert!(!unlocked(&agent, "work").await, "10 minutes in, 6 since the use: the status at minute 6 was no use");
    }

    #[tokio::test]
    async fn a_request_past_the_idle_timeout_finds_the_profile_locked_without_a_tick() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, clock, host) = agent_world(dir.path());
        install(&agent, &host, "work").await;
        clock.advance(6 * MIN, 6 * MIN);
        // No tick ran: the request itself triggers the check, before the worker command.
        assert!(!unlocked(&agent, "work").await);
    }

    #[tokio::test]
    async fn a_request_right_after_a_wake_finds_every_profile_locked_without_a_tick() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, clock, host) = agent_world(dir.path());
        install(&agent, &host, "work").await;
        install(&agent, &host, "home").await;
        clock.advance(60 * MIN, Duration::from_secs(30));
        assert!(!unlocked(&agent, "work").await);
        assert!(!unlocked(&agent, "home").await, "a profile that never idles locks on a suspend too");
    }

    #[tokio::test]
    async fn a_request_arriving_while_a_wake_is_being_locked_waits_for_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (mut agent, clock, host) = agent_world(dir.path());
        let (reached, release) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        Arc::get_mut(&mut agent).unwrap().lock_gate = Some((reached.clone(), release.clone()));
        install(&agent, &host, "home").await;
        clock.advance(60 * MIN, Duration::from_secs(30));
        // A finds the jump and stops at the gate, before the lock is done; B comes in meanwhile.
        let a = tokio::spawn({
            let agent = agent.clone();
            async move { unlocked(&agent, "home").await }
        });
        reached.notified().await;
        let b = tokio::spawn({
            let agent = agent.clone();
            async move { unlocked(&agent, "home").await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!b.is_finished(), "B must wait for A's lock, not slip past and see the open vault");
        release.notify_one();
        assert!(!a.await.unwrap() && !b.await.unwrap());
    }

    #[tokio::test]
    async fn a_wall_clock_jump_without_monotonic_time_locks_every_profile() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, clock, host) = agent_world(dir.path());
        install(&agent, &host, "work").await;
        install(&agent, &host, "home").await;
        // Drift under the slack, and a clock set back, change nothing.
        clock.advance(Duration::from_secs(80), Duration::from_secs(30));
        agent.tick().await;
        clock.set_wall(SystemTime::UNIX_EPOCH);
        agent.tick().await;
        assert!(unlocked(&agent, "work").await && unlocked(&agent, "home").await);
        // The machine sleeps for an hour: wall time moves, monotonic time barely does.
        clock.advance(60 * MIN, Duration::from_secs(30));
        agent.tick().await;
        assert!(!unlocked(&agent, "work").await && !unlocked(&agent, "home").await);
    }

    #[tokio::test]
    async fn a_panicking_command_answers_internal_wipes_that_profile_and_spares_the_others() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, clock, host) = agent_world(dir.path());
        install(&agent, &host, "work").await;
        install(&agent, &host, "home").await;
        let work = agent.config.profile(Some("work")).unwrap();
        let reply = agent.worker(&work).unwrap().call(Cmd::Panic, clock.mono()).await;
        assert_eq!(reply, Reply::Error { error: AgentError::Internal });
        assert!(!unlocked(&agent, "work").await, "half-dropped state is wiped");
        assert!(unlocked(&agent, "home").await, "other profiles keep working");
    }

    #[tokio::test]
    async fn a_dead_worker_answers_internal_then_is_replaced_locked() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, clock, host) = agent_world(dir.path());
        install(&agent, &host, "work").await;
        install(&agent, &host, "home").await;
        let work = agent.config.profile(Some("work")).unwrap();
        let worker = agent.worker(&work).unwrap();
        assert_eq!(worker.call(Cmd::Crash, clock.mono()).await, Reply::Error { error: AgentError::Internal });
        // Every call after the crash fails fast.
        // Joining the crashed thread is what "gone" means; a stop on it is harmless.
        worker.stop(clock.mono()).await;
        assert!(!worker.is_alive());
        assert_eq!(worker.call(Cmd::Status, clock.mono()).await, Reply::Error { error: AgentError::Internal });
        assert!(unlocked(&agent, "home").await);
        assert!(!unlocked(&agent, "work").await, "a fresh worker starts locked");
    }

    #[tokio::test]
    async fn shutdown_stops_every_worker() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, _, host) = agent_world(dir.path());
        install(&agent, &host, "work").await;
        install(&agent, &host, "home").await;
        agent.shutdown().await;
        assert_eq!(agent.worker_count(), 0);
        // A request that arrives after shutdown must not start a new worker.
        let status = agent.dispatch(Op::Status { profile: Some("work".into()) }).await;
        assert_eq!(status, Reply::Error { error: AgentError::Internal });
        assert_eq!(agent.worker_count(), 0);
    }
}
