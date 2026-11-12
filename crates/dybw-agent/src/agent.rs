//! The agent's shared state: the config, the per-profile workers, the clocks and the lock rules.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use dybw_proto::{AgentError, Op, Reply, Target};
use tokio::sync::Notify;

use crate::config::Config;
use crate::paths::ProfilePaths;
use crate::worker::{Cmd, Worker};

/// How often the idle and sleep checks run.
pub const TICK: Duration = Duration::from_secs(30);
/// Wall time may run this much ahead of monotonic time between two ticks before it counts as a suspend.
pub const SLEEP_SLACK: Duration = Duration::from_secs(60);
/// How long a client has to send its request.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

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

/// How the agent reads its environment; tests swap it.
pub type EnvFn = Box<dyn Fn(&str) -> Option<OsString> + Send + Sync>;

pub struct Agent {
    pub(crate) config: Config,
    pub(crate) home: PathBuf,
    /// The uid every peer must have.
    pub(crate) uid: u32,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) var: EnvFn,
    pub(crate) read_timeout: Duration,
    workers: Mutex<HashMap<String, Arc<Worker>>>,
    last_tick: Mutex<(SystemTime, Instant)>,
    pub(crate) stop: Notify,
    /// Set by `shutdown`: no worker starts after it.
    closed: AtomicBool,
}

impl Agent {
    pub fn new(config: Config, home: PathBuf, uid: u32, var: EnvFn) -> Agent {
        let clock = Arc::new(SystemClock);
        let last_tick = Mutex::new((clock.wall(), clock.mono()));
        Agent {
            config,
            home,
            uid,
            clock,
            var,
            read_timeout: READ_TIMEOUT,
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
    fn worker(&self, profile: &crate::config::Profile) -> Option<Arc<Worker>> {
        let mut workers = self.workers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.closed.load(Ordering::SeqCst) {
            return None;
        }
        if let Some(w) = workers.get(&profile.name).filter(|w| w.is_alive()) {
            return Some(w.clone());
        }
        let paths = ProfilePaths::with(&*self.var, &self.home, profile);
        let w = Arc::new(Worker::spawn(profile, paths.credentials));
        workers.insert(profile.name.clone(), w.clone());
        Some(w)
    }

    #[cfg(test)]
    pub(crate) fn worker_count(&self) -> usize {
        self.workers.lock().map(|w| w.len()).unwrap_or_default()
    }

    /// Answer one request. Anything not yet served answers `Internal`. `StopAgent` only answers `Done`: the
    /// connection handler notifies the stop once that reply is written.
    pub async fn dispatch(&self, op: Op) -> Reply {
        // Do not wait for the tick: a request right after a wake or past the idle timeout finds the profile locked.
        self.guard().await;
        tracing::info!(op = kind(&op), "request");
        match op {
            Op::StopAgent => Reply::Done,
            Op::Status { profile } => self.on_profile(profile.as_deref(), Cmd::Status).await,
            Op::Lock { target: Target::Profile(name) } => self.on_profile(Some(&name), Cmd::Lock).await,
            Op::Lock { target: Target::All } => {
                self.each(|| Cmd::Lock).await;
                Reply::Done
            }
            _ => Reply::Error { error: AgentError::Internal },
        }
    }

    async fn on_profile(&self, name: Option<&str>, cmd: Cmd) -> Reply {
        match self.config.profile(name) {
            Ok(profile) => match self.worker(&profile) {
                Some(worker) => worker.call(cmd, self.clock.mono()).await,
                None => Reply::Error { error: AgentError::Internal },
            },
            Err(_) => Reply::Error { error: AgentError::Config },
        }
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
        let (wall, mono) = (self.clock.wall(), self.clock.mono());
        let (last_wall, last_mono) = {
            let mut last = self.last_tick.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *last, (wall, mono))
        };
        let wall_step = wall.duration_since(last_wall).unwrap_or_default();
        let mono_step = mono.saturating_duration_since(last_mono);
        if wall_step.saturating_sub(mono_step) > SLEEP_SLACK {
            tracing::info!("suspend detected, locking every profile");
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
        for w in workers.values() {
            w.stop(self.clock.mono()).await;
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
pub(crate) mod testing {
    use super::*;

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

    pub const CONFIG: &str = "default = \"work\"\n\
        [profiles.work]\nserver_url = \"https://w.example.org\"\nemail = \"w@example.org\"\nlock_timeout_minutes = 5\n\
        [profiles.home]\nserver_url = \"https://h.example.org\"\nemail = \"h@example.org\"\nlock_timeout_minutes = 0\n";

    pub fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// An agent over [`CONFIG`], with the fake clock and every path under `dir`.
    pub fn agent(dir: &std::path::Path) -> (Arc<Agent>, Arc<FakeClock>) {
        let file = dir.join("config.toml");
        std::fs::write(&file, CONFIG).unwrap();
        let state = dir.join("state");
        let var = Box::new(move |name: &str| (name == "XDG_STATE_HOME").then(|| state.clone().into_os_string()));
        let mut agent = Agent::new(Config::load(&file).unwrap(), dir.to_owned(), me(), var);
        let clock = Arc::new(FakeClock(Mutex::new((SystemTime::now(), Instant::now()))));
        agent.clock = clock.clone();
        (Arc::new(agent), clock)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::testing::*;
    use super::*;
    use dybw_proto::ProfileStatus;

    const MIN: Duration = Duration::from_secs(60);

    async fn unlocked(agent: &Agent, profile: &str) -> bool {
        let status = agent.dispatch(Op::Status { profile: Some(profile.into()) }).await;
        format!("{status:?}").contains("unlocked: true")
    }

    async fn install(agent: &Agent, profile: &str) {
        let p = agent.config.profile(Some(profile)).unwrap();
        agent.worker(&p).unwrap().call(Cmd::Install, agent.clock.mono()).await;
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
                profiles: vec![ProfileStatus { profile: "work".into(), logged_in: false, unlocked: false }],
            }
        );
        assert_eq!(agent.worker_count(), 1);
        let creds = dir.path().join("state/dybw/profiles/work/credentials");
        std::fs::create_dir_all(creds.parent().unwrap()).unwrap();
        std::fs::write(&creds, "").unwrap();
        let status = agent.dispatch(Op::Status { profile: Some("work".into()) }).await;
        assert!(format!("{status:?}").contains("logged_in: true"));
    }

    #[tokio::test]
    async fn config_errors_unserved_ops_and_stop_are_answered() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, _) = agent(dir.path());
        let nope = Op::Status { profile: Some("nope".into()) };
        assert_eq!(agent.dispatch(nope).await, Reply::Error { error: AgentError::Config });
        let list = Op::List { profile: None, fields: vec![], folder: None };
        assert_eq!(agent.dispatch(list).await, Reply::Error { error: AgentError::Internal });
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
        let (agent, _) = agent(dir.path());
        install(&agent, "work").await;
        install(&agent, "home").await;
        assert_eq!(agent.dispatch(Op::Lock { target: Target::Profile("work".into()) }).await, Reply::Done);
        assert!(!unlocked(&agent, "work").await && unlocked(&agent, "home").await);
        install(&agent, "work").await;
        assert_eq!(agent.dispatch(Op::Lock { target: Target::All }).await, Reply::Done);
        assert!(!unlocked(&agent, "work").await && !unlocked(&agent, "home").await);
    }

    #[tokio::test]
    async fn a_profile_idle_past_its_timeout_locks_and_a_never_profile_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, clock) = agent(dir.path());
        install(&agent, "work").await; // 5 minutes
        install(&agent, "home").await; // never
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
        let (agent, clock) = agent(dir.path());
        install(&agent, "work").await;
        clock.advance(4 * MIN, 4 * MIN);
        let work = agent.config.profile(Some("work")).unwrap();
        agent.worker(&work).unwrap().call(Cmd::Install, clock.mono()).await; // a use of work at minute 4
        clock.advance(2 * MIN, 2 * MIN);
        assert!(unlocked(&agent, "work").await, "used 2 minutes ago");
        clock.advance(4 * MIN, 4 * MIN);
        assert!(!unlocked(&agent, "work").await, "10 minutes in, 6 since the use: the status at minute 6 was no use");
    }

    #[tokio::test]
    async fn a_request_past_the_idle_timeout_finds_the_profile_locked_without_a_tick() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, clock) = agent(dir.path());
        install(&agent, "work").await;
        clock.advance(6 * MIN, 6 * MIN);
        // No tick ran: the request itself triggers the check, before the worker command.
        assert!(!unlocked(&agent, "work").await);
    }

    #[tokio::test]
    async fn a_request_right_after_a_wake_finds_every_profile_locked_without_a_tick() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, clock) = agent(dir.path());
        install(&agent, "work").await;
        install(&agent, "home").await;
        clock.advance(60 * MIN, Duration::from_secs(30));
        assert!(!unlocked(&agent, "work").await);
        assert!(!unlocked(&agent, "home").await, "a profile that never idles locks on a suspend too");
    }

    #[tokio::test]
    async fn a_wall_clock_jump_without_monotonic_time_locks_every_profile() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, clock) = agent(dir.path());
        install(&agent, "work").await;
        install(&agent, "home").await;
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
        let (agent, clock) = agent(dir.path());
        install(&agent, "work").await;
        install(&agent, "home").await;
        let work = agent.config.profile(Some("work")).unwrap();
        let reply = agent.worker(&work).unwrap().call(Cmd::Panic, clock.mono()).await;
        assert_eq!(reply, Reply::Error { error: AgentError::Internal });
        assert!(!unlocked(&agent, "work").await, "half-dropped state is wiped");
        assert!(unlocked(&agent, "home").await, "other profiles keep working");
    }

    #[tokio::test]
    async fn a_dead_worker_answers_internal_then_is_replaced_locked() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, clock) = agent(dir.path());
        install(&agent, "work").await;
        install(&agent, "home").await;
        let work = agent.config.profile(Some("work")).unwrap();
        let worker = agent.worker(&work).unwrap();
        assert_eq!(worker.call(Cmd::Crash, clock.mono()).await, Reply::Error { error: AgentError::Internal });
        // Wait for the thread to be gone, then every further call fails fast.
        while worker.is_alive() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(worker.call(Cmd::Status, clock.mono()).await, Reply::Error { error: AgentError::Internal });
        assert!(unlocked(&agent, "home").await);
        assert!(!unlocked(&agent, "work").await, "a fresh worker starts locked");
    }

    #[tokio::test]
    async fn shutdown_stops_every_worker() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, _) = agent(dir.path());
        install(&agent, "work").await;
        install(&agent, "home").await;
        agent.shutdown().await;
        assert_eq!(agent.worker_count(), 0);
        // A request that arrives after shutdown must not start a new worker.
        let status = agent.dispatch(Op::Status { profile: Some("work".into()) }).await;
        assert_eq!(status, Reply::Error { error: AgentError::Internal });
        assert_eq!(agent.worker_count(), 0);
    }
}
