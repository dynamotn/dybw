//! Who is asking (ADR 0012, ADR 0025): the socket peer is `dybw`; the caller is the invoker above it, an AI harness
//! anywhere above it, or nobody we can name. Everything the kernel will not tell us is `Unknown`, never "clean".

use std::collections::HashSet;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dybw_peer::{Peer, Process, ProcessSource};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Largest script or executable hashed; a bigger one is `Unknown`.
const MAX_HASH_BYTES: u64 = 16 << 20;
/// The CLI (and the `rbw` stand-in): a `dybw` run by one of these is looked through.
const CLI_NAMES: [&str; 2] = ["dybw", "rbw"];
/// Processes that adopt orphans: an invoker named so is a detached caller, not a program that ran dybw.
const SUBREAPERS: [&str; 5] = ["systemd", "init", "launchd", "tini", "dumb-init"];
/// Privilege wrappers: anything run through them is not named by its invoker.
const ELEVATORS: [&str; 5] = ["sudo", "doas", "su", "run0", "pkexec"];
/// Interpreters matched by name prefix (`perl5.36`, `ruby3.3`, `nodejs`); python has its own flags.
const INTERPRETER_PREFIXES: [&str; 6] = ["node", "perl", "ruby", "php", "lua", "tclsh"];
/// Interpreters matched by exact name.
const INTERPRETERS: [&str; 4] = ["osascript", "bun", "deno", "pwsh"];
/// Launchers, multiplexers and terminals: they run whatever they are told, so a grant for one would be a grant for
/// everything run through it. Never remembered, and `dybw policy allow` refuses them (`sudo`, `doas` and the other
/// [`ELEVATORS`] make the caller unknown before this list is looked at).
const LAUNCHERS: [&str; 30] = [
    "xargs",
    "timeout",
    "env",
    "nohup",
    "setsid",
    "make",
    "git",
    "parallel",
    "watch",
    "zellij",
    "tmux",
    "screen",
    "kitty",
    "alacritty",
    "wezterm",
    "wezterm-gui",
    "iTerm2",
    "Terminal",
    "ghostty",
    "sudo",
    "doas",
    "launchctl",
    "open",
    "osascript",
    "ssh",
    "sshd",
    "cron",
    "crond",
    "at",
    "atd",
];
/// Environment variables a harness sets (profiles §4); they only ever tighten.
const MARKERS: [(&str, &str); 8] = [
    ("CLAUDECODE", "claude"),
    ("CODEX_SANDBOX", "codex"),
    ("GEMINI_CLI", "gemini"),
    ("CURSOR_AGENT", "cursor"),
    ("OPENCODE", "opencode"),
    ("AI_AGENT", "unknown-harness"),
    ("AGENT_SESSION_ID", "unknown-harness"),
    ("HERMES_HOME", "hermes"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Ancestry,
    Marker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// An AI harness is the peer, the invoker, or any ancestor.
    Ai { harness: String, via: Via },
    /// Cannot be named: orphan, replaced, unreadable. Asked every time, never remembered. `peer` is the executable
    /// of the peer when it could be read.
    Unknown { why: String, peer: Option<PathBuf> },
    /// A named invoker; `hash` is the SHA-256 (hex) of the script if any, else of the executable. `relative`: the
    /// script was given as a relative path, resolved against the cwd at resolve time (a script that `cd`s could
    /// stand for another file), so it is shown but never remembered.
    Invoker { exe: PathBuf, script: Option<PathBuf>, hash: String, relative: bool, at: At },
}

/// Where a named invoker was found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct At {
    /// The invoker process as the kernel names it (pid, start time, image): what a grant "for this process" is for.
    pub pid: u32,
    pub start: u64,
    pub image: Vec<u8>,
    /// Its parent exited (it was reparented to pid 1) or is launchd or a subreaper: nothing that ran it is left to
    /// tell who it works for, so it could be an AI agent's leftover.
    pub detached: bool,
    /// The peer's executable when it is a `dybw` or `rbw` other than the agent's companion (kept for the audit).
    pub peer: Option<PathBuf>,
    /// For an SSH client (the peer is the caller itself): the executable of the process that ran it, as the question
    /// and the audit show it (`git` for `git` → `ssh`).
    pub parent: Option<PathBuf>,
}

/// How long a grant for a caller may last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Asked every time.
    Never,
    /// Until the process exits, the profile locks or the agent stops; in the agent's memory only. For a script: its
    /// argv is the process's own memory and can claim any script (`$0=`), so only the process is held to account.
    Process,
    /// In `policy.json`, for a plain executable (kernel-reported path and content hash).
    Device,
}

impl Caller {
    /// How long a grant for this caller can last, whoever makes it (the "always" of a question or `dybw policy
    /// allow`): per device for a plain executable, per process for an interpreter running a script given by an
    /// absolute path, never for a bare interpreter (every script it runs would share it), a relative script, a
    /// launcher (see [`launcher`]), an unknown or an AI caller.
    pub fn scope(&self) -> Scope {
        let Caller::Invoker { exe, script, relative, .. } = self else { return Scope::Never };
        if *relative || launcher(exe) {
            return Scope::Never;
        }
        match (interpreter(exe), script) {
            (false, None) => Scope::Device,
            (true, Some(_)) => Scope::Process,
            _ => Scope::Never,
        }
    }

    /// May a question offer "always"? Only for a grant that can last, and never for a detached caller: its grants
    /// are made with `dybw policy allow --detached` alone.
    pub fn rememberable(&self) -> bool {
        self.scope() != Scope::Never && !self.detached()
    }

    pub fn detached(&self) -> bool {
        matches!(self, Caller::Invoker { at, .. } if at.detached)
    }
}

/// Is `exe` an interpreter or a shell (it runs a script whose name is only its own argv)?
pub fn interpreter(exe: &Path) -> bool {
    flag_letters(exe).is_some()
}

/// Is `exe` a launcher, multiplexer or terminal ([`LAUNCHERS`])?
pub fn launcher(exe: &Path) -> bool {
    exe.file_name().is_some_and(|n| LAUNCHERS.contains(&n.to_string_lossy().as_ref()))
}

/// One harness of the table. A process matches on any of: executable basename, a path fragment of the executable,
/// a fragment of any argv entry, or the basename of argv[0] / argv[1] (the interpreter's script).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Harness {
    pub name: String,
    pub exe: Vec<String>,
    pub exe_contains: Vec<String>,
    pub argv_contains: Vec<String>,
    pub argv_base: Vec<String>,
}

impl Harness {
    fn new(name: &str, exe: &[&str], exe_contains: &[&str], argv_contains: &[&str], argv_base: &[&str]) -> Self {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect();
        Self {
            name: name.into(),
            exe: own(exe),
            exe_contains: own(exe_contains),
            argv_contains: own(argv_contains),
            argv_base: own(argv_base),
        }
    }

    /// Without empty fragments (they would match everything); `None` when no name or nothing to match is left.
    fn cleaned(mut self) -> Option<Self> {
        for list in [&mut self.exe, &mut self.exe_contains, &mut self.argv_contains, &mut self.argv_base] {
            list.retain(|f| !f.is_empty());
        }
        let any = [&self.exe, &self.exe_contains, &self.argv_contains, &self.argv_base].iter().any(|l| !l.is_empty());
        (!self.name.is_empty() && any).then_some(self)
    }

    fn matches(&self, p: &Process) -> bool {
        let exe = p.exe.to_string_lossy();
        let base = p.exe.file_name().map(|b| b.to_string_lossy().into_owned()).unwrap_or_default();
        let argv: Vec<String> = p.argv.iter().flatten().map(|a| a.to_string_lossy().into_owned()).collect();
        self.exe.contains(&base)
            || self.exe_contains.iter().any(|e| exe.contains(e.as_str()))
            || self.argv_contains.iter().any(|c| argv.iter().any(|a| a.contains(c.as_str())))
            || argv.iter().take(2).any(|a| {
                let name = a.rsplit('/').next().unwrap_or_default().trim_start_matches('-');
                self.argv_base.iter().any(|b| b == name)
            })
    }
}

/// The harness table: device state, seeded from `docs/ai-harnesses.md` "Ancestry names". The optional
/// `harnesses.toml` can only add entries.
#[derive(Debug, Clone)]
pub struct Harnesses(Vec<Harness>);

#[derive(Deserialize, Default)]
struct HarnessFile {
    #[serde(default)]
    harness: Vec<Harness>,
}

impl Default for Harnesses {
    fn default() -> Self {
        Self(vec![
            Harness::new(
                "claude",
                &["claude"],
                &["/claude/versions/", "/installs/claude/"],
                &["@anthropic-ai/claude-code"],
                &["claude"],
            ),
            Harness::new("codex", &["codex"], &[], &["@openai/codex"], &[]),
            Harness::new("gemini", &[], &[], &["@google/gemini-cli"], &[]),
            Harness::new("antigravity", &["agy", "antigravity"], &[], &[], &[]),
            Harness::new("copilot", &["copilot"], &[], &["@github/copilot"], &[]),
            Harness::new("cursor", &[], &["cursor-agent/versions/"], &["cursor-agent/"], &["cursor-agent"]),
            Harness::new("goose", &["goose"], &[], &[], &[]),
            Harness::new("opencode", &["opencode"], &[], &["opencode.cjs"], &[]),
            Harness::new("aider", &[], &[], &[], &["aider"]),
            Harness::new("hermes", &[], &[], &[], &["hermes", "hermes-agent", "hermes-acp"]),
        ])
    }
}

impl Harnesses {
    /// The defaults plus the entries of `file`; a missing, oversized or malformed file adds nothing (and is logged).
    pub fn load(file: &Path) -> Self {
        let mut table = Self::default();
        let text = match std::fs::File::open(file).and_then(|f| read_capped(&f, 64 << 10)) {
            Ok(bytes) => String::from_utf8(bytes).ok(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return table,
            Err(_) => None,
        };
        match text.and_then(|t| toml::from_str::<HarnessFile>(&t).ok()) {
            Some(extra) => table.0.extend(extra.harness.into_iter().filter_map(Harness::cleaned)),
            None => tracing::warn!(file = %file.display(), "ignoring an unreadable harness list"),
        }
        table
    }

    fn find(&self, p: &Process) -> Option<&str> {
        self.0.iter().find(|h| h.matches(p)).map(|h| h.name.as_str())
    }
}

/// A marker in `env`, if any variable of [`MARKERS`] is present.
fn marker(env: &[(OsString, OsString)]) -> Option<&'static str> {
    MARKERS.iter().find(|(var, _)| env.iter().any(|(k, _)| k == var)).map(|(_, harness)| *harness)
}

/// What the walk saw of one process, to tell later whether it is still that process.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    pid: u32,
    ppid: u32,
    start: u64,
    image: Vec<u8>,
    exe: PathBuf,
}

/// An SSH client's programs as the process table names them, whatever its class: its own executable and the one of
/// the process that ran it. The question and the audit name them for every class (ADR 0012).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Programs {
    pub exe: Option<PathBuf>,
    pub parent: Option<PathBuf>,
}

/// A caller together with what it was resolved from, so the answer can be re-checked before a reply is written.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub caller: Caller,
    peer: Peer,
    chain: Vec<Seen>,
    /// For an SSH client ([`Resolver::resolve_client`]): its programs; empty otherwise.
    pub(crate) client: Programs,
}

impl Resolved {
    /// Test only: a caller taken as given, held to `peer` alone.
    #[cfg(test)]
    pub(crate) fn fixed(caller: Caller, peer: Peer) -> Self {
        Self { caller, peer, chain: Vec::new(), client: Programs::default() }
    }

    fn unknown(peer: Peer, why: &str) -> Self {
        let caller = Caller::Unknown { why: why.into(), peer: None };
        Self { caller, peer, chain: Vec::new(), client: Programs::default() }
    }
}

/// What this process would be taken for, with the real process table and the device's harness table (`dybw
/// doctor`); `None` when it cannot be told.
pub fn this_process(harnesses: &Path) -> Option<Caller> {
    let me = std::env::current_exe().and_then(std::fs::canonicalize).ok();
    Resolver::new(Arc::new(dybw_peer::Os), Harnesses::load(harnesses)).with_companion(me).caller_of_self()
}

pub struct Resolver {
    source: Arc<dyn ProcessSource>,
    harnesses: Harnesses,
    /// The `dybw` next to the agent's own executable: a peer that is this file needs no note in the audit.
    companion: Option<PathBuf>,
}

impl Resolver {
    pub fn new(source: Arc<dyn ProcessSource>, harnesses: Harnesses) -> Self {
        Self { source, harnesses, companion: None }
    }

    /// Set the companion CLI (canonical path).
    pub fn with_companion(mut self, companion: Option<PathBuf>) -> Self {
        self.companion = companion;
        self
    }

    /// Resolve the peer on a blocking thread (it reads and hashes files). Call it as soon as the connection is
    /// accepted.
    pub async fn resolve_async(self: Arc<Self>, peer: Peer) -> Resolved {
        let (me, p) = (self.clone(), peer.clone());
        let joined = tokio::task::spawn_blocking(move || me.resolve(p)).await;
        joined.unwrap_or(Resolved::unknown(peer, "the resolver failed"))
    }

    /// What this very process would be taken for were it the agent's peer (`dybw doctor` asks whether it runs under
    /// an AI harness); `None` when the process table cannot be read.
    pub fn caller_of_self(&self) -> Option<Caller> {
        use std::os::fd::AsFd;
        let (end, _other) = std::os::unix::net::UnixStream::pair().ok()?;
        Some(self.resolve(self.source.peer_of(end.as_fd()).ok()?).caller)
    }

    /// [`Resolver::resolve_client`] on a blocking thread: an SSH client on `ssh-agent.sock`.
    pub async fn resolve_client_async(self: Arc<Self>, peer: Peer) -> Resolved {
        let (me, p) = (self.clone(), peer.clone());
        let joined = tokio::task::spawn_blocking(move || me.resolve_client(p)).await;
        joined.unwrap_or(Resolved::unknown(peer, "the resolver failed"))
    }

    /// Resolve the peer on this thread.
    pub fn resolve(&self, peer: Peer) -> Resolved {
        let (caller, chain) = self.classify(&peer, false);
        Resolved { caller, peer, chain, client: Programs::default() }
    }

    /// Resolve an SSH client (profiles §8): the peer itself is the caller, named by its own executable, with the
    /// process that ran it as its `parent`. The same rules otherwise: an AI harness anywhere above it or a marker in
    /// its or its parent's environment makes it AI-class; an ancestry that cannot be read, a privilege wrapper or a
    /// file that cannot be hashed make it unknown.
    pub fn resolve_client(&self, peer: Peer) -> Resolved {
        let (caller, chain) = self.classify(&peer, true);
        let exe = |n: usize| chain.get(n).map(|s| s.exe.clone());
        let client = Programs { exe: exe(0), parent: exe(1) };
        Resolved { caller, peer, chain, client }
    }

    /// Is the peer still the process it was, with the same program, and every process the answer rests on unchanged
    /// (none exited, replaced or reparented)? Check before a value reply: a reused pid must not inherit a grant.
    pub fn recheck(&self, resolved: &Resolved) -> bool {
        self.source.still_same(&resolved.peer)
            && resolved.chain.iter().all(|seen| {
                self.source
                    .process(seen.pid)
                    .is_ok_and(|p| p.ppid == seen.ppid && p.start == seen.start && p.image == seen.image)
            })
    }

    /// `client`: the peer is the caller (an SSH client), not a `dybw` whose invoker is.
    fn classify(&self, peer: &Peer, client: bool) -> (Caller, Vec<Seen>) {
        if !self.source.still_same(peer) {
            return (Caller::Unknown { why: "the peer is gone or was replaced".into(), peer: None }, Vec::new());
        }
        // Ancestors from the peer up to pid 1 (a loop ends it). Any error is remembered, but an AI match found on the
        // way still wins.
        let mut chain: Vec<Process> = Vec::new();
        let mut pids: Vec<u32> = Vec::new();
        let mut complete = false;
        let mut pid = peer.pid;
        let mut seen_pids = HashSet::new();
        while seen_pids.insert(pid) {
            let Ok(p) = self.source.process(pid) else { break };
            let next = p.ppid;
            chain.push(p);
            pids.push(pid);
            if next <= 1 {
                complete = true;
                break;
            }
            pid = next;
        }
        let seen: Vec<Seen> = pids
            .iter()
            .zip(&chain)
            .map(|(&pid, p)| Seen { pid, ppid: p.ppid, start: p.start, image: p.image.clone(), exe: p.exe.clone() })
            .collect();
        let invoker = if client { chain.first().map(|p| (0, p)) } else { invoker_index(&chain) };
        let marked = if client { chain.get(1) } else { invoker.map(|(_, p)| p) };
        if let Some(ai) = self.ai(&chain, marked) {
            return (ai, seen);
        }
        let peer_exe = chain.first().map(|p| p.exe.clone());
        let unknown = |why: &str| Caller::Unknown { why: why.into(), peer: peer_exe.clone() };
        if !complete {
            return (unknown("the ancestry could not be read to the top"), seen);
        }
        // A process of this user whose argv could not be read (oversized, malformed) may be hiding a harness's argv.
        // Withheld arguments (another user's process, SIP) are normal and do not count.
        if chain.iter().any(|p| p.args == dybw_peer::Args::Unreadable) {
            return (unknown("an ancestor's arguments could not be read"), seen);
        }
        if !client && !chain.first().is_some_and(is_cli) {
            return (unknown("the peer is not dybw"), seen);
        }
        let Some((index, process)) = invoker else {
            return (unknown("no process above dybw (orphan)"), seen);
        };
        if chain.iter().any(|p| named(p, &ELEVATORS)) {
            return (unknown("run through a privilege wrapper"), seen);
        }
        if adopts_orphans(process) {
            return (unknown("the invoker adopts orphans: a detached caller"), seen);
        }
        let at = At {
            pid: pids.get(index).copied().unwrap_or_default(),
            start: process.start,
            image: process.image.clone(),
            // The walk stops below pid 1, so an invoker with nothing above it in the chain was reparented to it.
            detached: process.ppid <= 1 || chain.get(index + 1).is_some_and(adopts_orphans),
            peer: peer_exe.clone().filter(|exe| !client && self.companion.as_ref() != Some(exe)),
            parent: chain.get(1).filter(|_| client).map(|p| p.exe.clone()),
        };
        match self.identify(process, at) {
            // A reparented invoker fails the re-check on its ppid; an SSH client's parent is held to it too.
            Ok(caller) => (caller, seen.into_iter().take(index + 1 + usize::from(client)).collect()),
            Err(why) => (unknown(&why), seen),
        }
    }

    fn identify(&self, p: &Process, at: At) -> Result<Caller, String> {
        let found = match flag_letters(&p.exe) {
            Some(letters) => script_of(p, letters)?,
            None => None,
        };
        let relative = found.as_ref().is_some_and(|(_, relative)| *relative);
        let script = found.map(|(path, _)| path);
        // The script, or the running image of the executable (Linux: through /proc, whatever the path names now).
        let file = match &script {
            Some(script) => std::fs::File::open(script),
            None => self.source.executable(at.pid, &p.exe),
        };
        let file = file.map_err(|_| "the invoker's file cannot be read".to_owned())?;
        let uuid = if script.is_none() { p.exe_uuid } else { None };
        let hash = hash_file(file, p.started, uuid, &|| {})?;
        Ok(Caller::Invoker { exe: p.exe.clone(), script, hash, relative, at })
    }

    fn ai(&self, chain: &[Process], invoker: Option<&Process>) -> Option<Caller> {
        let ancestry = |harness: &str| Caller::Ai { harness: harness.into(), via: Via::Ancestry };
        if let Some(h) = chain.iter().find_map(|p| self.harnesses.find(p)) {
            return Some(ancestry(h));
        }
        let envs = chain.first().into_iter().chain(invoker);
        envs.filter_map(|p| p.env.as_deref().and_then(marker))
            .next()
            .map(|h| Caller::Ai { harness: h.into(), via: Via::Marker })
    }
}

/// Index in `chain` (peer first) of the invoker: the first ancestor that is not `dybw`/`rbw`. `None` for an orphan
/// (nothing above the peer, or only CLI names above it).
fn invoker_index(chain: &[Process]) -> Option<(usize, &Process)> {
    chain.iter().enumerate().skip(1).find(|(_, p)| !is_cli(p))
}

fn base(p: &Process) -> String {
    p.exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

fn named(p: &Process, names: &[&str]) -> bool {
    names.contains(&base(p).as_str())
}

fn is_cli(p: &Process) -> bool {
    named(p, &CLI_NAMES)
}

/// launchd, init, a subreaper or a container shim: a process it runs was either started by it or left to it.
fn adopts_orphans(p: &Process) -> bool {
    named(p, &SUBREAPERS) || base(p).starts_with("containerd-shim")
}

/// The valueless option letters an interpreter may carry before its script, `None` if it is not an interpreter.
/// Anything else (an option with a value, `-c`, `-e`, `-m`, `-s`, `-`, `--opt=x`) makes the script unknowable.
fn flag_letters(exe: &Path) -> Option<&'static [char]> {
    let name = exe.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    if ["sh", "bash", "zsh", "fish", "dash"].contains(&name.as_str()) {
        Some(&['e', 'x', 'u', 'l', 'i'])
    } else if name.starts_with("python") {
        Some(&['u', 'B', 'E', 'I', 's'])
    } else if INTERPRETERS.contains(&name.as_str()) || INTERPRETER_PREFIXES.iter().any(|p| name.starts_with(p)) {
        Some(&[])
    } else {
        None
    }
}

/// The script an interpreter runs: argv[1], or the argument after `--`, preceded only by known valueless flags;
/// canonical (a relative path is resolved against the process's cwd). `Ok(None)`: no argument at all (an interactive
/// interpreter). `Err`: cannot be named (inline code, any other option, hidden argv or cwd, a script that does not
/// resolve to a file).
fn script_of(p: &Process, letters: &[char]) -> Result<Option<(PathBuf, bool)>, String> {
    let argv = p.argv.as_deref().ok_or("the interpreter's arguments are not visible")?;
    let mut dashes = false;
    let mut script = None;
    for arg in argv.iter().skip(1) {
        let arg = arg.to_string_lossy();
        if !dashes && arg == "--" {
            dashes = true;
        } else if !dashes && arg.starts_with('-') {
            let valueless = arg.len() > 1 && arg.chars().skip(1).all(|c| letters.contains(&c));
            if !valueless {
                return Err("the interpreter has an option that may hide its script".into());
            }
        } else {
            script = Some(arg.into_owned());
            break;
        }
    }
    let Some(script) = script else { return Ok(None) };
    let path = match (Path::new(&script).is_absolute(), &p.cwd) {
        (true, _) => PathBuf::from(&script),
        (false, Some(cwd)) => cwd.join(&script),
        (false, None) => return Err("the script path is relative and the working directory is not visible".into()),
    };
    let path = std::fs::canonicalize(path).map_err(|_| "the script cannot be found".to_owned())?;
    if path.is_file() {
        Ok(Some((path, !Path::new(&script).is_absolute())))
    } else {
        Err("the script is not a file".into())
    }
}

fn read_capped(file: &std::fs::File, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(std::io::Error::other("file too large"));
    }
    Ok(bytes)
}

/// Slack for a start time kept in clock ticks (10 ms on Linux); macOS keeps microseconds.
const TICK: Duration = Duration::from_millis(if cfg!(target_os = "linux") { 20 } else { 0 });

/// The last time the file was written or its inode changed.
fn changed(md: &std::fs::Metadata) -> Option<SystemTime> {
    let ctime = SystemTime::UNIX_EPOCH
        .checked_add(Duration::new(u64::try_from(md.ctime()).ok()?, u32::try_from(md.ctime_nsec()).ok()?))?;
    Some(ctime.max(md.modified().ok()?))
}

/// The same inode, unchanged: size, data and inode change times.
fn same_stat(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    let key =
        |m: &std::fs::Metadata| (m.dev(), m.ino(), m.size(), m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec());
    key(a) == key(b)
}

/// SHA-256 (hex) of an open file: what is hashed is what was `fstat`ed, before and after the read. A file written or
/// changed after the process started is not what the process is running, nor is one that changed while it was read
/// (`between` runs after the read, for the tests); both are refused. With `uuid` (macOS: the running image's
/// `LC_UUID`), a Mach-O file that carries UUIDs must carry that one: a path now naming another build is not the
/// program that runs. A file without one keeps the path hash (shortcut: a stripped or non-Mach-O image is trusted
/// by path and content alone).
fn hash_file(
    file: std::fs::File,
    started: Option<SystemTime>,
    uuid: Option<[u8; 16]>,
    between: &dyn Fn(),
) -> Result<String, String> {
    let unreadable = |_| "the invoker's file cannot be read".to_owned();
    let md = file.metadata().map_err(unreadable)?;
    let started = started.ok_or("the invoker's start time is unknown")?;
    if changed(&md).is_none_or(|t| t > started + TICK) {
        return Err("the invoker's file changed after it started".into());
    }
    let bytes = read_capped(&file, MAX_HASH_BYTES).map_err(unreadable)?;
    between();
    if !same_stat(&md, &file.metadata().map_err(unreadable)?) {
        return Err("the invoker's file changed while it was read".into());
    }
    if let Some(uuid) = uuid {
        let found = macho_uuids(&bytes);
        if !found.is_empty() && !found.contains(&uuid) {
            return Err("the invoker's file is not the program it runs".into());
        }
    }
    Ok(hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 (hex) of a file the user names (`dybw policy allow`): the start-time rule is for a running process.
pub fn hash_of(path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|_| "the file cannot be read".to_owned())?;
    Ok(hex(&read_capped(&file, MAX_HASH_BYTES).map_err(|_| "the file cannot be read".to_owned())?))
}

/// `LC_UUID`: the load command that carries a Mach-O image's UUID.
const LC_UUID: u32 = 0x1b;

/// The `LC_UUID`s of a Mach-O file, one per slice of a universal file; empty when it is not Mach-O or has none.
fn macho_uuids(bytes: &[u8]) -> Vec<[u8; 16]> {
    let be32 = |at: usize| Some(u32::from_be_bytes(*bytes.get(at..)?.first_chunk::<4>()?));
    let be64 = |at: usize| Some(u64::from_be_bytes(*bytes.get(at..)?.first_chunk::<8>()?));
    let wide = match be32(0) {
        Some(0xcafe_babe) => false,
        Some(0xcafe_babf) => true,
        _ => return thin_uuid(bytes).into_iter().collect(),
    };
    let slices = be32(4).unwrap_or_default().min(64) as usize;
    (0..slices)
        .filter_map(|i| {
            let at = 8 + i * if wide { 32 } else { 20 };
            let offset = if wide { be64(at + 8)? } else { u64::from(be32(at + 8)?) };
            thin_uuid(bytes.get(usize::try_from(offset).ok()?..)?)
        })
        .collect()
}

/// The `LC_UUID` of a thin (64- or 32-bit, little-endian) Mach-O image.
fn thin_uuid(bytes: &[u8]) -> Option<[u8; 16]> {
    let le32 = |at: usize| Some(u32::from_le_bytes(*bytes.get(at..)?.first_chunk::<4>()?));
    let mut at = match le32(0)? {
        0xfeed_facf => 32,
        0xfeed_face => 28,
        _ => return None,
    };
    for _ in 0..le32(16)?.min(4096) {
        let (cmd, size) = (le32(at)?, le32(at + 4)? as usize);
        if cmd == LC_UUID {
            return bytes.get(at + 8..)?.first_chunk::<16>().copied();
        }
        if size < 8 {
            return None;
        }
        at = at.checked_add(size)?;
    }
    None
}

#[cfg(test)]
mod tests;
