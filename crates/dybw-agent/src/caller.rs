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

/// Most ancestors looked at before the walk gives up (`Unknown`).
const MAX_DEPTH: usize = 64;
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
    /// Cannot be named: orphan, replaced, unreadable. Asked every time, never remembered.
    Unknown { why: String },
    /// A named invoker; `hash` is the SHA-256 (hex) of the script if any, else of the executable. `relative`: the
    /// script was given as a relative path, resolved against the cwd at resolve time (a script that `cd`s could
    /// stand for another file), so it is shown but never remembered.
    Invoker { exe: PathBuf, script: Option<PathBuf>, hash: String, relative: bool },
}

impl Caller {
    /// May a grant for this caller be remembered? Not for an unknown or AI caller, a relative script, or a bare
    /// interpreter (every script it runs would share the grant).
    pub fn rememberable(&self) -> bool {
        match self {
            Caller::Invoker { exe, script, relative, .. } => {
                !relative && (script.is_some() || flag_letters(exe).is_none())
            }
            Caller::Ai { .. } | Caller::Unknown { .. } => false,
        }
    }
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
        let text = match std::fs::File::open(file).and_then(|f| read_capped(f, 64 << 10)) {
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
}

/// A caller together with what it was resolved from, so the answer can be re-checked before a reply is written.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub caller: Caller,
    peer: Peer,
    chain: Vec<Seen>,
}

impl Resolved {
    /// Test only: a caller taken as given, held to `peer` alone.
    #[cfg(test)]
    pub(crate) fn fixed(caller: Caller, peer: Peer) -> Self {
        Self { caller, peer, chain: Vec::new() }
    }

    fn unknown(peer: Peer, why: &str) -> Self {
        Self { caller: Caller::Unknown { why: why.into() }, peer, chain: Vec::new() }
    }
}

/// What this process would be taken for, with the real process table and the device's harness table (`dybw
/// doctor`); `None` when it cannot be told.
pub fn this_process(harnesses: &Path) -> Option<Caller> {
    Resolver::new(Arc::new(dybw_peer::Os), Harnesses::load(harnesses)).caller_of_self()
}

pub struct Resolver {
    source: Arc<dyn ProcessSource>,
    harnesses: Harnesses,
}

impl Resolver {
    pub fn new(source: Arc<dyn ProcessSource>, harnesses: Harnesses) -> Self {
        Self { source, harnesses }
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

    /// Resolve the peer on this thread.
    pub fn resolve(&self, peer: Peer) -> Resolved {
        let (caller, chain) = self.classify(&peer);
        Resolved { caller, peer, chain }
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

    fn classify(&self, peer: &Peer) -> (Caller, Vec<Seen>) {
        let unknown = |why: &str| (Caller::Unknown { why: why.into() }, Vec::new());
        if !self.source.still_same(peer) {
            return unknown("the peer is gone or was replaced");
        }
        // Ancestors from the peer up to pid 1. Any error is remembered, but an AI match found on the way still wins.
        let mut chain: Vec<Process> = Vec::new();
        let mut pids: Vec<u32> = Vec::new();
        let mut complete = false;
        let mut pid = peer.pid;
        let mut seen_pids = HashSet::new();
        while chain.len() < MAX_DEPTH && seen_pids.insert(pid) {
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
            .map(|(&pid, p)| Seen { pid, ppid: p.ppid, start: p.start, image: p.image.clone() })
            .collect();
        let invoker = invoker_index(&chain);
        if let Some(ai) = self.ai(&chain, invoker.map(|(_, p)| p)) {
            return (ai, seen);
        }
        if !complete {
            return (Caller::Unknown { why: "the ancestry could not be read to the top".into() }, seen);
        }
        if !chain.first().is_some_and(is_cli) {
            return (Caller::Unknown { why: "the peer is not dybw".into() }, seen);
        }
        let Some((index, process)) = invoker else {
            return (Caller::Unknown { why: "no process above dybw (orphan)".into() }, seen);
        };
        if chain.iter().any(|p| named(p, &ELEVATORS)) {
            return (Caller::Unknown { why: "run through a privilege wrapper".into() }, seen);
        }
        if named(process, &SUBREAPERS) || base(process).starts_with("containerd-shim") {
            return (Caller::Unknown { why: "the invoker adopts orphans: a detached caller".into() }, seen);
        }
        match identify(process) {
            Ok(caller) => (caller, seen.into_iter().take(index + 1).collect()),
            Err(why) => (Caller::Unknown { why }, seen),
        }
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

fn identify(p: &Process) -> Result<Caller, String> {
    let found = match flag_letters(&p.exe) {
        Some(letters) => script_of(p, letters)?,
        None => None,
    };
    let relative = found.as_ref().is_some_and(|(_, relative)| *relative);
    let script = found.map(|(path, _)| path);
    let hash = hash_file(script.as_deref().unwrap_or(&p.exe), p.started)?;
    Ok(Caller::Invoker { exe: p.exe.clone(), script, hash, relative })
}

fn read_capped(file: std::fs::File, cap: u64) -> std::io::Result<Vec<u8>> {
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

/// SHA-256 (hex) of the file, opened once: what is hashed is what was `fstat`ed. A file written or changed after the
/// process started is not what the process is running, so it is refused.
fn hash_file(path: &Path, started: Option<SystemTime>) -> Result<String, String> {
    let unreadable = |_| "the invoker's file cannot be read".to_owned();
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let md = file.metadata().map_err(unreadable)?;
    let started = started.ok_or("the invoker's start time is unknown")?;
    if changed(&md).is_none_or(|t| t > started + TICK) {
        return Err("the invoker's file changed after it started".into());
    }
    sha256_hex(file)
}

/// SHA-256 (hex) of a file the user names (`dybw policy allow`): the start-time rule is for a running process.
pub fn hash_of(path: &Path) -> Result<String, String> {
    sha256_hex(std::fs::File::open(path).map_err(|_| "the file cannot be read".to_owned())?)
}

fn sha256_hex(file: std::fs::File) -> Result<String, String> {
    let bytes = read_capped(file, MAX_HASH_BYTES).map_err(|_| "the invoker's file cannot be read".to_owned())?;
    Ok(Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests;
