//! Who is asking (ADR 0012, ADR 0025): the socket peer is `dybw`; the caller is the invoker above it, an AI harness
//! anywhere above it, or nobody we can name. Everything the kernel will not tell us is `Unknown`, never "clean".

use std::collections::HashSet;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dybw_peer::{Peer, Process, ProcessSource};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Most ancestors looked at before the walk gives up (`Unknown`).
const MAX_DEPTH: usize = 64;
/// Largest script or executable hashed; a bigger one is `Unknown`.
const MAX_HASH_BYTES: u64 = 64 << 20;
/// The CLI (and the `rbw` stand-in): a `dybw` run by one of these is looked through.
const CLI_NAMES: [&str; 2] = ["dybw", "rbw"];
const INTERPRETERS: [&str; 4] = ["node", "perl", "ruby", "osascript"];
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
    /// A named invoker; `hash` is the SHA-256 (hex) of the script if any, else of the executable.
    Invoker { exe: PathBuf, script: Option<PathBuf>, hash: String },
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
            Harness::new("claude", &["claude"], &[], &[], &[]),
            Harness::new("codex", &["codex"], &[], &["@openai/codex"], &[]),
            Harness::new("gemini", &[], &[], &["@google/gemini-cli"], &[]),
            Harness::new("antigravity", &["agy", "antigravity"], &[], &[], &[]),
            Harness::new("copilot", &["copilot"], &[], &["@github/copilot"], &[]),
            Harness::new("cursor", &[], &["cursor-agent/versions/"], &[], &["cursor-agent"]),
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
        let text = match read_capped(file, 64 << 10) {
            Ok(bytes) => String::from_utf8(bytes).ok(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return table,
            Err(_) => None,
        };
        match text.and_then(|t| toml::from_str::<HarnessFile>(&t).ok()) {
            Some(extra) => table.0.extend(extra.harness.into_iter().filter(|h| !h.name.is_empty())),
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

pub struct Resolver {
    source: Arc<dyn ProcessSource>,
    harnesses: Harnesses,
}

impl Resolver {
    pub fn new(source: Arc<dyn ProcessSource>, harnesses: Harnesses) -> Self {
        Self { source, harnesses }
    }

    /// Resolve the peer. Call it as soon as the connection is accepted.
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
        let Some((index, process)) = invoker else {
            return (Caller::Unknown { why: "no process above dybw (orphan)".into() }, seen);
        };
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
    let is_cli = |p: &Process| p.exe.file_name().is_some_and(|n| CLI_NAMES.iter().any(|c| n == *c));
    chain.iter().enumerate().skip(1).find(|(_, p)| !is_cli(p))
}

/// The option letters that mean "the program is given inline" for this interpreter, `None` if it is not one.
/// (`-e` is errexit for a shell, so only `-c` counts there.)
fn inline_letters(exe: &Path) -> Option<&'static [char]> {
    let name = exe.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    if ["sh", "bash", "zsh", "fish", "dash"].contains(&name.as_str()) {
        Some(&['c'])
    } else if INTERPRETERS.contains(&name.as_str()) || name.starts_with("python") {
        Some(&['c', 'e', 'E', 'm', 'p'])
    } else {
        None
    }
}

/// An option that gives the program inline (`-c`, `-e`, `-lc`, `--eval`) or as a module (`-m`).
fn is_inline(arg: &str, letters: &[char]) -> bool {
    match arg.strip_prefix('-') {
        Some(rest) if !rest.starts_with('-') => {
            rest.len() <= 3 && rest.chars().all(char::is_alphabetic) && rest.contains(letters)
        }
        _ => ["--eval", "--print", "--command"].contains(&arg),
    }
}

/// The script an interpreter runs: the first non-option argument that is an existing file (canonical). `Ok(None)`:
/// no script (an interactive shell); `Err`: cannot be named (inline code, a relative path we cannot resolve since
/// the working directory is not known, argv hidden).
fn script_of(p: &Process, letters: &[char]) -> Result<Option<PathBuf>, String> {
    let argv = p.argv.as_deref().ok_or("the interpreter's arguments are not visible")?;
    let mut after_dashes = false;
    for arg in argv.iter().skip(1) {
        let arg = arg.to_string_lossy();
        if !after_dashes && arg == "--" {
            after_dashes = true;
        } else if !after_dashes && is_inline(&arg, letters) {
            return Err("the interpreter runs inline code or a module".into());
        } else if after_dashes || !arg.starts_with('-') {
            if !Path::new(&*arg).is_absolute() {
                return Err("the script path is relative and its directory is unknown".into());
            }
            if let Ok(path) = std::fs::canonicalize(&*arg)
                && path.is_file()
            {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
}

fn identify(p: &Process) -> Result<Caller, String> {
    let script = match inline_letters(&p.exe) {
        Some(letters) => script_of(p, letters)?,
        None => None,
    };
    let hash = hash_file(script.as_deref().unwrap_or(&p.exe))?;
    Ok(Caller::Invoker { exe: p.exe.clone(), script, hash })
}

fn read_capped(path: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(std::io::Error::other("file too large"));
    }
    Ok(bytes)
}

fn hash_file(path: &Path) -> Result<String, String> {
    let bytes = read_capped(path, MAX_HASH_BYTES).map_err(|_| "the invoker's file cannot be read".to_owned())?;
    Ok(Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests;
