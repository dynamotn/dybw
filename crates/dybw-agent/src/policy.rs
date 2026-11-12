//! The caller policy (profiles §4, ADR 0012, ADR 0025): what each class of caller may do, and the device-local file
//! of remembered invokers. The pinentry is the boundary; this decides when it is asked, and never lets an AI-class
//! caller, an unknown one or a changed program ride on an earlier answer.
//!
//! The file is `policy.json` in the profile's state directory (0600, replaced atomically). It is trusted only when
//! it is a regular file owned by the agent's user and not readable by others; anything else, and any text that does
//! not parse, counts as "no entries" (and is logged), never as an allow.

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use dybw_native::prompter::one_line;
use dybw_proto::{PolicyEntry, PolicyRule};
use serde::{Deserialize, Serialize};

use crate::caller::Caller;

const FILE_VERSION: u32 = 1;
/// Largest policy file read; a bigger one is not ours.
const MAX_FILE: u64 = 1 << 20;
/// Longest path shown in a question.
const SHOWN: usize = 120;

/// What a request wants of the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Names, ids, list, search, status: no secret.
    Names,
    /// Any value, any field name, a password history.
    Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Ask the user; "always" may be offered only when `rememberable`.
    Confirm {
        rememberable: bool,
    },
    Deny,
}

/// How a value request ended, for the audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A remembered grant of this very invoker and program.
    Granted,
    /// The user said yes, once.
    Confirmed,
    /// The user said yes and "always": a grant was stored.
    Remembered,
    /// The user said no, or the question timed out or failed.
    Declined,
    /// The policy refused without asking (an AI-class caller, a deny entry, an item that needs a reprompt, a peer
    /// that changed).
    Denied,
    /// A policy change the user approved could not be written.
    Failed,
}

/// One decision on a value or a policy change, with no value in it.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub time: SystemTime,
    pub profile: String,
    pub caller: Caller,
    /// `get`, `history`, `policy-allow`, ...
    pub op: &'static str,
    /// The cipher id, for a value request.
    pub item: Option<String>,
    pub verdict: Verdict,
}

/// Where decisions are recorded.
pub trait Audit: Send + Sync {
    fn record(&self, event: AuditEvent);
}

/// Records nothing.
pub struct NoAudit;

impl Audit for NoAudit {
    fn record(&self, _event: AuditEvent) {}
}

/// What the policy says about `caller` asking for `access`, given the profile's entries.
///
/// An AI-class caller is denied every value. An unknown caller is asked every time. A named invoker is allowed by a
/// remembered grant that matches its executable, its script and the hash of the program as it is now; a deny entry
/// for its executable and script wins over everything; otherwise it is asked, with "always" offered only when the
/// caller can be named stably (see [`Caller::rememberable`]).
pub fn decide(caller: &Caller, entries: &[PolicyEntry], access: Access) -> Decision {
    if access == Access::Names {
        return Decision::Allow;
    }
    match caller {
        Caller::Ai { .. } => Decision::Deny,
        Caller::Unknown { .. } => Decision::Confirm { rememberable: false },
        Caller::Invoker { .. } => {
            // A path that is not text cannot be told apart from another once written: never matched, never kept.
            let Some((exe, script, hash)) = text_of(caller) else { return Decision::Confirm { rememberable: false } };
            let rememberable = caller.rememberable();
            let mine = || entries.iter().filter(|e| e.exe == exe && e.script.as_deref() == script);
            if mine().any(|e| e.rule == PolicyRule::Deny) {
                Decision::Deny
            } else if rememberable && mine().any(|e| e.rule == PolicyRule::Allow && e.hash == hash) {
                Decision::Allow
            } else {
                Decision::Confirm { rememberable }
            }
        }
    }
}

/// Executable, script and hash of an invoker, when its paths are text.
fn text_of(caller: &Caller) -> Option<(&str, Option<&str>, &str)> {
    let Caller::Invoker { exe, script, hash, .. } = caller else { return None };
    let script = match script {
        Some(s) => Some(s.to_str()?),
        None => None,
    };
    Some((exe.to_str()?, script, hash))
}

/// The grant a user's "always" stores for `caller`; `None` when it cannot be remembered.
pub fn grant_for(caller: &Caller) -> Option<PolicyEntry> {
    let (exe, script, hash) = text_of(caller).filter(|_| caller.rememberable())?;
    Some(PolicyEntry { exe: exe.into(), script: script.map(Into::into), hash: hash.into(), rule: PolicyRule::Allow })
}

/// `text` on one line and at most `cap` characters: a longer one keeps its head and its last 40 characters (the
/// file name) around "…", so a long path cannot pass for a shorter one that was granted. Cut first, then cleaned.
pub fn shown(text: &str, cap: usize) -> String {
    let n = text.chars().count();
    if n <= cap {
        return one_line(text);
    }
    let head: String = text.chars().take(cap - 41).collect();
    let tail: String = text.chars().skip(n - 40).collect();
    one_line(&format!("{head}…{tail}"))
}

/// Who is asking, on one line and cut, for a question or a log line.
pub fn who(caller: &Caller) -> String {
    let cut = |p: &Path| shown(&p.to_string_lossy(), SHOWN);
    match caller {
        Caller::Invoker { exe, script: Some(script), .. } => format!("{} running {}", cut(exe), cut(script)),
        Caller::Invoker { exe, script: None, .. } => cut(exe),
        Caller::Ai { harness, .. } => format!("the AI agent {}", one_line(harness)),
        Caller::Unknown { .. } => "detached or unknown caller — possibly an AI agent".to_owned(),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    entries: Vec<PolicyEntry>,
}

fn untrusted<T>(why: &str) -> std::io::Result<T> {
    Err(std::io::Error::other(why.to_owned()))
}

/// A profile's policy file.
pub struct Store {
    path: PathBuf,
    uid: u32,
}

impl Store {
    pub fn new(path: &Path, uid: u32) -> Self {
        Self { path: path.to_owned(), uid }
    }

    /// The entries, or none when there is no file or it cannot be trusted.
    pub fn load(&self) -> Vec<PolicyEntry> {
        match self.read() {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                tracing::warn!(file = %self.path.display(), "ignoring the caller policy: {e}");
                Vec::new()
            }
        }
    }

    fn read(&self) -> std::io::Result<Vec<PolicyEntry>> {
        let link = std::fs::symlink_metadata(&self.path)?;
        // Not opened before it is known to be a plain file: opening a FIFO would wait for ever.
        if !link.is_file() {
            return untrusted("it is not a regular file");
        }
        let file = std::fs::File::open(&self.path)?;
        let meta = file.metadata()?;
        if (meta.dev(), meta.ino()) != (link.dev(), link.ino()) || meta.uid() != self.uid {
            return untrusted("it is not the file it was, or it is owned by another user");
        }
        if meta.mode() & 0o077 != 0 {
            return untrusted("it must not be accessible to others (chmod 600)");
        }
        let mut text = String::new();
        file.take(MAX_FILE + 1).read_to_string(&mut text)?;
        if text.len() as u64 > MAX_FILE {
            return untrusted("it is too large");
        }
        let parsed: File =
            serde_json::from_str(&text).or_else(|e| untrusted(&format!("not valid (line {})", e.line())))?;
        if parsed.version != FILE_VERSION {
            return untrusted("its version is not supported");
        }
        Ok(parsed.entries)
    }

    fn save(&self, entries: Vec<PolicyEntry>) -> std::io::Result<()> {
        let text =
            serde_json::to_vec_pretty(&File { version: FILE_VERSION, entries }).map_err(std::io::Error::other)?;
        dybw_native::fsutil::write_private(&self.path, &text)
    }

    /// The entries to change: none when there is no file; an error when there is one that cannot be trusted, so a
    /// write never replaces (and drops the deny entries of) a file that failed to load.
    fn load_for_write(&self) -> std::io::Result<Vec<PolicyEntry>> {
        match self.read() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            other => other,
        }
    }

    /// Set the rule of `entry`'s executable and script, replacing what was there.
    pub fn set(&self, entry: PolicyEntry) -> std::io::Result<()> {
        let mut entries = self.load_for_write()?;
        entries.retain(|e| !(e.exe == entry.exe && e.script == entry.script));
        entries.push(entry);
        self.save(entries)
    }

    /// Drop every entry whose executable or script is `invoker`; how many were dropped.
    pub fn forget(&self, invoker: &str) -> std::io::Result<usize> {
        let mut entries = self.load_for_write()?;
        let before = entries.len();
        entries.retain(|e| e.exe != invoker && e.script.as_deref() != Some(invoker));
        let dropped = before - entries.len();
        if dropped > 0 {
            self.save(entries)?;
        }
        Ok(dropped)
    }
}

#[cfg(test)]
mod tests;
