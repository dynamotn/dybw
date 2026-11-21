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

use crate::caller::{Caller, Scope};

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
    /// One value or the field names.
    Value,
    /// Every value at once (`--full`, `--raw`) or the password history: never covered by a grant.
    Whole,
    /// A change of the vault (`add`, `edit`, `remove`): asked every time, never offered "always".
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Ask the user; "always" is offered unless `remember` is [`Scope::Never`], and stores a grant of that scope.
    Confirm {
        remember: Scope,
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
    /// A request that failed before any decision (no such item, ambiguous, locked, no profile).
    /// Also a policy change or a vault write the user approved that could not be done, and a reprompt that could
    /// not be checked.
    Failed,
    /// A names-only request (`list`, `search`) answered.
    Listed,
    /// The master password asked again for an item that needs it (ADR 0025) was right.
    Reprompted,
}

/// One decision on a value or a policy change, with no value in it.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub time: SystemTime,
    pub profile: String,
    pub caller: Caller,
    /// `get`, `history`, `policy-allow`, ...
    pub op: &'static str,
    /// For `get`: what was selected (`password`, `field`, `full`, `raw`, `list-fields`); never a field name.
    pub kind: Option<&'static str>,
    /// The cipher id, for a value request.
    pub item: Option<String>,
    pub verdict: Verdict,
    /// For an SSH signature (`ssh-sign`): the key and where the connection goes.
    pub ssh: Option<SignAudit>,
    /// Where the user answered a confirmation: `touch-id` or `pinentry`; `None` when nobody was asked.
    pub channel: Option<&'static str>,
}

/// What an SSH signature's audit line adds: never the data signed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignAudit {
    /// The key's `SHA256:` fingerprint.
    pub key: String,
    /// The fingerprint of the host key the connection was bound to with `session-bind@openssh.com`, if any.
    pub dest: Option<String>,
    /// Some hop of the connection was forwarded (`ssh -A`).
    pub forwarded: bool,
    /// The SSH client's programs, whatever its class (an AI-class or unknown caller names none of its own).
    pub client: crate::caller::Programs,
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

/// What the policy says about `caller` asking for `access`, given the profile's entries and the per-process grants
/// the profile holds in memory (`held`).
///
/// An AI-class caller is denied every value and every write; an unknown caller every write, and is asked every time
/// for a value. A write is asked every time ([`Access::Write`]), whatever is granted. For a named invoker, a deny
/// entry for its executable (with no script: any script; with one: that script) wins over everything. Then a grant
/// allows it: for a plain executable an `allow` entry with no script, the hash of the program as it is now and the
/// same `detached` state; for an interpreter's script a grant held for this very process (entries with a script are
/// ignored: argv can claim any script). A grant never covers [`Access::Whole`]. Otherwise it is asked, with
/// "always" offered only when [`Caller::rememberable`].
pub fn decide(caller: &Caller, entries: &[PolicyEntry], held: &[Caller], access: Access) -> Decision {
    let never = Decision::Confirm { remember: Scope::Never };
    if access == Access::Names {
        return Decision::Allow;
    }
    let Caller::Invoker { at, .. } = caller else {
        return if matches!(caller, Caller::Ai { .. }) || access == Access::Write { Decision::Deny } else { never };
    };
    // A path that is not text cannot be told apart from another once written: never matched, never kept.
    let Some((exe, script, hash)) = text_of(caller) else { return never };
    let denied = |e: &&PolicyEntry| e.rule == PolicyRule::Deny && e.exe == exe;
    if entries.iter().filter(denied).any(|e| e.script.is_none() || e.script.as_deref() == script) {
        return Decision::Deny;
    }
    if matches!(access, Access::Whole | Access::Write) {
        return never;
    }
    let granted = match caller.scope() {
        Scope::Device => entries.iter().any(|e| {
            e.rule == PolicyRule::Allow
                && e.exe == exe
                && e.script.is_none()
                && e.hash == hash
                && e.detached == at.detached
        }),
        Scope::Process => held.contains(caller),
        Scope::Never => false,
    };
    match (granted, caller.rememberable()) {
        (true, _) => Decision::Allow,
        (false, true) => Decision::Confirm { remember: caller.scope() },
        (false, false) => never,
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

/// The entry a user's "always" stores for `caller`; `None` unless its grants are kept on the device and "always"
/// may be offered (so never a detached one).
pub fn grant_for(caller: &Caller) -> Option<PolicyEntry> {
    let (exe, _, hash) = text_of(caller).filter(|_| caller.rememberable() && caller.scope() == Scope::Device)?;
    Some(PolicyEntry { exe: exe.into(), script: None, hash: hash.into(), rule: PolicyRule::Allow, detached: false })
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

/// What a question says of a detached caller.
pub const DETACHED: &str = "a detached caller (parent exited) — possibly an AI agent";

/// Who is asking, on one line and cut, for a question or a log line. A script is only what the process claims.
pub fn who(caller: &Caller) -> String {
    let cut = |p: &Path| shown(&p.to_string_lossy(), SHOWN);
    let detached = if caller.detached() { format!(", {DETACHED}") } else { String::new() };
    match caller {
        Caller::Invoker { exe, script: Some(script), .. } => {
            format!("{} which claims to run {}{detached}", cut(exe), cut(script))
        }
        Caller::Invoker { exe, script: None, .. } => format!("{}{detached}", cut(exe)),
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

pub(crate) fn untrusted<T>(why: &str) -> std::io::Result<T> {
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

    /// The entries, or why the file cannot be trusted; a missing file is `NotFound`.
    pub fn read(&self) -> std::io::Result<Vec<PolicyEntry>> {
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

    /// Set the rule of `entry`'s executable and script, replacing what was there: a deny replaces every entry of
    /// them, an allow the allow of the same `detached` state and any deny.
    pub fn set(&self, entry: PolicyEntry) -> std::io::Result<()> {
        let mut entries = self.load_for_write()?;
        let replaced = |e: &PolicyEntry| {
            let deny = e.rule == PolicyRule::Deny || entry.rule == PolicyRule::Deny;
            e.exe == entry.exe && e.script == entry.script && (deny || e.detached == entry.detached)
        };
        entries.retain(|e| !replaced(e));
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
