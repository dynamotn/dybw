//! The audit log (ADR 0012): one JSON line per value request (`get`, `history`, `code`), write (`add`, `edit`,
//! `remove`) or policy change, in
//! `$XDG_STATE_HOME/dybw/audit.log`. A line names the profile, the caller (program and script, or the harness), the
//! op, what `get` selected, the item's id and the verdict. Never a value, never an item or field name.
//!
//! The file is 0600, opened append-only without following a symlink, and trusted only like `policy.json`: a regular
//! file of this user that others cannot read. It is rotated once to `audit.log.1` at 10 MiB, so it stays bounded.
//! A line that cannot be written is logged and dropped: the reply is never held back for the log (availability
//! over completeness; `dybw doctor` shows a log that cannot be written or read).

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::caller::Caller;
use crate::policy::{Audit, AuditEvent, Verdict, shown, untrusted};

/// Size at which the log moves to `audit.log.1`.
pub const ROTATE_AT: u64 = 10 << 20;
/// Largest log read: the rotation size and a generous last line.
const MAX_READ: u64 = ROTATE_AT + (1 << 20);

/// One line of the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// RFC 3339, UTC.
    pub time: String,
    pub profile: String,
    /// `ai`, `unknown` or `invoker`.
    pub class: String,
    pub exe: Option<String>,
    pub script: Option<String>,
    pub harness: Option<String>,
    pub op: String,
    pub kind: Option<String>,
    pub item: Option<String>,
    pub verdict: String,
    /// Why an unknown caller could not be named (a fixed text of the agent's).
    #[serde(default)]
    pub why: Option<String>,
    /// The peer's executable, for an unknown caller and for a `dybw` that is not the agent's companion.
    #[serde(default)]
    pub peer: Option<String>,
}

fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Granted => "granted",
        Verdict::Confirmed => "confirmed",
        Verdict::Remembered => "remembered",
        Verdict::Declined => "declined",
        Verdict::Denied => "denied",
        Verdict::Failed => "failed",
        Verdict::Listed => "listed",
        Verdict::Reprompted => "reprompted",
    }
}

/// The line for `event`: every string cleaned and cut, since a path, a harness name or an id is not ours to trust.
fn entry_of(event: &AuditEvent) -> Entry {
    let text = |s: &str| shown(s, 200);
    let path = |p: &Path| text(&p.to_string_lossy());
    let (class, exe, script, harness, why, peer) = match &event.caller {
        Caller::Ai { harness, .. } => ("ai", None, None, Some(text(harness)), None, None),
        Caller::Unknown { why, peer } => ("unknown", None, None, None, Some(text(why)), peer.as_deref().map(path)),
        Caller::Invoker { exe, script, at, .. } => {
            ("invoker", Some(path(exe)), script.as_deref().map(path), None, None, at.peer.as_deref().map(path))
        }
    };
    Entry {
        time: rfc3339(event.time),
        profile: text(&event.profile),
        class: class.to_owned(),
        exe,
        script,
        harness,
        op: event.op.to_owned(),
        kind: event.kind.map(str::to_owned),
        item: event.item.as_deref().map(text),
        verdict: verdict_name(event.verdict).to_owned(),
        why,
        peer,
    }
}

/// `t` as `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days, no calendar crate); a time before 1970 reads as the epoch.
fn rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rest) = (i64::try_from(secs / 86_400).unwrap_or(0), secs % 86_400);
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rest / 3_600, rest % 3_600 / 60, rest % 60)
}

/// `path` opened for appending (created 0600) or reading, never through a symlink, never waiting on a FIFO, and
/// only when it is a regular file of `uid` that others cannot touch.
fn open_checked(path: &Path, uid: u32, append: bool) -> std::io::Result<File> {
    let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32;
    let mut options = OpenOptions::new();
    if append {
        options.append(true).create(true).mode(0o600);
    } else {
        options.read(true);
    }
    let file = options.custom_flags(flags).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return untrusted("it is not a regular file");
    }
    if meta.uid() != uid {
        return untrusted("it is owned by another user");
    }
    if meta.mode() & 0o077 != 0 {
        return untrusted("it must not be accessible to others (chmod 600)");
    }
    Ok(file)
}

/// The writer the agent records into.
pub struct FileAudit {
    path: PathBuf,
    uid: u32,
    /// One writer at a time, so a rotation never races an append.
    lock: Mutex<()>,
}

impl FileAudit {
    pub fn new(path: &Path, uid: u32) -> Self {
        Self { path: path.to_owned(), uid, lock: Mutex::new(()) }
    }

    fn append(&self, entry: &Entry) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(entry).map_err(std::io::Error::other)?;
        line.push(b'\n');
        DirBuilder::new().recursive(true).mode(0o700).create(self.path.parent().unwrap_or(Path::new(".")))?;
        let mut file = open_checked(&self.path, self.uid, true)?;
        if file.metadata()?.len() >= ROTATE_AT {
            let mut older = self.path.clone().into_os_string();
            older.push(".1");
            // A failed rotation must not stop the log: keep appending to the live file (it just grows).
            match std::fs::rename(&self.path, older) {
                Ok(()) => file = open_checked(&self.path, self.uid, true)?,
                Err(e) => tracing::warn!(file = %self.path.display(), "the audit log was not rotated: {e}"),
            }
        }
        file.write_all(&line)
    }
}

impl Audit for FileAudit {
    /// A small append on the caller's thread: the worker is waiting on a person anyway at this point, and an
    /// async hop would only add a place to lose a line.
    fn record(&self, event: AuditEvent) {
        let _one = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(e) = self.append(&entry_of(&event)) {
            tracing::warn!(file = %self.path.display(), "the audit line was not written: {e}");
        }
    }
}

/// What a read of the log found.
#[derive(Debug, Default)]
pub struct Log {
    pub entries: Vec<Entry>,
    /// Lines that are not an entry (edited, or from a newer version).
    pub skipped: usize,
}

/// The entries of `audit.log` (not of `audit.log.1`), oldest first. A missing file is `NotFound`; one that cannot
/// be trusted, or is too large, is an error.
pub fn read(path: &Path, uid: u32) -> std::io::Result<Log> {
    let file = open_checked(path, uid, false)?;
    let mut bytes = Vec::new();
    file.take(MAX_READ + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_READ {
        return untrusted("it is too large");
    }
    let mut log = Log::default();
    for line in String::from_utf8_lossy(&bytes).lines().filter(|l| !l.is_empty()) {
        match serde_json::from_str(line) {
            Ok(entry) => log.entries.push(entry),
            Err(_) => log.skipped += 1,
        }
    }
    Ok(log)
}

#[cfg(test)]
mod tests;
