#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use super::*;
use crate::caller::{At, Via};

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn event(caller: Caller, verdict: Verdict) -> AuditEvent {
    AuditEvent {
        time: UNIX_EPOCH + Duration::from_secs(1_794_528_000),
        profile: "work".into(),
        caller,
        op: "get",
        kind: Some("field"),
        item: Some("5f0c-id".into()),
        verdict,
    }
}

fn tool() -> Caller {
    Caller::Invoker {
        exe: "/usr/bin/tool".into(),
        script: Some("/opt/a.sh".into()),
        hash: "secret-hash".into(),
        relative: false,
        at: At::default(),
    }
}

fn log_in(dir: &Path) -> FileAudit {
    FileAudit::new(&dir.join("state/dybw/audit.log"), me())
}

#[test]
fn times_are_rfc_3339_utc() {
    let at = |s| rfc3339(UNIX_EPOCH + Duration::from_secs(s));
    assert_eq!(at(0), "1970-01-01T00:00:00Z");
    assert_eq!(at(951_782_400 + 86_399), "2000-02-29T23:59:59Z");
    assert_eq!(at(1_794_528_000), "2026-11-13T00:00:00Z");
    assert_eq!(rfc3339(UNIX_EPOCH - Duration::from_secs(5)), "1970-01-01T00:00:00Z");
}

#[test]
fn a_decision_is_one_json_line_without_a_value_or_a_name() {
    let dir = tempfile::tempdir().unwrap();
    let audit = log_in(dir.path());
    audit.record(event(tool(), Verdict::Remembered));
    audit.record(event(Caller::Ai { harness: "claude".into(), via: Via::Ancestry }, Verdict::Denied));
    let peer = Some("/tmp/x/dybw".into());
    audit.record(event(Caller::Unknown { why: "no process above dybw (orphan)".into(), peer }, Verdict::Declined));
    for verdict in [Verdict::Granted, Verdict::Confirmed, Verdict::Failed, Verdict::Listed] {
        audit.record(event(tool(), verdict));
    }
    let path = dir.path().join("state/dybw/audit.log");
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 7);
    assert!(!text.contains("secret-hash"), "no hash: {text}");
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    let log = read(&path, me()).unwrap();
    assert_eq!(log.skipped, 0);
    let verdicts: Vec<_> = log.entries.iter().map(|e| e.verdict.as_str()).collect();
    assert_eq!(verdicts, ["remembered", "denied", "declined", "granted", "confirmed", "failed", "listed"]);
    assert_eq!(
        log.entries[0],
        Entry {
            time: "2026-11-13T00:00:00Z".into(),
            profile: "work".into(),
            class: "invoker".into(),
            exe: Some("/usr/bin/tool".into()),
            script: Some("/opt/a.sh".into()),
            harness: None,
            op: "get".into(),
            kind: Some("field".into()),
            item: Some("5f0c-id".into()),
            verdict: "remembered".into(),
            why: None,
            peer: None,
        }
    );
    assert_eq!((log.entries[1].class.as_str(), log.entries[1].harness.as_deref()), ("ai", Some("claude")));
    assert_eq!((log.entries[2].class.as_str(), log.entries[2].exe.as_deref()), ("unknown", None));
    // An unknown caller's line says why, and which program was on the socket.
    assert_eq!(log.entries[2].why.as_deref(), Some("no process above dybw (orphan)"));
    assert_eq!(log.entries[2].peer.as_deref(), Some("/tmp/x/dybw"));
    // So does a named one's when its `dybw` is not the agent's companion.
    let elsewhere = At { peer: Some("/opt/other/dybw".into()), ..At::default() };
    let Caller::Invoker { exe, script, hash, relative, .. } = tool() else { unreachable!() };
    audit.record(event(Caller::Invoker { exe, script, hash, relative, at: elsewhere }, Verdict::Granted));
    let log = read(&path, me()).unwrap();
    assert_eq!(log.entries.last().unwrap().peer.as_deref(), Some("/opt/other/dybw"));
    // A line written before these fields existed still reads.
    let old = r#"{"time":"t","profile":"p","class":"ai","exe":null,"script":null,"harness":"h","op":"get","kind":null,"item":null,"verdict":"denied"}"#;
    assert!(serde_json::from_str::<Entry>(old).unwrap().why.is_none());
}

#[test]
fn strings_that_are_not_ours_are_cleaned_and_cut() {
    let dir = tempfile::tempdir().unwrap();
    let audit = log_in(dir.path());
    let forged = Caller::Invoker {
        exe: "/x\n{\"verdict\":\"granted\"}".into(),
        script: None,
        hash: "h".into(),
        relative: false,
        at: At::default(),
    };
    let mut e = event(forged, Verdict::Denied);
    e.item = Some("i".repeat(500));
    audit.record(e);
    let text = std::fs::read_to_string(dir.path().join("state/dybw/audit.log")).unwrap();
    assert_eq!(text.lines().count(), 1, "one line per decision: {text}");
    let log = read(&dir.path().join("state/dybw/audit.log"), me()).unwrap();
    assert_eq!(log.entries[0].item.as_ref().unwrap().chars().count(), 200);
    assert!(!log.entries[0].exe.as_ref().unwrap().contains('\n'));
}

#[test]
fn a_full_log_moves_to_one_older_generation() {
    let dir = tempfile::tempdir().unwrap();
    let audit = log_in(dir.path());
    audit.record(event(tool(), Verdict::Granted));
    let path = dir.path().join("state/dybw/audit.log");
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().set_len(ROTATE_AT).unwrap();
    audit.record(event(tool(), Verdict::Confirmed));
    assert_eq!(std::fs::metadata(dir.path().join("state/dybw/audit.log.1")).unwrap().len(), ROTATE_AT);
    let log = read(&path, me()).unwrap();
    assert_eq!(log.entries.len(), 1);
    assert_eq!(log.entries[0].verdict, "confirmed");
    // A second rotation replaces the first generation instead of adding one.
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().set_len(ROTATE_AT).unwrap();
    audit.record(event(tool(), Verdict::Granted));
    let names: Vec<_> = std::fs::read_dir(path.parent().unwrap()).unwrap().map(|f| f.unwrap().file_name()).collect();
    assert_eq!(names.len(), 2, "{names:?}");
}

#[test]
fn a_log_that_cannot_be_trusted_is_not_written_or_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let audit = FileAudit::new(&path, me());
    let assert_untouched = |size: u64| assert_eq!(std::fs::metadata(&path).map_or(0, |m| m.len()), size);

    // Open to others.
    std::fs::write(&path, "").unwrap();
    std::fs::set_permissions(&path, PermissionsExt::from_mode(0o644)).unwrap();
    audit.record(event(tool(), Verdict::Granted));
    assert_untouched(0);
    assert!(read(&path, me()).unwrap_err().to_string().contains("chmod 600"));
    // Another owner.
    std::fs::set_permissions(&path, PermissionsExt::from_mode(0o600)).unwrap();
    assert!(read(&path, me().wrapping_add(1)).unwrap_err().to_string().contains("another user"));
    // A symlink, even to a good file.
    let link = dir.path().join("link.log");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    FileAudit::new(&link, me()).record(event(tool(), Verdict::Granted));
    assert_untouched(0);
    assert!(read(&link, me()).is_err());
    // A directory, and a missing file.
    std::fs::create_dir(dir.path().join("d")).unwrap();
    assert!(read(&dir.path().join("d"), me()).is_err());
    assert_eq!(read(&dir.path().join("none"), me()).unwrap_err().kind(), std::io::ErrorKind::NotFound);
    // A FIFO is not waited on.
    let fifo = dir.path().join("fifo");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    assert!(read(&fifo, me()).is_err());
    FileAudit::new(&fifo, me()).record(event(tool(), Verdict::Granted));
}

#[test]
fn a_directory_that_cannot_be_made_loses_the_line_but_never_panics() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file"), "").unwrap();
    FileAudit::new(&dir.path().join("file/dybw/audit.log"), me()).record(event(tool(), Verdict::Granted));
}

#[test]
fn a_poisoned_lock_does_not_stop_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let audit = std::sync::Arc::new(log_in(dir.path()));
    let twin = audit.clone();
    let _ = std::thread::spawn(move || {
        let _held = twin.lock.lock().unwrap();
        panic!("poison");
    })
    .join();
    audit.record(event(tool(), Verdict::Granted));
    assert_eq!(read(&dir.path().join("state/dybw/audit.log"), me()).unwrap().entries.len(), 1);
}

#[test]
fn edited_lines_are_counted_and_an_oversized_log_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let good = serde_json::to_string(&entry_of(&event(tool(), Verdict::Granted))).unwrap();
    std::fs::write(&path, format!("{good}\nnot json\n\n{{\"time\":1}}\n{good}\n")).unwrap();
    std::fs::set_permissions(&path, PermissionsExt::from_mode(0o600)).unwrap();
    let log = read(&path, me()).unwrap();
    assert_eq!((log.entries.len(), log.skipped), (2, 2));
    std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(MAX_READ + 1).unwrap();
    assert!(read(&path, me()).unwrap_err().to_string().contains("too large"));
}

#[test]
fn a_failed_rotation_keeps_appending_to_the_live_log() {
    let dir = tempfile::tempdir().unwrap();
    let audit = log_in(dir.path());
    audit.record(event(tool(), Verdict::Granted));
    let path = dir.path().join("state/dybw/audit.log");
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().set_len(ROTATE_AT).unwrap();
    // A directory where the older generation goes: the rename fails.
    std::fs::create_dir(dir.path().join("state/dybw/audit.log.1")).unwrap();
    audit.record(event(tool(), Verdict::Confirmed));
    audit.record(event(tool(), Verdict::Denied));
    // The padding that made the file "full" glues itself to the first new line; the later one is whole.
    let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
    assert!(text.contains("\"verdict\":\"confirmed\"") && text.contains("\"verdict\":\"denied\""));
    assert_eq!(read(&path, me()).unwrap().entries.len(), 2);
    assert!(std::fs::metadata(&path).unwrap().len() > ROTATE_AT, "nothing was truncated");
}
