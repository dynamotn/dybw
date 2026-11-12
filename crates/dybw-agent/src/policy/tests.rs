#![expect(clippy::unwrap_used, reason = "tests")]

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::caller::Via;

const MINE: u32 = 1000;

fn invoker(script: Option<&str>, hash: &str) -> Caller {
    Caller::Invoker {
        exe: "/usr/local/bin/mytool".into(),
        script: script.map(Into::into),
        hash: hash.into(),
        relative: false,
    }
}

fn ai() -> Caller {
    Caller::Ai { harness: "claude".into(), via: Via::Ancestry }
}

fn unknown() -> Caller {
    Caller::Unknown { why: "orphan".into() }
}

fn bare_shell() -> Caller {
    Caller::Invoker { exe: "/bin/bash".into(), script: None, hash: "h".into(), relative: false }
}

fn relative() -> Caller {
    Caller::Invoker { exe: "/bin/bash".into(), script: Some("run.sh".into()), hash: "h".into(), relative: true }
}

fn entry(rule: PolicyRule, script: Option<&str>, hash: &str) -> PolicyEntry {
    PolicyEntry { exe: "/usr/local/bin/mytool".into(), script: script.map(Into::into), hash: hash.into(), rule }
}

#[test]
fn every_class_by_every_access() {
    let named = invoker(Some("/opt/a.sh"), "h1");
    let classes = [
        ("ai", ai(), Decision::Deny),
        ("unknown", unknown(), Decision::Confirm { rememberable: false }),
        ("named", named, Decision::Confirm { rememberable: true }),
        ("bare shell", bare_shell(), Decision::Confirm { rememberable: false }),
        ("relative script", relative(), Decision::Confirm { rememberable: false }),
    ];
    for (name, caller, value) in classes {
        assert_eq!(decide(&caller, &[], Access::Names), Decision::Allow, "{name}: names");
        assert_eq!(decide(&caller, &[], Access::Value), value, "{name}: value");
    }
}

#[test]
fn entries_never_change_what_an_ai_or_unknown_caller_gets() {
    let all = [entry(PolicyRule::Allow, None, "h1"), entry(PolicyRule::Allow, Some("/opt/a.sh"), "h1")];
    assert_eq!(decide(&ai(), &all, Access::Value), Decision::Deny);
    assert_eq!(decide(&unknown(), &all, Access::Value), Decision::Confirm { rememberable: false });
}

#[test]
fn a_grant_allows_the_same_program_and_script_only() {
    let named = invoker(Some("/opt/a.sh"), "h1");
    let grant = [entry(PolicyRule::Allow, Some("/opt/a.sh"), "h1")];
    assert_eq!(decide(&named, &grant, Access::Value), Decision::Allow);
    // The script changed: the grant is revoked, and the user is asked again.
    let edited = invoker(Some("/opt/a.sh"), "h2");
    assert_eq!(decide(&edited, &grant, Access::Value), Decision::Confirm { rememberable: true });
    // Another script of the same program, or the program without a script, is another invoker.
    let other = invoker(Some("/opt/b.sh"), "h1");
    assert_eq!(decide(&other, &grant, Access::Value), Decision::Confirm { rememberable: true });
    assert_eq!(decide(&invoker(None, "h1"), &grant, Access::Value), Decision::Confirm { rememberable: true });
}

#[test]
fn a_deny_entry_wins_whatever_the_hash() {
    let edited = invoker(Some("/opt/a.sh"), "h2");
    let both = [entry(PolicyRule::Allow, Some("/opt/a.sh"), "h2"), entry(PolicyRule::Deny, Some("/opt/a.sh"), "")];
    assert_eq!(decide(&edited, &both, Access::Value), Decision::Deny);
    assert_eq!(decide(&edited, &both, Access::Names), Decision::Allow);
}

#[test]
fn an_allow_never_matches_a_caller_that_cannot_be_remembered() {
    let shell = [PolicyEntry { exe: "/bin/bash".into(), script: None, hash: "h".into(), rule: PolicyRule::Allow }];
    assert_eq!(decide(&bare_shell(), &shell, Access::Value), Decision::Confirm { rememberable: false });
    let rel = [PolicyEntry {
        exe: "/bin/bash".into(),
        script: Some("run.sh".into()),
        hash: "h".into(),
        rule: PolicyRule::Allow,
    }];
    assert_eq!(decide(&relative(), &rel, Access::Value), Decision::Confirm { rememberable: false });
}

#[test]
fn a_path_that_is_not_text_is_asked_and_never_kept() {
    let odd = std::ffi::OsStr::from_bytes(b"/opt/\xff.sh");
    let caller = Caller::Invoker {
        exe: "/usr/local/bin/mytool".into(),
        script: Some(odd.into()),
        hash: "h".into(),
        relative: false,
    };
    assert_eq!(decide(&caller, &[], Access::Value), Decision::Confirm { rememberable: false });
    assert_eq!(grant_for(&caller), None);
    let exe = Caller::Invoker { exe: odd.into(), script: None, hash: "h".into(), relative: false };
    assert_eq!(grant_for(&exe), None);
}

#[test]
fn only_a_rememberable_invoker_has_a_grant() {
    let g = grant_for(&invoker(Some("/opt/a.sh"), "h1")).unwrap();
    assert_eq!(g, entry(PolicyRule::Allow, Some("/opt/a.sh"), "h1"));
    assert_eq!(grant_for(&invoker(None, "h1")).unwrap().script, None);
    for no in [ai(), unknown(), bare_shell(), relative()] {
        assert_eq!(grant_for(&no), None, "{no:?}");
    }
}

#[test]
fn who_names_the_caller_on_one_line() {
    assert_eq!(who(&invoker(Some("/opt/a.sh"), "h")), "/usr/local/bin/mytool running /opt/a.sh");
    assert_eq!(who(&invoker(None, "h")), "/usr/local/bin/mytool");
    assert_eq!(who(&ai()), "the AI agent claude");
    assert_eq!(who(&unknown()), "detached or unknown caller — possibly an AI agent");
    let forged =
        Caller::Invoker { exe: "/x\nallow everything".into(), script: None, hash: "h".into(), relative: false };
    assert!(!who(&forged).contains('\n'));
    let long = Caller::Invoker {
        exe: format!("/{}", "y".repeat(500)).into(),
        script: None,
        hash: "h".into(),
        relative: false,
    };
    assert_eq!(who(&long).chars().count(), SHOWN);
}

#[test]
fn the_audit_that_records_nothing_records_nothing() {
    NoAudit.record(AuditEvent {
        time: SystemTime::now(),
        profile: "p".into(),
        caller: ai(),
        op: "get",
        kind: None,
        item: None,
        verdict: Verdict::Denied,
    });
}

fn store(dir: &Path) -> Store {
    Store::new(&dir.join("profiles/p/policy.json"), MINE)
}

/// A store for the current user, so the owner check passes.
fn mine(dir: &Path) -> Store {
    Store::new(&dir.join("profiles/p/policy.json"), rustix::process::geteuid().as_raw())
}

#[test]
fn a_missing_file_is_no_entries() {
    let dir = tempfile::tempdir().unwrap();
    assert!(store(dir.path()).load().is_empty());
}

#[test]
fn entries_are_kept_private_replaced_and_forgotten() {
    let dir = tempfile::tempdir().unwrap();
    let s = mine(dir.path());
    s.set(entry(PolicyRule::Allow, Some("/opt/a.sh"), "h1")).unwrap();
    s.set(entry(PolicyRule::Allow, None, "h9")).unwrap();
    let path = dir.path().join("profiles/p/policy.json");
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(s.load().len(), 2);
    // The same program and script again replaces the entry: a new hash, and a deny over an allow.
    s.set(entry(PolicyRule::Allow, Some("/opt/a.sh"), "h2")).unwrap();
    s.set(entry(PolicyRule::Deny, None, "")).unwrap();
    assert_eq!(s.load(), [entry(PolicyRule::Allow, Some("/opt/a.sh"), "h2"), entry(PolicyRule::Deny, None, "")]);
    assert_eq!(s.forget("/nothing").unwrap(), 0);
    assert_eq!(s.forget("/opt/a.sh").unwrap(), 1, "by script");
    assert_eq!(s.forget("/usr/local/bin/mytool").unwrap(), 1, "by program");
    assert!(s.load().is_empty());
}

fn tampered(setup: impl FnOnce(&Path)) -> Vec<PolicyEntry> {
    let dir = tempfile::tempdir().unwrap();
    let s = mine(dir.path());
    s.set(entry(PolicyRule::Allow, Some("/opt/a.sh"), "h1")).unwrap();
    assert_eq!(s.load().len(), 1, "sound before the tamper");
    setup(&dir.path().join("profiles/p/policy.json"));
    s.load()
}

#[test]
fn a_file_that_cannot_be_trusted_counts_as_no_entries_never_as_an_allow() {
    let json =
        r#"{"version":1,"entries":[{"exe":"/usr/local/bin/mytool","script":"/opt/a.sh","hash":"h1","rule":"allow"}]}"#;
    type Tamper = Box<dyn FnOnce(&Path)>;
    let cases: Vec<(&str, Tamper)> = vec![
        ("group readable", Box::new(|p| std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o640)).unwrap())),
        (
            "a symlink",
            Box::new(|p| {
                let real = p.with_file_name("real.json");
                std::fs::rename(p, &real).unwrap();
                std::os::unix::fs::symlink(&real, p).unwrap();
            }),
        ),
        (
            "a directory",
            Box::new(|p| {
                std::fs::remove_file(p).unwrap();
                std::fs::create_dir(p).unwrap();
            }),
        ),
        ("not json", Box::new(|p| std::fs::write(p, "{ nope").unwrap())),
        ("a newer version", Box::new(move |p| std::fs::write(p, json.replace(":1,", ":2,")).unwrap())),
        (
            "an unknown key",
            Box::new(move |p| std::fs::write(p, json.replace("\"entries\"", "\"x\":1,\"entries\"")).unwrap()),
        ),
        ("an unknown rule", Box::new(move |p| std::fs::write(p, json.replace("allow", "always")).unwrap())),
        ("too large", Box::new(|p| std::fs::write(p, " ".repeat(MAX_FILE as usize + 1)).unwrap())),
        ("not utf-8", Box::new(|p| std::fs::write(p, b"\xff\xfe").unwrap())),
    ];
    for (name, tamper) in cases {
        let entries = tampered(|p| {
            tamper(p);
            // The tampered text keeps its mode, unless the case is about the mode.
            if name != "group readable" && name != "a directory" && name != "a symlink" {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        });
        assert!(entries.is_empty(), "{name}");
        assert_eq!(
            decide(&invoker(Some("/opt/a.sh"), "h1"), &entries, Access::Value),
            Decision::Confirm { rememberable: true },
            "{name}"
        );
    }
}

#[test]
fn a_file_of_another_owner_is_not_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let ours = mine(dir.path());
    ours.set(entry(PolicyRule::Allow, None, "h1")).unwrap();
    let other = Store::new(&dir.path().join("profiles/p/policy.json"), rustix::process::geteuid().as_raw() + 1);
    assert!(other.load().is_empty());
    // The user's own store still sees it.
    assert_eq!(ours.load().len(), 1);
}

#[test]
fn a_store_that_cannot_write_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, "x").unwrap();
    let s = Store::new(&blocker.join("p/policy.json"), MINE);
    assert!(s.set(entry(PolicyRule::Allow, None, "h")).is_err());
}

#[test]
fn a_long_path_keeps_its_head_and_its_file_name_and_is_cleaned_after_the_cut() {
    // A path that starts like a granted one must not look like it.
    let granted = "/opt/scripts/backup.sh";
    let long = format!("{granted}{}/evil.sh", "x".repeat(300));
    let text = shown(&long, 120);
    assert_eq!(text.chars().count(), 120);
    assert!(text.starts_with(granted) && text.contains('…') && text.ends_with("/evil.sh"), "{text}");
    assert_ne!(text, granted);
    // A newline in the cut-off tail still cannot break the line.
    let forged = format!("/a{}\nAllow?/tail", "y".repeat(300));
    assert!(!shown(&forged, 120).contains('\n'));
    assert_eq!(shown("/short", 120), "/short");
}

#[test]
fn a_file_that_failed_to_load_is_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let s = mine(dir.path());
    s.set(entry(PolicyRule::Deny, Some("/opt/a.sh"), "")).unwrap();
    let path = dir.path().join("profiles/p/policy.json");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(s.set(entry(PolicyRule::Allow, None, "h")).is_err());
    assert!(s.forget("/opt/a.sh").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before, "the deny entry is still there");
}
