#![expect(clippy::unwrap_used, reason = "tests")]

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::caller::{At, Via};

const MINE: u32 = 1000;
const NEVER: Decision = Decision::Confirm { remember: Scope::Never };

fn at(pid: u32) -> At {
    At { pid, ..At::default() }
}

/// A plain program (its grants are kept on the device), or that program claiming a script (which it cannot run).
fn invoker(script: Option<&str>, hash: &str) -> Caller {
    Caller::Invoker {
        exe: "/usr/local/bin/mytool".into(),
        script: script.map(Into::into),
        hash: hash.into(),
        relative: false,
        at: At::default(),
    }
}

/// `caller` with its parent gone.
fn detached(caller: Caller) -> Caller {
    let Caller::Invoker { exe, script, hash, relative, at } = caller else { unreachable!() };
    Caller::Invoker { exe, script, hash, relative, at: At { detached: true, ..at } }
}

/// bash running /opt/a.sh, as process `pid`.
fn script(pid: u32) -> Caller {
    Caller::Invoker {
        exe: "/bin/bash".into(),
        script: Some("/opt/a.sh".into()),
        hash: "h1".into(),
        relative: false,
        at: at(pid),
    }
}

fn ai() -> Caller {
    Caller::Ai { harness: "claude".into(), via: Via::Ancestry }
}

fn unknown() -> Caller {
    Caller::Unknown { why: "orphan".into(), peer: None }
}

fn bare_shell() -> Caller {
    Caller::Invoker { exe: "/bin/bash".into(), script: None, hash: "h".into(), relative: false, at: At::default() }
}

fn relative() -> Caller {
    Caller::Invoker {
        exe: "/bin/bash".into(),
        script: Some("run.sh".into()),
        hash: "h".into(),
        relative: true,
        at: at(1),
    }
}

fn launcher() -> Caller {
    Caller::Invoker { exe: "/usr/bin/xargs".into(), script: None, hash: "h".into(), relative: false, at: At::default() }
}

fn entry(rule: PolicyRule, script: Option<&str>, hash: &str) -> PolicyEntry {
    PolicyEntry {
        exe: "/usr/local/bin/mytool".into(),
        script: script.map(Into::into),
        hash: hash.into(),
        rule,
        detached: false,
    }
}

#[test]
fn every_class_by_every_access() {
    let device = Decision::Confirm { remember: Scope::Device };
    let process = Decision::Confirm { remember: Scope::Process };
    let classes = [
        ("ai", ai(), Decision::Deny, Decision::Deny),
        ("unknown", unknown(), NEVER, NEVER),
        ("program", invoker(None, "h1"), device, NEVER),
        ("script", script(1), process, NEVER),
        ("detached program", detached(invoker(None, "h1")), NEVER, NEVER),
        ("detached script", detached(script(1)), NEVER, NEVER),
        ("a program that claims a script", invoker(Some("/opt/a.sh"), "h1"), NEVER, NEVER),
        ("bare shell", bare_shell(), NEVER, NEVER),
        ("relative script", relative(), NEVER, NEVER),
        ("launcher", launcher(), NEVER, NEVER),
    ];
    for (name, caller, value, whole) in classes {
        assert_eq!(decide(&caller, &[], &[], Access::Names), Decision::Allow, "{name}: names");
        assert_eq!(decide(&caller, &[], &[], Access::Value), value, "{name}: value");
        assert_eq!(decide(&caller, &[], &[], Access::Whole), whole, "{name}: whole");
    }
}

#[test]
fn entries_and_held_grants_never_change_what_an_ai_or_unknown_caller_gets() {
    let all = [entry(PolicyRule::Allow, None, "h1"), entry(PolicyRule::Allow, Some("/opt/a.sh"), "h1")];
    assert_eq!(decide(&ai(), &all, &[ai()], Access::Value), Decision::Deny);
    assert_eq!(decide(&unknown(), &all, &[unknown()], Access::Value), NEVER);
}

#[test]
fn a_grant_allows_the_same_program_as_it_is_now_in_the_same_detached_state() {
    let named = invoker(None, "h1");
    let grant = [entry(PolicyRule::Allow, None, "h1")];
    assert_eq!(decide(&named, &grant, &[], Access::Value), Decision::Allow);
    // Never the whole item, its raw JSON or its history.
    assert_eq!(decide(&named, &grant, &[], Access::Whole), NEVER);
    // The program changed: the grant is revoked, and the user is asked again.
    let edited = invoker(None, "h2");
    assert_eq!(decide(&edited, &grant, &[], Access::Value), Decision::Confirm { remember: Scope::Device });
    // Detached, the program has no grant of its own: asked, never offered always.
    assert_eq!(decide(&detached(named.clone()), &grant, &[], Access::Value), NEVER);
    // A detached grant (`dybw policy allow --detached`) is for the detached program only.
    let loose = [PolicyEntry { detached: true, ..entry(PolicyRule::Allow, None, "h1") }];
    assert_eq!(decide(&detached(named.clone()), &loose, &[], Access::Value), Decision::Allow);
    assert_eq!(decide(&named, &loose, &[], Access::Value), Decision::Confirm { remember: Scope::Device });
}

#[test]
fn a_script_is_granted_for_its_process_only_and_entries_with_a_script_are_ignored() {
    let stored = [PolicyEntry { exe: "/bin/bash".into(), ..entry(PolicyRule::Allow, Some("/opt/a.sh"), "h1") }];
    let process = Decision::Confirm { remember: Scope::Process };
    assert_eq!(decide(&script(1), &stored, &[], Access::Value), process, "argv can claim any script");
    assert_eq!(decide(&script(1), &[], &[script(1)], Access::Value), Decision::Allow);
    assert_eq!(decide(&script(2), &[], &[script(1)], Access::Value), process, "another process");
    assert_eq!(decide(&detached(script(1)), &[], &[script(1)], Access::Value), NEVER, "its parent went since");
    assert_eq!(decide(&script(1), &[], &[script(1)], Access::Whole), NEVER);
}

#[test]
fn a_deny_entry_wins_whatever_the_hash_and_one_without_a_script_covers_every_script() {
    let claims = invoker(Some("/opt/a.sh"), "h2");
    let both = [entry(PolicyRule::Allow, Some("/opt/a.sh"), "h2"), entry(PolicyRule::Deny, Some("/opt/a.sh"), "")];
    assert_eq!(decide(&claims, &both, &[], Access::Value), Decision::Deny);
    assert_eq!(decide(&claims, &both, &[], Access::Names), Decision::Allow);
    assert_eq!(decide(&invoker(Some("/opt/b.sh"), "h2"), &both, &[], Access::Value), NEVER, "another script");
    let all = [entry(PolicyRule::Deny, None, ""), entry(PolicyRule::Allow, None, "h1")];
    for caller in [invoker(Some("/opt/a.sh"), "h1"), invoker(Some("/opt/b.sh"), "h1"), invoker(None, "h1")] {
        assert_eq!(decide(&caller, &all, &[], Access::Value), Decision::Deny, "{caller:?}");
    }
}

#[test]
fn an_allow_never_matches_a_caller_that_cannot_be_remembered() {
    let bash = PolicyEntry { exe: "/bin/bash".into(), ..entry(PolicyRule::Allow, None, "h") };
    assert_eq!(decide(&bare_shell(), &[bash], &[bare_shell()], Access::Value), NEVER);
    let rel = PolicyEntry { exe: "/bin/bash".into(), ..entry(PolicyRule::Allow, Some("run.sh"), "h") };
    assert_eq!(decide(&relative(), &[rel], &[relative()], Access::Value), NEVER);
    let xargs = PolicyEntry { exe: "/usr/bin/xargs".into(), ..entry(PolicyRule::Allow, None, "h") };
    assert_eq!(decide(&launcher(), &[xargs], &[launcher()], Access::Value), NEVER);
}

#[test]
fn a_path_that_is_not_text_is_asked_and_never_kept() {
    let odd = std::ffi::OsStr::from_bytes(b"/opt/\xff.sh");
    let caller = Caller::Invoker {
        exe: "/bin/bash".into(),
        script: Some(odd.into()),
        hash: "h".into(),
        relative: false,
        at: at(1),
    };
    assert_eq!(decide(&caller, &[], std::slice::from_ref(&caller), Access::Value), NEVER);
    let exe = Caller::Invoker { exe: odd.into(), script: None, hash: "h".into(), relative: false, at: At::default() };
    assert_eq!(grant_for(&exe), None);
}

#[test]
fn only_a_plain_program_that_may_be_offered_always_has_an_entry() {
    assert_eq!(grant_for(&invoker(None, "h1")).unwrap(), entry(PolicyRule::Allow, None, "h1"));
    for no in [
        ai(),
        unknown(),
        bare_shell(),
        relative(),
        script(1),
        launcher(),
        detached(invoker(None, "h1")),
        invoker(Some("/opt/a.sh"), "h1"),
    ] {
        assert_eq!(grant_for(&no), None, "{no:?}");
    }
}

#[test]
fn who_names_the_caller_on_one_line() {
    assert_eq!(who(&invoker(Some("/opt/a.sh"), "h")), "/usr/local/bin/mytool which claims to run /opt/a.sh");
    assert_eq!(who(&invoker(None, "h")), "/usr/local/bin/mytool");
    assert_eq!(who(&detached(invoker(None, "h"))), format!("/usr/local/bin/mytool, {DETACHED}"));
    assert!(who(&detached(script(1))).ends_with(DETACHED));
    assert_eq!(who(&ai()), "the AI agent claude");
    assert_eq!(who(&unknown()), "detached or unknown caller — possibly an AI agent");
    let forged = Caller::Invoker {
        exe: "/x\nallow everything".into(),
        script: None,
        hash: "h".into(),
        relative: false,
        at: At::default(),
    };
    assert!(!who(&forged).contains('\n'));
    let long = Caller::Invoker {
        exe: format!("/{}", "y".repeat(500)).into(),
        script: None,
        hash: "h".into(),
        relative: false,
        at: At::default(),
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
    s.set(entry(PolicyRule::Allow, None, "h1")).unwrap();
    assert_eq!(s.load().len(), 1, "sound before the tamper");
    setup(&dir.path().join("profiles/p/policy.json"));
    s.load()
}

#[test]
fn a_file_that_cannot_be_trusted_counts_as_no_entries_never_as_an_allow() {
    let json = r#"{"version":1,"entries":[{"exe":"/usr/local/bin/mytool","script":null,"hash":"h1","rule":"allow"}]}"#;
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
            decide(&invoker(None, "h1"), &entries, &[], Access::Value),
            Decision::Confirm { remember: Scope::Device },
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
