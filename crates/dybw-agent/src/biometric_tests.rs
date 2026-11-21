//! The `biometric` protector and the Touch ID confirmations through the agent (ADR 0006), against the scripted host
//! and its fake Secure Enclave: enrolment, unlock, what keeps and what drops the protector, the AI rules, and which
//! questions Touch ID answers. No test touches a sensor.
#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use dybw_peer::enclave::Error as Enclave;
use dybw_proto::{AgentError, Op, ProtectorInfo, Reply, Select};
use serde_json::Value;

use crate::agent::testing::{Rig, invoker};
use crate::caller::{At, Caller};
use crate::pin_tests::{PASSWORD, ai, answer, asked, err, lock_op, org, protectors, unlocked, world};
use crate::policy::Verdict;
use crate::write_tests::{add_op, remove_op, setup, unknown, writes};

const PIN: &str = "135790";

fn add(any: bool, watch: bool) -> Op {
    Op::UnlockAdd { profile: org(), protector: "biometric".into(), any, watch }
}

fn unlock_op() -> Op {
    Op::Unlock { profile: org() }
}

fn file(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join(".local/state/dybw/profiles/org/unlock/biometric")
}

/// The audit's (op, verdict) for the local unlock lines.
fn audited(rig: &Rig) -> Vec<(&'static str, Verdict)> {
    rig.audit.events().iter().filter(|e| e.op.starts_with("unlock")).map(|e| (e.op, e.verdict)).collect()
}

/// What the user does at the next Touch ID sheets.
fn touch(rig: &Rig, answers: &[Result<(), Enclave>]) {
    rig.host.world().touches.extend(answers.iter().copied());
}

/// The reasons of the Touch ID sheets shown since the last call.
fn sheets(rig: &Rig) -> Vec<String> {
    std::mem::take(&mut rig.host.world().reasons)
}

/// Locked: the master password unlocks and is the enrolment's; no Touch ID at enrolment. Locked again after.
async fn enrolled() -> (tempfile::TempDir, Rig) {
    let (dir, rig) = world();
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(add(false, false)).await, Reply::Done);
    assert_eq!(asked(&rig), ["Master password:"], "one master password, no PIN");
    assert!(sheets(&rig).is_empty(), "no Touch ID at enrolment");
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    (dir, rig)
}

#[tokio::test]
async fn touch_id_is_enrolled_with_the_master_password_and_unlocks_after_a_lock() {
    let (dir, rig) = enrolled().await;
    let blob = file(&dir);
    assert_eq!(std::fs::metadata(&blob).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(blob.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
    let stored: Value = serde_json::from_slice(&std::fs::read(&blob).unwrap()).unwrap();
    assert_eq!(stored["protector"]["protector"], "biometric");
    assert_eq!(stored["handle"].as_array().unwrap().len(), crate::host::fake::HANDLE.len());
    assert_eq!(stored["ephemeral"].as_array().unwrap().len(), 65);
    assert_eq!(rig.host.world().created, [(false, false)], "biometryCurrentSet, no watch");
    assert_eq!(protectors(&rig).await, [ProtectorInfo { name: "biometric".into(), attempts_left: None }]);
    let status = rig.agent.dispatch(Op::Status { profile: org() }).await;
    assert!(format!("{status:?}").contains("protectors: [\"biometric\"]"), "{status:?}");
    // The lock dropped the keys and kept the protector: one touch unlocks, nothing is typed.
    touch(&rig, &[Ok(())]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert!(asked(&rig).is_empty());
    assert_eq!(sheets(&rig), ["Unlock dybw profile org"]);
    assert!(unlocked(&rig).await);
    assert_eq!(audited(&rig), [("unlock-add", Verdict::Confirmed), ("unlock-biometric", Verdict::Confirmed)]);
    let line = rig.audit.events().into_iter().find(|e| e.op == "unlock-biometric").unwrap();
    assert_eq!(line.channel, Some("touch-id"), "answered on the sheet");
    let list = Op::List { profile: org(), fields: vec![], folder: None };
    assert!(matches!(rig.agent.dispatch(list).await, Reply::Items { items } if !items.is_empty()));
    // Every unlock asks.
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    touch(&rig, &[Ok(())]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert_eq!(sheets(&rig).len(), 1);
}

#[tokio::test]
async fn the_options_choose_any_finger_and_the_watch_and_an_unlocked_profile_asks_the_master_password() {
    let (_dir, rig) = world();
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(add(true, true)).await, Reply::Done);
    // Unlocked now: enrolling again asks for the master password, naming Touch ID.
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(add(false, true)).await, Reply::Done);
    assert_eq!(rig.host.world().created, [(true, true), (false, true)]);
    let question = rig.host.world().asked.last().cloned().unwrap();
    assert!(question.0.ends_with("type the master password to set Touch ID for this device"), "{question:?}");
    assert!(sheets(&rig).is_empty());
}

#[tokio::test]
async fn a_cancel_or_a_sensor_that_cannot_answer_goes_on_to_the_pin_then_the_master_password_and_keeps_it() {
    let (dir, rig) = enrolled().await;
    answer(&rig, &[PASSWORD, PIN, PIN]);
    assert_eq!(
        rig.agent.dispatch(Op::UnlockAdd { profile: org(), protector: "pin".into(), any: false, watch: false }).await,
        Reply::Done
    );
    assert!(sheets(&rig).is_empty(), "an enrolment's unlock asks the master password, never Touch ID");
    asked(&rig);
    let mut want = vec![("unlock-add", Verdict::Confirmed), ("unlock-add", Verdict::Confirmed)];
    for (refusal, verdict) in [
        (Enclave::Cancelled, Verdict::Declined),
        (Enclave::Unavailable, Verdict::Failed),
        (Enclave::LockedOut, Verdict::Failed),
        (Enclave::Failed, Verdict::Failed),
        (Enclave::Other(-42), Verdict::Failed),
    ] {
        assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
        touch(&rig, &[Err(refusal)]);
        answer(&rig, &[PIN]);
        assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done, "{refusal}");
        assert_eq!((sheets(&rig).len(), asked(&rig)), (1, vec!["PIN:".to_owned()]), "Touch ID first, then the PIN");
        assert!(file(&dir).exists(), "{refusal} keeps it");
        want.extend([("unlock-biometric", verdict), ("unlock-pin", Verdict::Confirmed)]);
    }
    assert_eq!(audited(&rig), want);
    // Without a PIN, a cancel goes on to the master password.
    assert_eq!(rig.agent.dispatch(Op::UnlockRemove { profile: org(), protector: "pin".into() }).await, Reply::Done);
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    touch(&rig, &[Err(Enclave::Cancelled)]);
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert_eq!(asked(&rig), ["Master password:"]);
    assert_eq!(protectors(&rig).await, [ProtectorInfo { name: "biometric".into(), attempts_left: None }]);
}

#[tokio::test]
async fn a_changed_set_of_fingers_drops_it_and_the_next_unlock_shows_no_sheet() {
    let (dir, rig) = enrolled().await;
    touch(&rig, &[Err(Enclave::Invalidated)]);
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert_eq!(asked(&rig), ["Master password:"]);
    assert!(!file(&dir).exists());
    let dropped = [("unlock-biometric", Verdict::Denied), ("unlock-biometric-dropped", Verdict::Failed)];
    assert_eq!(audited(&rig)[1..], dropped);
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    sheets(&rig);
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert!(sheets(&rig).is_empty());
}

#[tokio::test]
async fn a_protector_that_does_not_fit_this_mac_device_or_kind_is_dropped() {
    let (dir, rig) = enrolled().await;
    let good: Value = serde_json::from_slice(&std::fs::read(file(&dir)).unwrap()).unwrap();
    let edited = |edit: &dyn Fn(&mut Value)| {
        let mut v = good.clone();
        edit(&mut v);
        serde_json::to_vec(&v).unwrap()
    };
    let cases: Vec<(&str, Vec<u8>, bool)> = vec![
        ("not a protector", b"{}".to_vec(), false),
        ("a short ephemeral key", edited(&|v| v["ephemeral"] = serde_json::json!([4, 1, 2])), false),
        ("a PIN blob", edited(&|v| v["protector"]["protector"] = "pin".into()), false),
        ("another Mac's key", edited(&|v| v["handle"] = serde_json::json!([1, 2, 3])), true),
    ];
    for (case, raw, sheet) in cases {
        std::fs::write(file(&dir), raw).unwrap();
        touch(&rig, &[Ok(())]);
        answer(&rig, &[PASSWORD]);
        assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done, "{case}");
        assert_eq!((sheets(&rig).len(), asked(&rig).len()), (usize::from(sheet), 1), "{case}");
        assert!(!file(&dir).exists(), "{case}");
        assert_eq!(audited(&rig).last(), Some(&("unlock-biometric-dropped", Verdict::Failed)), "{case}");
        rig.host.world().touches.clear();
        assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    }
    // Another machine, or another device id: dropped before any sheet.
    for edit in [&|v: &mut Value| v["protector"]["machine"] = "another-machine".into(), &|v: &mut Value| {
        v["protector"]["deviceId"] = "another-device".into();
    }] as [&dyn Fn(&mut Value); 2]
    {
        std::fs::write(file(&dir), edited(edit)).unwrap();
        touch(&rig, &[Ok(())]);
        answer(&rig, &[PASSWORD]);
        assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
        assert!(sheets(&rig).is_empty() && !file(&dir).exists());
        assert_eq!(audited(&rig).last(), Some(&("unlock-biometric-dropped", Verdict::Failed)));
        rig.host.world().touches.clear();
        assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    }
    // A machine without a Secure Enclave (a file another build left): dropped, and `remove` would find it too.
    std::fs::write(file(&dir), serde_json::to_vec(&good).unwrap()).unwrap();
    rig.host.world().enclave = false;
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert!(sheets(&rig).is_empty() && !file(&dir).exists());
    rig.host.world().enclave = true;
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    // No fingerprint: nothing is asked of Touch ID, and the protector stays.
    std::fs::write(file(&dir), serde_json::to_vec(&good).unwrap()).unwrap();
    rig.host.world().machine = None;
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    sheets(&rig);
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert!(sheets(&rig).is_empty() && file(&dir).exists());
}

#[tokio::test]
async fn an_unknown_caller_raises_no_sheet_and_goes_to_the_master_password() {
    let (dir, rig) = enrolled().await;
    touch(&rig, &[Ok(())]);
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch_as(unlock_op(), unknown()).await, Reply::Done);
    assert_eq!(asked(&rig), ["Master password:"]);
    assert!(sheets(&rig).is_empty() && file(&dir).exists());
}

#[tokio::test]
async fn a_server_that_refuses_the_api_key_shows_no_sheet_and_keeps_it() {
    let (dir, rig) = enrolled().await;
    rig.host.world().token_status = 400;
    touch(&rig, &[Ok(())]);
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, err(AgentError::Server));
    assert_eq!(asked(&rig), ["Master password:"]);
    assert!(sheets(&rig).is_empty() && file(&dir).exists());
}

#[tokio::test]
async fn an_account_that_refuses_the_key_drops_it_and_refuses_the_unlock() {
    let (dir, rig) = enrolled().await;
    std::fs::write(dir.path().join(".local/state/dybw/profiles/org/core/security-version"), "9").unwrap();
    touch(&rig, &[Ok(())]);
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, err(AgentError::Refused("security-downgrade".into())));
    assert!(!file(&dir).exists());
}

#[tokio::test]
async fn ai_callers_a_mac_without_an_enclave_and_a_failed_enrolment_get_nothing() {
    let (dir, rig) = world();
    assert_eq!(rig.agent.dispatch_as(add(false, false), ai()).await, err(AgentError::Denied));
    rig.host.world().enclave = false;
    assert_eq!(rig.agent.dispatch(add(false, false)).await, err(AgentError::NoSuchProtector("biometric".into())));
    assert!(asked(&rig).is_empty(), "said before the master password");
    rig.host.world().enclave = true;
    rig.host.world().enclave_fails = Some(Enclave::Other(-34018));
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(add(false, false)).await, err(AgentError::Internal));
    rig.host.world().enclave_fails = None;
    rig.host.world().machine = Some(String::new());
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(add(false, false)).await, err(AgentError::Internal), "the core refuses the binding");
    rig.host.world().machine = Some("fake-machine".into());
    // The protectors' directory cannot be made.
    std::fs::write(file(&dir).parent().unwrap(), "in the way").unwrap();
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(add(false, false)).await, err(AgentError::Internal));
    std::fs::remove_file(file(&dir).parent().unwrap()).unwrap();
    let verdicts = [Verdict::Denied, Verdict::Failed, Verdict::Failed, Verdict::Failed];
    assert_eq!(audited(&rig), verdicts.map(|v| ("unlock-add", v)));
    // Enrolled: an AI caller cannot unlock with it, and no sheet shows.
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(add(false, false)).await, Reply::Done);
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    touch(&rig, &[Ok(())]);
    assert_eq!(rig.agent.dispatch_as(unlock_op(), ai()).await, err(AgentError::Denied));
    assert!(sheets(&rig).is_empty());
    assert_eq!(
        rig.agent.dispatch_as(Op::UnlockRemove { profile: org(), protector: "biometric".into() }, ai()).await,
        err(AgentError::Denied)
    );
    assert!(file(&dir).exists());
}

#[tokio::test]
async fn remove_purge_and_a_new_login_drop_it() {
    let (dir, rig) = enrolled().await;
    let remove = || Op::UnlockRemove { profile: org(), protector: "biometric".into() };
    assert_eq!(rig.agent.dispatch(remove()).await, Reply::Done);
    assert!(!file(&dir).exists());
    assert_eq!(rig.agent.dispatch(remove()).await, err(AgentError::NoSuchProtector("biometric".into())));
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(add(false, false)).await, Reply::Done);
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(Op::Purge { profile: org() }).await, Reply::Done);
    assert!(!file(&dir).exists());
    assert!(sheets(&rig).is_empty(), "a purge is confirmed in the pinentry");
    let purge = rig.audit.events().into_iter().find(|e| e.op == "purge").unwrap();
    assert_eq!((purge.verdict, purge.channel), (Verdict::Confirmed, Some("pinentry")));
    assert_eq!(audited(&rig).last(), Some(&("unlock-biometric-dropped", Verdict::Failed)));
}

#[tokio::test]
async fn a_lock_while_the_sheet_is_open_leaves_the_profile_locked_and_keeps_it() {
    let (dir, rig) = enrolled().await;
    rig.host.world().touch_hangs = true;
    let agent = rig.agent.clone();
    let pending = tokio::spawn(async move { agent.dispatch(unlock_op()).await });
    crate::read_tests::until(|| rig.host.world().reasons.len() == 1).await;
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    assert_eq!(pending.await.unwrap(), err(AgentError::Locked));
    assert!(file(&dir).exists() && !unlocked(&rig).await);
}

#[tokio::test]
async fn an_ssh_unlock_names_its_client_on_the_sheet() {
    let (_dir, rig) = enrolled().await;
    touch(&rig, &[Ok(())]);
    assert!(rig.agent.ssh_unlock("org", invoker(), "ssh git@host".into()).await);
    assert_eq!(sheets(&rig), ["Unlock dybw profile org: ssh git@host"]);
}

/// A plain program: a stable identity, so Touch ID may ask for it (ruling).
fn program() -> Caller {
    Caller::Invoker {
        exe: "/usr/local/bin/mytool".into(),
        script: None,
        hash: "h1".into(),
        relative: false,
        at: At::default(),
    }
}

/// Each audit line's op, verdict and where the question was answered.
fn channels(rig: &Rig) -> Vec<(&'static str, Verdict, Option<&'static str>)> {
    rig.audit.events().iter().map(|e| (e.op, e.verdict, e.channel)).collect()
}

const TOUCH: Option<&str> = Some("touch-id");
const PINENTRY: Option<&str> = Some("pinentry");

#[tokio::test]
async fn a_write_is_confirmed_by_touch_id_naming_the_item_then_the_caller() {
    let (_dir, rig) = setup(|_| {}).await;
    touch(&rig, &[Ok(())]);
    assert_eq!(rig.agent.dispatch_as(remove_op("x1"), program()).await, Reply::Done);
    assert_eq!(sheets(&rig), ["remove \"Plain\" (dybw profile work) for mytool"]);
    assert!(rig.host.world().confirmed.is_empty(), "no pinentry");
    // A finger that does not match is a no.
    touch(&rig, &[Err(Enclave::Failed)]);
    assert_eq!(rig.agent.dispatch_as(remove_op("x2"), program()).await, err(AgentError::Denied));
    assert!(rig.host.world().confirmed.is_empty());
    // A cancel, or no Touch ID: the same question in the pinentry.
    touch(&rig, &[Err(Enclave::Cancelled)]);
    rig.host.allow();
    assert_eq!(rig.agent.dispatch_as(remove_op("x2"), program()).await, Reply::Done);
    rig.host.allow();
    assert_eq!(rig.agent.dispatch_as(add_op("New", None, &[]), program()).await, Reply::Done);
    let want = ["remove \"Twelve\"", "remove \"Twelve\"", "add \"New\""]
        .map(|w| format!("{w} (dybw profile work) for mytool"));
    assert_eq!(sheets(&rig), want, "no match, a cancel, then no Touch ID");
    assert_eq!(rig.host.world().confirmed.len(), 2);
    // A removal that takes a marked item from other tools: the pinentry only, which says so.
    rig.host.allow();
    assert_eq!(rig.agent.dispatch_as(remove_op("m1"), program()).await, Reply::Done);
    // A caller whose grants cannot last (here, a script run by a program that is not an interpreter): the pinentry.
    touch(&rig, &[Ok(())]);
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(add_op("Other", None, &[])).await, Reply::Done);
    assert!(sheets(&rig).is_empty());
    assert_eq!(writes(&rig), 5);
    assert_eq!(
        channels(&rig),
        [
            ("remove", Verdict::Confirmed, TOUCH),
            ("remove", Verdict::Declined, TOUCH),
            ("remove", Verdict::Confirmed, PINENTRY),
            ("add", Verdict::Confirmed, PINENTRY),
            ("remove", Verdict::Confirmed, PINENTRY),
            ("add", Verdict::Confirmed, PINENTRY),
        ]
    );
}

#[tokio::test]
async fn touch_id_says_yes_once_and_a_cancel_offers_always_in_the_pinentry() {
    let (_dir, rig) = setup(|_| {}).await;
    let password = || crate::read_tests::get_op("x1", Select::Password);
    // "Always" could be offered: Touch ID asks first, and a match is a yes for this read only.
    touch(&rig, &[Ok(())]);
    assert!(matches!(rig.agent.dispatch_as(password(), program()).await, Reply::Value { .. }));
    assert_eq!(sheets(&rig), ["read the main value of \"Plain\" (dybw profile work) for mytool"]);
    assert!(rig.host.world().offered.is_empty(), "no pinentry");
    // A cancel: the pinentry's three answers, where "always" is kept.
    touch(&rig, &[Err(Enclave::Cancelled)]);
    rig.host.allow_always();
    assert!(matches!(rig.agent.dispatch_as(password(), program()).await, Reply::Value { .. }));
    assert_eq!(rig.host.world().offered, [true]);
    // The grant answers now: nobody is asked.
    assert!(matches!(rig.agent.dispatch_as(password(), program()).await, Reply::Value { .. }));
    assert_eq!(sheets(&rig).len(), 1);
    // The sheet names the field, or the full item.
    touch(&rig, &[Ok(()), Ok(())]);
    assert!(matches!(
        rig.agent.dispatch_as(crate::read_tests::history_op("x1"), program()).await,
        Reply::History { .. }
    ));
    let full = crate::read_tests::get_op("x1", Select::Full);
    assert!(!matches!(rig.agent.dispatch_as(full, program()).await, Reply::Error { .. }));
    let want = ["read the password history of \"Plain\"", "read the full item \"Plain\""]
        .map(|w| format!("{w} (dybw profile work) for mytool"));
    assert_eq!(sheets(&rig), want);
    // No stable identity (unknown, detached, a grant that cannot last): the pinentry only, though Touch ID would answer.
    let at = At { detached: true, ..At::default() };
    let detached =
        Caller::Invoker { exe: "/usr/local/bin/mytool".into(), script: None, hash: "h1".into(), relative: false, at };
    for caller in [unknown(), detached, invoker()] {
        rig.host.allow();
        assert!(matches!(rig.agent.dispatch_as(password(), caller).await, Reply::Value { .. }));
    }
    assert!(sheets(&rig).is_empty());
    let got: Vec<_> = channels(&rig).into_iter().map(|(_, v, c)| (v, c)).collect();
    let want = [
        (Verdict::Confirmed, TOUCH),
        (Verdict::Remembered, PINENTRY),
        (Verdict::Granted, None),
        (Verdict::Confirmed, TOUCH),
        (Verdict::Confirmed, TOUCH),
        (Verdict::Confirmed, PINENTRY),
        (Verdict::Confirmed, PINENTRY),
        (Verdict::Confirmed, PINENTRY),
    ];
    assert_eq!(got, want);
}

#[test]
fn the_sheet_fits_with_the_item_and_profile_first() {
    let long = |exe: String, script: Option<String>| Caller::Invoker {
        exe: exe.into(),
        script: script.map(Into::into),
        hash: "h".into(),
        relative: false,
        at: At::default(),
    };
    let item = "i".repeat(80);
    let what = format!(
        "read the field \"{}\" of \"{}\"",
        crate::worker::cut(&"f".repeat(40), 16),
        crate::worker::cut(&item, 32)
    );
    let profile = "p".repeat(64);
    for caller in [
        long(format!("/opt/{}", "e".repeat(48)), None),
        long("/usr/bin/python3".into(), Some(format!("/home/me/{}", "s".repeat(48)))),
    ] {
        let reason = crate::worker::touch_reason(&profile, &caller, &what).unwrap();
        assert!(reason.chars().count() <= 120, "{reason}");
        let essentials = format!("{what} (dybw profile {}…) for ", "p".repeat(19));
        assert!(reason.starts_with(&essentials), "{reason}");
        assert!(
            reason.starts_with(&format!("read the field \"{}…\" of \"{}…\"", "f".repeat(15), "i".repeat(31))),
            "{reason}"
        );
    }
    let script = long("/usr/bin/python3".into(), Some("/opt/x/backup.py".into()));
    assert_eq!(crate::worker::touch_reason("w", &script, "go").unwrap(), "go (dybw profile w) for python3 (backup.py)");
    // A quote in a name cannot close the sheet's quote; no stable identity, no sheet.
    assert_eq!(crate::worker::cut("a\"b\nc", 10), "a'b\u{fffd}c");
    assert_eq!(
        (crate::worker::touch_reason("p", &ai(), "x"), crate::worker::touch_reason("p", &unknown(), "x")),
        (None, None)
    );
}
