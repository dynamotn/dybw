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
    // Another machine: the Secure Enclave answers, the core refuses the binding.
    std::fs::write(file(&dir), serde_json::to_vec(&good).unwrap()).unwrap();
    rig.host.world().machine = Some("another-machine".into());
    touch(&rig, &[Ok(())]);
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert!(!file(&dir).exists());
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

const WHO: &str = "/usr/local/bin/mytool running /opt/scripts/backup.sh";

#[tokio::test]
async fn a_write_is_confirmed_by_touch_id_naming_the_caller_and_the_item() {
    let (_dir, rig) = setup(|_| {}).await;
    touch(&rig, &[Ok(())]);
    assert_eq!(rig.agent.dispatch(remove_op("x1")).await, Reply::Done);
    assert_eq!(sheets(&rig), [format!("let {WHO} remove \"Plain\" (dybw profile work)")]);
    assert!(rig.host.world().confirmed.is_empty(), "no pinentry");
    // A finger that does not match is a no.
    touch(&rig, &[Err(Enclave::Failed)]);
    assert_eq!(rig.agent.dispatch(remove_op("x2")).await, err(AgentError::Denied));
    assert!(rig.host.world().confirmed.is_empty());
    // A cancel, or no Touch ID: the same question in the pinentry.
    touch(&rig, &[Err(Enclave::Cancelled)]);
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(remove_op("x2")).await, Reply::Done);
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(add_op("New", None, &[])).await, Reply::Done);
    let want =
        ["remove \"Twelve\"", "remove \"Twelve\"", "add \"New\""].map(|w| format!("let {WHO} {w} (dybw profile work)"));
    assert_eq!(sheets(&rig), want, "no match, a cancel, then no Touch ID");
    assert_eq!(rig.host.world().confirmed.len(), 2);
    // A removal that takes a marked item from other tools: the pinentry only, which says so.
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(remove_op("m1")).await, Reply::Done);
    assert!(sheets(&rig).is_empty());
    assert_eq!(writes(&rig), 4);
}

#[tokio::test]
async fn a_read_that_offers_always_keeps_the_pinentry_and_one_asked_every_time_uses_touch_id() {
    let (_dir, rig) = setup(|_| {}).await;
    let password = || crate::read_tests::get_op("x1", Select::Password);
    let program = Caller::Invoker {
        exe: "/usr/local/bin/mytool".into(),
        script: None,
        hash: "h1".into(),
        relative: false,
        at: At::default(),
    };
    rig.host.allow();
    assert!(matches!(rig.agent.dispatch_as(password(), program).await, Reply::Value { .. }));
    assert!(sheets(&rig).is_empty(), "\"always\" is offered: the pinentry's three answers");
    assert_eq!(rig.host.world().offered, [true]);
    touch(&rig, &[Ok(()), Ok(())]);
    assert!(matches!(rig.agent.dispatch(crate::read_tests::history_op("x1")).await, Reply::History { .. }));
    assert!(matches!(rig.agent.dispatch_as(password(), unknown()).await, Reply::Value { .. }));
    let want = [
        format!("let {WHO} history \"Plain\" (dybw profile work)"),
        "let an unknown caller (possibly an AI agent) get \"Plain\" (dybw profile work)".to_owned(),
    ];
    assert_eq!(sheets(&rig), want);
}

#[test]
fn the_sheet_names_each_kind_of_caller_briefly() {
    let detached = Caller::Invoker {
        exe: format!("/very/long/{}/tool", "x".repeat(80)).into(),
        script: None,
        hash: String::new(),
        relative: false,
        at: At { detached: true, ..At::default() },
    };
    let shown = crate::worker::touch_who(&detached);
    assert!(shown.starts_with("/very/l…") && shown.ends_with("/tool (detached, possibly an AI agent)"), "{shown}");
    assert!(shown.chars().count() < 90, "{shown}");
    assert_eq!(crate::worker::touch_who(&ai()), "the AI agent claude");
    assert_eq!(crate::worker::touch_who(&invoker()), WHO);
    assert_eq!(crate::worker::touch_name("a\"b"), "\"a\\\"b\"", "a name cannot close the quote");
}
