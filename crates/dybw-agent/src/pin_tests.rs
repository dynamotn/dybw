//! The `pin` protector through the agent (ADR 0006), against the scripted host: enrolment, unlock with the PIN,
//! the five-attempt limit, what keeps and what drops the PIN, the binding, a rotation, and the AI rules. The `org`
//! vector account is used: its `/sync` has a private key, which a key from a protector must open.
#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::time::Instant;

use dybw_proto::{AgentError, Op, ProtectorInfo, Reply, Target};

use crate::agent::testing::{Rig, rig, seed_credentials};
use crate::caller::{Caller, Via};
use crate::host::fake::Answer;
use crate::policy::Verdict;

const PASSWORD: &str = "vectors-org-password";
const PIN: &str = "246813";

fn org() -> Option<String> {
    Some("org".into())
}

fn err(error: AgentError) -> Reply {
    Reply::Error { error }
}

fn add() -> Op {
    Op::UnlockAdd { profile: org(), protector: "pin".into() }
}

fn unlock_op() -> Op {
    Op::Unlock { profile: org() }
}

fn lock_op() -> Op {
    Op::Lock { target: Target::Profile("org".into()) }
}

fn ai() -> Caller {
    Caller::Ai { harness: "claude".into(), via: Via::Ancestry }
}

/// The org account's vault, logged in, locked.
fn world() -> (tempfile::TempDir, Rig) {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.host.vault(include_str!("../tests/fixtures/org-vault.json"));
    seed_credentials(&rig.agent, "org");
    (dir, rig)
}

fn answer(rig: &Rig, texts: &[&'static str]) {
    texts.iter().for_each(|t| rig.host.answer(Answer::Text(t)));
}

/// The field labels asked since the last call.
fn asked(rig: &Rig) -> Vec<String> {
    std::mem::take(&mut rig.host.world().prompts)
}

/// The audit's (op, verdict) for the local unlock lines.
fn audited(rig: &Rig) -> Vec<(&'static str, Verdict)> {
    rig.audit.events().iter().filter(|e| e.op.starts_with("unlock")).map(|e| (e.op, e.verdict)).collect()
}

async fn protectors(rig: &Rig) -> Vec<ProtectorInfo> {
    match rig.agent.dispatch(Op::UnlockList { profile: org() }).await {
        Reply::Protectors { profile, protectors } if profile == "org" => protectors,
        other => panic!("{other:?}"),
    }
}

async fn unlocked(rig: &Rig) -> bool {
    let status = rig.agent.dispatch(Op::Status { profile: org() }).await;
    format!("{status:?}").contains("unlocked: true")
}

/// Locked: the master password unlocks, then the PIN twice. Locked again after.
async fn enrolled() -> (tempfile::TempDir, Rig) {
    let (dir, rig) = world();
    answer(&rig, &[PASSWORD, PIN, PIN]);
    assert_eq!(rig.agent.dispatch(add()).await, Reply::Done);
    assert_eq!(asked(&rig), ["Master password:", "PIN:", "PIN again:"], "one master password only");
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    (dir, rig)
}

#[tokio::test]
async fn a_pin_is_enrolled_with_the_master_password_and_unlocks_after_a_lock() {
    let (_dir, rig) = enrolled().await;
    assert_eq!(protectors(&rig).await, [ProtectorInfo { name: "pin".into(), attempts_left: 5 }]);
    let status = rig.agent.dispatch(Op::Status { profile: org() }).await;
    assert!(format!("{status:?}").contains("protectors: [\"pin\"]"), "{status:?}");
    // The lock dropped the keys and kept the PIN: the PIN alone unlocks.
    answer(&rig, &[PIN]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert_eq!(asked(&rig), ["PIN:"]);
    assert!(unlocked(&rig).await);
    let question = rig.host.world().asked.last().cloned().unwrap();
    assert!(
        question.0.contains("with its PIN (5 tries left)") && question.0.contains("master password"),
        "{question:?}"
    );
    assert_eq!(audited(&rig), [("unlock-add", Verdict::Confirmed), ("unlock-pin", Verdict::Confirmed)]);
    // The vault is the real one: a list reads it.
    let list = Op::List { profile: org(), fields: vec![], folder: None };
    assert!(matches!(rig.agent.dispatch(list).await, Reply::Items { items } if !items.is_empty()));
}

#[tokio::test]
async fn enrolment_when_unlocked_asks_for_the_master_password_and_refuses_a_wrong_one() {
    let (_dir, rig) = world();
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    asked(&rig);
    answer(&rig, &["not the password"]);
    assert_eq!(rig.agent.dispatch(add()).await, err(AgentError::Denied));
    assert_eq!(asked(&rig), ["Master password:"], "no PIN is asked after a wrong master password");
    assert!(protectors(&rig).await.is_empty());
    answer(&rig, &[PASSWORD, PIN, PIN]);
    assert_eq!(rig.agent.dispatch(add()).await, Reply::Done);
    assert_eq!(asked(&rig), ["Master password:", "PIN:", "PIN again:"]);
    assert_eq!(audited(&rig), [("unlock-add", Verdict::Declined), ("unlock-add", Verdict::Confirmed)]);
}

#[tokio::test]
async fn a_short_or_mistyped_pin_is_asked_again_three_times_at_most() {
    let (_dir, rig) = world();
    answer(&rig, &[PASSWORD, "12345", "246813", "246814", PIN, PIN]);
    assert_eq!(rig.agent.dispatch(add()).await, Reply::Done);
    let errors: Vec<_> = rig.host.world().asked.iter().map(|q| q.1.clone()).collect();
    let want = [None, None, Some("The PIN is too short."), None, Some("The two PINs differ."), None];
    assert_eq!(errors, want.map(|e| e.map(str::to_owned)));
    assert_eq!(rig.agent.dispatch(Op::UnlockRemove { profile: org(), protector: "pin".into() }).await, Reply::Done);
    answer(&rig, &[PASSWORD, "1", "2", "3"]);
    assert_eq!(rig.agent.dispatch(add()).await, err(AgentError::Denied));
    assert!(protectors(&rig).await.is_empty());
}

#[tokio::test]
async fn five_wrong_pins_drop_it_and_the_master_password_unlocks() {
    let (_dir, rig) = enrolled().await;
    answer(&rig, &["000000", "000001", "000002", "000003", "000004", PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert_eq!(asked(&rig), ["PIN:", "PIN:", "PIN:", "PIN:", "PIN:", "Master password:"]);
    // The fifth PIN question, after the three of the enrolment.
    let fifth = rig.host.world().asked[7].clone();
    assert!(fifth.0.contains("(1 tries left)") && fifth.1.as_deref() == Some("Wrong PIN."), "{fifth:?}");
    assert!(protectors(&rig).await.is_empty(), "the sixth try needs the master password");
    let pins = audited(&rig).into_iter().filter(|(op, _)| *op == "unlock-pin").count();
    assert_eq!(pins, 5);
    assert_eq!(audited(&rig).last(), Some(&("unlock-pin-dropped", Verdict::Failed)));
}

#[tokio::test]
async fn wrong_pins_count_across_unlocks_and_a_right_one_resets_the_count() {
    let (_dir, rig) = enrolled().await;
    // Two wrong, then a cancel: the master password is asked instead, and cancelled too.
    answer(&rig, &["000000", "000001"]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, err(AgentError::Denied));
    assert_eq!(asked(&rig), ["PIN:", "PIN:", "PIN:", "Master password:"]);
    assert_eq!(protectors(&rig).await[0].attempts_left, 3);
    answer(&rig, &[PIN]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert_eq!(protectors(&rig).await[0].attempts_left, 5);
}

#[tokio::test]
async fn lock_and_idle_keep_the_pin_and_login_purge_and_exit_drop_it() {
    let (_dir, rig) = enrolled().await;
    assert_eq!(rig.agent.dispatch(Op::Lock { target: Target::All }).await, Reply::Done);
    assert_eq!(protectors(&rig).await.len(), 1, "kept across a lock");
    // A new login (the API key again) is a new account session.
    answer(&rig, &["user.0b3b6d1e-6f3a-4a52-9f54-2f1c8f0c9a11", "abcdefghij0123456789"]);
    assert_eq!(rig.agent.dispatch(Op::Login { profile: org() }).await, Reply::Done);
    assert!(protectors(&rig).await.is_empty());

    let (_dir, rig) = enrolled().await;
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(Op::Purge { profile: org() }).await, Reply::Done);
    assert!(protectors(&rig).await.is_empty());
    assert_eq!(audited(&rig).last(), Some(&("unlock-pin-dropped", Verdict::Failed)));

    let (_dir, rig) = enrolled().await;
    rig.agent.shutdown().await;
    assert!(rig.agent.running("org").is_none(), "the PIN went with the worker");
}

#[tokio::test]
async fn a_pin_unlocks_offline_from_the_cached_copy() {
    let (_dir, rig) = enrolled().await;
    rig.host.world().online = false;
    answer(&rig, &[PIN]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert!(unlocked(&rig).await);
}

#[tokio::test]
async fn a_blob_bound_to_another_machine_is_dropped_and_reported() {
    let (_dir, rig) = enrolled().await;
    rig.host.world().machine = Some("another-machine".into());
    answer(&rig, &[PIN, PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert_eq!(asked(&rig), ["PIN:", "Master password:"]);
    assert!(protectors(&rig).await.is_empty());
    assert_eq!(audited(&rig)[1..], [("unlock-pin", Verdict::Denied), ("unlock-pin-dropped", Verdict::Failed)]);
}

#[tokio::test]
async fn no_machine_fingerprint_means_no_pin_question_and_no_enrolment() {
    let (_dir, rig) = enrolled().await;
    rig.host.world().machine = None;
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    assert_eq!(asked(&rig), ["Master password:"]);
    assert_eq!(protectors(&rig).await.len(), 1, "kept: nothing says it is wrong");
    answer(&rig, &[PASSWORD, PIN, PIN]);
    assert_eq!(rig.agent.dispatch(add()).await, err(AgentError::Internal));
}

#[tokio::test]
async fn a_rotation_seen_at_a_sync_or_at_an_unlock_drops_the_pin() {
    let (_dir, rig) = enrolled().await;
    answer(&rig, &[PIN]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    // The server's account now has a private key this user key does not open (another account's: pbkdf2).
    rig.host.world().profile = None;
    assert_eq!(rig.agent.dispatch(Op::Sync { target: Target::Profile("org".into()) }).await, Reply::Done);
    assert!(protectors(&rig).await.is_empty(), "dropped at the sync");

    let (_dir, rig) = enrolled().await;
    rig.host.world().profile = None;
    answer(&rig, &[PIN]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, err(AgentError::Denied));
    assert_eq!(asked(&rig), ["PIN:", "Master password:"], "stale: the master password is asked");
    assert!(protectors(&rig).await.is_empty());
}

#[tokio::test]
async fn an_ai_caller_may_list_but_not_add_remove_or_be_asked_for_a_pin() {
    let (_dir, rig) = enrolled().await;
    assert_eq!(rig.agent.dispatch_as(add(), ai()).await, err(AgentError::Denied));
    let remove = Op::UnlockRemove { profile: org(), protector: "pin".into() };
    assert_eq!(rig.agent.dispatch_as(remove.clone(), ai()).await, err(AgentError::Denied));
    let unknown = Caller::Unknown { why: "gone".into(), peer: None };
    assert_eq!(rig.agent.dispatch_as(remove, unknown).await, err(AgentError::Denied));
    assert_eq!(rig.agent.dispatch_as(unlock_op(), ai()).await, err(AgentError::Denied));
    let list = Op::List { profile: org(), fields: vec![], folder: None };
    assert_eq!(rig.agent.dispatch_as(list, ai()).await, err(AgentError::Locked));
    assert!(asked(&rig).is_empty(), "nothing was asked on an AI caller's behalf");
    let listed = rig.agent.dispatch_as(Op::UnlockList { profile: org() }, ai()).await;
    assert!(matches!(listed, Reply::Protectors { protectors, .. } if protectors.len() == 1));
    let denied: Vec<_> = rig.audit.events().iter().filter(|e| e.verdict == Verdict::Denied).map(|e| e.op).collect();
    assert_eq!(denied, ["unlock-add", "unlock-remove", "unlock-remove", "unlock"]);
}

#[tokio::test]
async fn the_worker_refuses_a_caller_that_is_not_a_named_invoker() {
    let (_dir, rig) = enrolled().await;
    let w = rig.agent.running("org").unwrap();
    let still = crate::worker::Recheck::new(|| true);
    let cmd = crate::worker::Cmd::UnlockAdd { protector: "pin".into(), caller: ai(), still };
    assert_eq!(w.call(cmd, Instant::now()).await, err(AgentError::Denied));
    let cmd = crate::worker::Cmd::UnlockRemove { protector: "pin".into(), caller: ai() };
    assert_eq!(w.call(cmd, Instant::now()).await, err(AgentError::Denied));
    assert_eq!(protectors(&rig).await.len(), 1);
}

#[tokio::test]
async fn an_unknown_or_absent_protector_is_named() {
    let (_dir, rig) = world();
    let nfc = Op::UnlockAdd { profile: org(), protector: "nfc".into() };
    assert_eq!(rig.agent.dispatch(nfc).await, err(AgentError::NoSuchProtector("nfc".into())));
    let remove = Op::UnlockRemove { profile: org(), protector: "pin".into() };
    assert_eq!(rig.agent.dispatch(remove).await, err(AgentError::NoSuchProtector("pin".into())));
    assert!(asked(&rig).is_empty());
}

#[tokio::test]
async fn enrolment_stops_at_a_cancelled_unlock_a_changed_caller_or_an_empty_fingerprint() {
    let (_dir, rig) = world();
    assert_eq!(rig.agent.dispatch(add()).await, err(AgentError::Denied), "the master password was cancelled");
    assert_eq!(asked(&rig), ["Master password:"]);
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, Reply::Done);
    let w = rig.agent.running("org").unwrap();
    let gone = crate::worker::Recheck::new(|| false);
    let cmd = crate::worker::Cmd::UnlockAdd {
        protector: "pin".into(),
        caller: crate::agent::testing::invoker(),
        still: gone,
    };
    answer(&rig, &[PASSWORD, PIN, PIN]);
    assert_eq!(w.call(cmd, Instant::now()).await, err(AgentError::Denied), "the caller changed while asked");
    rig.host.world().machine = Some(String::new());
    answer(&rig, &[PASSWORD, PIN, PIN]);
    assert_eq!(rig.agent.dispatch(add()).await, err(AgentError::Internal), "the core refuses an empty binding");
    assert!(protectors(&rig).await.is_empty());
}

#[tokio::test]
async fn a_server_that_refuses_the_api_key_asks_no_pin() {
    let (_dir, rig) = enrolled().await;
    rig.host.world().token_status = 400;
    answer(&rig, &[PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, err(AgentError::Server));
    assert_eq!(asked(&rig), ["Master password:"]);
    assert_eq!(protectors(&rig).await.len(), 1);
}

#[tokio::test]
async fn a_security_downgrade_after_the_pin_drops_it_and_refuses_the_unlock() {
    let (dir, rig) = enrolled().await;
    let state = dir.path().join(".local/state/dybw/profiles/org/core/security-version");
    assert!(state.parent().unwrap().is_dir(), "{state:?}");
    std::fs::write(&state, "9").unwrap();
    answer(&rig, &[PIN, PASSWORD]);
    assert_eq!(rig.agent.dispatch(unlock_op()).await, err(AgentError::Refused("security-downgrade".into())));
    assert!(protectors(&rig).await.is_empty());
}

#[tokio::test]
async fn an_ssh_unlock_takes_the_pin_too() {
    let (_dir, rig) = enrolled().await;
    answer(&rig, &[PIN]);
    assert!(rig.agent.ssh_unlock("org", crate::agent::testing::invoker(), "ssh git@host".into()).await);
    assert_eq!(asked(&rig), ["PIN:"]);
    let question = rig.host.world().asked.last().cloned().unwrap();
    assert!(question.0.starts_with("Unlock dybw profile org: ssh git@host with its PIN"), "{question:?}");
}

#[tokio::test]
async fn a_lock_while_the_pin_is_typed_leaves_the_profile_locked() {
    let (_dir, rig) = enrolled().await;
    rig.host.answer(Answer::Hang);
    let agent = rig.agent.clone();
    let pending = tokio::spawn(async move { agent.dispatch(unlock_op()).await });
    crate::read_tests::until(|| rig.host.world().prompts.len() == 1).await;
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    assert_eq!(pending.await.unwrap(), err(AgentError::Locked));
    assert_eq!(protectors(&rig).await[0].attempts_left, 5);
}
