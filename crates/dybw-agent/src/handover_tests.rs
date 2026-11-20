//! The `login` protector and the keyring handover (ADR 0006), against a fake keyring and the scripted host:
//! enrolment, unlock by the handed-over password, a password change (ruling L5), what drops the protector, and the
//! lock at the last session's close. The `org` vector account is used, as for the PIN.
#![expect(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

use dybw_proto::{AgentError, Op, ProtectorInfo, Reply, Target};
use tempfile::TempDir;

use super::*;
use crate::agent::testing::Rig;
use crate::host::fake::Answer;
use crate::pin_tests::{PASSWORD, ai, answer, asked, err, lock_op, org, protectors, unlocked, world};

const PW: &str = "correct horse battery";
const NEW: &str = "staple 2 the battery";

/// A keyring in memory.
#[derive(Default)]
struct Ring(Mutex<HashMap<&'static str, Vec<u8>>>);

impl Ring {
    fn put(&self, name: &'static str, payload: &str) -> &Self {
        self.0.lock().unwrap().insert(name, payload.as_bytes().to_vec());
        self
    }

    fn left(&self) -> Vec<&'static str> {
        let mut names: Vec<_> = self.0.lock().unwrap().keys().copied().collect();
        names.sort_unstable();
        names
    }
}

impl Keyring for Ring {
    fn take(&self, name: &str) -> Option<Zeroizing<Vec<u8>>> {
        self.0.lock().unwrap().remove(name).map(Zeroizing::new)
    }
}

fn add() -> Op {
    Op::UnlockAdd { profile: org(), protector: "login".into() }
}

fn blob(dir: &TempDir) -> PathBuf {
    dir.path().join(".local/state/dybw/profiles/org/unlock/login")
}

fn pending(dir: &TempDir) -> PathBuf {
    blob(dir).with_extension("pending")
}

/// The audit's (op, verdict) for the lines about the login protector.
fn audited(rig: &Rig) -> Vec<(&'static str, Verdict)> {
    rig.audit.events().iter().filter(|e| e.kind == Some("login")).map(|e| (e.op, e.verdict)).collect()
}

/// One look at `ring`, with logind's sessions in `sessions`, and every worker's answer to it.
async fn look(rig: &Rig, ring: &Ring, sessions: &Path) {
    for answer in rig.agent.handover(ring, sessions).await {
        answer.await.unwrap();
    }
}

/// One look, with no logind.
async fn hand(rig: &Rig, ring: &Ring) {
    look(rig, ring, Path::new("/nonexistent")).await;
}

/// Locked: the master password unlocks, then the login password twice. Locked again after.
async fn enrolled() -> (TempDir, Rig) {
    let (dir, rig) = world();
    answer(&rig, &[PASSWORD, PW, PW]);
    assert_eq!(rig.agent.dispatch(add()).await, Reply::Done);
    assert_eq!(asked(&rig), ["Master password:", "Login password:", "Login password again:"]);
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    (dir, rig)
}

/// A password change from `old` to `new`, handed over.
async fn change(rig: &Rig, old: &str, new: &str) {
    hand(rig, Ring::default().put(LOGIN_OLD, old).put(LOGIN, new)).await;
}

/// A login with `pw`, handed over: whether it unlocked.
async fn login(rig: &Rig, pw: &str) -> bool {
    let ring = Ring::default();
    hand(rig, ring.put(LOGIN, pw)).await;
    assert!(ring.left().is_empty(), "read once");
    unlocked(rig).await
}

#[tokio::test]
async fn a_login_protector_is_kept_on_disk_and_the_password_handed_over_unlocks() {
    let (dir, rig) = enrolled().await;
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!((mode(&blob(&dir)), mode(blob(&dir).parent().unwrap())), (0o600, 0o700));
    let question = rig.host.world().asked[1].0.clone();
    assert!(question.contains("not checked against the") && question.contains("Without a TPM2"), "{question}");
    assert_eq!(protectors(&rig).await, [ProtectorInfo { name: "login".into(), attempts_left: None }]);
    let status = rig.agent.dispatch(Op::Status { profile: org() }).await;
    assert!(format!("{status:?}").contains("protectors: [\"login\"], login_handover: None"), "{status:?}");

    assert!(login(&rig, PW).await);
    assert!(asked(&rig).is_empty(), "nothing is asked");
    let status = rig.agent.dispatch(Op::Status { profile: org() }).await;
    assert!(format!("{status:?}").contains("login_handover: Some("), "{status:?}");
    assert_eq!(audited(&rig), [("unlock-add", Verdict::Confirmed), ("unlock-login", Verdict::Confirmed)]);
    // An unlocked profile is left as it is.
    assert!(login(&rig, "anything").await);
    assert_eq!(audited(&rig).len(), 2);
    let list = Op::List { profile: org(), fields: vec![], folder: None };
    assert!(matches!(rig.agent.dispatch(list).await, Reply::Items { items } if !items.is_empty()));
}

#[tokio::test]
async fn a_password_that_opens_nothing_invalidates_the_protector_and_asks_nothing() {
    // A reset by root: the new password came with no old one, so nothing was re-wrapped (ruling C1).
    let (dir, rig) = enrolled().await;
    assert!(!login(&rig, "reset by root").await);
    assert!(!blob(&dir).exists());
    assert!(asked(&rig).is_empty());
    assert_eq!(audited(&rig)[1..], [("unlock-login", Verdict::Denied), ("unlock-login-dropped", Verdict::Failed)]);
    // Nothing is left to open: the keyring is not even read, and enrolling again needs the master password.
    let ring = Ring::default();
    hand(&rig, ring.put(LOGIN, PW)).await;
    assert_eq!(ring.left(), [LOGIN]);
    assert!(!unlocked(&rig).await && protectors(&rig).await.is_empty());

    // With a pending re-wrap too: both go.
    let (dir, rig) = enrolled().await;
    change(&rig, PW, NEW).await;
    assert!(!login(&rig, "a third one").await);
    assert!(!blob(&dir).exists() && !pending(&dir).exists());
}

#[tokio::test]
async fn without_a_login_protector_the_keyring_is_left_alone() {
    let (_dir, rig) = world();
    let ring = Ring::default();
    hand(&rig, ring.put(LOGIN, PW).put(LOCK, "-")).await;
    assert_eq!(ring.left(), [LOCK, LOGIN]);
    // Told directly, a worker without the protector does nothing either.
    let token = || Token(Zeroizing::new(PW.as_bytes().to_vec()));
    for old in [None, Some(token())] {
        let cmd = Cmd::LoginToken { token: token(), old };
        assert_eq!(rig.agent.on_profile(org().as_deref(), cmd).await, Reply::Done);
    }
    assert!(!unlocked(&rig).await);
    assert_eq!(format!("{:?}", token()), "Token");
}

#[tokio::test]
async fn a_password_change_is_rewrapped_and_the_next_login_confirms_it() {
    let (dir, rig) = enrolled().await;
    let before = std::fs::read(blob(&dir)).unwrap();
    change(&rig, PW, NEW).await;
    assert!(!unlocked(&rig).await, "a password change does not unlock");
    assert!(pending(&dir).exists() && std::fs::read(blob(&dir)).unwrap() == before, "the old wrap is kept");
    assert_eq!(audited(&rig)[1..], [("unlock-login-rewrap", Verdict::Confirmed)]);
    assert!(login(&rig, NEW).await);
    assert!(!pending(&dir).exists(), "the new wrap is now the protector");
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    assert!(login(&rig, NEW).await, "the new wrap opens again");
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    assert!(!login(&rig, PW).await, "the old password no longer opens it, and invalidates it");
    assert!(!blob(&dir).exists());
}

#[tokio::test]
async fn a_change_that_did_not_happen_keeps_the_old_password() {
    let (dir, rig) = enrolled().await;
    change(&rig, PW, NEW).await;
    assert!(login(&rig, PW).await);
    assert!(!pending(&dir).exists(), "the pending wrap is dropped");
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    assert!(login(&rig, PW).await, "the old password still opens it");
}

#[tokio::test]
async fn a_second_change_before_a_login_rewraps_the_pending_key_and_a_wrong_old_one_nothing() {
    let (dir, rig) = enrolled().await;
    change(&rig, "not it", NEW).await;
    assert!(!pending(&dir).exists() && blob(&dir).exists(), "a wrong old password re-wraps and deletes nothing");
    assert_eq!(audited(&rig)[1..], [("unlock-login-rewrap", Verdict::Denied)]);
    change(&rig, PW, NEW).await;
    change(&rig, NEW, "third password").await;
    assert!(login(&rig, "third password").await);
}

#[tokio::test]
async fn a_rewrap_that_cannot_be_saved_is_reported() {
    let (dir, rig) = enrolled().await;
    std::fs::create_dir_all(pending(&dir).join("in-the-way")).unwrap();
    change(&rig, PW, NEW).await;
    assert_eq!(audited(&rig)[1..], [("unlock-login-rewrap", Verdict::Failed)]);
}

#[tokio::test]
async fn a_blob_for_another_machine_or_an_unreadable_one_is_dropped() {
    let (dir, rig) = enrolled().await;
    rig.host.world().machine = Some("another-machine".into());
    assert!(!login(&rig, PW).await);
    assert!(!blob(&dir).exists());
    let want = [("unlock-login", Verdict::Denied), ("unlock-login-dropped", Verdict::Failed)];
    assert_eq!(audited(&rig)[1..], want);

    let (dir, rig) = enrolled().await;
    std::fs::write(blob(&dir), b"{not json").unwrap();
    change(&rig, PW, NEW).await;
    assert!(!blob(&dir).exists());
    assert_eq!(
        audited(&rig)[1..],
        [("unlock-login-rewrap", Verdict::Denied), ("unlock-login-dropped", Verdict::Failed)]
    );

    // A PIN blob moved into the login protector's place is not a login protector.
    let (dir, rig) = enrolled().await;
    let pin = std::fs::read_to_string(blob(&dir)).unwrap().replace("\"login\"", "\"pin\"");
    std::fs::write(blob(&dir), pin).unwrap();
    assert!(!login(&rig, PW).await);
    assert!(!blob(&dir).exists());

    // An unreadable pending wrap goes; the protector itself still opens.
    let (dir, rig) = enrolled().await;
    std::fs::write(pending(&dir), b"{not json").unwrap();
    assert!(login(&rig, PW).await);
    assert!(!pending(&dir).exists() && blob(&dir).exists());
}

#[tokio::test]
async fn no_fingerprint_or_no_account_leaves_the_profile_locked_and_the_protector_kept() {
    let (dir, rig) = enrolled().await;
    rig.host.world().machine = None;
    assert!(!login(&rig, PW).await);
    change(&rig, PW, NEW).await;
    rig.host.world().machine = Some("fake-machine".into());
    rig.host.world().token_status = 400;
    assert!(!login(&rig, PW).await);
    change(&rig, PW, NEW).await;
    assert!(blob(&dir).exists() && !pending(&dir).exists());
    assert!(audited(&rig)[1..].is_empty());
}

#[tokio::test]
async fn a_rotation_a_downgrade_a_new_login_a_purge_or_a_remove_drops_it() {
    // A rotation seen at a sync.
    let (dir, rig) = enrolled().await;
    assert!(login(&rig, PW).await);
    rig.host.world().profile = None;
    assert_eq!(rig.agent.dispatch(Op::Sync { target: Target::Profile("org".into()) }).await, Reply::Done);
    assert!(!blob(&dir).exists());
    assert_eq!(audited(&rig).last(), Some(&("unlock-login-dropped", Verdict::Failed)));

    // A rotation seen when the password comes, at a login and at a change.
    let (dir, rig) = enrolled().await;
    rig.host.world().profile = None;
    change(&rig, PW, NEW).await;
    assert!(!blob(&dir).exists());
    let (dir, rig) = enrolled().await;
    rig.host.world().profile = None;
    assert!(!login(&rig, PW).await);
    assert!(!blob(&dir).exists());

    // A security downgrade: the account refuses the key.
    let (dir, rig) = enrolled().await;
    std::fs::write(dir.path().join(".local/state/dybw/profiles/org/core/security-version"), "9").unwrap();
    assert!(!login(&rig, PW).await);
    assert!(!blob(&dir).exists());

    let (dir, rig) = enrolled().await;
    answer(&rig, &["user.0b3b6d1e-6f3a-4a52-9f54-2f1c8f0c9a11", "abcdefghij0123456789"]);
    assert_eq!(rig.agent.dispatch(Op::Login { profile: org() }).await, Reply::Done);
    assert!(!blob(&dir).exists());

    let (dir, rig) = enrolled().await;
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(Op::Purge { profile: org() }).await, Reply::Done);
    assert!(!blob(&dir).exists());

    let (dir, rig) = enrolled().await;
    let remove = || Op::UnlockRemove { profile: org(), protector: "login".into() };
    assert_eq!(rig.agent.dispatch(remove()).await, Reply::Done);
    assert!(!blob(&dir).exists());
    assert_eq!(rig.agent.dispatch(remove()).await, err(AgentError::NoSuchProtector("login".into())));
    assert_eq!(audited(&rig)[1..], [("unlock-remove", Verdict::Confirmed)]);
}

#[tokio::test]
async fn an_ai_caller_cannot_enrol_or_remove_it() {
    let (dir, rig) = enrolled().await;
    assert_eq!(rig.agent.dispatch_as(add(), ai()).await, err(AgentError::Denied));
    let remove = Op::UnlockRemove { profile: org(), protector: "login".into() };
    assert_eq!(rig.agent.dispatch_as(remove, ai()).await, err(AgentError::Denied));
    assert!(blob(&dir).exists());
    assert_eq!(audited(&rig)[1..], [("unlock-add", Verdict::Denied), ("unlock-remove", Verdict::Denied)]);
    // Through the worker itself.
    let still = crate::worker::Recheck::new(|| true);
    let cmd = Cmd::UnlockAdd { protector: "login".into(), caller: ai(), still };
    assert_eq!(rig.agent.on_profile(org().as_deref(), cmd).await, err(AgentError::Denied));
}

#[tokio::test]
async fn an_enrolment_that_cannot_be_saved_or_an_unknown_name_is_refused() {
    let (dir, rig) = world();
    std::fs::create_dir_all(blob(&dir).join("in-the-way")).unwrap();
    answer(&rig, &[PASSWORD, PW, "typo", PW, PW]);
    assert_eq!(rig.agent.dispatch(add()).await, err(AgentError::Internal));
    let errors: Vec<_> = rig.host.world().asked.iter().map(|q| q.1.clone()).collect();
    assert_eq!(errors[3].as_deref(), Some("The two passwords differ."));
    assert_eq!(audited(&rig), [("unlock-add", Verdict::Failed)]);
    let nfc = Op::UnlockRemove { profile: org(), protector: "nfc".into() };
    assert_eq!(rig.agent.dispatch(nfc).await, err(AgentError::NoSuchProtector("nfc".into())));
}

#[tokio::test]
async fn a_login_password_waits_for_an_unlock_in_flight_and_then_does_nothing() {
    let (_dir, rig) = enrolled().await;
    rig.host.answer(Answer::HeldText(PASSWORD));
    let agent = rig.agent.clone();
    let typing = tokio::spawn(async move { agent.dispatch(Op::Unlock { profile: org() }).await });
    crate::read_tests::until(|| rig.host.world().prompts.len() == 1).await;
    let agent = rig.agent.clone();
    let answers = agent.handover(Ring::default().put(LOGIN, PW), Path::new("/")).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    rig.host.world().release.notify_one();
    assert_eq!(typing.await.unwrap(), Reply::Done);
    for answer in answers {
        assert_eq!(answer.await.unwrap(), Reply::Done);
    }
    assert_eq!(audited(&rig).len(), 1, "the login password unlocked nothing");
}

#[tokio::test]
async fn a_worker_busy_with_a_pinentry_does_not_stall_the_next_look() {
    let (_dir, rig) = enrolled().await;
    rig.host.answer(Answer::Hang);
    let agent = rig.agent.clone();
    let typing = tokio::spawn(async move { agent.dispatch(Op::Unlock { profile: org() }).await });
    crate::read_tests::until(|| rig.host.world().prompts.len() == 1).await;
    // The password waits for the unlock in flight; the look does not.
    let second = std::time::Duration::from_secs(2);
    let ring = Ring::default();
    let answers = tokio::time::timeout(second, rig.agent.handover(ring.put(LOGIN, PW), Path::new("/x")));
    let answers = answers.await.expect("the look waited for a busy worker");
    // A session close in the next look is not held up either: it locks, which cancels the question.
    tokio::time::timeout(second, look(&rig, Ring::default().put(LOCK, "c1"), Path::new("/x"))).await.unwrap();
    assert_eq!(typing.await.unwrap(), err(AgentError::Locked));
    drop(answers);
}

#[tokio::test]
async fn a_leftover_old_password_equal_to_the_new_one_is_a_plain_login() {
    let (dir, rig) = enrolled().await;
    hand(&rig, Ring::default().put(LOGIN_OLD, PW).put(LOGIN, PW)).await;
    assert!(unlocked(&rig).await && !pending(&dir).exists());
    assert_eq!(audited(&rig)[1..], [("unlock-login", Verdict::Confirmed)]);
}

/// A logind session file.
fn session(dir: &Path, id: &str, uid: u32, class: &str, state: &str) {
    std::fs::write(dir.join(id), format!("# This is private data.\nUID={uid}\nCLASS={class}\nSTATE={state}\n"))
        .unwrap();
}

#[test]
fn only_an_open_user_session_of_this_user_counts() {
    let dir = tempfile::tempdir().unwrap();
    let (d, me) = (dir.path(), 1000);
    let fifo = std::process::Command::new("mkfifo").arg(d.join("3.ref")).status().unwrap();
    assert!(fifo.success());
    session(d, "3", me, "user", "closing");
    session(d, "4", me, "manager", "active");
    session(d, "5", 1001, "user", "active");
    std::fs::write(d.join("6"), "UIDX=1000\nCLASS=user\nSTATE=active\n").unwrap();
    std::fs::create_dir(d.join("7")).unwrap();
    assert!(!others_open(d, me, "2"), "a closing, a manager, another user's, a malformed one, a directory");
    session(d, "2", me, "user", "active");
    assert!(!others_open(d, me, "2"), "the one closing does not count");
    session(d, "8", me, "user-early", "online");
    assert!(others_open(d, me, "2"));
    assert!(!others_open(&d.join("nothing"), me, "2"));
}

#[tokio::test]
async fn the_last_session_closed_locks_every_profile_and_another_open_one_does_not() {
    let (_dir, rig) = enrolled().await;
    let sessions = tempfile::tempdir().unwrap();
    let me = crate::agent::testing::me();
    session(sessions.path(), "2", me, "user", "active");
    session(sessions.path(), "3", me, "user", "active");
    assert!(login(&rig, PW).await);
    let ring = Ring::default();
    look(&rig, ring.put(LOCK, "-"), sessions.path()).await;
    look(&rig, ring.put(LOCK, "3"), sessions.path()).await;
    assert!(ring.left().is_empty() && unlocked(&rig).await, "no session named, then session 2 still open");
    std::fs::remove_file(sessions.path().join("2")).unwrap();
    // A profile without the protector, running, locks too, and is audited.
    let _ = rig.agent.dispatch(Op::Status { profile: Some("work".into()) }).await;
    look(&rig, ring.put(LOCK, "3"), sessions.path()).await;
    let mut locked: Vec<_> =
        rig.audit.events().into_iter().filter(|e| e.op == "lock-session").map(|e| e.profile).collect();
    locked.sort();
    assert_eq!(locked, ["org", "work"]);
    assert!(!unlocked(&rig).await);
    assert_eq!(audited(&rig).last(), Some(&("lock-session", Verdict::Confirmed)));
}

#[cfg(target_os = "linux")]
#[test]
fn the_real_keyring_answers_none_for_an_absent_or_unreadable_entry() {
    // A keyring refused by seccomp passes only where CI says it has none (`DYBW_NO_KEYRING_TESTS=1`).
    assert!(dybw_peer::keyring::tests_skipped() || dybw_peer::keyring::readable().is_ok(), "keyctl is refused");
    assert_eq!(UserKeyring.take("dybw:test-absent"), None);
    // A name the kernel cannot take is an error, logged once: no entry.
    assert_eq!(UserKeyring.take("a\0b"), None);
    assert_eq!(UserKeyring.take("a\0b"), None);
}

#[tokio::test]
async fn a_pin_and_a_login_protector_live_side_by_side() {
    const PIN: &str = "246813";
    let pin_add = || Op::UnlockAdd { profile: org(), protector: "pin".into() };
    let remove = |p: &str| Op::UnlockRemove { profile: org(), protector: p.into() };
    let info = |name: &str, left| ProtectorInfo { name: name.into(), attempts_left: left };
    let (dir, rig) = world();
    answer(&rig, &[PASSWORD, PIN, PIN]);
    assert_eq!(rig.agent.dispatch(pin_add()).await, Reply::Done);
    answer(&rig, &[PASSWORD, PW, PW]);
    assert_eq!(rig.agent.dispatch(add()).await, Reply::Done);
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    // One wrong PIN, then cancels: a count of 4 left.
    answer(&rig, &["000000"]);
    assert_eq!(rig.agent.dispatch(Op::Unlock { profile: org() }).await, err(AgentError::Denied));
    assert_eq!(protectors(&rig).await, [info("pin", Some(4)), info("login", None)]);
    asked(&rig);

    // A login password unlocks and leaves the PIN and its count alone.
    assert!(login(&rig, PW).await);
    assert!(asked(&rig).is_empty());
    assert_eq!(protectors(&rig).await, [info("pin", Some(4)), info("login", None)]);

    // A password that comes while the PIN is being typed waits for it, then does nothing.
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    rig.host.answer(Answer::HeldText(PIN));
    let agent = rig.agent.clone();
    let typing = tokio::spawn(async move { agent.dispatch(Op::Unlock { profile: org() }).await });
    crate::read_tests::until(|| rig.host.world().prompts.len() == 1).await;
    let answers = rig.agent.handover(Ring::default().put(LOGIN, PW), Path::new("/x")).await;
    rig.host.world().release.notify_one();
    assert_eq!(typing.await.unwrap(), Reply::Done);
    for answer in answers {
        assert_eq!(answer.await.unwrap(), Reply::Done);
    }
    let logins = |rig: &Rig| audited(rig).iter().filter(|(op, _)| *op == "unlock-login").count();
    assert_eq!(logins(&rig), 1, "only the first password unlocked");
    assert_eq!(protectors(&rig).await, [info("pin", Some(5)), info("login", None)], "the right PIN reset the count");

    // A password that opens nothing drops the login protector only.
    assert_eq!(rig.agent.dispatch(lock_op()).await, Reply::Done);
    assert!(!login(&rig, "reset by root").await);
    assert!(!blob(&dir).exists());
    assert_eq!(protectors(&rig).await, [info("pin", Some(5))]);

    // Removing one keeps the other, both ways.
    answer(&rig, &[PIN]);
    assert_eq!(rig.agent.dispatch(Op::Unlock { profile: org() }).await, Reply::Done);
    answer(&rig, &[PASSWORD, PW, PW]);
    assert_eq!(rig.agent.dispatch(add()).await, Reply::Done);
    assert_eq!(rig.agent.dispatch(remove("pin")).await, Reply::Done);
    assert_eq!(protectors(&rig).await, [info("login", None)]);
    answer(&rig, &[PASSWORD, PIN, PIN]);
    assert_eq!(rig.agent.dispatch(pin_add()).await, Reply::Done);
    assert_eq!(rig.agent.dispatch(remove("login")).await, Reply::Done);
    assert_eq!(protectors(&rig).await, [info("pin", Some(5))]);
}
