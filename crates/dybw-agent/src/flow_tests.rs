//! Login, unlock, sync, lock and status through the agent, against the scripted host: no network, no pinentry.
#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use dybw_proto::{AgentError, Op, Reply, Target};

use crate::agent::Agent;
use crate::agent::testing::{agent_world, seed_credentials, unlock};
use crate::host::fake::{Answer, PASSWORD};

const CID: &str = "user.0b3b6d1e-6f3a-4a52-9f54-2f1c8f0c9a11";
const SECRET: &str = "abcdefghij0123456789XY";

fn err(error: AgentError) -> Reply {
    Reply::Error { error }
}

fn state(dir: &std::path::Path, profile: &str, file: &str) -> std::path::PathBuf {
    dir.join("state/dybw/profiles").join(profile).join(file)
}

fn cache(dir: &std::path::Path, profile: &str) -> std::path::PathBuf {
    dir.join("cache/dybw/profiles").join(profile).join("sync.json")
}

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

async fn run(agent: &Agent, op: Op) -> Reply {
    agent.dispatch(op).await
}

fn login(p: &str) -> Op {
    Op::Login { profile: Some(p.into()) }
}

fn unlock_op(p: &str) -> Op {
    Op::Unlock { profile: Some(p.into()) }
}

fn sync_op(p: &str) -> Op {
    Op::Sync { target: Target::Profile(p.into()) }
}

fn lock_op(p: &str) -> Op {
    Op::Lock { target: Target::Profile(p.into()) }
}

async fn status(agent: &Agent, p: &str) -> (bool, bool, Option<u64>) {
    match run(agent, Op::Status { profile: Some(p.into()) }).await {
        Reply::Status { profiles, .. } => (profiles[0].logged_in, profiles[0].unlocked, profiles[0].last_sync),
        other => panic!("{other:?}"),
    }
}

/// Wait for `ready`, at most 5 s: the worker runs on its own thread.
async fn until(ready: impl Fn() -> bool) {
    for _ in 0..500 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("gave up waiting");
}

#[tokio::test]
async fn login_asks_for_both_halves_checks_the_key_and_stores_it_privately() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    host.answer(Answer::Text(CID));
    host.answer(Answer::Text(SECRET));
    assert_eq!(run(&agent, login("work")).await, Reply::Done);

    let file = state(dir.path(), "work", "credentials");
    assert_eq!(mode(&file), 0o600);
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("identity_origin = \"https://w.example.org\"") && text.contains(CID));
    {
        let w = host.world();
        assert_eq!(w.asked.len(), 2);
        assert!(w.asked[0].0.contains("client_id") && w.asked[1].0.contains("client_secret"));
        assert!(w.asked.iter().all(|(d, e)| !d.contains(SECRET) && e.is_none()), "no secret in a question");
        assert_eq!(w.device_names, ["dybw+on+testhost"]);
        // Servers hide SSH key items from clients older than 2024.12.
        assert_eq!(w.client_versions, ["2025.1.0"]);
        assert_eq!(w.count("/identity/connect/token"), 1);
    }
    assert!(status(&agent, "work").await.0);
}

#[tokio::test]
async fn login_stores_nothing_unless_it_was_asked_for_and_the_server_took_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    let file = state(dir.path(), "work", "credentials");
    let tries = |first: Answer, second: Option<Answer>| {
        host.answer(first);
        second.into_iter().for_each(|a| host.answer(a));
    };

    tries(Answer::Cancel, None);
    assert_eq!(run(&agent, login("work")).await, err(AgentError::Denied));
    tries(Answer::Text(""), None);
    assert_eq!(run(&agent, login("work")).await, err(AgentError::Denied), "an empty answer is a no");
    tries(Answer::Timeout, None);
    assert_eq!(run(&agent, login("work")).await, err(AgentError::Denied), "a timeout is a no");
    tries(Answer::Fail, None);
    assert_eq!(run(&agent, login("work")).await, err(AgentError::Prompt));
    tries(Answer::Text(CID), Some(Answer::Cancel));
    assert_eq!(run(&agent, login("work")).await, err(AgentError::Denied), "cancel at the secret");
    assert_eq!(host.world().requests.len(), 0, "nothing was sent before the key was complete");

    host.world().token_status = 400;
    tries(Answer::Text(CID), Some(Answer::Text(SECRET)));
    assert_eq!(run(&agent, login("work")).await, err(AgentError::Server), "a refused key");
    host.world().token_status = 200;
    host.world().online = false;
    tries(Answer::Text(CID), Some(Answer::Text(SECRET)));
    assert_eq!(run(&agent, login("work")).await, err(AgentError::Network));
    assert!(!file.exists());
}

#[tokio::test]
async fn login_needs_an_api_key_profile_and_a_usable_server_url() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    assert_eq!(run(&agent, login("pw")).await, err(AgentError::Config), "auth = password is not in P4.1");
    assert_eq!(run(&agent, login("plain")).await, err(AgentError::Config), "plain http to a remote host");
    assert!(host.world().asked.is_empty());
}

#[tokio::test]
async fn unlock_needs_a_login_and_a_key_saved_for_this_server() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::NotLoggedIn));
    assert_eq!(run(&agent, unlock_op("pw")).await, err(AgentError::Config));
    assert_eq!(run(&agent, unlock_op("plain")).await, err(AgentError::Config));
    assert!(host.world().asked.is_empty(), "no password question before there is a key");
    seed_credentials(&agent, "work");
    let file = state(dir.path(), "work", "credentials");
    std::fs::write(
        &file,
        "identity_origin = \"https://elsewhere.example.org\"\nclient_id = \"a\"\nclient_secret = \"b\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Config), "a key for another server");
    assert!(host.world().asked.is_empty() && host.world().requests.is_empty());
}

#[tokio::test]
async fn an_online_unlock_opens_the_vault_and_keeps_the_ciphertext_privately() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    seed_credentials(&agent, "work");
    assert_eq!(status(&agent, "work").await, (true, false, None));
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(run(&agent, unlock_op("work")).await, Reply::Done);

    let (logged_in, unlocked, last_sync) = status(&agent, "work").await;
    assert!(logged_in && unlocked && last_sync.is_some());
    let cache = cache(dir.path(), "work");
    assert_eq!(mode(&cache), 0o600);
    let saved = std::fs::read_to_string(&cache).unwrap();
    assert!(saved.contains("\"email\":\"pbkdf2@vectors.invalid\"") && saved.contains("\"type\":\"pbkdf2\""));
    assert!(!saved.contains(PASSWORD));
    assert_eq!(mode(&state(dir.path(), "work", "core/kdf-pin")), 0o600, "the core's pin is kept as a 0600 file");
    {
        let w = host.world();
        assert_eq!(w.asked.len(), 1);
        assert!(w.asked[0].0.contains("work") && w.asked[0].0.contains("pbkdf2@vectors.invalid"));
        assert_eq!((w.count("connect/token"), w.count("excludeDomains=true"), w.count("prelogin")), (1, 1, 1));
        assert_eq!(w.device_names, ["dybw+on+testhost"]);
    }
    // Unlocked already: nothing is asked or sent again.
    assert_eq!(run(&agent, unlock_op("work")).await, Reply::Done);
    {
        let w = host.world();
        assert_eq!((w.asked.len(), w.count("connect/token")), (1, 1));
    }
}

#[tokio::test]
async fn a_wrong_password_is_asked_again_with_the_reason_and_gives_up_after_three() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    seed_credentials(&agent, "work");
    host.answer(Answer::Text("nope"));
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(run(&agent, unlock_op("work")).await, Reply::Done);
    {
        let w = host.world();
        assert_eq!(w.asked.len(), 2);
        assert_eq!(w.asked[0].1, None);
        assert_eq!(w.asked[1].1.as_deref(), Some("Wrong master password."));
    }
    run(&agent, lock_op("work")).await;
    host.world().asked.clear();
    for _ in 0..3 {
        host.answer(Answer::Text("nope"));
    }
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Denied));
    assert_eq!(host.world().asked.len(), 3);
    assert!(!status(&agent, "work").await.1);
}

#[tokio::test]
async fn a_cancelled_or_failed_password_prompt_is_an_error_not_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    seed_credentials(&agent, "work");
    host.answer(Answer::Cancel);
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Denied));
    host.answer(Answer::Fail);
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Prompt));
    assert_eq!(host.world().requests.len(), 0, "no request without a password");
    // The worker is still fine.
    unlock(&agent, &host, "work").await;
}

#[tokio::test]
async fn when_the_server_is_unreachable_the_offline_copy_unlocks_and_nothing_is_synced() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    unlock(&agent, &host, "work").await;
    run(&agent, lock_op("work")).await;
    assert!(!status(&agent, "work").await.1);
    let syncs = host.world().count("excludeDomains=true");

    host.world().online = false;
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(run(&agent, unlock_op("work")).await, Reply::Done);
    assert!(status(&agent, "work").await.1);
    assert_eq!(host.world().count("excludeDomains=true"), syncs, "the copy was used, not the server");
    assert!(status(&agent, "work").await.2.is_some(), "the last sync is the copy's");

    // A wrong password offline is a wrong password.
    run(&agent, lock_op("work")).await;
    for _ in 0..3 {
        host.answer(Answer::Text("nope"));
    }
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Denied));
}

#[tokio::test]
async fn offline_without_a_usable_copy_is_a_network_error() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    unlock(&agent, &host, "work").await;
    run(&agent, lock_op("work")).await;
    host.world().online = false;
    let file = cache(dir.path(), "work");
    let broken: [&dyn Fn(); 4] = [
        &|| std::fs::remove_file(&file).unwrap(),
        &|| std::fs::write(&file, "not json").unwrap(),
        &|| std::fs::write(&file, r#"{"email":"someone@else.invalid","sync":{}}"#).unwrap(),
        &|| {
            std::fs::remove_file(&file).unwrap();
            std::fs::create_dir(&file).unwrap();
        },
    ];
    for break_it in broken {
        let _ = std::fs::remove_dir(&file);
        break_it();
        host.answer(Answer::Text(PASSWORD));
        assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Network));
        assert!(!status(&agent, "work").await.1);
    }
}

#[tokio::test]
async fn a_server_that_refuses_the_key_is_not_offline() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    unlock(&agent, &host, "work").await;
    run(&agent, lock_op("work")).await;
    host.world().token_status = 400;
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Server));
    assert!(!status(&agent, "work").await.1, "the copy was not used behind a refusal");
}

#[tokio::test]
async fn a_weaker_kdf_than_the_pinned_one_and_a_broken_state_dir_refuse_the_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    seed_credentials(&agent, "work");
    // ADR 0017: the device pinned 1,000,000 iterations for this server; the account offers 600,000.
    let pin = state(dir.path(), "work", "core/kdf-pin");
    std::fs::create_dir_all(pin.parent().unwrap()).unwrap();
    let origin = "https://w.example.org";
    std::fs::write(&pin, format!(r#"{{"kdf":0,"iterations":1000000,"memory":0,"parallelism":0,"origin":"{origin}"}}"#))
        .unwrap();
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Refused("kdf-downgrade".into())));
    assert!(!status(&agent, "work").await.1);

    // The core cannot read its own state: an internal error, not a refusal by the server.
    std::fs::remove_file(&pin).unwrap();
    std::fs::remove_dir(pin.parent().unwrap()).unwrap();
    std::fs::write(pin.parent().unwrap(), "in the way").unwrap();
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Internal));
}

#[tokio::test]
async fn sync_needs_an_unlocked_profile_and_refreshes_the_copy() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    assert_eq!(run(&agent, sync_op("work")).await, err(AgentError::Locked));
    unlock(&agent, &host, "work").await;
    host.world().sync_marker = 5;
    assert_eq!(run(&agent, sync_op("work")).await, Reply::Done);
    assert_eq!(host.world().count("excludeDomains=true"), 2);
    let saved = std::fs::read_to_string(cache(dir.path(), "work")).unwrap();
    assert!(saved.contains("\"marker\":5"), "the new copy is the offline copy");
    assert_eq!(mode(&cache(dir.path(), "work")), 0o600);
    assert!(status(&agent, "work").await.1);
}

#[tokio::test]
async fn a_failed_sync_says_why_and_leaves_the_vault_unlocked() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    unlock(&agent, &host, "work").await;
    host.world().online = false;
    assert_eq!(run(&agent, sync_op("work")).await, err(AgentError::Network));
    host.world().online = true;
    host.world().token_status = 400;
    assert_eq!(run(&agent, sync_op("work")).await, err(AgentError::Server));
    host.world().token_status = 200;
    host.world().sync_fails = true;
    assert_eq!(run(&agent, sync_op("work")).await, err(AgentError::Server), "logged in, but /sync refused");
    host.world().sync_fails = false;
    std::fs::remove_file(state(dir.path(), "work", "credentials")).unwrap();
    assert_eq!(run(&agent, sync_op("work")).await, err(AgentError::NotLoggedIn));
    assert!(status(&agent, "work").await.1);
}

#[tokio::test]
async fn sync_all_skips_locked_profiles_and_reports_the_first_failure() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    unlock(&agent, &host, "work").await;
    status(&agent, "home").await; // a worker that is locked
    assert_eq!(run(&agent, Op::Sync { target: Target::All }).await, Reply::Done);
    assert_eq!(host.world().count("excludeDomains=true"), 2, "only the unlocked profile synced");
    unlock(&agent, &host, "home").await;
    host.world().online = false;
    assert_eq!(run(&agent, Op::Sync { target: Target::All }).await, err(AgentError::Network));
}

#[tokio::test]
async fn an_unlocked_profile_syncs_on_its_interval_and_a_lock_stops_it() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    unlock(&agent, &host, "fast").await; // sync_interval_seconds = 1
    until(|| host.world().count("excludeDomains=true") >= 2).await;
    // A failing periodic sync is logged and the vault stays unlocked.
    host.world().online = false;
    let tokens = host.world().count("connect/token");
    until(|| host.world().count("connect/token") > tokens).await;
    assert!(status(&agent, "fast").await.1);
    run(&agent, lock_op("fast")).await;
    let seen = host.world().requests.len();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(host.world().requests.len(), seen, "a locked profile does not sync");
}

#[tokio::test]
async fn a_periodic_sync_skips_a_round_while_another_operation_runs() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    unlock(&agent, &host, "fast").await;
    host.world().sync_hangs = true;
    let base = host.world().count("excludeDomains=true");
    let hung = tokio::spawn({
        let agent = agent.clone();
        async move { run(&agent, sync_op("fast")).await }
    });
    until(|| host.world().count("excludeDomains=true") > base).await;
    // Whichever sync got the turn holds it: the interval (1 s) ticks twice and no other sync starts.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(host.world().count("excludeDomains=true"), base + 1);
    run(&agent, lock_op("fast")).await;
    assert_eq!(hung.await.unwrap(), err(AgentError::Locked));
}

#[tokio::test]
async fn lock_cancels_an_unlock_waiting_on_the_user_and_nothing_queues_behind_it() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, clock, host) = agent_world(dir.path());
    seed_credentials(&agent, "work");
    host.answer(Answer::Hang);
    let waiting = tokio::spawn({
        let agent = agent.clone();
        async move { run(&agent, unlock_op("work")).await }
    });
    until(|| host.world().asked.len() == 1).await;
    let quick = Duration::from_secs(2);
    // The prompt is open; the loop is free.
    assert!(tokio::time::timeout(quick, status(&agent, "work")).await.is_ok());
    clock.advance(Duration::from_secs(1), Duration::from_secs(1));
    assert!(tokio::time::timeout(quick, agent.tick()).await.is_ok(), "the idle check does not queue behind it");
    assert_eq!(tokio::time::timeout(quick, run(&agent, lock_op("work"))).await.unwrap(), Reply::Done);
    assert_eq!(waiting.await.unwrap(), err(AgentError::Locked));
    assert!(!status(&agent, "work").await.1);
    // The profile is usable again.
    unlock(&agent, &host, "work").await;
}

#[tokio::test]
async fn lock_cancels_a_sync_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    unlock(&agent, &host, "work").await;
    host.world().sync_hangs = true;
    let hung = tokio::spawn({
        let agent = agent.clone();
        async move { run(&agent, sync_op("work")).await }
    });
    until(|| host.world().count("excludeDomains=true") >= 2).await;
    assert_eq!(run(&agent, lock_op("work")).await, Reply::Done);
    assert_eq!(hung.await.unwrap(), err(AgentError::Locked));
    assert_eq!(run(&agent, sync_op("work")).await, err(AgentError::Locked));
    assert!(!status(&agent, "work").await.1);
}

#[tokio::test]
async fn a_broken_device_file_or_key_file_is_an_internal_error_not_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    // The device id cannot be read: `devices` is a file.
    seed_credentials(&agent, "work");
    let devices = state(dir.path(), "work", "devices");
    std::fs::write(&devices, "in the way").unwrap();
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Internal));
    std::fs::remove_file(&devices).unwrap();

    // The key cannot be stored: a directory sits where the file goes. Nothing is claimed as stored.
    let file = state(dir.path(), "home", "credentials");
    std::fs::create_dir_all(&file).unwrap();
    host.answer(Answer::Text(CID));
    host.answer(Answer::Text(SECRET));
    assert_eq!(run(&agent, login("home")).await, err(AgentError::Internal));
}

#[tokio::test]
async fn a_host_that_cannot_make_a_client_or_a_device_name_is_an_internal_error() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    seed_credentials(&agent, "work");
    host.world().http_fails = true;
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Internal));
    host.world().http_fails = false;
    host.world().hostname = "bad\nname".into();
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(
        run(&agent, unlock_op("work")).await,
        err(AgentError::Internal),
        "a device name with a control character"
    );
    assert_eq!(host.world().requests.len(), 0);
}

#[tokio::test]
async fn a_sync_that_cannot_start_a_client_says_so_and_keeps_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    unlock(&agent, &host, "work").await;
    host.world().http_fails = true;
    assert_eq!(run(&agent, sync_op("work")).await, err(AgentError::Internal));
    assert!(status(&agent, "work").await.1);
}

#[tokio::test]
async fn an_unreadable_pin_and_a_security_downgrade_are_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    seed_credentials(&agent, "work");
    let core = state(dir.path(), "work", "core");
    std::fs::create_dir_all(&core).unwrap();
    std::fs::write(core.join("kdf-pin"), "not json").unwrap();
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Refused("kdf-pin-unreadable".into())));
    std::fs::remove_file(core.join("kdf-pin")).unwrap();
    // This device saw security state version 99; a legacy key offers 0.
    std::fs::write(core.join("security-version"), "99").unwrap();
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Refused("security-downgrade".into())));
    let shown = AgentError::Refused("kdf-downgrade".into()).to_string();
    assert!(shown.contains("kdf-downgrade") && shown.contains("agent log"));
    assert!(!status(&agent, "work").await.1);
}

#[tokio::test]
async fn input_that_cannot_be_an_api_key_is_refused_before_anything_is_sent_or_stored() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    let file = state(dir.path(), "work", "credentials");
    // The master password typed at the client_id question, then at the client_secret question.
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(run(&agent, login("work")).await, err(AgentError::NotAnApiKey));
    for bad in
        ["with space and symbols!!", "short", "abcdefghij0123456789XYabcdefghij0123456789XYabcdefghij0123456789XYZ"]
    {
        host.answer(Answer::Text(CID));
        host.answer(Answer::Text(bad));
        assert_eq!(run(&agent, login("work")).await, err(AgentError::NotAnApiKey), "{bad}");
    }
    for bad_id in ["user.not-a-uuid", "0b3b6d1e-6f3a-4a52-9f54-2f1c8f0c9a11", "user.0b3b6d1e6f3a4a529f542f1c8f0c9a11"] {
        host.answer(Answer::Text(bad_id));
        assert_eq!(run(&agent, login("work")).await, err(AgentError::NotAnApiKey), "{bad_id}");
    }
    assert!(host.world().requests.is_empty(), "nothing was sent");
    assert!(!file.exists(), "nothing was stored");
    // Upper-case hex is a uuid too.
    host.answer(Answer::Text("user.0B3B6D1E-6F3A-4A52-9F54-2F1C8F0C9A11"));
    host.answer(Answer::Text(SECRET));
    assert_eq!(run(&agent, login("work")).await, Reply::Done);
    let w = host.world();
    assert!(w.asked.iter().all(|(d, _)| d.contains("NOT your master password")), "every question says what it is");
}

#[tokio::test]
async fn a_second_login_waits_for_the_first_and_never_opens_a_second_pinentry() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    host.answer(Answer::Hang);
    let first = tokio::spawn({
        let agent = agent.clone();
        async move { run(&agent, login("work")).await }
    });
    until(|| host.world().asked.len() == 1).await;
    let second = tokio::spawn({
        let agent = agent.clone();
        async move { run(&agent, login("work")).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(host.world().asked.len(), 1, "one question open, not two");
    assert!(!second.is_finished());
    run(&agent, lock_op("work")).await;
    assert_eq!(first.await.unwrap(), err(AgentError::Locked));
    assert_eq!(second.await.unwrap(), err(AgentError::Locked));
}

#[tokio::test]
async fn unusable_unlock_data_is_a_server_refusal_with_the_reason_in_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    unlock(&agent, &host, "work").await;
    run(&agent, lock_op("work")).await;
    // An offline copy without its KDF cannot unlock an account that has no `masterPasswordUnlock`.
    let file = cache(dir.path(), "work");
    let mut saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    saved["kdf"] = serde_json::Value::Null;
    std::fs::write(&file, saved.to_string()).unwrap();
    host.world().online = false;
    host.answer(Answer::Text(PASSWORD));
    assert_eq!(run(&agent, unlock_op("work")).await, err(AgentError::Server));
    assert!(!status(&agent, "work").await.1);
}
