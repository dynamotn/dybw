//! `code`, the writes (`add`, `edit`, `remove`) and the master-password reprompt through the agent, against the
//! scripted host: the fake server applies each cipher write to what its next `/sync` sends.
#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::time::{Duration, SystemTime};

use dybw_core::crypto::SymmetricKey;
use dybw_core::totp::TotpKey;
use dybw_native::ports::random::OsRandom;
use dybw_proto::{AgentError, Charset, Field, Op, Part, Reply, Select};
use serde_json::{Value, json};

use crate::agent::testing::{Rig, rig, unlock};
use crate::caller::{At, Caller, Via};
use crate::host::fake::{Answer, PASSWORD};
use crate::policy::Verdict;
use crate::read_tests::{VAULT, err, get_op, history_op, items, text, until};

/// The pbkdf2 vector account's user key (dybw-core `vectors/accounts/pbkdf2.json`), to make items in tests.
const USER_KEY: [u8; 64] = [
    57, 170, 193, 44, 87, 151, 157, 242, 110, 167, 220, 208, 63, 212, 71, 88, 33, 96, 173, 55, 161, 4, 68, 125, 62,
    143, 111, 21, 229, 119, 245, 58, 126, 62, 189, 157, 50, 105, 135, 55, 158, 238, 160, 126, 221, 169, 125, 245, 45,
    80, 172, 232, 27, 90, 67, 184, 0, 61, 199, 122, 33, 200, 62, 197,
];
const REV: &str = "2026-01-01T00:00:00.000Z";
const TOTP: &str = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";
/// 30 s periods start here (1 700 000 010 is a multiple of 30).
const PERIOD_START: u64 = 1_700_000_010;

fn enc(text: &str) -> String {
    SymmetricKey::from_bytes(&USER_KEY).unwrap().encrypt_str(text, &OsRandom).unwrap()
}

/// A personal login under the user key, with the password `old-pass`.
fn login(id: &str, name: &str, totp: Option<&str>) -> Value {
    json!({
        "id": id, "type": 1, "name": enc(name), "notes": null, "folderId": null, "organizationId": null,
        "reprompt": 0, "revisionDate": REV, "fields": [], "passwordHistory": [],
        "login": { "username": enc("me"), "password": enc("old-pass"), "totp": totp.map(enc), "uris": null },
    })
}

/// The fixture vault, the marked item `m1` and the logins `x1` (no TOTP key) and `x2` (digits 12), unlocked on
/// `work`, after `edit`. No item asks for a reprompt unless `edit` says so.
async fn setup(edit: impl FnOnce(&mut Value)) -> (tempfile::TempDir, Rig) {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    let mut vault: Value = serde_json::from_str(VAULT).unwrap();
    let list = vault["ciphers"].as_array_mut().unwrap();
    list.push(serde_json::from_str(include_str!("../tests/fixtures/marked-item.json")).unwrap());
    list.push(login("x1", "Plain", None));
    list.push(login("x2", "Twelve", Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12")));
    for c in list {
        c["reprompt"] = json!(0);
        c["revisionDate"] = json!(REV);
    }
    edit(&mut vault);
    rig.host.vault(&vault.to_string());
    unlock(&rig.agent, &rig.host, "work").await;
    (dir, rig)
}

fn reprompting(id: &'static str) -> impl FnOnce(&mut Value) {
    move |v| {
        v["ciphers"].as_array_mut().unwrap().iter_mut().filter(|c| c["id"] == id).for_each(|c| c["reprompt"] = json!(1))
    }
}

fn w() -> Option<String> {
    Some("work".into())
}

fn code_op(needle: &str, next: bool) -> Op {
    Op::Code { profile: w(), needle: needle.into(), user: None, folder: None, ignorecase: false, next }
}

fn add_op(name: &str, folder: Option<&str>, ask: &[Part]) -> Op {
    Op::Add {
        profile: w(),
        name: name.into(),
        user: Some("robot".into()),
        uris: vec!["https://new.example.invalid".into()],
        folder: folder.map(Into::into),
        ask: ask.to_vec(),
    }
}

fn edit_op(needle: &str, ask: &[Part]) -> Op {
    Op::Edit { profile: w(), needle: needle.into(), user: None, folder: None, ask: ask.to_vec() }
}

fn remove_op(needle: &str) -> Op {
    Op::Remove { profile: w(), needle: needle.into(), user: None, folder: None }
}

fn ai() -> Caller {
    Caller::Ai { harness: "claude".into(), via: Via::Ancestry }
}

fn unknown() -> Caller {
    Caller::Unknown { why: "orphan".into(), peer: None }
}

/// A plain program: "always" stores a grant for it.
fn program() -> Caller {
    Caller::Invoker {
        exe: "/usr/local/bin/mytool".into(),
        script: None,
        hash: "h1".into(),
        relative: false,
        at: At::default(),
    }
}

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn code_at(secs: u64) -> String {
    TotpKey::parse(TOTP).unwrap().generate(secs).code().to_owned()
}

/// Every audited (op, item, verdict).
fn audited(rig: &Rig) -> Vec<(&'static str, Option<String>, Verdict)> {
    rig.audit.events().into_iter().map(|e| (e.op, e.item, e.verdict)).collect()
}

/// How many cipher writes reached the server.
fn writes(rig: &Rig) -> usize {
    rig.host.world().bodies.len()
}

fn cipher(rig: &Rig, id: &str) -> Value {
    let list: Vec<Value> = serde_json::from_str(&rig.host.world().ciphers).unwrap();
    list.into_iter().find(|c| c["id"] == id).unwrap()
}

#[tokio::test]
async fn an_ai_caller_gets_no_code_and_writes_nothing_an_unknown_one_writes_nothing() {
    let (_dir, rig) = setup(|_| {}).await;
    let asked = rig.host.world().asked.len();
    for op in [
        code_op("c1", false),
        add_op("New", None, &[Part::Password]),
        edit_op("x1", &[Part::Password]),
        remove_op("x1"),
    ] {
        rig.host.allow();
        assert_eq!(rig.agent.dispatch_as(op, ai()).await, err(AgentError::Denied));
    }
    for op in [add_op("New", None, &[Part::Password]), edit_op("x1", &[Part::Password]), remove_op("x1")] {
        rig.host.allow();
        assert_eq!(rig.agent.dispatch_as(op, unknown()).await, err(AgentError::Denied));
    }
    assert!(rig.host.world().confirmed.is_empty(), "never asked");
    assert_eq!(rig.host.world().asked.len(), asked, "no password asked");
    assert_eq!(writes(&rig), 0);
    let ops: Vec<_> = audited(&rig).into_iter().map(|(op, item, v)| (op, item.is_none(), v)).collect();
    let denied = |op| (op, true, Verdict::Denied);
    assert_eq!(
        ops,
        [
            denied("code"),
            denied("add"),
            denied("edit"),
            denied("remove"),
            denied("add"),
            denied("edit"),
            denied("remove")
        ]
    );
    // An unknown caller may still ask for a code: the user is asked, as for any value.
    rig.host.allow();
    assert!(matches!(rig.agent.dispatch_as(code_op("c1", false), unknown()).await, Reply::Code { .. }));
    assert_eq!(rig.host.world().offered, [false]);
}

#[tokio::test]
async fn a_code_is_a_value_read_behind_the_same_gate_and_never_the_key() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.clock.set_wall(at(PERIOD_START + 7));
    assert_eq!(rig.agent.dispatch(code_op("c1", false)).await, err(AgentError::Denied), "the user said no");
    assert_eq!(rig.agent.opens("work").await, 0, "nothing opened without a yes");
    rig.host.allow();
    let Reply::Code { code, seconds_left } = rig.agent.dispatch(code_op("c1", false)).await else { panic!() };
    assert_eq!((code.expose(), seconds_left), (code_at(PERIOD_START + 7).as_str(), 23));
    let asked = rig.host.world().confirmed[1].clone();
    assert!(
        asked.ends_with(&format!("(dybw code) to read a TOTP code of the item {}?", crate::read_tests::C1)),
        "{asked}"
    );
    let id = Some("c1".to_owned());
    assert_eq!(audited(&rig), [("code", id.clone(), Verdict::Declined), ("code", id, Verdict::Confirmed)]);
    // A grant of a program covers codes, as any single value.
    rig.host.allow_always();
    assert!(matches!(rig.agent.dispatch_as(code_op("c1", false), program()).await, Reply::Code { .. }));
    assert!(matches!(rig.agent.dispatch_as(code_op("c1", false), program()).await, Reply::Code { .. }));
    assert_eq!(rig.host.world().confirmed.len(), 3, "the grant answered the second");
}

#[tokio::test]
async fn code_next_waits_for_the_next_period_when_under_five_seconds_are_left() {
    let (_dir, rig) = setup(|_| {}).await;
    let wall = at(PERIOD_START) - Duration::from_millis(50);
    rig.clock.set_wall(wall);
    rig.host.allow();
    let Reply::Code { code, seconds_left } = rig.agent.dispatch(code_op("c1", false)).await else { panic!() };
    assert_eq!((code.expose(), seconds_left), (code_at(PERIOD_START - 1).as_str(), 1));
    rig.host.allow();
    let Reply::Code { code, seconds_left } = rig.agent.dispatch(code_op("c1", true)).await else { panic!() };
    assert_eq!((code.expose(), seconds_left), (code_at(PERIOD_START).as_str(), 30));
    // With 5 s or more left, `next` changes nothing.
    rig.clock.set_wall(at(PERIOD_START - 5));
    rig.host.allow();
    let Reply::Code { code, seconds_left } = rig.agent.dispatch(code_op("c1", true)).await else { panic!() };
    assert_eq!((code.expose(), seconds_left), (code_at(PERIOD_START - 5).as_str(), 5));
}

#[tokio::test]
async fn a_code_of_an_item_without_a_totp_key_or_with_one_out_of_range_says_so() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(code_op("x1", false)).await, err(AgentError::NoSuchField("totp".into())));
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(code_op("n1", false)).await, err(AgentError::NoSuchField("totp".into())), "a note");
    rig.host.allow();
    let reply = rig.agent.dispatch(code_op("x2", false)).await;
    assert_eq!(reply, err(AgentError::Totp("the TOTP digits 12 is outside 1..=10".into())));
    let Reply::Error { error } = reply else { panic!() };
    assert!(!error.to_string().contains("JBSWY3DPEHPK3PXP"), "the key is never shown");
}

#[tokio::test]
async fn edit_asks_the_new_password_in_the_pinentry_keeps_the_old_one_and_syncs() {
    let (_dir, rig) = setup(|_| {}).await;
    let syncs = rig.host.world().count("/api/sync?excludeDomains=true");
    rig.host.allow();
    rig.host.answer(Answer::Text("new-pass"));
    assert_eq!(rig.agent.dispatch(edit_op("Plain", &[Part::Password])).await, Reply::Done);
    {
        let world = rig.host.world();
        let confirm = world.confirmed[0].clone();
        assert!(
            confirm.ends_with(
                "(dybw edit) to change the password of the item \"Plain\" (user \"me\", no folder, id x1)? (asked for \
                 every change)"
            ),
            "{confirm}"
        );
        let (desc, _) = world.asked.last().unwrap().clone();
        assert!(
            desc.contains("the new value of the password of the item \"Plain\" (NOT your master password)"),
            "{desc}"
        );
        assert_eq!(world.prompts.last().unwrap(), "New password:");
        assert_eq!(world.count("/api/ciphers/x1"), 1);
        assert_eq!(world.count("/api/sync?excludeDomains=true"), syncs + 2, "fetched before, synced after");
        assert!(!world.bodies[0].to_string().contains("new-pass"), "sent encrypted");
    }
    assert_eq!(audited(&rig), [("edit", Some("x1".to_owned()), Verdict::Confirmed)]);
    rig.host.allow();
    assert_eq!(text(rig.agent.dispatch(get_op("x1", Select::Password)).await), "new-pass", "the vault was synced");
    rig.host.allow();
    let Reply::History { entries } = rig.agent.dispatch(history_op("x1")).await else { panic!() };
    assert_eq!(entries[0].password.expose(), "old-pass");
}

#[tokio::test]
async fn a_write_that_went_through_is_done_even_when_the_sync_after_it_fails() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.world().sync_fails_after_write = true;
    rig.host.allow();
    rig.host.answer(Answer::Text("new-pass"));
    assert_eq!(rig.agent.dispatch(edit_op("x1", &[Part::Password])).await, Reply::Done);
    assert_eq!(writes(&rig), 1);
    rig.host.allow();
    assert_eq!(text(rig.agent.dispatch(get_op("x1", Select::Password)).await), "old-pass", "the copy is behind");
    rig.host.world().sync_fails_after_write = false;
    assert_eq!(rig.agent.dispatch(Op::Sync { target: dybw_proto::Target::Profile("work".into()) }).await, Reply::Done);
    rig.host.allow();
    assert_eq!(text(rig.agent.dispatch(get_op("x1", Select::Password)).await), "new-pass", "until the next sync");
}

#[tokio::test]
async fn a_deny_entry_refuses_every_write_of_that_program_without_asking() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.allow();
    let deny = dybw_proto::PolicyAction::Deny { invoker: "/usr/local/bin/mytool".into(), script: None };
    assert_eq!(rig.agent.dispatch(Op::Policy { profile: w(), action: deny }).await, Reply::Done);
    for op in [add_op("New", None, &[]), edit_op("x1", &[Part::Notes]), remove_op("m1")] {
        rig.host.allow();
        assert_eq!(rig.agent.dispatch_as(op, program()).await, err(AgentError::Denied));
    }
    assert_eq!(rig.host.world().confirmed.len(), 1, "only the policy change was asked");
    // Refused before the plan: not even a marked item's field names were opened.
    assert_eq!(rig.agent.opens("work").await, 0);
    assert_eq!(writes(&rig), 0);
    let verdicts: Vec<_> = audited(&rig).into_iter().map(|(op, _, v)| (op, v)).collect();
    let denied = |op| (op, Verdict::Denied);
    assert_eq!(verdicts[1..], [denied("add"), denied("edit"), denied("remove")]);
}

#[tokio::test]
async fn every_write_is_asked_every_time_and_never_offered_always() {
    let (_dir, rig) = setup(|_| {}).await;
    // The program holds a grant for values.
    rig.host.allow_always();
    rig.agent.dispatch_as(get_op("x1", Select::Password), program()).await;
    for pass in ["p1", "p2"] {
        rig.host.allow_always();
        rig.host.answer(Answer::Text(pass));
        assert_eq!(rig.agent.dispatch_as(edit_op("x1", &[Part::Password]), program()).await, Reply::Done);
    }
    assert_eq!(rig.host.world().offered, [true, false, false]);
    // No yes, no write.
    assert_eq!(rig.agent.dispatch_as(remove_op("x1"), program()).await, err(AgentError::Denied));
    assert_eq!(rig.host.world().confirmed.len(), 4);
    assert_eq!(writes(&rig), 2);
    let verdicts: Vec<_> = audited(&rig).into_iter().map(|(op, _, v)| (op, v)).collect();
    assert_eq!(
        verdicts,
        [
            ("get", Verdict::Remembered),
            ("edit", Verdict::Confirmed),
            ("edit", Verdict::Confirmed),
            ("remove", Verdict::Declined)
        ]
    );
}

#[tokio::test]
async fn a_cancelled_value_or_an_edit_that_changes_nothing_sends_nothing() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(edit_op("x1", &[Part::Password])).await, err(AgentError::Denied), "no answer");
    rig.host.allow();
    rig.host.answer(Answer::Text("old-pass"));
    assert_eq!(rig.agent.dispatch(edit_op("x1", &[Part::Password])).await, Reply::Done);
    assert_eq!(writes(&rig), 0);
    let verdicts: Vec<_> = audited(&rig).into_iter().map(|(_, _, v)| v).collect();
    assert_eq!(verdicts, [Verdict::Declined, Verdict::Confirmed]);
}

#[tokio::test]
async fn an_edit_of_the_totp_key_or_of_nothing_is_refused_before_anything_is_asked() {
    let (_dir, rig) = setup(|_| {}).await;
    let reply = rig.agent.dispatch(edit_op("x1", &[Part::Password, Part::Totp])).await;
    assert_eq!(reply, err(AgentError::WriteRefused("totp-edit".into())));
    assert_eq!(rig.agent.dispatch(edit_op("x1", &[])).await, err(AgentError::WriteRefused("nothing-to-change".into())));
    assert_eq!(rig.agent.dispatch(edit_op("nope", &[Part::Notes])).await, err(AgentError::NotFound));
    assert!(rig.host.world().confirmed.is_empty());
}

#[tokio::test]
async fn editing_a_marked_item_keeps_every_marker_and_other_field_byte_for_byte() {
    let (_dir, rig) = setup(|_| {}).await;
    let before = cipher(&rig, "m1");
    rig.host.allow();
    rig.host.answer(Answer::Text("rotated-token"));
    rig.host.answer(Answer::Text("rotated by hand"));
    assert_eq!(rig.agent.dispatch(edit_op("m1", &[Part::Password, Part::Notes])).await, Reply::Done);
    let sent = rig.host.world().bodies[0].clone();
    assert_eq!(sent["fields"], before["fields"], "markers and the other namespace's fields, as stored");
    assert_eq!(sent["xUnknown"], before["xUnknown"], "an unknown key passes through");
    assert_eq!(sent["login"]["username"], before["login"]["username"]);
    rig.host.allow();
    assert_eq!(text(rig.agent.dispatch(get_op("m1", Select::Field("notes".into()))).await), "rotated by hand");
    rig.host.allow();
    assert_eq!(text(rig.agent.dispatch(get_op("m1", Select::Field("obsidian:id".into()))).await), "alpha");
}

#[tokio::test]
async fn a_write_on_an_item_that_changed_on_the_server_is_refused_and_nothing_is_lost() {
    let (_dir, rig) = setup(|_| {}).await;
    // Someone edits x1 elsewhere after the last sync (the write's own fetch shows the vault each new copy).
    let edited_elsewhere = |date: &str| {
        let mut w = rig.host.world();
        let mut list: Vec<Value> = serde_json::from_str(&w.ciphers).unwrap();
        list.iter_mut().filter(|c| c["id"] == "x1").for_each(|c| c["revisionDate"] = json!(date));
        w.ciphers = Value::Array(list).to_string();
        w.ciphers.clone()
    };
    for (op, date) in
        [(edit_op("x1", &[Part::Password]), "2026-02-02T00:00:00.000Z"), (remove_op("x1"), "2026-03-03T00:00:00.000Z")]
    {
        let changed = edited_elsewhere(date);
        rig.host.allow();
        rig.host.answer(Answer::Text("new-pass"));
        assert_eq!(rig.agent.dispatch(op).await, err(AgentError::OutOfDate));
        assert_eq!(rig.host.world().ciphers, changed, "the server's copy is as it was");
    }
    assert_eq!(writes(&rig), 0, "nothing sent");
    // The server itself answers "out of date" (a change between the fetch and the write).
    rig.host.world().out_of_date = true;
    for op in [edit_op("x1", &[Part::Password]), add_op("New", None, &[])] {
        rig.host.allow();
        rig.host.answer(Answer::Text("newer-pass"));
        assert_eq!(rig.agent.dispatch(op).await, err(AgentError::OutOfDate));
    }
    // Purged elsewhere: gone from the server's copy.
    rig.host.world().out_of_date = false;
    rig.host.world().ciphers = "[]".into();
    rig.host.allow();
    let reply = rig.agent.dispatch(remove_op("x1")).await;
    assert_eq!(reply, err(AgentError::WriteRefused("gone".into())));
    let verdicts: Vec<_> = audited(&rig).into_iter().map(|(_, _, v)| v).collect();
    assert_eq!(verdicts, [Verdict::Failed; 5]);
}

#[tokio::test]
async fn remove_moves_to_the_trash_and_names_the_namespaces_marking_the_item() {
    let (_dir, rig) = setup(|_| {}).await;
    // The question names the markers from the field names alone: a no opens nothing.
    assert_eq!(rig.agent.dispatch(remove_op("m1")).await, err(AgentError::Denied));
    assert!(rig.host.world().confirmed[0].contains("it is marked for obsidian, other"));
    assert_eq!(rig.agent.opens("work").await, 0);
    rig.host.world().confirmed.clear();
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(remove_op("m1")).await, Reply::Done);
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(remove_op("x1")).await, Reply::Done);
    {
        let world = rig.host.world();
        assert!(
            world.confirmed[0].ends_with(
                "(dybw remove) to move the item \"API token\" (user \"bot\", no folder, id m1) to the trash; it is marked for \
                 obsidian, other, whose tools lose it? (asked for every change)"
            ),
            "{}",
            world.confirmed[0]
        );
        assert!(world.confirmed[1].ends_with(
            "to move the item \"Plain\" (user \"me\", no folder, id x1) to the trash? (asked for every change)"
        ));
        assert_eq!((world.count("/api/ciphers/m1/delete"), world.count("/api/ciphers/x1/delete")), (1, 1));
    }
    assert!(cipher(&rig, "m1")["deletedDate"].is_string(), "in the trash, not purged");
    let list = Op::List { profile: w(), fields: vec![Field::Name], folder: None };
    let rows = items(rig.agent.dispatch(list).await);
    assert!(!rows.iter().any(|r| r.id == "m1" || r.id == "x1"), "the sync after shows them gone");
}

#[tokio::test]
async fn add_creates_a_login_whose_values_come_from_the_pinentry_only() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.allow();
    for value in ["s3cret-pass", "my notes", TOTP] {
        rig.host.answer(Answer::Text(value));
    }
    let op = add_op("New", Some("Work ünï 😀"), &[Part::Password, Part::Notes, Part::Totp]);
    assert_eq!(rig.agent.dispatch(op).await, Reply::Done);
    {
        let world = rig.host.world();
        assert!(world.confirmed[0].ends_with(
            "(dybw add) to add the login \"New\" for the user \"robot\" in the folder \"Work ünï 😀\" with the URIs \"https://new.example.invalid\"? (asked for every \
         change)"
        ));
        assert_eq!(world.prompts[1..], ["New password:", "Notes:", "TOTP key:"]);
        let sent = world.bodies[0].to_string();
        assert!(!sent.contains("s3cret") && !sent.contains("my notes") && !sent.contains("JBSWY3DP"), "{sent}");
        assert_eq!(world.bodies[0]["folderId"], "folder-1");
    }
    assert_eq!(audited(&rig), [("add", Some("new1".to_owned()), Verdict::Confirmed)]);
    rig.host.allow();
    assert_eq!(text(rig.agent.dispatch(get_op("New", Select::Password)).await), "s3cret-pass");
    rig.host.allow();
    assert_eq!(
        text(rig.agent.dispatch(get_op("New", Select::Field("uri".into()))).await),
        "https://new.example.invalid"
    );
    rig.host.allow();
    assert!(matches!(rig.agent.dispatch(code_op("New", false)).await, Reply::Code { .. }));
}

#[tokio::test]
async fn add_refuses_a_totp_key_that_gives_no_code_before_anything_is_sent() {
    let (_dir, rig) = setup(|_| {}).await;
    for (key, why) in [
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12", "the TOTP digits 12 is outside 1..=10"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0", "the TOTP period 0 is outside 1..=4294967295 seconds"),
    ] {
        rig.host.allow();
        rig.host.answer(Answer::Text(key));
        assert_eq!(rig.agent.dispatch(add_op("New", None, &[Part::Totp])).await, err(AgentError::Totp(why.into())));
    }
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(add_op(" ", None, &[])).await, err(AgentError::WriteRefused("name-required".into())));
    assert_eq!(writes(&rig), 0);
    let verdicts: Vec<_> = audited(&rig).into_iter().map(|(_, _, v)| v).collect();
    assert_eq!(verdicts, [Verdict::Failed; 3]);
}

#[tokio::test]
async fn a_peer_that_changes_while_the_user_is_asked_writes_nothing() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.world().confirms.push_back(Answer::Held);
    let agent = rig.agent.clone();
    let pending = tokio::spawn(async move { agent.dispatch(remove_op("x1")).await });
    until(|| rig.host.world().confirmed.len() == 1).await;
    rig.tree.add(100, crate::agent::testing::process(102));
    rig.host.world().release.notify_one();
    assert_eq!(pending.await.unwrap(), err(AgentError::Denied));
    assert_eq!(writes(&rig), 0);
    assert_eq!(audited(&rig), [("remove", Some("x1".to_owned()), Verdict::Denied)]);
}

#[tokio::test]
async fn an_item_changed_by_a_sync_while_the_user_was_asked_is_not_written() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.world().confirms.push_back(Answer::Held);
    let agent = rig.agent.clone();
    let pending = tokio::spawn(async move { agent.dispatch(remove_op("x1")).await });
    until(|| rig.host.world().confirmed.len() == 1).await;
    // Renamed elsewhere, and synced in while the question is on the screen.
    {
        let mut w = rig.host.world();
        let mut list: Vec<Value> = serde_json::from_str(&w.ciphers).unwrap();
        list.iter_mut().filter(|c| c["id"] == "x1").for_each(|c| c["name"] = json!(enc("Renamed")));
        w.ciphers = Value::Array(list).to_string();
    }
    let sync = Op::Sync { target: dybw_proto::Target::Profile("work".into()) };
    assert_eq!(rig.agent.dispatch(sync).await, Reply::Done);
    rig.host.world().release.notify_one();
    assert_eq!(pending.await.unwrap(), err(AgentError::Denied));
    assert_eq!(writes(&rig), 0);
}

#[tokio::test]
async fn an_organization_item_is_written_with_its_key_and_a_read_only_one_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    let mut vault: Value = serde_json::from_str(include_str!("../tests/fixtures/org-vault.json")).unwrap();
    for c in vault["ciphers"].as_array_mut().unwrap() {
        c["revisionDate"] = json!(REV);
        c["reprompt"] = json!(0);
        if c["id"] == "o2" {
            c["edit"] = json!(false);
        }
    }
    rig.host.vault(&vault.to_string());
    crate::agent::testing::seed_credentials(&rig.agent, "org");
    rig.host.answer(Answer::Text("vectors-org-password"));
    assert_eq!(rig.agent.dispatch(Op::Unlock { profile: Some("org".into()) }).await, Reply::Done);
    let org = |needle: &str, ask: &[Part]| Op::Edit {
        profile: Some("org".into()),
        needle: needle.into(),
        user: None,
        folder: None,
        ask: ask.to_vec(),
    };
    rig.host.allow();
    rig.host.answer(Answer::Text("org notes"));
    assert_eq!(rig.agent.dispatch(org("o3", &[Part::Notes])).await, Reply::Done);
    rig.host.allow();
    rig.host.answer(Answer::Text("more notes"));
    assert_eq!(rig.agent.dispatch(org("o2", &[Part::Notes])).await, err(AgentError::WriteRefused("read-only".into())));
    rig.host.allow();
    let reply = rig
        .agent
        .dispatch(Op::Remove { profile: Some("org".into()), needle: "o2".into(), user: None, folder: None })
        .await;
    assert_eq!(reply, err(AgentError::WriteRefused("read-only".into())));
    assert_eq!(writes(&rig), 1, "only o3");
    rig.host.allow();
    let get = Op::Get {
        profile: Some("org".into()),
        needle: "o3".into(),
        user: None,
        folder: None,
        ignorecase: false,
        select: Select::Field("notes".into()),
    };
    assert_eq!(text(rig.agent.dispatch(get).await), "org notes");
}

#[tokio::test]
async fn a_reprompt_item_needs_the_master_password_before_any_value() {
    let (_dir, rig) = setup(reprompting("c1")).await;
    let opens = rig.agent.opens("work").await;
    // Right: the value.
    rig.host.allow();
    rig.host.answer(Answer::Text(PASSWORD));
    assert_eq!(text(rig.agent.dispatch(get_op("c1", Select::Password)).await), "pw-ünï-😀");
    let (desc, _) = rig.host.world().asked.last().unwrap().clone();
    assert!(desc.starts_with(
        "dybw profile work: the item \"Mail ünï 😀\" (user \"me@example.invalid\", folder \"Work ünï 😀\", id c1) asks \
             for the master password again (dybw get by "
    ));
    assert_eq!(rig.host.world().prompts.last().unwrap(), "Master password:");
    // Wrong, cancelled, failed: nothing is opened, for a code, the history or a value.
    rig.host.allow();
    rig.host.answer(Answer::Text("wrong password"));
    assert_eq!(rig.agent.dispatch(code_op("c1", false)).await, err(AgentError::Denied));
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(history_op("c1")).await, err(AgentError::Denied));
    rig.host.allow();
    rig.host.answer(Answer::Fail);
    assert_eq!(rig.agent.dispatch(get_op("c1", Select::Full)).await, err(AgentError::Prompt));
    assert_eq!(rig.agent.opens("work").await, opens + 1, "only the right answer opened it");
    let got: Vec<_> = audited(&rig).into_iter().map(|(op, _, v)| (op, v)).collect();
    assert_eq!(
        got,
        [
            ("get", Verdict::Confirmed),
            ("get", Verdict::Reprompted),
            ("code", Verdict::Confirmed),
            ("code", Verdict::Denied),
            ("history", Verdict::Confirmed),
            ("history", Verdict::Declined),
            ("get", Verdict::Confirmed),
            ("get", Verdict::Declined),
        ]
    );
    // A policy refusal comes first: no master password is asked for a no.
    let asked = rig.host.world().asked.len();
    assert_eq!(rig.agent.dispatch(get_op("c1", Select::Password)).await, err(AgentError::Denied));
    assert_eq!(rig.host.world().asked.len(), asked);
}

#[tokio::test]
async fn a_reprompt_item_needs_the_master_password_before_any_change() {
    let (_dir, rig) = setup(reprompting("x1")).await;
    rig.host.allow();
    rig.host.answer(Answer::Text("wrong password"));
    assert_eq!(rig.agent.dispatch(edit_op("x1", &[Part::Password])).await, err(AgentError::Denied));
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(remove_op("x1")).await, err(AgentError::Denied), "cancelled");
    assert_eq!(writes(&rig), 0);
    rig.host.allow();
    rig.host.answer(Answer::Text(PASSWORD));
    rig.host.answer(Answer::Text("new-pass"));
    assert_eq!(rig.agent.dispatch(edit_op("x1", &[Part::Password])).await, Reply::Done);
    let prompts = rig.host.world().prompts.clone();
    assert_eq!(prompts[prompts.len() - 2..], ["Master password:", "New password:"]);
    let got: Vec<_> = audited(&rig).into_iter().map(|(op, _, v)| (op, v)).collect();
    assert_eq!(
        got,
        [
            ("edit", Verdict::Denied),
            ("remove", Verdict::Declined),
            ("edit", Verdict::Reprompted),
            ("edit", Verdict::Confirmed)
        ]
    );
}

#[tokio::test]
async fn a_reprompt_check_that_cannot_run_fails_closed() {
    // No account key in the copy: the password cannot be checked, so nothing is given.
    let (_dir, rig) = setup(reprompting("x1")).await;
    rig.host.world().profile = Some(r#"{"id":"u1","key":"2.AAAA|AAAA|AAAA"}"#.into());
    assert_eq!(rig.agent.dispatch(Op::Sync { target: dybw_proto::Target::Profile("work".into()) }).await, Reply::Done);
    rig.host.allow();
    rig.host.answer(Answer::Text(PASSWORD));
    assert_eq!(rig.agent.dispatch(get_op("x1", Select::Password)).await, err(AgentError::Internal));
    assert_eq!(audited(&rig).last().unwrap().2, Verdict::Failed);
}

#[tokio::test]
async fn a_code_is_made_when_the_user_has_answered_not_when_it_was_asked_for() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.clock.set_wall(at(PERIOD_START + 2));
    rig.host.world().confirms.push_back(Answer::Held);
    let agent = rig.agent.clone();
    let pending = tokio::spawn(async move { agent.dispatch(code_op("c1", false)).await });
    until(|| rig.host.world().confirmed.len() == 1).await;
    // The user takes 40 s to answer: the code is the one of the period they answered in.
    rig.clock.advance(Duration::from_secs(40), Duration::from_secs(40));
    rig.host.world().release.notify_one();
    let Reply::Code { code, seconds_left } = pending.await.unwrap() else { panic!() };
    assert_eq!((code.expose(), seconds_left), (code_at(PERIOD_START + 42).as_str(), 18));
}

#[tokio::test]
async fn a_reprompt_password_that_opens_another_user_key_is_refused() {
    let (_dir, rig) = setup(reprompting("x1")).await;
    // The copy now wraps another user key under the same master password (as after a key rotation elsewhere).
    let kdf = dybw_core::crypto::KdfParams::Pbkdf2 { iterations: 600_000 };
    let runner = dybw_native::ports::kdf::BlockingArgon2;
    let master = dybw_core::crypto::derive_master_key(PASSWORD, "pbkdf2@vectors.invalid", kdf, &runner).await.unwrap();
    let other = SymmetricKey::generate(&OsRandom).unwrap();
    let format = dybw_core::crypto::ContentFormat::LegacyKey;
    let wrapped = SymmetricKey::stretch(&master).encrypt_as(&other.to_bytes(), format, &OsRandom).unwrap();
    rig.host.world().profile = Some(json!({ "id": "u1", "key": wrapped }).to_string());
    assert_eq!(rig.agent.dispatch(Op::Sync { target: dybw_proto::Target::Profile("work".into()) }).await, Reply::Done);
    rig.host.allow();
    rig.host.answer(Answer::Text(PASSWORD));
    assert_eq!(rig.agent.dispatch(get_op("x1", Select::Password)).await, err(AgentError::Denied));
    assert_eq!(audited(&rig).last().unwrap().2, Verdict::Denied);
}

#[tokio::test]
async fn an_organization_login_that_hides_its_password_gives_no_password_totp_or_history() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    let mut vault: Value = serde_json::from_str(include_str!("../tests/fixtures/org-vault.json")).unwrap();
    for c in vault["ciphers"].as_array_mut().unwrap() {
        c["reprompt"] = json!(0);
        if c["id"] == "o1" {
            c["viewPassword"] = json!(false);
        }
    }
    rig.host.vault(&vault.to_string());
    crate::agent::testing::seed_credentials(&rig.agent, "org");
    rig.host.answer(Answer::Text("vectors-org-password"));
    assert_eq!(rig.agent.dispatch(Op::Unlock { profile: Some("org".into()) }).await, Reply::Done);
    let org = |mut op: Op| {
        if let Op::Get { profile, .. } | Op::Code { profile, .. } | Op::History { profile, .. } = &mut op {
            *profile = Some("org".into());
        }
        op
    };
    let hidden = [
        get_op("o1", Select::Password),
        get_op("o1", Select::Field("password".into())),
        get_op("o1", Select::Field("totp".into())),
        get_op("o1", Select::Full),
        get_op("o1", Select::Raw),
        history_op("o1"),
        code_op("o1", false),
    ];
    for op in hidden {
        rig.host.allow();
        assert_eq!(rig.agent.dispatch(org(op)).await, err(AgentError::Denied));
    }
    assert!(rig.host.world().confirmed.is_empty(), "refused before any question");
    assert_eq!(rig.agent.opens("org").await, 0);
    assert_eq!(audited(&rig).len(), 7);
    // A custom field of the hidden type is hidden with the password, as the official clients hide it. Telling it from
    // a shown one needs the item opened, so the user is asked first (no instant answer tells it apart), then refused.
    rig.host.world().confirms.clear();
    let hidden = || org(get_op("o1", Select::Field("hidden".into())));
    assert_eq!(rig.agent.dispatch(hidden()).await, err(AgentError::Denied), "declined");
    assert_eq!(rig.agent.opens("org").await, 0, "nothing opened before the yes");
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(hidden()).await, err(AgentError::Denied));
    assert_eq!(rig.host.world().confirmed.len(), 2, "asked both times");
    assert_eq!(audited(&rig).last().unwrap().2, Verdict::Denied);
    // What the organization shows is still given.
    rig.host.allow();
    assert!(matches!(rig.agent.dispatch(org(get_op("o1", Select::ListFields))).await, Reply::FieldNames { .. }));
    rig.host.allow();
    assert_eq!(text(rig.agent.dispatch(org(get_op("o1", Select::Field("user".into())))).await), "me@example.invalid");
    rig.host.allow();
    assert_eq!(text(rig.agent.dispatch(org(get_op("o1", Select::Field("text".into())))).await), "shown");
}

fn generate_op(name: &str, folder: Option<&str>, length: u32, charset: Charset) -> Op {
    Op::Generate {
        profile: w(),
        name: name.into(),
        user: Some("robot".into()),
        uris: vec![],
        folder: folder.map(Into::into),
        length,
        charset,
    }
}

#[tokio::test]
async fn add_creates_a_missing_folder_under_the_same_confirmation_once() {
    let (_dir, rig) = setup(|_| {}).await;
    // Declined: no folder is made either.
    rig.host.answer(Answer::Text("pw"));
    assert_eq!(rig.agent.dispatch(add_op("New", Some("Fresh"), &[Part::Password])).await, err(AgentError::Denied));
    assert_eq!(rig.host.world().count("/api/folders"), 0);
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(add_op("New", Some("Fresh"), &[Part::Password])).await, Reply::Done);
    {
        let world = rig.host.world();
        assert!(
            world.confirmed[1].contains("to add the login \"New\" for the user \"robot\" in the new folder \"Fresh\"")
        );
        assert_eq!(world.count("/api/folders"), 1);
        let made = world.bodies[0]["folderId"].as_str().unwrap().to_owned();
        assert!(made.starts_with("made-"), "{made}");
        assert!(!world.folders.contains("Fresh"), "the folder name is sent encrypted");
    }
    // The folder exists now: a second add goes into it and makes none.
    rig.host.allow();
    rig.host.answer(Answer::Text("pw2"));
    assert_eq!(rig.agent.dispatch(add_op("Newer", Some("Fresh"), &[Part::Password])).await, Reply::Done);
    {
        let world = rig.host.world();
        assert!(world.confirmed[2].contains(" in the folder \"Fresh\""), "{}", world.confirmed[2]);
        assert_eq!(world.count("/api/folders"), 1);
        assert_eq!(world.bodies[1]["folderId"], world.bodies[0]["folderId"]);
    }
    let list = Op::List { profile: w(), fields: vec![Field::Name], folder: Some("Fresh".into()) };
    let names: Vec<_> = items(rig.agent.dispatch(list).await).into_iter().filter_map(|r| r.name).collect();
    assert_eq!(names, ["New", "Newer"]);
}

#[tokio::test]
async fn a_folder_made_elsewhere_while_the_user_was_asked_is_used_not_made_again() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.world().confirms.push_back(Answer::Held);
    rig.host.answer(Answer::Text("pw"));
    let agent = rig.agent.clone();
    let pending = tokio::spawn(async move { agent.dispatch(add_op("New", Some("Fresh"), &[Part::Password])).await });
    until(|| rig.host.world().confirmed.len() == 1).await;
    rig.host.world().folders = json!([{ "id": "elsewhere", "name": enc("Fresh") }]).to_string();
    rig.host.world().release.notify_one();
    assert_eq!(pending.await.unwrap(), Reply::Done);
    let world = rig.host.world();
    assert_eq!((world.count("/api/folders"), world.bodies[0]["folderId"].as_str()), (0, Some("elsewhere")));
}

#[tokio::test]
async fn a_folder_the_server_will_not_make_fails_the_add_and_writes_no_login() {
    let (_dir, rig) = setup(|_| {}).await;
    // Refused, or answered without an id.
    for status in [500, 200] {
        rig.host.allow();
        rig.host.answer(Answer::Text("pw"));
        rig.host.world().folder_reply = Some(status);
        let reply = rig.agent.dispatch(add_op("New", Some("Fresh"), &[Part::Password])).await;
        assert_eq!(reply, err(AgentError::Server));
    }
    assert_eq!(writes(&rig), 0);
    assert_eq!(audited(&rig).iter().map(|e| e.2).collect::<Vec<_>>(), [Verdict::Failed; 2]);
}

#[tokio::test]
async fn generate_makes_the_password_in_the_agent_and_asks_for_none() {
    let (_dir, rig) = setup(|_| {}).await;
    let prompts = rig.host.world().prompts.len();
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(generate_op("Made", None, 24, Charset::NoSymbols)).await, Reply::Done);
    {
        let world = rig.host.world();
        assert!(world.confirmed[0].ends_with(
            "(dybw generate) to add the login \"Made\" for the user \"robot\" and a generated password (24 characters)? \
             (asked for every change)"
        ));
        assert_eq!(world.prompts.len(), prompts, "no value asked for");
    }
    assert_eq!(audited(&rig), [("generate", Some("new1".to_owned()), Verdict::Confirmed)]);
    rig.host.allow();
    let pw = text(rig.agent.dispatch(get_op("Made", Select::Password)).await);
    assert!(pw.len() == 24 && pw.chars().all(|c| c.is_ascii_alphanumeric()), "{pw}");
    assert!(!rig.host.world().bodies[0].to_string().contains(&pw));
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(generate_op("Words", Some("Fresh"), 5, Charset::Diceware)).await, Reply::Done);
    assert!(rig.host.world().confirmed[2].contains("in the new folder \"Fresh\" and a generated password (5 words)"));
    rig.host.allow();
    assert_eq!(text(rig.agent.dispatch(get_op("Words", Select::Password)).await).split(' ').count(), 5);
}

#[tokio::test]
async fn generate_refuses_a_bad_length_before_asking_and_an_ai_caller_outright() {
    let (_dir, rig) = setup(|_| {}).await;
    for n in [0, 1025] {
        rig.host.allow();
        let reply = rig.agent.dispatch(generate_op("Made", None, n, Charset::All)).await;
        assert_eq!(reply, err(AgentError::WriteRefused("length".into())));
    }
    rig.host.allow();
    assert_eq!(rig.agent.dispatch_as(generate_op("Made", None, 8, Charset::All), ai()).await, err(AgentError::Denied));
    rig.host.allow();
    let reply = rig.agent.dispatch_as(generate_op("Made", None, 8, Charset::All), unknown()).await;
    assert_eq!(reply, err(AgentError::Denied));
    assert!(rig.host.world().confirmed.is_empty(), "never asked");
    assert_eq!(writes(&rig), 0);
    assert_eq!(audited(&rig), [("generate", None, Verdict::Denied), ("generate", None, Verdict::Denied)]);
}
