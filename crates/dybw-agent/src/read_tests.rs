//! list, search, get and history through the agent, against the scripted host and the pbkdf2 account's public
//! test vectors (`tests/fixtures/vault.json`, from dybw-core's `open/*` and `folders/legacy` vectors): one item of
//! every type, and the value gate in front of every value.
#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::sync::Arc;
use std::time::Duration;

use dybw_proto::{AgentError, Candidate, Field, Op, Reply, Select, Target};
use serde_json::{Value, json};

use crate::agent::Agent;
use crate::agent::testing::{agent_world, unlock};
use crate::host::fake::{Answer, FakeHost};

const VAULT: &str = include_str!("../tests/fixtures/vault.json");
const MAIL: &str = "Mail ünï 😀";

/// A vault of the fixture (after `edit`), unlocked on profile `work`.
async fn setup(edit: impl FnOnce(&mut Value)) -> (tempfile::TempDir, Arc<Agent>, FakeHost) {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    let mut vault: Value = serde_json::from_str(VAULT).unwrap();
    edit(&mut vault);
    host.vault(&vault.to_string());
    unlock(&agent, &host, "work").await;
    (dir, agent, host)
}

fn cipher(vault: &Value, id: &str) -> Value {
    vault["ciphers"].as_array().unwrap().iter().find(|c| c["id"] == id).unwrap().clone()
}

fn err(error: AgentError) -> Reply {
    Reply::Error { error }
}

fn get_op(needle: &str, select: Select) -> Op {
    Op::Get { profile: Some("work".into()), needle: needle.into(), user: None, folder: None, ignorecase: false, select }
}

fn history_op(needle: &str) -> Op {
    Op::History { profile: Some("work".into()), needle: needle.into(), user: None, folder: None }
}

fn list_op(fields: &[Field], folder: Option<&str>) -> Op {
    Op::List { profile: Some("work".into()), fields: fields.to_vec(), folder: folder.map(Into::into) }
}

fn search_op(term: &str, fields: &[Field], folder: Option<&str>) -> Op {
    Op::Search {
        profile: Some("work".into()),
        term: term.into(),
        fields: fields.to_vec(),
        folder: folder.map(Into::into),
    }
}

/// The user says yes once, then the request is made.
async fn allowed(agent: &Agent, host: &FakeHost, op: Op) -> Reply {
    host.allow();
    agent.dispatch(op).await
}

async fn value_of(agent: &Agent, host: &FakeHost, needle: &str, select: Select) -> Reply {
    allowed(agent, host, get_op(needle, select)).await
}

fn text(reply: Reply) -> String {
    match reply {
        Reply::Value { value } => value.expose().to_owned(),
        other => panic!("{other:?}"),
    }
}

fn items(reply: Reply) -> Vec<dybw_proto::ItemSummary> {
    match reply {
        Reply::Items { items } => items,
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
async fn list_shows_only_the_fields_asked_for_and_never_asks_or_opens() {
    let (_dir, agent, host) = setup(|_| {}).await;
    let all = [Field::Id, Field::Name, Field::User, Field::Folder, Field::Type];
    let rows = items(agent.dispatch(list_op(&all, None)).await);
    assert_eq!(rows.len(), 14);
    let row = |id: &str| rows.iter().find(|r| r.id == id).unwrap();
    let c1 = row("c1");
    assert_eq!(c1.name.as_deref(), Some(MAIL));
    assert_eq!(c1.user.as_deref(), Some("me@example.invalid"));
    assert_eq!(c1.folder.as_deref(), Some("Work ünï 😀"));
    assert_eq!(c1.kind.as_deref(), Some("Login"));
    assert_eq!((row("k1").user.clone(), row("k1").kind.as_deref()), (None, Some("Card")));
    assert_eq!(row("i1").kind.as_deref(), Some("Identity"));
    assert_eq!(row("n1").kind.as_deref(), Some("Note"));
    assert_eq!(row("s1").kind.as_deref(), Some("SshKey"));
    assert_eq!(
        (row("u1").kind.as_deref(), row("u1").folder.clone()),
        (Some("Unknown"), None),
        "folder f is not listed"
    );

    let only_name = items(agent.dispatch(list_op(&[Field::Name], None)).await);
    let c1 = only_name.iter().find(|r| r.id == "c1").unwrap();
    assert_eq!(
        (c1.name.as_deref(), c1.user.clone(), c1.folder.clone(), c1.kind.clone()),
        (Some(MAIL), None, None, None)
    );
    assert!(items(agent.dispatch(list_op(&[], None)).await).iter().all(|r| r.name.is_none()));

    let in_folder = items(agent.dispatch(list_op(&[Field::Name], Some("Work ünï 😀"))).await);
    assert_eq!(in_folder.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["c1"]);
    assert!(items(agent.dispatch(list_op(&[Field::Name], Some("nowhere"))).await).is_empty());

    assert!(host.world().confirmed.is_empty(), "no prompt for a list");
    assert_eq!(agent.opens("work").await, 0, "a list decrypts the summary and nothing else");
}

#[tokio::test]
async fn search_matches_a_part_of_the_name_or_the_user_without_opening_anything() {
    let (_dir, agent, host) = setup(|_| {}).await;
    let ids = |rows: Vec<dybw_proto::ItemSummary>| {
        let mut ids: Vec<_> = rows.into_iter().map(|r| r.id).collect();
        ids.sort();
        ids
    };
    assert_eq!(ids(items(agent.dispatch(search_op("MAIL", &[Field::Name], None)).await)), ["c1"]);
    assert_eq!(ids(items(agent.dispatch(search_op("Me@Example", &[Field::Name], None)).await)), ["c1"], "the user");
    assert_eq!(ids(items(agent.dispatch(search_op("partial", &[Field::Name], None)).await)), ["i2", "k2"]);
    assert!(items(agent.dispatch(search_op("zzz", &[Field::Name], None)).await).is_empty());
    assert_eq!(ids(items(agent.dispatch(search_op("partial", &[], Some("Work ünï 😀"))).await)), Vec::<String>::new());
    assert_eq!(ids(items(agent.dispatch(search_op("mail", &[], Some("Work ünï 😀"))).await)), ["c1"]);
    assert!(host.world().confirmed.is_empty());
    assert_eq!(agent.opens("work").await, 0);
}

#[tokio::test]
async fn items_that_cannot_be_shown_are_left_out_a_trashed_one_included() {
    let (_dir, agent, _host) = setup(|v| {
        let list = v["ciphers"].as_array_mut().unwrap();
        for c in list.iter_mut() {
            match c["id"].as_str().unwrap() {
                "c2" => c["name"] = json!("not a cipher string"),
                "n1" => c["deletedDate"] = json!("2025-01-01T00:00:00Z"),
                "n2" => c["deletedDate"] = Value::Null,
                _ => {}
            }
        }
        let mut held = list.iter().find(|c| c["id"] == "c1").unwrap().clone();
        held["id"] = json!("o1");
        held["organizationId"] = json!("org-x");
        list.push(held);
    })
    .await;
    let rows = items(agent.dispatch(list_op(&[Field::Name], None)).await);
    let ids: Vec<_> = rows.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(rows.len(), 12, "{ids:?}");
    for gone in ["c2", "n1", "o1"] {
        assert!(!ids.contains(&gone), "{gone}");
        assert_eq!(agent.dispatch(get_op(gone, Select::Password)).await, err(AgentError::NotFound), "{gone}");
    }
    assert!(ids.contains(&"n2"), "a null deletedDate is not the trash");
}

#[tokio::test]
async fn an_item_that_lists_but_does_not_open_is_an_internal_error_after_the_confirmation() {
    // The summary needs the name and user; the notes are only read when the item is opened.
    let (_dir, agent, host) = setup(|v| {
        for c in v["ciphers"].as_array_mut().unwrap() {
            if c["id"] == "c1" {
                c["notes"] = json!("not a cipher string");
            }
        }
    })
    .await;
    assert_eq!(items(agent.dispatch(list_op(&[Field::Name], None)).await).len(), 14);
    assert_eq!(value_of(&agent, &host, "c1", Select::Password).await, err(AgentError::Internal));
    assert_eq!(host.world().confirmed.len(), 1);
}

#[tokio::test]
async fn get_prints_the_main_value_of_every_item_type() {
    let (_dir, agent, host) = setup(|_| {}).await;
    let cases = [
        ("c1", "pw-ünï-😀"),
        ("n1", "the note's text"),
        ("k1", "4111111111111111"),
        ("i1", "firstName-value middleName-value lastName-value"),
        ("i2", "Ann"),
        ("s1", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI deploy@example.invalid"),
        ("u1", "a type from a newer server"),
    ];
    for (id, expected) in cases {
        assert_eq!(text(value_of(&agent, &host, id, Select::Password).await), expected, "{id}");
    }
    for (id, missing) in [("c2", "password"), ("k3", "number"), ("n2", "notes"), ("s2", "public-key"), ("u2", "notes")]
    {
        let reply = value_of(&agent, &host, id, Select::Password).await;
        assert_eq!(reply, err(AgentError::NoSuchField(missing.into())), "{id}");
    }
    assert_eq!(value_of(&agent, &host, "i3", Select::Password).await, err(AgentError::NotFound));
}

#[tokio::test]
async fn get_field_reads_any_property_or_custom_field() {
    let (_dir, agent, host) = setup(|_| {}).await;
    let cases = [
        ("c1", "user", "me@example.invalid"),
        ("c1", "username", "me@example.invalid"),
        ("c1", "password", "pw-ünï-😀"),
        ("c1", "uri", "https://a.example.invalid"),
        ("c1", "totp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"),
        ("c1", "notes", "line 1\nline 2"),
        ("c1", "name", MAIL),
        ("c1", "text", "shown"),
        ("c1", "hidden", "kept-secret"),
        ("c1", "flag", "true"),
        ("k1", "cvv", "123"),
        ("k1", "code", "123"),
        ("k1", "cardholder", "Ann Example"),
        ("k1", "pin", "0000"),
        (
            "s1",
            "private-key",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----",
        ),
        ("s1", "fingerprint", "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"),
        ("i1", "email", "email-value"),
        ("i1", "username", "username-value"),
        ("i1", "postal-code", "postalCode-value"),
        ("u1", "iban", "XX00 0000"),
        ("n1", "f", "v"),
    ];
    for (id, field, expected) in cases {
        assert_eq!(text(value_of(&agent, &host, id, Select::Field(field.into())).await), expected, "{id} {field}");
    }
    for (id, field) in [("c1", "nope"), ("c1", "linked"), ("c2", "uri"), ("n2", "user"), ("k2", "uri")] {
        let reply = value_of(&agent, &host, id, Select::Field(field.into())).await;
        assert_eq!(reply, err(AgentError::NoSuchField(field.into())), "{id} {field}");
    }
}

#[tokio::test]
async fn get_full_lists_every_value_present() {
    let (_dir, agent, host) = setup(|_| {}).await;
    let Reply::Full { entries } = value_of(&agent, &host, "c1", Select::Full).await else { panic!() };
    let got: Vec<(&str, &str)> = entries.iter().map(|e| (e.name.as_str(), e.value.expose())).collect();
    assert_eq!(
        got,
        [
            ("user", "me@example.invalid"),
            ("password", "pw-ünï-😀"),
            ("totp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"),
            ("uri", "https://a.example.invalid"),
            ("uri", "https://b.example.invalid"),
            ("uri", "^https://c\\.example\\.invalid/"),
            ("notes", "line 1\nline 2"),
            ("text", "shown"),
            ("hidden", "kept-secret"),
            ("flag", "true"),
            ("", ""),
        ],
        "the linked field has no value"
    );
    let Reply::Full { entries } = value_of(&agent, &host, "u1", Select::Full).await else { panic!() };
    let got: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.value.expose())).collect();
    assert_eq!(got, [("notes", "a type from a newer server"), ("iban", "XX00 0000")]);
}

#[tokio::test]
async fn get_raw_is_the_decrypted_item_as_json() {
    let (_dir, agent, host) = setup(|_| {}).await;
    let Reply::Raw { json } = value_of(&agent, &host, "c1", Select::Raw).await else { panic!() };
    let got: Value = serde_json::from_str(json.expose()).unwrap();
    assert_eq!(
        got,
        json!({
            "id": "c1", "type": 1, "name": MAIL, "notes": "line 1\nline 2", "folderId": "folder-1",
            "organizationId": null, "reprompt": true,
            "fields": [
                {"name": "text", "value": "shown", "type": 0, "linkedId": null},
                {"name": "hidden", "value": "kept-secret", "type": 1, "linkedId": null},
                {"name": "flag", "value": "true", "type": 2, "linkedId": null},
                {"name": "linked", "value": null, "type": 3, "linkedId": 100},
                {"name": "", "value": "", "type": 0, "linkedId": null},
            ],
            "passwordHistory": [
                {"password": "old-2", "lastUsedDate": "2025-02-01T00:00:00Z"},
                {"password": "old-1", "lastUsedDate": null},
            ],
            "login": {
                "username": "me@example.invalid", "password": "pw-ünï-😀",
                "totp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
                "uris": [
                    {"uri": "https://a.example.invalid", "match": null},
                    {"uri": "https://b.example.invalid", "match": 0},
                    {"uri": "^https://c\\.example\\.invalid/", "match": 4},
                ],
            },
        })
    );
    // The other shapes: a type part per type, none for a note or a type this build does not know.
    let raw = |reply| match reply {
        Reply::Raw { json } => serde_json::from_str::<Value>(json.expose()).unwrap(),
        other => panic!("{other:?}"),
    };
    let card = raw(value_of(&agent, &host, "k2", Select::Raw).await);
    assert_eq!(card["card"]["number"], "5500000000000004");
    assert_eq!(card["card"]["code"], Value::Null);
    assert_eq!(
        raw(value_of(&agent, &host, "i1", Select::Raw).await)["identity"]["licenseNumber"],
        "licenseNumber-value"
    );
    assert_eq!(raw(value_of(&agent, &host, "s2", Select::Raw).await)["sshKey"]["publicKey"], Value::Null);
    for id in ["n1", "u1"] {
        let item = raw(value_of(&agent, &host, id, Select::Raw).await);
        assert!(item.as_object().unwrap().len() == 9, "{id}: {item}");
    }
}

#[tokio::test]
async fn list_fields_names_the_custom_fields_with_no_prompt() {
    let (_dir, agent, host) = setup(|_| {}).await;
    let reply = agent.dispatch(get_op("c1", Select::ListFields)).await;
    assert_eq!(reply, Reply::FieldNames { names: ["text", "hidden", "flag", "linked", ""].map(String::from).to_vec() });
    assert!(host.world().confirmed.is_empty(), "names are not values");
    assert_eq!(agent.opens("work").await, 1);
    assert_eq!(agent.dispatch(get_op("c2", Select::ListFields)).await, Reply::FieldNames { names: vec![] });
}

#[tokio::test]
async fn history_lists_the_old_passwords_newest_first_after_a_confirmation() {
    let (_dir, agent, host) = setup(|_| {}).await;
    let Reply::History { entries } = allowed(&agent, &host, history_op("c1")).await else { panic!() };
    let got: Vec<_> = entries.iter().map(|e| (e.last_used.as_str(), e.password.expose())).collect();
    assert_eq!(got, [("2025-02-01T00:00:00Z", "old-2"), ("unknown", "old-1")]);
    assert_eq!(allowed(&agent, &host, history_op("n1")).await, Reply::History { entries: vec![] });
    let asked = host.world().confirmed.clone();
    assert_eq!(asked[0], format!("dybw profile work: allow reading its password history of the item \"{MAIL}\"?"));
    // No confirmation, no history.
    assert_eq!(agent.dispatch(history_op("c1")).await, err(AgentError::Denied));
}

#[tokio::test]
async fn every_value_request_is_confirmed_first_naming_the_profile_the_item_and_what_is_read() {
    let (_dir, agent, host) = setup(|_| {}).await;
    value_of(&agent, &host, "c1", Select::Password).await;
    value_of(&agent, &host, MAIL, Select::Field("hidden".into())).await;
    value_of(&agent, &host, "c1", Select::Full).await;
    value_of(&agent, &host, "c1", Select::Raw).await;
    let asked = host.world().confirmed.clone();
    let lead = "dybw profile work: allow reading ";
    let tail = format!(" of the item \"{MAIL}\"?");
    let what = [
        "its main value (password, notes, number or public key)",
        "its field \"hidden\"",
        "the full item (every value)",
        "the raw item as JSON",
    ];
    assert_eq!(asked, what.map(|w| format!("{lead}{w}{tail}")));
}

#[tokio::test]
async fn text_that_comes_from_the_item_or_the_client_stays_on_one_line_in_the_question() {
    let (_dir, agent, host) = setup(|_| {}).await;
    let name = format!("x\nAllow everything?{}", "y".repeat(200));
    value_of(&agent, &host, "c1", Select::Field(name)).await;
    let asked = host.world().confirmed.clone();
    assert_eq!(asked.len(), 1);
    assert!(!asked[0].contains('\n') && !asked[0].contains("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"));
}

#[tokio::test]
async fn a_no_a_timeout_or_a_dead_prompt_gives_nothing_and_opens_nothing() {
    let (_dir, agent, host) = setup(|_| {}).await;
    // No answer scripted is a no, as is a cancel and a timeout; a prompt that cannot be put is not a no.
    assert_eq!(agent.dispatch(get_op("c1", Select::Password)).await, err(AgentError::Denied));
    host.world().confirms.push_back(Answer::Cancel);
    assert_eq!(agent.dispatch(get_op("c1", Select::Raw)).await, err(AgentError::Denied));
    host.world().confirms.push_back(Answer::Timeout);
    assert_eq!(agent.dispatch(history_op("c1")).await, err(AgentError::Denied));
    host.world().confirms.push_back(Answer::Fail);
    assert_eq!(agent.dispatch(get_op("c1", Select::Full)).await, err(AgentError::Prompt));
    assert_eq!(host.world().confirmed.len(), 4);
    assert_eq!(agent.opens("work").await, 0, "the item was never opened: the gate comes before the decrypt");
    value_of(&agent, &host, "c1", Select::Password).await;
    assert_eq!(agent.opens("work").await, 1, "and one yes opens exactly one item");
}

#[tokio::test]
async fn lookup_takes_the_id_then_the_name_and_ignorecase_and_user_narrow_the_name() {
    let (_dir, agent, host) = setup(|_| {}).await;
    let name_of = |reply| text(reply);
    assert_eq!(name_of(value_of(&agent, &host, "c1", Select::Field("name".into())).await), MAIL);
    assert_eq!(name_of(value_of(&agent, &host, MAIL, Select::Field("name".into())).await), MAIL);
    assert_eq!(agent.dispatch(get_op("mail ünï 😀", Select::Password)).await, err(AgentError::NotFound));
    let mut op = get_op("MAIL ÜNÏ 😀", Select::Password);
    let Op::Get { ignorecase, user, .. } = &mut op else { panic!() };
    *ignorecase = true;
    *user = Some("ME@example.INVALID".into());
    assert_eq!(text(allowed(&agent, &host, op).await), "pw-ünï-😀");
    let mut op = get_op(MAIL, Select::Password);
    let Op::Get { user, .. } = &mut op else { panic!() };
    *user = Some("someone@else.invalid".into());
    assert_eq!(agent.dispatch(op).await, err(AgentError::NotFound));
    assert_eq!(host.world().confirmed.len(), 3, "only a found item is asked about");
}

#[tokio::test]
async fn several_matches_are_ambiguous_by_id_name_and_user_only_with_no_prompt_and_no_decrypt() {
    let (_dir, agent, host) = setup(|v| {
        let list = v["ciphers"].as_array_mut().unwrap();
        let mut twin = list.iter().find(|c| c["id"] == "c1").unwrap().clone();
        twin["id"] = json!("c1b");
        twin["folderId"] = json!("folder-2");
        list.push(twin);
    })
    .await;
    let Reply::Error { error: AgentError::Ambiguous { candidates } } = agent.dispatch(get_op(MAIL, Select::Raw)).await
    else {
        panic!()
    };
    let want = |id: &str| Candidate { id: id.into(), name: MAIL.into(), user: Some("me@example.invalid".into()) };
    assert_eq!(candidates, [want("c1"), want("c1b")]);
    assert!(matches!(agent.dispatch(history_op(MAIL)).await, Reply::Error { error: AgentError::Ambiguous { .. } }));
    let k = agent.dispatch(get_op("Partial", Select::Password)).await;
    let Reply::Error { error: AgentError::Ambiguous { candidates } } = k else { panic!("{k:?}") };
    assert_eq!(
        candidates.iter().map(|c| (c.id.as_str(), c.user.clone())).collect::<Vec<_>>(),
        [("k2", None), ("i2", None)]
    );
    assert!(host.world().confirmed.is_empty(), "no prompt for an ambiguous needle");
    assert_eq!(agent.opens("work").await, 0);

    // The folder narrows it to one.
    let mut op = get_op(MAIL, Select::Field("name".into()));
    let Op::Get { folder, .. } = &mut op else { panic!() };
    *folder = Some("Work ünï 😀".into());
    assert_eq!(text(allowed(&agent, &host, op).await), MAIL);
    // The id is exact: it needs no narrowing.
    assert_eq!(text(value_of(&agent, &host, "c1b", Select::Field("name".into())).await), MAIL);
}

#[tokio::test]
async fn a_url_finds_the_login_with_that_host_when_no_name_matches() {
    let (_dir, agent, host) = setup(|v| {
        let list = v["ciphers"].as_array_mut().unwrap();
        let mut twin = list.iter().find(|c| c["id"] == "c1").unwrap().clone();
        twin["id"] = json!("c1b");
        list.push(twin);
    })
    .await;
    // Both items carry the URI: ambiguous. The twin is gone in the next vault, so one is left.
    let both = agent.dispatch(get_op("https://A.example.invalid/some/path?x=1", Select::Password)).await;
    assert!(
        matches!(both, Reply::Error { error: AgentError::Ambiguous { ref candidates } } if candidates.len() == 2),
        "{both:?}"
    );
    assert!(host.world().confirmed.is_empty());
    assert!(agent.opens("work").await > 0, "a URL match reads the URIs of the logins (and no other type)");

    let (_dir, agent, host) = setup(|_| {}).await;
    let by_host = value_of(&agent, &host, "https://b.example.invalid", Select::Password).await;
    assert_eq!(text(by_host), "pw-ünï-😀");
    for no in ["https://nothing.example.invalid", "a.example.invalid", "c.example.invalid", "https:///"] {
        assert_eq!(agent.dispatch(get_op(no, Select::Password)).await, err(AgentError::NotFound), "{no}");
    }
}

#[tokio::test]
async fn a_locked_profile_answers_locked_and_a_lock_while_waiting_for_the_user_cancels_the_read() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    for op in [list_op(&[], None), search_op("x", &[], None), get_op("c1", Select::Password), history_op("c1")] {
        assert_eq!(agent.dispatch(op).await, err(AgentError::Locked));
    }
    drop((agent, host, dir));

    let (_dir, agent, host) = setup(|_| {}).await;
    host.world().confirms.push_back(Answer::Hang);
    let first = tokio::spawn({
        let agent = agent.clone();
        async move { agent.dispatch(get_op("c1", Select::Password)).await }
    });
    until(|| host.world().confirmed.len() == 1).await;
    // A second request waits for the first answer: one question on the screen at a time.
    let second = tokio::spawn({
        let agent = agent.clone();
        async move { agent.dispatch(history_op("c1")).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(host.world().confirmed.len(), 1);
    assert_eq!(agent.dispatch(Op::Lock { target: Target::Profile("work".into()) }).await, Reply::Done);
    assert_eq!(first.await.unwrap(), err(AgentError::Locked));
    assert_eq!(second.await.unwrap(), err(AgentError::Locked));
    assert_eq!(host.world().confirmed.len(), 1);
    assert_eq!(agent.opens("work").await, 0);
    assert_eq!(agent.dispatch(get_op("c1", Select::Password)).await, err(AgentError::Locked));
}

#[tokio::test]
async fn nothing_is_kept_between_requests_so_a_sync_is_seen_at_once() {
    let (_dir, agent, host) = setup(|_| {}).await;
    assert_eq!(text(value_of(&agent, &host, "n1", Select::Password).await), "the note's text");
    let mut vault: Value = serde_json::from_str(VAULT).unwrap();
    vault["ciphers"].as_array_mut().unwrap().retain(|c| c["id"] != "n1");
    host.vault(&vault.to_string());
    assert_eq!(agent.dispatch(Op::Sync { target: Target::Profile("work".into()) }).await, Reply::Done);
    assert_eq!(agent.dispatch(get_op("n1", Select::Password)).await, err(AgentError::NotFound));
    assert_eq!(cipher(&serde_json::from_str(VAULT).unwrap(), "n1")["type"], 2);
}
