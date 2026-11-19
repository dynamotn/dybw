//! list, search, get and history through the agent, against the scripted host and the pbkdf2 account's public
//! test vectors (`tests/fixtures/vault.json`, from dybw-core's `open/*` and `folders/legacy` vectors): one item of
//! every type, and the value gate in front of every value.
#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::sync::Arc;
use std::time::Duration;

use dybw_proto::{AgentError, Candidate, Field, Op, Reply, Select, Target};
use serde_json::{Value, json};

use crate::agent::Agent;
use crate::agent::testing::{agent_world, seed_credentials, unlock};
use crate::host::fake::{Answer, FakeHost};

pub(crate) const VAULT: &str = include_str!("../tests/fixtures/vault.json");
pub(crate) const MAIL: &str = "Mail ünï 😀";
/// How every question starts: the profile and the stock caller of the tests.
pub(crate) const WHO: &str =
    "dybw profile work: allow /usr/local/bin/mytool which claims to run /opt/scripts/backup.sh";

/// A vault of the fixture (after `edit`), unlocked on profile `work`.
pub(crate) async fn setup(edit: impl FnOnce(&mut Value)) -> (tempfile::TempDir, Arc<Agent>, FakeHost) {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    let mut vault: Value = serde_json::from_str(VAULT).unwrap();
    // The vectors' items ask for a reprompt: most tests are about something else.
    vault["ciphers"].as_array_mut().unwrap().iter_mut().for_each(|c| c["reprompt"] = json!(0));
    edit(&mut vault);
    host.vault(&vault.to_string());
    unlock(&agent, &host, "work").await;
    (dir, agent, host)
}

/// The `org` account's vault (the vectors' `open/organization`, its own keys and organizations), unlocked.
async fn org_setup() -> (tempfile::TempDir, Arc<Agent>, FakeHost) {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    host.vault(include_str!("../tests/fixtures/org-vault.json"));
    seed_credentials(&agent, "org");
    host.answer(Answer::Text("vectors-org-password"));
    assert_eq!(agent.dispatch(Op::Unlock { profile: Some("org".into()) }).await, Reply::Done);
    (dir, agent, host)
}

fn cipher(vault: &Value, id: &str) -> Value {
    vault["ciphers"].as_array().unwrap().iter().find(|c| c["id"] == id).unwrap().clone()
}

pub(crate) fn err(error: AgentError) -> Reply {
    Reply::Error { error }
}

pub(crate) fn get_op(needle: &str, select: Select) -> Op {
    Op::Get { profile: Some("work".into()), needle: needle.into(), user: None, folder: None, ignorecase: false, select }
}

pub(crate) fn history_op(needle: &str) -> Op {
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

/// The same request for the `org` profile.
fn org(mut op: Op) -> Op {
    if let Op::List { profile, .. }
    | Op::Search { profile, .. }
    | Op::Get { profile, .. }
    | Op::History { profile, .. } = &mut op
    {
        *profile = Some("org".into());
    }
    op
}

/// The user says yes once, then the request is made.
async fn allowed(agent: &Agent, host: &FakeHost, op: Op) -> Reply {
    host.allow();
    agent.dispatch(op).await
}

async fn value_of(agent: &Agent, host: &FakeHost, needle: &str, select: Select) -> Reply {
    allowed(agent, host, get_op(needle, select)).await
}

pub(crate) fn text(reply: Reply) -> String {
    match reply {
        Reply::Value { value } => value.expose().to_owned(),
        other => panic!("{other:?}"),
    }
}

pub(crate) fn items(reply: Reply) -> Vec<dybw_proto::ItemSummary> {
    match reply {
        Reply::Items { items } => items,
        other => panic!("{other:?}"),
    }
}

/// Wait for `ready`, at most 5 s: the worker runs on its own thread.
pub(crate) async fn until(ready: impl Fn() -> bool) {
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
async fn an_item_whose_field_names_do_not_read_is_an_internal_error_for_list_fields() {
    let (_dir, agent, host) = setup(|v| {
        v["ciphers"].as_array_mut().unwrap().iter_mut().filter(|c| c["id"] == "c1").for_each(|c| {
            c["fields"][0]["name"] = json!("not a cipher string");
        });
    })
    .await;
    assert_eq!(agent.dispatch(get_op("c1", Select::ListFields)).await, err(AgentError::Internal));
    assert!(host.world().confirmed.is_empty());
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
            ("password", "pw-ünï-😀"),
            ("user", "me@example.invalid"),
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
async fn get_full_starts_with_the_value_get_prints() {
    let (_dir, agent, host) = setup(|_| {}).await;
    for (id, first, plain) in [
        ("k1", "number", "4111111111111111"),
        ("s1", "public-key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI deploy@example.invalid"),
    ] {
        let Reply::Full { entries } = value_of(&agent, &host, id, Select::Full).await else { panic!() };
        assert_eq!((entries[0].name.as_str(), entries[0].value.expose()), (first, plain), "{id}");
        assert_eq!(entries.iter().filter(|e| e.name == first).count(), 1, "{id}: once");
    }
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
            "organizationId": null, "reprompt": false,
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
async fn list_fields_names_the_custom_fields_with_no_question_and_without_opening_the_item() {
    let (_dir, agent, host) = setup(|_| {}).await;
    let reply = agent.dispatch(get_op("c1", Select::ListFields)).await;
    assert_eq!(reply, Reply::FieldNames { names: ["text", "hidden", "flag", "linked", ""].map(String::from).to_vec() });
    assert_eq!(agent.dispatch(get_op("c2", Select::ListFields)).await, Reply::FieldNames { names: vec![] });
    assert!(host.world().confirmed.is_empty(), "names only, as rbw: nobody is asked");
    assert_eq!(agent.opens("work").await, 0, "only the names are decrypted, the item is never opened");
}

#[tokio::test]
async fn an_item_that_changed_while_the_user_was_asked_is_denied_and_not_opened() {
    let (_dir, agent, host) = setup(|_| {}).await;
    host.world().confirms.push_back(Answer::Held);
    let task = tokio::spawn({
        let agent = agent.clone();
        async move { agent.dispatch(get_op("c2", Select::Password)).await }
    });
    until(|| host.world().confirmed.len() == 1).await;
    // A sync during the question gives c2 another name (c3's): the answer was about the old one.
    let mut vault: Value = serde_json::from_str(VAULT).unwrap();
    let list = vault["ciphers"].as_array_mut().unwrap();
    let other = list.iter().find(|c| c["id"] == "c3").unwrap()["name"].clone();
    list.iter_mut().for_each(|c| c["reprompt"] = json!(0));
    list.iter_mut().find(|c| c["id"] == "c2").unwrap()["name"] = other;
    host.vault(&vault.to_string());
    assert_eq!(agent.dispatch(Op::Sync { target: Target::Profile("work".into()) }).await, Reply::Done);
    host.world().release.notify_one();
    assert_eq!(task.await.unwrap(), err(AgentError::Denied));
    assert_eq!(agent.opens("work").await, 0);
    // Asked again, about what it is now, it opens.
    assert_eq!(text(value_of(&agent, &host, "c2", Select::Field("name".into())).await), "");
}

#[tokio::test]
async fn history_lists_the_old_passwords_newest_first_after_a_confirmation() {
    let (_dir, agent, host) = setup(|_| {}).await;
    let Reply::History { entries } = allowed(&agent, &host, history_op("c1")).await else { panic!() };
    let got: Vec<_> = entries.iter().map(|e| (e.last_used.as_str(), e.password.expose())).collect();
    assert_eq!(got, [("2025-02-01T00:00:00Z", "old-2"), ("unknown", "old-1")]);
    assert_eq!(allowed(&agent, &host, history_op("n1")).await, Reply::History { entries: vec![] });
    let asked = host.world().confirmed.clone();
    assert_eq!(asked[0], format!("{WHO} (dybw history) to read its password history of the item \"{MAIL}\"?"));
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
    let lead = format!("{WHO} (dybw get) to read ");
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
async fn a_url_finds_the_login_whose_uris_match_it_as_rbw_does_and_opens_nothing_before_the_yes() {
    let (_dir, agent, host) = setup(|_| {}).await;
    // c1's URIs: https://a.example.invalid (default match: domain), https://b.example.invalid (domain), and the
    // regular expression ^https://c\.example\.invalid/.
    for url in [
        "https://a.example.invalid/some/path",
        "https://www.a.example.invalid",
        "https://b.example.invalid/x?y=1",
        "https://c.example.invalid/anything",
    ] {
        assert_eq!(agent.dispatch(get_op(url, Select::Password)).await, err(AgentError::Denied), "{url}");
    }
    let asked = host.world().confirmed.clone();
    assert_eq!(asked.len(), 4);
    assert!(asked.iter().all(|q| q.ends_with(&format!("of the item \"{MAIL}\"?"))), "{asked:?}");
    for url in
        ["http://a.example.invalid", "https://example.invalid", "https://xa.example.invalid", "a.example.invalid"]
    {
        assert_eq!(agent.dispatch(get_op(url, Select::Password)).await, err(AgentError::NotFound), "{url}");
    }
    assert_eq!(host.world().confirmed.len(), 4, "no question for a URL that names nothing");
    assert_eq!(agent.opens("work").await, 0, "the URIs are decrypted for the lookup, nothing else");
    assert_eq!(text(value_of(&agent, &host, "https://a.example.invalid", Select::Password).await), "pw-ünï-😀");
}

#[tokio::test]
async fn a_uuid_needle_is_the_item_with_that_id_in_any_spelling_then_a_name_as_rbw_does() {
    const ID: &str = "0b3c6f0e-6a3e-4c55-9a59-1c2d3e4f5a6b";
    let (_dir, agent, host) = setup(|v| {
        v["ciphers"].as_array_mut().unwrap().iter_mut().filter(|c| c["id"] == "c1").for_each(|c| c["id"] = json!(ID));
    })
    .await;
    assert_eq!(text(value_of(&agent, &host, &ID.to_uppercase(), Select::Field("name".into())).await), MAIL);
    let other = "0b3c6f0e-6a3e-4c55-9a59-000000000000";
    assert_eq!(agent.dispatch(get_op(other, Select::Password)).await, err(AgentError::NotFound), "then the names");
}

#[tokio::test]
async fn an_item_outside_any_folder_wins_and_a_part_of_the_name_is_tried_last_as_rbw_does() {
    let (_dir, agent, host) = setup(|v| {
        let list = v["ciphers"].as_array_mut().unwrap();
        let mut twin = list.iter().find(|c| c["id"] == "c1").unwrap().clone();
        twin["id"] = json!("c1b");
        twin["folderId"] = Value::Null;
        list.push(twin);
    })
    .await;
    let id_of = |needle: &str, folder: Option<&str>| {
        let mut op = get_op(needle, Select::Raw);
        let Op::Get { folder: f, .. } = &mut op else { panic!() };
        *f = folder.map(Into::into);
        let (agent, host) = (agent.clone(), host.clone());
        async move {
            let Reply::Raw { json } = allowed(&agent, &host, op).await else { panic!() };
            serde_json::from_str::<Value>(json.expose()).unwrap()["id"].as_str().unwrap().to_owned()
        }
    };
    // c1 is in a folder, its twin is not: with no --folder, the twin is the one (rbw's strict-folder pass).
    assert_eq!(id_of(MAIL, None).await, "c1b");
    assert_eq!(id_of(MAIL, Some("Work ünï 😀")).await, "c1");
    // No item is named exactly that: a part of the name, by the same passes.
    assert_eq!(id_of("ünï 😀", None).await, "c1b");
    assert_eq!(id_of("ünï 😀", Some("Work")).await, "c1");
    // -i: a part of the name in any case.
    let mut op = get_op("MAIL ÜNÏ", Select::Field("name".into()));
    let Op::Get { ignorecase, .. } = &mut op else { panic!() };
    *ignorecase = true;
    assert_eq!(text(allowed(&agent, &host, op).await), MAIL);
}

#[tokio::test]
async fn a_reprompt_item_gives_no_value_without_the_master_password_but_its_name_shows() {
    let (_dir, agent, host) = setup(|v| {
        for c in v["ciphers"].as_array_mut().unwrap() {
            if c["id"] == "c1" {
                c["reprompt"] = json!(1);
            }
        }
    })
    .await;
    for select in [Select::Password, Select::Field("user".into()), Select::Full, Select::Raw, Select::ListFields] {
        host.allow();
        assert_eq!(agent.dispatch(get_op("c1", select)).await, err(AgentError::Denied));
    }
    host.allow();
    assert_eq!(agent.dispatch(history_op(MAIL)).await, err(AgentError::Denied));
    assert_eq!(host.world().prompts[1..], ["Master password:"; 6], "asked each time, never answered");
    assert_eq!(agent.opens("work").await, 0);
    let rows = items(agent.dispatch(list_op(&[Field::Name], None)).await);
    assert!(rows.iter().any(|r| r.id == "c1"));
    assert_eq!(text(value_of(&agent, &host, "n1", Select::Password).await), "the note's text", "others are unaffected");
}

#[tokio::test]
async fn organization_items_read_like_personal_ones_with_the_organizations_unlocked() {
    let (_dir, agent, host) = org_setup().await;
    let rows = items(agent.dispatch(org(list_op(&[Field::Name, Field::Type], None))).await);
    let mut seen: Vec<_> =
        rows.iter().map(|r| (r.id.as_str(), r.name.as_deref().unwrap(), r.kind.as_deref().unwrap())).collect();
    seen.sort();
    assert_eq!(
        seen,
        [("o1", MAIL, "Login"), ("o2", "Visa", "Card"), ("o3", "Partial", "Identity"), ("p1", "Note", "Note")]
    );
    assert_eq!(items(agent.dispatch(org(search_op("visa", &[Field::Name], None))).await).len(), 1);
    assert_eq!(
        text(allowed(&agent, &host, org(get_op("o3", Select::Password))).await),
        "Ann",
        "an organization item (org-b)"
    );
    assert_eq!(
        text(allowed(&agent, &host, org(get_op("Note", Select::Password))).await),
        "the note's text",
        "a personal item"
    );
    assert_eq!(text(allowed(&agent, &host, org(get_op("p1", Select::Field("f".into())))).await), "v");
    // The vectors' o1 and o2 ask for a reprompt: no master password, no value.
    host.allow();
    assert_eq!(agent.dispatch(org(get_op("o1", Select::Password))).await, err(AgentError::Denied));
    assert_eq!(agent.dispatch(org(get_op("o2", Select::ListFields))).await, err(AgentError::Denied));
}

#[tokio::test]
async fn an_organization_item_of_an_organization_that_cannot_be_unlocked_is_left_out() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    let mut vault: Value = serde_json::from_str(include_str!("../tests/fixtures/org-vault.json")).unwrap();
    vault["profile"]["organizations"][0]["enabled"] = json!(false);
    host.vault(&vault.to_string());
    seed_credentials(&agent, "org");
    host.answer(Answer::Text("vectors-org-password"));
    assert_eq!(agent.dispatch(Op::Unlock { profile: Some("org".into()) }).await, Reply::Done);
    let rows = items(agent.dispatch(org(list_op(&[Field::Name], None))).await);
    let mut ids: Vec<_> = rows.iter().map(|r| r.id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, ["o3", "p1"], "org-a is off: its items are held");
}

#[tokio::test]
async fn a_lock_while_waiting_for_the_user_cancels_the_read() {
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
    // The profile is locked now: a new request starts with the unlock, which the user cancels.
    assert_eq!(agent.dispatch(get_op("c1", Select::Password)).await, err(AgentError::Denied));
}

/// A locked profile with a stored key and the fixture vault (nothing unlocked yet).
fn locked_world() -> (tempfile::TempDir, Arc<Agent>, FakeHost) {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    let mut vault: Value = serde_json::from_str(VAULT).unwrap();
    vault["ciphers"].as_array_mut().unwrap().iter_mut().for_each(|c| c["reprompt"] = json!(0));
    host.vault(&vault.to_string());
    seed_credentials(&agent, "work");
    (dir, agent, host)
}

async fn unlocked(agent: &Agent) -> bool {
    let Reply::Status { profiles, .. } = agent.dispatch(Op::Status { profile: Some("work".into()) }).await else {
        panic!("no status")
    };
    profiles[0].unlocked
}

#[tokio::test]
async fn a_locked_profile_unlocks_on_first_need_with_one_password_prompt_then_the_value_confirm() {
    let (_dir, agent, host) = locked_world();
    host.answer(Answer::Text(crate::host::fake::PASSWORD));
    assert_eq!(text(allowed(&agent, &host, get_op("n1", Select::Password)).await), "the note's text");
    assert_eq!(host.world().asked.len(), 1, "exactly one master-password prompt");
    assert_eq!(host.world().confirmed.len(), 1, "and then the value confirm");
    assert!(unlocked(&agent).await);
    // Unlocked now: no second password prompt.
    assert!(!items(agent.dispatch(list_op(&[], None)).await).is_empty());
    assert_eq!(host.world().asked.len(), 1);
}

#[tokio::test]
async fn list_search_and_history_also_unlock_on_first_need() {
    for op in [list_op(&[], None), search_op("a", &[], None), history_op("c1")] {
        let (_dir, agent, host) = locked_world();
        host.answer(Answer::Text(crate::host::fake::PASSWORD));
        host.allow();
        let reply = agent.dispatch(op).await;
        assert!(!matches!(reply, Reply::Error { error: AgentError::Locked }), "{reply:?}");
        assert_eq!(host.world().asked.len(), 1);
        assert!(unlocked(&agent).await);
    }
}

#[tokio::test]
async fn two_requests_on_a_locked_profile_share_one_unlock() {
    let (_dir, agent, host) = locked_world();
    host.answer(Answer::Held);
    let asks: Vec<_> = (0..2)
        .map(|_| {
            let agent = agent.clone();
            tokio::spawn(async move { agent.dispatch(list_op(&[], None)).await })
        })
        .collect();
    until(|| host.world().asked.len() == 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    host.world().release.notify_one();
    for ask in asks {
        assert!(matches!(ask.await.unwrap(), Reply::Items { .. }));
    }
    assert_eq!(host.world().asked.len(), 1, "the second request waited for the first unlock");
}

/// The value gate starts at the unlock: a cancelled or failed unlock is its own error, and nothing is looked up,
/// confirmed or opened. (If the unlock error were swallowed, the read would go on and answer `Locked`.)
#[tokio::test]
async fn a_cancelled_first_need_unlock_opens_nothing_and_shows_no_value_confirm() {
    for (cancel, expected) in [(true, AgentError::Denied), (false, AgentError::Prompt)] {
        for op in [get_op("c1", Select::Password), history_op("c1"), list_op(&[], None), search_op("a", &[], None)] {
            let (_dir, agent, host) = locked_world();
            host.answer(if cancel { Answer::Cancel } else { Answer::Fail });
            host.allow(); // a confirm would be answered yes: it must not be shown at all
            assert_eq!(agent.dispatch(op).await, err(expected.clone()));
            assert!(host.world().confirmed.is_empty(), "no value confirm after a failed unlock");
            assert_eq!(agent.opens("work").await, 0);
            assert!(!unlocked(&agent).await);
        }
    }
}

#[tokio::test]
async fn a_logged_out_profile_is_not_logged_in_by_a_read() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, _, host) = agent_world(dir.path());
    assert_eq!(agent.dispatch(get_op("c1", Select::Password)).await, err(AgentError::NotLoggedIn));
    assert!(host.world().asked.is_empty());
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
