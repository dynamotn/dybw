//! The rbw shim's requests through the agent: `get` in rbw's view (`rbw: true`), `list --raw` URIs, the values a
//! write carries (rbw's `$EDITOR`), `-i` on history/edit/remove, and `purge`. Expected values follow rbw 1.15.0
//! `src/bin/rbw/commands.rs` (`display_short` 351-409, `display_field` 411-689, `display_fields_list` 857-995,
//! `decrypt_cipher` 2300-2627).
#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use dybw_proto::{
    AgentError, Field, Op, RbwCard, RbwData, RbwField, RbwIdentity, RbwItem, RbwLogin, RbwPast, RbwSshKey, RbwUri,
    Reply, Sealed, Secret, Select,
};
use serde_json::{Value, json};

use crate::agent::testing::Rig;
use crate::host::fake::Answer;
use crate::policy::Verdict;
use crate::read_tests::{C1, MAIL, err, get_op, items, text};
use crate::write_tests::{
    PERIOD_START, TOTP, ai, at, audited, code_at, edit_op, login, remove_op, setup, unknown, w, writes,
};

fn rbw_op(needle: &str, select: Select) -> Op {
    let Op::Get { profile, needle, user, folder, ignorecase, select, .. } = get_op(needle, select) else { panic!() };
    Op::Get { profile, needle, user, folder, ignorecase, select, rbw: true }
}

async fn rbw(rig: &Rig, needle: &str, select: Select) -> Reply {
    rig.host.allow();
    rig.agent.dispatch(rbw_op(needle, select)).await
}

fn field(name: &str) -> Select {
    Select::Field(name.into())
}

#[tokio::test]
async fn rbw_get_prints_the_main_value_rbw_prints_or_names_what_is_missing() {
    let (_dir, rig) = setup(|v| {
        // An identity with no part of a name.
        let i2 = v["ciphers"].as_array_mut().unwrap().iter_mut().find(|c| c["id"] == "i2").unwrap();
        i2["identity"]["firstName"] = Value::Null;
    })
    .await;
    let cases = [
        ("c1", "pw-ünï-😀"),
        ("n1", "the note's text"),
        ("k1", "4111111111111111"),
        // rbw puts the title first (commands.rs:378-384).
        ("i1", "title-value firstName-value middleName-value lastName-value"),
        ("s1", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI deploy@example.invalid"),
        ("u1", "a type from a newer server"),
    ];
    for (id, expected) in cases {
        assert_eq!(text(rbw(&rig, id, Select::Password).await), expected, "{id}");
    }
    let missing = [
        ("c2", "password"),
        ("k3", "card number"),
        ("i2", "name"),
        ("n2", "notes"),
        ("s2", "public key"),
        ("u2", "notes"),
    ];
    for (id, what) in missing {
        assert_eq!(rbw(&rig, id, Select::Password).await, err(AgentError::NoValue(what.into())), "{id}");
    }
    assert_eq!(rbw(&rig, "c2", field("Password")).await, err(AgentError::NoValue("password".into())));
}

#[tokio::test]
async fn rbw_get_field_resolves_each_name_as_rbw_does() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.clock.set_wall(at(PERIOD_START + 3));
    let code = code_at(PERIOD_START + 3);
    let cases = [
        ("c1", "USER", "me@example.invalid"),
        ("c1", "username", "me@example.invalid"),
        ("c1", "password", "pw-ünï-😀"),
        ("c1", "Notes", "line 1\nline 2"),
        ("c1", "note", "line 1\nline 2"),
        ("c1", "sites", "https://a.example.invalid\nhttps://b.example.invalid\n^https://c\\.example\\.invalid/"),
        ("c1", "totp", code.as_str()),
        ("c1", "code", code.as_str()),
        // A custom field: the first whose name holds the text, ignoring case; a field with no value is empty.
        ("c1", "HID", "kept-secret"),
        ("c1", "lin", ""),
        ("c1", "", "shown"),
        ("k1", "number", "4111111111111111"),
        ("k1", "card", "4111111111111111"),
        ("k1", "exp", "12/2030"),
        ("k1", "month", "12"),
        ("k1", "exp_year", "2030"),
        ("k1", "cvv", "123"),
        ("k1", "name", "Ann Example"),
        ("k1", "cardholder_name", "Ann Example"),
        ("k1", "type", "Visa"),
        ("k1", "notes", "card notes"),
        ("k1", "pi", "0000"),
        ("i1", "name", "title-value firstName-value middleName-value lastName-value"),
        ("i1", "email", "email-value"),
        ("i1", "address", "address1-value\naddress2-value\naddress3-value"),
        ("i1", "city", "city-value"),
        ("i1", "state", "state-value"),
        ("i1", "zip", "postalCode-value"),
        ("i1", "country", "country-value"),
        ("i1", "phone", "phone-value"),
        ("i1", "ssn", "ssn-value"),
        ("i1", "license", "licenseNumber-value"),
        ("i1", "passport", "passportNumber-value"),
        ("i1", "user", "username-value"),
        ("i2", "notes", "n"),
        ("n1", "NOTES", "the note's text"),
        ("n1", "f", "v"),
        ("s1", "public_key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI deploy@example.invalid"),
        ("s1", "fingerprint", "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"),
        (
            "s1",
            "private_key",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----",
        ),
        ("u1", "notes", "a type from a newer server"),
        ("u1", "IBAN", "XX00 0000"),
        ("x1", "uris", ""),
    ];
    for (id, name, expected) in cases {
        assert_eq!(text(rbw(&rig, id, field(name)).await), expected, "{id} {name}");
    }
    // What rbw prints nothing for: a part the item lacks, a name no field holds, a name of another type's part.
    let silent = [
        ("c1", "name"),
        ("c1", "nope"),
        ("x1", "totp"),
        ("x1", "notes"),
        ("k1", "code"),
        ("k2", "exp"),
        ("k2", "cvv"),
        ("i1", "title"),
        ("i2", "address"),
        ("s1", "notes"),
        ("s1", "nope"),
        ("n2", "f"),
        ("u2", "x"),
    ];
    for (id, name) in silent {
        assert_eq!(rbw(&rig, id, field(name)).await, Reply::Done, "{id} {name}");
    }
    let Reply::Error { error: AgentError::Totp(why) } = rbw(&rig, "x2", field("totp")).await else { panic!() };
    assert!(!why.contains("JBSWY3DPEHPK3PXP"), "the key is never shown: {why}");
}

#[tokio::test]
async fn rbw_full_and_raw_are_the_item_in_rbws_shape_behind_the_whole_item_gate() {
    let (_dir, rig) = setup(|v| {
        let u1 = v["ciphers"].as_array_mut().unwrap().iter_mut().find(|c| c["id"] == "u1").unwrap();
        u1["fields"][0]["type"] = json!(7);
    })
    .await;
    let s = |v: &str| Some(Secret::new(v.into()));
    let Reply::RbwItem { item } = rbw(&rig, "c1", Select::Raw).await else { panic!() };
    let expected = RbwItem {
        id: "c1".into(),
        folder: Some("Work ünï 😀".into()),
        name: MAIL.into(),
        data: RbwData::Login(RbwLogin {
            username: s("me@example.invalid"),
            password: s("pw-ünï-😀"),
            totp: s(TOTP),
            uris: Some(vec![
                RbwUri { uri: Secret::new("https://a.example.invalid".into()), match_type: None },
                RbwUri { uri: Secret::new("https://b.example.invalid".into()), match_type: Some(0) },
                RbwUri { uri: Secret::new("^https://c\\.example\\.invalid/".into()), match_type: Some(4) },
            ]),
        }),
        fields: vec![
            RbwField { name: Some("text".into()), value: s("shown"), ty: Some("text".into()) },
            RbwField { name: Some("hidden".into()), value: s("kept-secret"), ty: Some("hidden".into()) },
            RbwField { name: Some("flag".into()), value: s("true"), ty: Some("boolean".into()) },
            RbwField { name: Some("linked".into()), value: None, ty: Some("linked".into()) },
            RbwField { name: Some(String::new()), value: s(""), ty: Some("text".into()) },
        ],
        notes: s("line 1\nline 2"),
        history: vec![
            RbwPast { last_used_date: "2025-02-01T00:00:00Z".into(), password: Secret::new("old-2".into()) },
            RbwPast { last_used_date: "unknown".into(), password: Secret::new("old-1".into()) },
        ],
    };
    assert_eq!(*item, expected);
    let Reply::RbwItem { item: full } = rbw(&rig, "c1", Select::Full).await else { panic!() };
    assert_eq!(full, item, "--full is drawn by the client from the same item");
    let asked = rig.host.world().confirmed.clone();
    assert!(asked[0].ends_with(&format!("(dybw get) to read the raw item as JSON of the item {C1}?")), "{}", asked[0]);
    assert!(asked[1].contains("to read the full item (every value)"), "{}", asked[1]);
    assert_eq!(rig.host.world().offered, [false, false], "the whole item: never \"always\"");
    let data = |id: &'static str| {
        let rig = &rig;
        async move {
            let Reply::RbwItem { item } = rbw(rig, id, Select::Raw).await else { panic!() };
            item
        }
    };
    let k2 = data("k2").await;
    let none = || None;
    assert_eq!(
        k2.data,
        RbwData::Card(RbwCard {
            cardholder_name: none(),
            number: s("5500000000000004"),
            brand: none(),
            exp_month: none(),
            exp_year: none(),
            code: none()
        })
    );
    assert_eq!((k2.folder, k2.notes, k2.fields, k2.history), (None, None, vec![], vec![]));
    let RbwData::Identity(i1) = data("i1").await.data else { panic!() };
    assert_eq!(
        *i1,
        RbwIdentity {
            title: s("title-value"),
            first_name: s("firstName-value"),
            middle_name: s("middleName-value"),
            last_name: s("lastName-value"),
            address1: s("address1-value"),
            address2: s("address2-value"),
            address3: s("address3-value"),
            city: s("city-value"),
            state: s("state-value"),
            postal_code: s("postalCode-value"),
            country: s("country-value"),
            phone: s("phone-value"),
            email: s("email-value"),
            ssn: s("ssn-value"),
            license_number: s("licenseNumber-value"),
            passport_number: s("passportNumber-value"),
            username: s("username-value"),
        }
    );
    assert_eq!(
        data("s2").await.data,
        RbwData::SshKey(RbwSshKey { public_key: none(), fingerprint: none(), private_key: none() })
    );
    for id in ["n1", "u1"] {
        assert_eq!(data(id).await.data, RbwData::SecureNote, "{id}");
    }
    let fields = data("u1").await.fields;
    assert_eq!(fields[0].ty, None, "a field type rbw does not know has no name");
}

#[tokio::test]
async fn rbw_list_fields_names_the_parts_present_with_no_question_and_without_opening() {
    let (_dir, rig) = setup(|_| {}).await;
    let names = |id: &'static str| {
        let rig = &rig;
        async move {
            match rig.agent.dispatch(rbw_op(id, Select::ListFields)).await {
                Reply::FieldNames { names } => names,
                other => panic!("{other:?}"),
            }
        }
    };
    let cases: [(&str, &[&str]); 10] = [
        ("c1", &["username", "totp", "uris", "password", "notes", "text", "hidden", "flag", "linked", ""]),
        ("c2", &["uris"]),
        ("k1", &["number", "exp_month", "exp_year", "cvv", "cardholder", "brand", "notes", "pin"]),
        ("k2", &["number"]),
        (
            "i1",
            &[
                "name", "email", "address", "city", "state", "postcode", "country", "phone", "ssn", "license",
                "passport", "username",
            ],
        ),
        ("i2", &["name", "notes"]),
        ("s1", &["fingerprint", "public_key"]),
        ("n1", &["notes", "f"]),
        ("u1", &["notes", "iban"]),
        ("u2", &[]),
    ];
    for (id, expected) in cases {
        assert_eq!(names(id).await, expected, "{id}");
    }
    assert!(rig.host.world().confirmed.is_empty(), "names only: nobody is asked");
    assert_eq!(rig.agent.opens("work").await, 0, "no item is opened");
}

#[tokio::test]
async fn an_organization_login_that_hides_its_password_hides_it_from_rbws_names_too() {
    let dir = tempfile::tempdir().unwrap();
    let rig = crate::agent::testing::rig(dir.path());
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
    let org = |select: Select| {
        let Op::Get { needle, user, folder, ignorecase, select, .. } = rbw_op("o1", select) else { panic!() };
        Op::Get { profile: Some("org".into()), needle, user, folder, ignorecase, select, rbw: true }
    };
    for select in [Select::Password, field("PASSWORD"), field("Totp"), field("code"), Select::Full, Select::Raw] {
        rig.host.allow();
        assert_eq!(rig.agent.dispatch(org(select.clone())).await, err(AgentError::Denied), "{select:?}");
    }
    assert!(rig.host.world().confirmed.is_empty(), "refused before any question");
    // rbw reads the first field whose name holds the text: one of the hidden type is refused after the yes.
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(org(field("HIDD"))).await, err(AgentError::Denied));
    assert_eq!(rig.host.world().confirmed.len(), 1);
    assert_eq!(rig.agent.opens("org").await, 0);
    rig.host.allow();
    assert_eq!(text(rig.agent.dispatch(org(field("tex"))).await), "shown");
    rig.host.allow();
    assert_eq!(text(rig.agent.dispatch(org(field("user"))).await), "me@example.invalid", "a login part");
}

#[tokio::test]
async fn list_and_search_give_a_logins_uris_only_when_asked() {
    let (_dir, rig) = setup(|_| {}).await;
    let list = |fields: &[Field]| Op::List { profile: w(), fields: fields.to_vec(), folder: None };
    let rows = items(rig.agent.dispatch(list(&[Field::Name, Field::Uri])).await);
    let uris = |id: &str| rows.iter().find(|r| r.id == id).unwrap().uris.clone();
    assert_eq!(
        uris("c1"),
        Some(vec![
            "https://a.example.invalid".into(),
            "https://b.example.invalid".into(),
            "^https://c\\.example\\.invalid/".into()
        ])
    );
    assert_eq!(uris("c2"), Some(vec![]), "a login without URIs");
    assert_eq!(uris("k1"), None, "not a login");
    assert!(items(rig.agent.dispatch(list(&[Field::Name])).await).iter().all(|r| r.uris.is_none()));
    // A search never matches a URI: its term is matched against names and users only.
    let search = |term: &str| Op::Search { profile: w(), term: term.into(), folder: None, fields: vec![Field::Uri] };
    assert!(items(rig.agent.dispatch(search("b.example")).await).is_empty());
    let found = items(rig.agent.dispatch(search("ünï")).await);
    assert_eq!(found.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["c1"]);
    assert_eq!(found[0].uris.as_ref().map(Vec::len), Some(3));
    assert!(rig.host.world().confirmed.is_empty());
    assert_eq!(rig.agent.opens("work").await, 0);
    // An AI-class caller gets names and ids, never a URI.
    for op in [list(&[Field::Name, Field::Uri]), search("ünï")] {
        let rows = items(rig.agent.dispatch_as(op, ai()).await);
        assert!(!rows.is_empty() && rows.iter().all(|r| r.uris.is_none()), "{rows:?}");
    }
}

fn sealed(v: &str) -> Option<Sealed> {
    Some(Sealed::new(v.into()))
}

fn add_with(name: &str, password: Option<Sealed>, notes: Option<Sealed>) -> Op {
    Op::Add { profile: w(), name: name.into(), user: None, uris: vec![], folder: None, ask: vec![], password, notes }
}

fn edit_with(needle: &str, ignorecase: bool, password: Option<Sealed>, notes: Option<Sealed>) -> Op {
    let Op::Edit { profile, needle, user, folder, ask, .. } = edit_op(needle, &[]) else { panic!() };
    Op::Edit { profile, needle, user, folder, ask, ignorecase, password, notes, text: None }
}

#[tokio::test]
async fn values_a_write_carries_are_confirmed_every_time_and_never_asked_for() {
    let (_dir, rig) = setup(|_| {}).await;
    let asked = rig.host.world().asked.len();
    // Declined: nothing is written.
    assert_eq!(rig.agent.dispatch(add_with("Edited", sealed("p1"), sealed("n1"))).await, err(AgentError::Denied));
    assert_eq!(writes(&rig), 0);
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(add_with("Edited", sealed("p1"), sealed("line 1\nline 2"))).await, Reply::Done);
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(add_with("Other", sealed("p2"), None)).await, Reply::Done);
    {
        let world = rig.host.world();
        assert_eq!(world.confirmed.len(), 3, "each write is asked, also the second of the same caller");
        assert_eq!(world.offered, [false, false, false], "never \"always\"");
        assert_eq!(world.asked.len(), asked, "the values came with the request: no pinentry value");
        assert!(world.confirmed[1].contains("(dybw add) to add the login \"Edited\"?"), "{}", world.confirmed[1]);
        assert!(!world.bodies.iter().any(|b| b.to_string().contains("line 1")), "sent encrypted");
    }
    assert_eq!(text(rbw(&rig, "Edited", Select::Password).await), "p1");
    assert_eq!(text(rbw(&rig, "Edited", field("notes")).await), "line 1\nline 2");
    // An edit, found ignoring case: the old password goes to the history.
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(edit_with("plain", true, sealed("new-pass"), sealed(""))).await, Reply::Done);
    let confirm = rig.host.world().confirmed.last().unwrap().clone();
    assert!(confirm.contains("to change the password and the notes of the item \"Plain\""), "{confirm}");
    assert_eq!(text(rbw(&rig, "x1", Select::Password).await), "new-pass");
    let Reply::RbwItem { item } = rbw(&rig, "x1", Select::Raw).await else { panic!() };
    assert_eq!(item.history[0].password.expose(), "old-pass");
    // Notes alone, as rbw's edit of a note.
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(edit_with("n1", false, None, sealed("new text"))).await, Reply::Done);
    assert_eq!(text(rbw(&rig, "n1", Select::Password).await), "new text");
    // Without `-i` the case must match: nothing is found and nobody is asked.
    let before = rig.host.world().confirmed.len();
    assert_eq!(rig.agent.dispatch(edit_with("PLAIN", false, sealed("x"), None)).await, err(AgentError::NotFound));
    assert_eq!(rig.host.world().confirmed.len(), before);
}

#[tokio::test]
async fn an_ai_or_unknown_caller_cannot_write_values_it_carries() {
    let (_dir, rig) = setup(|_| {}).await;
    for caller in [ai(), unknown()] {
        for op in [add_with("New", sealed("p"), sealed("n")), edit_with("x1", false, sealed("p"), None)] {
            rig.host.allow();
            assert_eq!(rig.agent.dispatch_as(op, caller.clone()).await, err(AgentError::Denied));
        }
    }
    assert!(rig.host.world().confirmed.is_empty(), "refused before any question");
    assert_eq!(writes(&rig), 0);
    assert!(audited(&rig).iter().all(|(_, _, v)| *v == Verdict::Denied));
}

#[tokio::test]
async fn history_and_remove_find_their_item_ignoring_case_with_dash_i() {
    let (_dir, rig) = setup(|v| {
        v["ciphers"].as_array_mut().unwrap().push(login("y1", "Second", None));
    })
    .await;
    let history =
        |ignorecase| Op::History { profile: w(), needle: "plain".into(), user: None, folder: None, ignorecase };
    assert_eq!(rig.agent.dispatch(history(false)).await, err(AgentError::NotFound));
    rig.host.allow();
    assert!(matches!(rig.agent.dispatch(history(true)).await, Reply::History { .. }));
    let Op::Remove { profile, user, folder, .. } = remove_op("x") else { panic!() };
    let remove = |ignorecase| Op::Remove {
        profile: profile.clone(),
        needle: "SECOND".into(),
        user: user.clone(),
        folder: folder.clone(),
        ignorecase,
    };
    assert_eq!(rig.agent.dispatch(remove(false)).await, err(AgentError::NotFound));
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(remove(true)).await, Reply::Done);
    assert_eq!(writes(&rig), 1);
}

fn purge() -> Op {
    Op::Purge { profile: w() }
}

fn unlocked(reply: Reply) -> bool {
    let Reply::Status { profiles, .. } = reply else { panic!() };
    profiles[0].unlocked
}

#[tokio::test]
async fn purge_locks_and_deletes_the_local_copy_once_the_user_says_yes() {
    let (dir, rig) = setup(|_| {}).await;
    let state = dir.path().join(".local/state/dybw/profiles/work");
    let cache = dir.path().join(".cache/dybw/profiles/work");
    assert!(cache.join("sync.json").exists());
    let status = || Op::Status { profile: w() };
    // Refused to an AI or unknown caller, before anything.
    for caller in [ai(), unknown()] {
        assert_eq!(rig.agent.dispatch_as(purge(), caller).await, err(AgentError::Denied));
    }
    assert!(rig.host.world().confirmed.is_empty());
    // The user says no: nothing changes.
    assert_eq!(rig.agent.dispatch(purge()).await, err(AgentError::Denied));
    assert!(cache.join("sync.json").exists() && unlocked(rig.agent.dispatch(status()).await));
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(purge()).await, Reply::Done);
    let confirm = rig.host.world().confirmed.last().unwrap().clone();
    assert!(
        confirm.ends_with("(rbw purge) to lock the profile and delete its local copy of the vault? (asked every time)"),
        "{confirm}"
    );
    assert_eq!(rig.host.world().offered.last(), Some(&false));
    assert!(!cache.exists(), "the copy is gone");
    assert!(!unlocked(rig.agent.dispatch(status()).await), "locked");
    assert!(state.join("credentials").exists(), "the API key stays");
    assert!(state.join("devices/dybw").exists(), "the device id stays");
    let verdicts: Vec<_> = audited(&rig).into_iter().map(|(op, _, v)| (op, v)).collect();
    assert_eq!(
        verdicts,
        [
            ("purge", Verdict::Denied),
            ("purge", Verdict::Denied),
            ("purge", Verdict::Declined),
            ("purge", Verdict::Confirmed)
        ]
    );
    // Purged again, with nothing left to delete and the profile locked: still asked, still fine.
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(purge()).await, Reply::Done);
}

#[tokio::test]
async fn a_purge_that_cannot_delete_the_copy_fails_and_a_deny_entry_refuses_it_unasked() {
    let (dir, rig) = setup(|_| {}).await;
    let cache = dir.path().join(".cache/dybw/profiles/work");
    std::fs::remove_dir_all(&cache).unwrap();
    std::fs::write(&cache, "a file where the directory was").unwrap();
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(purge()).await, err(AgentError::Internal));
    assert_eq!(audited(&rig).last().unwrap().2, Verdict::Failed);
    rig.host.allow();
    let deny = dybw_proto::PolicyAction::Deny { invoker: "/usr/local/bin/mytool".into(), script: None };
    assert_eq!(rig.agent.dispatch(Op::Policy { profile: w(), action: deny }).await, Reply::Done);
    let asked = rig.host.world().confirmed.len();
    assert_eq!(rig.agent.dispatch(purge()).await, err(AgentError::Denied));
    assert_eq!(rig.host.world().confirmed.len(), asked, "not asked");
}

#[tokio::test]
async fn rbw_edit_reads_only_the_password_and_notes_and_says_why() {
    let (_dir, rig) = setup(|_| {}).await;
    let s = |v: &str| Some(Secret::new(v.into()));
    let Reply::RbwItem { item } = rbw(&rig, "c1", Select::EditText).await else { panic!() };
    let login = RbwLogin { username: None, password: s("pw-ünï-😀"), totp: None, uris: None };
    assert_eq!(
        (item.data, item.notes, item.fields, item.history),
        (RbwData::Login(login), s("line 1\nline 2"), vec![], vec![])
    );
    let asked = rig.host.world().confirmed[0].clone();
    assert!(
        asked.ends_with(&format!("(dybw edit) to read its current password and notes, to edit them of the item {C1}?")),
        "{asked}"
    );
    assert_eq!(rig.host.world().offered, [false], "never \"always\"");
    // The same without the rbw flag; a note; another type is refused.
    rig.host.allow();
    let Reply::RbwItem { item } = rig.agent.dispatch(get_op("n1", Select::EditText)).await else { panic!() };
    assert_eq!((item.data, item.notes), (RbwData::SecureNote, s("the note's text")));
    assert_eq!(rbw(&rig, "k1", Select::EditText).await, err(AgentError::WriteRefused("rbw-type".into())));
}

fn edit_text(needle: &str, text: &str) -> Op {
    let Op::Edit { profile, needle, user, folder, ask, .. } = edit_op(needle, &[]) else { panic!() };
    Op::Edit { profile, needle, user, folder, ask, ignorecase: false, password: None, notes: None, text: sealed(text) }
}

#[tokio::test]
async fn rbw_edit_text_from_stdin_is_split_by_the_items_type_in_the_agent() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(edit_text("x1", "pw3\n\nn3\n# c\n")).await, Reply::Done);
    let confirm = rig.host.world().confirmed[0].clone();
    assert!(confirm.contains("to change the password and the notes of the item \"Plain\""), "{confirm}");
    assert_eq!(text(rbw(&rig, "x1", Select::Password).await), "pw3");
    assert_eq!(text(rbw(&rig, "x1", field("notes")).await), "n3");
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(edit_text("n1", "a\n\nb\n")).await, Reply::Done);
    assert_eq!(text(rbw(&rig, "n1", Select::Password).await), "a\n\nb", "a note's whole text");
    let asked = rig.host.world().confirmed.len();
    assert_eq!(rig.agent.dispatch(edit_text("k1", "x")).await, err(AgentError::WriteRefused("rbw-type".into())));
    assert_eq!(
        rig.agent.dispatch(edit_text("x1", "\n# nothing\n")).await,
        err(AgentError::WriteRefused("empty".into()))
    );
    assert_eq!(rig.host.world().confirmed.len(), asked, "refused before any question");
}
