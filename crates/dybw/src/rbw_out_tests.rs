//! What the rbw shim prints, byte for byte, and its errors with their exit codes. Each golden is built from rbw
//! 1.15.0's own code (`src/bin/rbw/commands.rs`, cited per test), not from running rbw (the conformance run compares
//! with the real binary).

#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use dybw_proto::{
    AgentError, Candidate, HistoryEntry, ItemSummary, Op, ProfileStatus, RbwCard, RbwData, RbwField, RbwIdentity,
    RbwItem, RbwLogin, RbwPast, RbwSshKey, RbwUri, Reply, Sealed, Secret, Select,
};

use super::*;
use crate::tests::{Act, ClipLog, env_in, fake, s, secret, status};

/// `args` as `rbw` against a fake agent giving `acts` in turn, `vars` on top of the test environment; the output and
/// the requests the agent saw.
pub(crate) fn rbw_run(
    acts: Vec<Act>,
    vars: &[(&'static str, String)],
    args: &[&str],
    tweak: impl FnOnce(&mut Env),
) -> ((u8, String, String), Vec<Op>) {
    let f = fake(acts);
    let mut env = env_in(f.base.path(), None, None);
    let inner = std::mem::replace(&mut env.var, Box::new(|_| None));
    let vars: Vec<(&'static str, String)> = vars.to_vec();
    env.var = Box::new(move |n| vars.iter().find(|(k, _)| *k == n).map(|(_, v)| v.into()).or_else(|| inner(n)));
    tweak(&mut env);
    let (mut out, mut err) = (vec![], vec![]);
    let argv: Vec<std::ffi::OsString> = ["rbw"].iter().chain(args).map(Into::into).collect();
    let code = rbw::run(argv, &env, &mut out, &mut err);
    drop(env);
    ((code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap()), f.ops())
}

/// One request, one reply.
fn one(args: &[&str], reply: Reply) -> (u8, String, String) {
    rbw_run(vec![Act::Reply(reply)], &[], args, |_| {}).0
}

fn sec(v: &str) -> Option<Secret> {
    Some(Secret::new(v.into()))
}

fn row(
    id: &str,
    name: &str,
    user: Option<&str>,
    folder: Option<&str>,
    kind: &str,
    uris: Option<&[&str]>,
) -> ItemSummary {
    ItemSummary {
        id: s(id),
        name: Some(s(name)),
        user: user.map(s),
        folder: folder.map(s),
        kind: Some(s(kind)),
        uris: uris.map(|u| u.iter().map(|u| s(u)).collect()),
    }
}

fn rows() -> Vec<ItemSummary> {
    vec![
        row("2", "bank", None, None, "Card", None),
        row("1", "Mail ünï\twith tab", Some("me"), Some("Work 😀"), "SshKey", None),
        row("3", "alpha", Some("u3"), None, "Login", Some(&["https://a.invalid", "https://b.invalid"])),
    ]
}

// list and search: `print_entry_list` (1426-1482), sorted by name (1379, 1515), rbw's type names (2182-2191)

#[test]
fn list_prints_the_fields_asked_for_tab_separated_sorted_by_name_and_raw() {
    let cell = |r: &ItemSummary, f: &str| -> String {
        match f {
            "id" => r.id.clone(),
            "name" => r.name.clone().unwrap(),
            "user" => r.user.clone().unwrap_or_default(),
            "folder" => r.folder.clone().unwrap_or_default(),
            _ => r.kind.clone().map(|k| if k == "SshKey" { s("SSH Key") } else { k }).unwrap(),
        }
    };
    let mut sorted = rows();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(sorted.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["1", "3", "2"], "bytes: upper case first");
    let names = ["id", "name", "user", "folder", "type"];
    // Every non-empty set of the five, in order, then reversed, and a field asked twice.
    let mut combos: Vec<Vec<&str>> = (1u32..32)
        .map(|m| names.iter().enumerate().filter(|(i, _)| m & (1 << i) != 0).map(|(_, n)| *n).collect())
        .collect();
    combos.extend(combos.clone().into_iter().map(|mut c| {
        c.reverse();
        c
    }));
    combos.push(vec!["name", "name"]);
    for combo in combos {
        let arg = combo.join(",");
        let expected: String =
            sorted.iter().map(|r| combo.iter().map(|f| cell(r, f)).collect::<Vec<_>>().join("\t") + "\n").collect();
        for cmd in [&["list", "--fields", &arg][..], &["search", "a", "--fields", &arg]] {
            assert_eq!(one(cmd, Reply::Items { items: rows() }), (0, expected.clone(), s("")), "{cmd:?}");
        }
    }
    assert_eq!(one(&["ls"], Reply::Items { items: rows() }).1, "Mail ünï\twith tab\nalpha\nbank\n", "the default");
    // `--raw`: pretty JSON of every field, URIs as the agent gave them (a login's only).
    let raw = r#"[
  {
    "id": "1",
    "name": "Mail ünï\twith tab",
    "user": "me",
    "folder": "Work 😀",
    "uris": null,
    "type": "SSH Key"
  },
  {
    "id": "3",
    "name": "alpha",
    "user": "u3",
    "folder": null,
    "uris": [
      "https://a.invalid",
      "https://b.invalid"
    ],
    "type": "Login"
  },
  {
    "id": "2",
    "name": "bank",
    "user": null,
    "folder": null,
    "uris": null,
    "type": "Card"
  }
]
"#;
    assert_eq!(one(&["list", "--raw"], Reply::Items { items: rows() }), (0, s(raw), s("")));
    // A search row has URIs for every type, empty but for a login (`From<DecryptedSearchCipher>`, 325-336).
    let searched = raw.replace("\"uris\": null", "\"uris\": []");
    assert_eq!(one(&["search", "a", "--raw"], Reply::Items { items: rows() }), (0, searched, s("")));
    assert_eq!(one(&["list", "--raw"], Reply::Items { items: vec![] }), (0, s("[]\n"), s("")));
    assert_eq!(one(&["list"], Reply::Items { items: vec![] }), (0, s(""), s("")));
}

/// Fails every write with a broken pipe, as stdout piped into `head` that has exited.
struct Closed;

impl std::io::Write for Closed {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_closed_pipe_ends_a_list_quietly_and_fails_any_other_output() {
    let f = fake(vec![Act::Reply(Reply::Items { items: rows() }), Act::Reply(Reply::Value { value: secret("v") })]);
    let env = env_in(f.base.path(), None, None);
    let mut err = vec![];
    assert_eq!(rbw::run(["rbw", "list"], &env, &mut Closed, &mut err), 0);
    assert!(err.is_empty());
    assert_eq!(rbw::run(["rbw", "get", "n"], &env, &mut Closed, &mut err), 1);
    assert!(String::from_utf8(err).unwrap().starts_with("rbw get: cannot write the output"));
}

// get: `get` (1387-1424), `display_short` (351-409), `display_long` (691-854), `display_json` (997-1003)

pub(crate) fn note_item(notes: Option<&str>) -> RbwItem {
    RbwItem {
        id: s("n1"),
        folder: None,
        name: s("note"),
        data: RbwData::SecureNote,
        fields: vec![],
        notes: notes.and_then(sec),
        history: vec![],
    }
}

fn login_item() -> RbwItem {
    RbwItem {
        id: s("c1"),
        folder: Some(s("Work")),
        name: s("Mail"),
        data: RbwData::Login(RbwLogin {
            username: sec("me"),
            password: sec("pw"),
            totp: sec("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"),
            uris: Some(vec![
                RbwUri { uri: Secret::new(s("https://a.invalid")), match_type: None },
                RbwUri { uri: Secret::new(s("https://b.invalid")), match_type: Some(0) },
                RbwUri { uri: Secret::new(s("^https://c")), match_type: Some(4) },
                RbwUri { uri: Secret::new(s("x")), match_type: Some(9) },
            ]),
        }),
        fields: vec![
            RbwField { name: Some(s("text")), value: sec("shown"), ty: Some(s("text")) },
            RbwField { name: None, value: None, ty: None },
        ],
        notes: sec("line 1\nline 2"),
        history: vec![RbwPast { last_used_date: s("2025-02-01T00:00:00Z"), password: Secret::new(s("old")) }],
    }
}

fn full(item: RbwItem) -> (u8, String, String) {
    one(&["get", "me@x", "--full"], Reply::RbwItem { item: Box::new(item) })
}

#[test]
fn get_prints_the_value_and_says_what_an_entry_lacks_with_exit_0() {
    assert_eq!(one(&["get", "n"], Reply::Value { value: secret("pw ünï\tx") }), (0, s("pw ünï\tx\n"), s("")));
    let lacks = Reply::Error { error: AgentError::NoValue(s("card number")) };
    let (code, out, err) = rbw_run(vec![Act::Reply(lacks)], &[], &["get", "n", "me"], |_| {}).0;
    assert_eq!((code, out.as_str(), err.as_str()), (0, "", "entry for 'me@n' had no card number\n"));
    // `--field`: nothing printed for a part the entry lacks; a TOTP key that gives no code is said on stderr.
    assert_eq!(one(&["get", "n", "-f", "x"], Reply::Done), (0, s(""), s("")));
    let totp = Reply::Error { error: AgentError::Totp(s("the TOTP digits 12 is outside 1..=10")) };
    assert_eq!(one(&["get", "n", "-f", "totp"], totp.clone()), (0, s(""), s("the TOTP digits 12 is outside 1..=10\n")));
    assert_eq!(one(&["code", "n"], totp), (1, s(""), s("rbw code: the TOTP digits 12 is outside 1..=10\n")));
    assert_eq!(
        one(&["get", "n", "-l"], Reply::FieldNames { names: vec![s("username"), s("uris"), s("Ünï f")] }),
        (0, s("username\nuris\nÜnï f\n"), s(""))
    );
}

#[test]
fn get_full_is_rbws_long_display_for_every_type() {
    let login = "pw\nUsername: me\nTOTP Secret: otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\nURI: https://a.invalid\nURI: \
                 https://b.invalid\nMatch type: domain\nURI: ^https://c\nMatch type: regular_expression\nURI: x\ntext: \
                 shown\n(null): \n\nline 1\nline 2\n";
    assert_eq!(full(login_item()), (0, s(login), s("")));
    // No password, nothing else shown: the message, and the notes with no blank line before them.
    let mut bare = login_item();
    bare.fields.clear();
    bare.data = RbwData::Login(RbwLogin { username: None, password: None, totp: None, uris: Some(vec![]) });
    assert_eq!(full(bare), (0, s("line 1\nline 2\n"), s("entry for 'me@x' had no password\n")));
    let card = RbwItem {
        data: RbwData::Card(RbwCard {
            cardholder_name: sec("Ann"),
            number: sec("4111"),
            brand: sec("Visa"),
            exp_month: sec("12"),
            exp_year: sec("2030"),
            code: sec("123"),
        }),
        notes: sec("cn"),
        ..login_item()
    };
    assert_eq!(full(card), (0, s("4111\nExpiration: 12/2030\nCVV: 123\nName: Ann\nBrand: Visa\n\ncn\n"), s("")));
    let half = RbwItem {
        data: RbwData::Card(RbwCard {
            cardholder_name: None,
            number: None,
            brand: None,
            exp_month: sec("12"),
            exp_year: None,
            code: None,
        }),
        notes: None,
        ..login_item()
    };
    assert_eq!(full(half), (0, s(""), s("entry for 'me@x' had no card number\n")));
    let none = || None;
    let identity = |title, first| RbwIdentity {
        title,
        first_name: first,
        middle_name: none(),
        last_name: sec("Ex"),
        address1: sec("a1"),
        address2: none(),
        address3: sec("a3"),
        city: sec("c"),
        state: sec("s"),
        postal_code: sec("p"),
        country: sec("co"),
        phone: sec("ph"),
        email: sec("e"),
        ssn: sec("ssn"),
        license_number: sec("l"),
        passport_number: sec("pa"),
        username: sec("u"),
    };
    let person =
        RbwItem { data: RbwData::Identity(Box::new(identity(sec("Dr"), sec("Ann")))), notes: None, ..login_item() };
    let lines = "Dr Ann Ex\nAddress: a1\nAddress: a3\nCity: c\nState: s\nPostcode: p\nCountry: co\nPhone: ph\nEmail: \
                 e\nSSN: ssn\nLicense: l\nPassport: pa\nUsername: u\n";
    assert_eq!(full(person), (0, s(lines), s("")));
    let mut nameless = identity(None, None);
    nameless.last_name = None;
    let nameless = RbwItem { data: RbwData::Identity(Box::new(nameless)), ..login_item() };
    let (_, out, err) = full(nameless);
    assert!(out.starts_with("Address: a1\n") && out.ends_with("Username: u\n\nline 1\nline 2\n"), "{out}");
    assert_eq!(err, "entry for 'me@x' had no name\n");
    assert_eq!(full(note_item(Some("the note"))), (0, s("the note\n"), s("")));
    assert_eq!(full(note_item(None)), (0, s(""), s("entry for 'me@x' had no notes\n")));
    let ssh = RbwItem {
        data: RbwData::SshKey(RbwSshKey {
            public_key: sec("ssh-ed25519 AAA"),
            fingerprint: sec("SHA256:x"),
            private_key: sec("never shown"),
        }),
        fields: vec![RbwField { name: Some(s("f")), value: sec("v"), ty: Some(s("text")) }],
        notes: None,
        ..login_item()
    };
    assert_eq!(full(ssh), (0, s("ssh-ed25519 AAA\nFingerprint: SHA256:x\nf: v\n"), s("")));
}

#[test]
fn get_raw_is_rbws_pretty_json_with_untagged_data() {
    let raw = r#"{
  "id": "c1",
  "folder": "Work",
  "name": "Mail",
  "data": {
    "username": "me",
    "password": "pw",
    "totp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
    "uris": [
      {
        "uri": "https://a.invalid",
        "match_type": null
      },
      {
        "uri": "https://b.invalid",
        "match_type": 0
      },
      {
        "uri": "^https://c",
        "match_type": 4
      },
      {
        "uri": "x",
        "match_type": 9
      }
    ]
  },
  "fields": [
    {
      "name": "text",
      "value": "shown",
      "type": "text"
    },
    {
      "name": null,
      "value": null,
      "type": null
    }
  ],
  "notes": "line 1\nline 2",
  "history": [
    {
      "last_used_date": "2025-02-01T00:00:00Z",
      "password": "old"
    }
  ]
}
"#;
    let get = |item| one(&["get", "x", "--raw"], Reply::RbwItem { item: Box::new(item) });
    assert_eq!(get(login_item()), (0, s(raw), s("")));
    let note = "{\n  \"id\": \"n1\",\n  \"folder\": null,\n  \"name\": \"note\",\n  \"data\": null,\n  \"fields\": [],\n  \
                \"notes\": null,\n  \"history\": []\n}\n";
    assert_eq!(get(note_item(None)), (0, s(note), s("")));
    let none = || None;
    let card = RbwData::Card(RbwCard {
        cardholder_name: none(),
        number: sec("4111"),
        brand: none(),
        exp_month: none(),
        exp_year: none(),
        code: none(),
    });
    let (_, out, _) = get(RbwItem { data: card, ..note_item(None) });
    assert!(out.contains("\"data\": {\n    \"cardholder_name\": null,\n    \"number\": \"4111\",\n    \"brand\": null,\n    \"exp_month\": null,\n    \"exp_year\": null,\n    \"code\": null\n  },"), "{out}");
    let ssh = RbwData::SshKey(RbwSshKey { public_key: sec("k"), fingerprint: none(), private_key: sec("p") });
    let (_, out, _) = get(RbwItem { data: ssh, ..note_item(None) });
    assert!(
        out.contains(
            "\"data\": {\n    \"public_key\": \"k\",\n    \"fingerprint\": null,\n    \"private_key\": \"p\"\n  },"
        ),
        "{out}"
    );
}

#[test]
fn get_raw_of_an_identity_keeps_rbws_key_order() {
    let none = || None;
    let id = RbwIdentity {
        title: sec("Dr"),
        first_name: none(),
        middle_name: none(),
        last_name: none(),
        address1: none(),
        address2: none(),
        address3: none(),
        city: none(),
        state: none(),
        postal_code: sec("p"),
        country: none(),
        phone: none(),
        email: none(),
        ssn: none(),
        license_number: none(),
        passport_number: none(),
        username: sec("u"),
    };
    let item = RbwItem { data: RbwData::Identity(Box::new(id)), ..note_item(None) };
    let (_, out, _) = one(&["get", "x", "--raw"], Reply::RbwItem { item: Box::new(item) });
    let keys: Vec<&str> =
        out.lines().filter(|l| l.starts_with("    \"")).map(|l| l.trim().split('"').nth(1).unwrap()).collect();
    assert_eq!(
        keys,
        [
            "title",
            "first_name",
            "middle_name",
            "last_name",
            "address1",
            "address2",
            "address3",
            "city",
            "state",
            "postal_code",
            "country",
            "phone",
            "email",
            "ssn",
            "license_number",
            "passport_number",
            "username"
        ]
    );
}

#[test]
fn get_c_copies_what_would_be_printed_but_raw_and_list_fields_still_print() {
    let clip = |args: &[&str], reply: Reply| {
        let log = ClipLog::default();
        let result = rbw_run(vec![Act::Reply(reply)], &[], args, |env| env.clip = log.clip(None)).0;
        (result, log.events())
    };
    let ((code, out, _), events) = clip(&["get", "n", "-c"], Reply::Value { value: secret("hunter2") });
    assert_eq!((code, out.as_str(), events[0].as_str()), (0, "", "copy:hunter2"));
    let ((_, out, _), events) =
        clip(&["get", "n", "--full", "-c"], Reply::RbwItem { item: Box::new(note_item(Some("t"))) });
    assert_eq!((out.as_str(), events[0].as_str()), ("", "copy:t"));
    let ((_, out, _), events) = clip(&["get", "n", "--raw", "-c"], Reply::RbwItem { item: Box::new(note_item(None)) });
    assert!(out.starts_with('{') && events.is_empty(), "{out} {events:?}");
    let ((_, out, _), events) = clip(&["get", "n", "-l", "-c"], Reply::FieldNames { names: vec![s("a")] });
    assert_eq!((out.as_str(), events.len()), ("a\n", 0));
    let ((_, _, _), events) = clip(&["get", "n", "-f", "x", "-c"], Reply::Done);
    assert!(events.is_empty(), "nothing to copy");
    let ((_, out, _), events) =
        clip(&["code", "n", "--clipboard"], Reply::Code { code: secret("123456"), seconds_left: 3 });
    assert_eq!((out.as_str(), events[0].as_str()), ("", "copy:123456"));
}

// errors: `find_entry_raw` (2094-2103), `get`'s context (1408-1410), `code` (1543-1553), main.rs's `{e:#}` and exit 1

#[test]
fn a_lookup_that_fails_says_so_in_rbws_words() {
    let none = Reply::Error { error: AgentError::NotFound };
    let many = Reply::Error {
        error: AgentError::Ambiguous {
            candidates: vec![
                Candidate { id: s("1"), name: s("Mail"), user: Some(s("me")) },
                Candidate { id: s("2"), name: s("Mail"), user: None },
            ],
        },
    };
    for cmd in ["get", "code", "history", "remove", "edit"] {
        assert_eq!(
            one(&[cmd, "Mail"], none.clone()),
            (1, s(""), format!("rbw {cmd}: couldn't find entry for 'Mail': no entry found\n")),
            "{cmd}"
        );
        assert_eq!(
            one(&[cmd, "Mail", "me"], many.clone()),
            (
                1,
                s(""),
                format!("rbw {cmd}: couldn't find entry for 'me@Mail': multiple entries found: me@Mail, Mail\n")
            ),
            "{cmd}"
        );
    }
    // rbw names a URL needle as the url crate writes it; a UUID and anything else as typed.
    let url = one(&["get", "HTTPS://Example.ORG"], none.clone()).2;
    assert_eq!(url, "rbw get: couldn't find entry for 'https://example.org/': no entry found\n");
    let id = "6A3B1C52-0F5E-4D8E-9B1A-2F6F1C0D7E11";
    assert_eq!(one(&["get", id], none.clone()).2, format!("rbw get: couldn't find entry for '{id}': no entry found\n"));
    assert_eq!(one(&["get", "foo:bar"], none).2, "rbw get: couldn't find entry for 'foo:bar': no entry found\n");
}

#[test]
fn code_history_and_the_agents_errors_in_rbws_words() {
    assert_eq!(one(&["code", "n"], Reply::Code { code: secret("123456"), seconds_left: 3 }), (0, s("123456\n"), s("")));
    let err = |e| Reply::Error { error: e };
    assert_eq!(
        one(&["code", "n"], err(AgentError::NoSuchField(s("totp")))),
        (1, s(""), s("rbw code: entry does not contain a totp secret\n"))
    );
    assert_eq!(one(&["totp", "n"], err(AgentError::NotALogin)), (1, s(""), s("rbw code: not a login entry\n")));
    assert_eq!(one(&["get", "n"], err(AgentError::Locked)), (1, s(""), s("rbw get: agent is locked\n")));
    assert_eq!(
        one(&["get", "n", "-f", "x"], err(AgentError::NoSuchField(s("totp")))).2,
        "rbw get: the item has no field named \"totp\"\n"
    );
    // With no RBW_PROFILE, `sync` first asks which profile is the default: that is what fails here.
    assert_eq!(one(&["sync"], err(AgentError::NotLoggedIn)).2, "rbw sync: not logged in (run `rbw login`)\n");
    let history = Reply::History {
        entries: vec![
            HistoryEntry { last_used: s("2025-02-01T00:00:00Z"), password: secret("old\tpw") },
            HistoryEntry { last_used: s("unknown"), password: secret("older") },
        ],
    };
    assert_eq!(one(&["history", "n"], history), (0, s("2025-02-01T00:00:00Z: old\tpw\nunknown: older\n"), s("")));
}

#[test]
fn a_reply_that_does_not_fit_the_command_is_an_error() {
    for args in
        [&["list"][..], &["get", "n"], &["code", "n"], &["history", "n"], &["unlocked"], &["unlock"], &["edit", "n"]]
    {
        let reply = if matches!(args[0], "unlocked" | "get") { Reply::Items { items: vec![] } } else { Reply::Done };
        let (code, _, err) = one(args, reply);
        assert_eq!(code, 1, "{args:?}");
        assert!(err.ends_with("the agent sent a reply that does not fit the request\n"), "{args:?}: {err}");
    }
}

// unlocked, unlock (1336-1351, actions.rs:17-45), generate (1657-1751), purge

fn logged(logged_in: bool) -> Reply {
    Reply::Status {
        agent_version: s("0.1.0"),
        profiles: vec![ProfileStatus { profile: s("work"), logged_in, unlocked: false, last_sync: None }],
    }
}

#[test]
fn unlocked_says_why_not_as_rbw() {
    assert_eq!(one(&["unlocked"], status(true)), (0, s(""), s("")));
    assert_eq!(one(&["unlocked"], status(false)), (1, s(""), s("rbw unlocked: agent is locked\n")));
    let empty = Reply::Status { agent_version: s("0.1.0"), profiles: vec![] };
    assert_eq!(one(&["unlocked"], empty).0, 1);
    let alone = rbw_run(vec![], &[], &["unlocked"], |_| {});
    assert_eq!(alone, ((1, s(""), s("rbw unlocked: agent not running\n")), vec![]));
}

#[test]
fn unlock_logs_in_first_when_the_profile_is_not_logged_in() {
    let (result, ops) = rbw_run(
        vec![Act::Reply(logged(false)), Act::Reply(Reply::Done), Act::Reply(Reply::Done)],
        &[],
        &["unlock"],
        |_| {},
    );
    assert_eq!(result, (0, s(""), s("")));
    assert_eq!(ops, [Op::Status { profile: None }, Op::Login { profile: None }, Op::Unlock { profile: None }]);
    let (result, ops) = rbw_run(vec![Act::Reply(logged(true)), Act::Reply(Reply::Done)], &[], &["unlock"], |_| {});
    assert_eq!(result.0, 0);
    assert_eq!(ops, [Op::Status { profile: None }, Op::Unlock { profile: None }]);
    let empty = Reply::Status { agent_version: s("0.1.0"), profiles: vec![] };
    let (_, ops) =
        rbw_run(vec![Act::Reply(empty), Act::Reply(Reply::Done), Act::Reply(Reply::Done)], &[], &["unlock"], |_| {});
    assert_eq!(ops.len(), 3, "no profile reported: log in");
    let failed = Reply::Error { error: AgentError::Prompt };
    let (result, ops) = rbw_run(vec![Act::Reply(logged(false)), Act::Reply(failed)], &[], &["unlock"], |_| {});
    assert_eq!(result.0, 1);
    assert_eq!(ops.len(), 2, "no unlock after a failed login");
}

#[test]
fn generate_with_a_name_prints_the_password_then_saves_that_one() {
    let (result, ops) = rbw_run(
        vec![Act::Reply(Reply::Done)],
        &[("RBW_PROFILE", s("p"))],
        &["generate", "16", "n", "me", "--uri", "https://a", "--folder", "f", "--nonconfusables"],
        |_| {},
    );
    let (code, out, err) = result;
    assert_eq!((code, err.as_str()), (0, ""));
    let printed = out.strip_suffix('\n').unwrap();
    assert_eq!(printed.chars().count(), 16);
    assert_eq!(
        ops,
        [Op::Add {
            profile: Some(s("p")),
            name: s("n"),
            user: Some(s("me")),
            uris: vec![s("https://a")],
            folder: Some(s("f")),
            ask: vec![],
            password: Some(Sealed::new(s(printed))),
            notes: None,
        }]
    );
    // The password is printed before the write, as rbw does; a refused write still fails the command.
    let (result, _) = rbw_run(
        vec![Act::Reply(Reply::Error { error: AgentError::Denied })],
        &[],
        &["gen", "4", "n", "--diceware"],
        |_| {},
    );
    assert_eq!(result.0, 1);
    assert_eq!(result.1.split(' ').count(), 4, "{}", result.1);
}

#[test]
fn purge_is_a_request_and_prints_nothing() {
    assert_eq!(one(&["purge"], Reply::Done), (0, s(""), s("")));
    assert_eq!(one(&["purge"], Reply::Error { error: AgentError::Denied }).0, 1);
}

/// A login read through `get --raw` for `edit` (the test of the editor flow is in `rbw_edit_tests`).
pub(crate) fn edit_reply(item: RbwItem) -> Act {
    Act::Reply(Reply::RbwItem { item: Box::new(item) })
}

pub(crate) fn login_for_edit() -> RbwItem {
    login_item()
}

pub(crate) fn card_for_edit() -> RbwItem {
    let none = || None;
    let card = RbwCard {
        cardholder_name: none(),
        number: sec("4111"),
        brand: none(),
        exp_month: none(),
        exp_year: none(),
        code: none(),
    };
    RbwItem { data: RbwData::Card(card), ..login_item() }
}

pub(crate) fn edit_read(needle: &str, ignorecase: bool) -> Op {
    Op::Get {
        profile: None,
        needle: s(needle),
        user: None,
        folder: None,
        ignorecase,
        select: Select::EditText,
        rbw: true,
    }
}
