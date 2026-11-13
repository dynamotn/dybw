//! Parsing, output per op, exit codes, error texts and autostart, against a fake agent on a real socket.

#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::Duration;

use dybw_proto::{
    AgentError, Candidate, Entry, HistoryEntry, ItemSummary, Op, PolicyAction, PolicyEntry, PolicyRule, ProfileStatus,
    Reply, Request, Response, Secret, Select, Target, decode_request, encode,
};

use super::*;

/// What the fake agent does with one connection.
enum Act {
    Reply(Reply),
    /// Read the request, close without answering.
    Close,
    /// Answer with these bytes.
    Raw(Vec<u8>),
}

fn env_in(base: &Path, profile: Option<&'static str>, exe_dir: Option<PathBuf>) -> Env {
    let base = base.to_owned();
    Env {
        var: Box::new(move |name| match name {
            "XDG_RUNTIME_DIR" => Some(base.clone().into()),
            "HOME" => Some(base.clone().into()),
            "DYBW_PROFILE" => profile.map(Into::into),
            _ => None,
        }),
        uid: euid(),
        exe_dir,
        start_wait: Duration::from_secs(3),
        started_log: Default::default(),
    }
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A short base path: a socket path is limited to about 100 bytes.
fn base() -> tempfile::TempDir {
    let base = tempfile::Builder::new().prefix("d").tempdir_in("/tmp").unwrap();
    std::fs::create_dir(base.path().join("dybw")).unwrap();
    std::fs::set_permissions(base.path().join("dybw"), PermissionsExt::from_mode(0o700)).unwrap();
    base
}

fn read_request(stream: &mut UnixStream) -> Request {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).unwrap();
    let mut frame = head.to_vec();
    frame.resize(4 + u32::from_be_bytes(head) as usize, 0);
    stream.read_exact(&mut frame[4..]).unwrap();
    decode_request(&frame).unwrap().unwrap().0
}

/// Serve one connection per act; the thread returns the requests it saw.
fn serve(listener: UnixListener, acts: Vec<Act>) -> JoinHandle<Vec<Op>> {
    std::thread::spawn(move || {
        let mut seen = vec![];
        for act in acts {
            let (mut stream, _) = listener.accept().unwrap();
            seen.push(read_request(&mut stream).op);
            match act {
                Act::Reply(r) => stream.write_all(&encode(&Response::new(r)).unwrap()).unwrap(),
                Act::Raw(bytes) => stream.write_all(&bytes).unwrap(),
                Act::Close => {}
            }
        }
        seen
    })
}

struct Fake {
    base: tempfile::TempDir,
    agent: JoinHandle<Vec<Op>>,
}

fn fake(acts: Vec<Act>) -> Fake {
    let base = base();
    let listener = UnixListener::bind(base.path().join("dybw/agent.sock")).unwrap();
    Fake { agent: serve(listener, acts), base }
}

impl Fake {
    fn run(&self, args: &[&str]) -> (u8, String, String) {
        run_in(&env_in(self.base.path(), None, None), args)
    }

    fn ops(self) -> Vec<Op> {
        self.agent.join().unwrap()
    }
}

fn run_in(env: &Env, args: &[&str]) -> (u8, String, String) {
    let (mut out, mut err) = (vec![], vec![]);
    let code = run(["dybw"].iter().chain(args), env, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

/// One command against a fake agent that gives one reply; returns the result and the op the agent saw.
fn one(args: &[&str], reply: Reply) -> ((u8, String, String), Op) {
    let f = fake(vec![Act::Reply(reply)]);
    let result = f.run(args);
    (result, f.ops().remove(0))
}

fn secret(v: &str) -> Secret {
    Secret::new(v.into())
}

fn s(v: &str) -> String {
    v.into()
}

fn item(id: &str, name: &str, user: Option<&str>) -> ItemSummary {
    ItemSummary { id: s(id), name: Some(s(name)), user: user.map(s), folder: Some(s("work")), kind: Some(s("Login")) }
}

fn status(unlocked: bool) -> Reply {
    Reply::Status {
        agent_version: s("0.1.0"),
        profiles: vec![ProfileStatus { profile: s("work"), logged_in: true, unlocked, last_sync: Some(1_700_000_000) }],
    }
}

// parsing

#[test]
fn help_and_version_succeed_without_an_agent() {
    // No socket, no exe_dir: a connect attempt or a start would fail.
    let env = env_in(base().path(), None, None);
    let (code, out, _) = run_in(&env, &["--help"]);
    assert_eq!((code, out.contains("Usage")), (0, true));
    assert!(out.contains("unlocked") && out.contains("agent"));
    let (code, out, _) = run_in(&env, &["--version"]);
    assert_eq!((code, out.trim()), (0, format!("dybw {}", env!("CARGO_PKG_VERSION")).as_str()));
}

#[test]
fn usage_errors_exit_1_on_stderr() {
    let env = env_in(base().path(), None, None);
    for args in
        [&["frobnicate"][..], &[], &["get"], &["list", "--fields", "name,bogus"], &["get", "x", "--full", "--raw"]]
    {
        let (code, out, err) = run_in(&env, args);
        assert_eq!((code, out.as_str()), (1, ""), "{args:?}");
        assert!(err.contains("error") || err.contains("Usage"), "{args:?}: {err}");
    }
    assert!(run_in(&env, &["list", "--fields", "bogus"]).2.contains("unknown field"));
}

#[test]
fn every_command_maps_to_its_op() {
    let get =
        |select| Op::Get { profile: Some(s("p")), needle: s("n"), user: None, folder: None, ignorecase: false, select };
    let cases: Vec<(Vec<&str>, Reply, Op)> = vec![
        (vec!["login"], Reply::Done, Op::Login { profile: Some(s("p")) }),
        (vec!["unlock"], Reply::Done, Op::Unlock { profile: Some(s("p")) }),
        (vec!["lock", "--all"], Reply::Done, Op::Lock { target: Target::All }),
        (vec!["lock"], Reply::Done, Op::Lock { target: Target::Profile(s("p")) }),
        (vec!["sync", "--all"], Reply::Done, Op::Sync { target: Target::All }),
        (vec!["sync"], Reply::Done, Op::Sync { target: Target::Profile(s("p")) }),
        (vec!["status"], status(true), Op::Status { profile: Some(s("p")) }),
        (
            vec!["list", "--fields", "id,user,folder,type", "--folder", "f"],
            Reply::Items { items: vec![] },
            Op::List {
                profile: Some(s("p")),
                fields: vec![Field::Id, Field::User, Field::Folder, Field::Type],
                folder: Some(s("f")),
            },
        ),
        (
            vec!["search", "t"],
            Reply::Items { items: vec![] },
            Op::Search { profile: Some(s("p")), term: s("t"), folder: None, fields: vec![Field::Name] },
        ),
        (vec!["get", "n"], Reply::Value { value: secret("v") }, get(Select::Password)),
        (vec!["get", "n", "-f", "totp"], Reply::Value { value: secret("v") }, get(Select::Field(s("totp")))),
        (vec!["get", "n", "--full"], Reply::Full { entries: vec![] }, get(Select::Full)),
        (vec!["get", "n", "--raw"], Reply::Raw { json: secret("{}") }, get(Select::Raw)),
        (vec!["get", "n", "-l"], Reply::FieldNames { names: vec![] }, get(Select::ListFields)),
        (
            vec!["get", "n", "me", "--folder", "f", "-i"],
            Reply::Value { value: secret("v") },
            Op::Get {
                profile: Some(s("p")),
                needle: s("n"),
                user: Some(s("me")),
                folder: Some(s("f")),
                ignorecase: true,
                select: Select::Password,
            },
        ),
        (
            vec!["history", "n", "me", "--folder", "f"],
            Reply::History { entries: vec![] },
            Op::History { profile: Some(s("p")), needle: s("n"), user: Some(s("me")), folder: Some(s("f")) },
        ),
    ];
    for (args, reply, want) in cases {
        // `lock` and `sync` without --all first ask for the status; -p names the profile, so they do not.
        let mut full = vec!["-p", "p"];
        full.extend(&args);
        let (result, op) = one(&full, reply);
        assert_eq!((result.0, op), (0, want), "{args:?}: {}", result.2);
    }
}

#[test]
fn the_profile_flag_beats_the_environment_and_the_agent_picks_otherwise() {
    let f = fake(vec![Act::Reply(Reply::Done), Act::Reply(Reply::Done), Act::Reply(Reply::Done)]);
    let with_env = env_in(f.base.path(), Some("fromenv"), None);
    assert_eq!(run_in(&with_env, &["unlock"]).0, 0);
    assert_eq!(run_in(&with_env, &["-p", "flag", "unlock"]).0, 0);
    let empty = env_in(f.base.path(), Some(""), None);
    assert_eq!(run_in(&empty, &["unlock"]).0, 0);
    assert_eq!(
        f.ops(),
        [
            Op::Unlock { profile: Some(s("fromenv")) },
            Op::Unlock { profile: Some(s("flag")) },
            Op::Unlock { profile: None },
        ]
    );
}

#[test]
fn lock_and_sync_without_a_profile_use_the_agents_default() {
    let f = fake(vec![
        Act::Reply(status(true)),
        Act::Reply(Reply::Done),
        Act::Reply(status(true)),
        Act::Reply(Reply::Done),
    ]);
    assert_eq!(f.run(&["lock"]).0, 0);
    assert_eq!(f.run(&["sync"]).0, 0);
    assert_eq!(
        f.ops(),
        [
            Op::Status { profile: None },
            Op::Lock { target: Target::Profile(s("work")) },
            Op::Status { profile: None },
            Op::Sync { target: Target::Profile(s("work")) },
        ]
    );
}

#[test]
fn a_status_that_names_no_profile_or_the_wrong_reply_is_a_failure() {
    let f = fake(vec![Act::Reply(Reply::Status { agent_version: s("1"), profiles: vec![] }), Act::Reply(Reply::Done)]);
    assert_eq!(f.run(&["lock"]).0, 1);
    let (code, _, err) = f.run(&["lock"]);
    assert_eq!(code, 1);
    assert!(err.contains("does not fit the request"), "{err}");
}

// output

#[test]
fn list_prints_tab_separated_fields_and_empty_cells() {
    let rows = vec![item("1", "mail", Some("me")), ItemSummary { user: None, folder: None, ..item("2", "bank", None) }];
    let (r, _) = one(&["list", "--fields", "id,name,user,folder,type"], Reply::Items { items: rows.clone() });
    assert_eq!(r.1, "1\tmail\tme\twork\tLogin\n2\tbank\t\t\tLogin\n");
    let (r, _) = one(&["list"], Reply::Items { items: rows.clone() });
    assert_eq!(r.1, "mail\nbank\n");
    let (r, _) = one(&["search", "a", "--fields", "name,user"], Reply::Items { items: rows });
    assert_eq!(r.1, "mail\tme\nbank\t\n");
}

#[test]
fn list_raw_is_json_with_the_requested_fields() {
    let rows = vec![item("1", "mail", Some("me")), ItemSummary { user: None, ..item("2", "bank", None) }];
    let (r, _) = one(&["list", "--raw", "--fields", "name,user"], Reply::Items { items: rows });
    let json: Value = serde_json::from_str(&r.1).unwrap();
    assert_eq!(
        json,
        serde_json::json!([{"id": "1", "name": "mail", "user": "me"}, {"id": "2", "name": "bank", "user": null}])
    );
    let (r, _) =
        one(&["list", "--raw", "--fields", "id,folder,type"], Reply::Items { items: vec![item("1", "a", None)] });
    assert_eq!(r.1, "[{\"folder\":\"work\",\"id\":\"1\",\"type\":\"Login\"}]\n");
}

#[test]
fn get_prints_the_value_and_a_newline() {
    let (r, _) = one(&["get", "n"], Reply::Value { value: secret("hunter2") });
    assert_eq!((r.0, r.1.as_str(), r.2.as_str()), (0, "hunter2\n", ""));
    let (r, _) = one(&["get", "n", "--raw"], Reply::Raw { json: secret("{\"a\":1}") });
    assert_eq!(r.1, "{\"a\":1}\n");
    let (r, _) = one(&["get", "n", "-l"], Reply::FieldNames { names: vec![s("pin"), s("api")] });
    assert_eq!(r.1, "pin\napi\n");
}

#[test]
fn get_full_prints_the_main_value_then_fields_and_notes() {
    let entries = vec![
        Entry { name: s("password"), value: secret("pw") },
        Entry { name: s("user"), value: secret("me") },
        Entry { name: s("pin"), value: secret("1234") },
        Entry { name: s("notes"), value: secret("line1\nline2") },
    ];
    let (r, _) = one(&["get", "n", "--full"], Reply::Full { entries });
    assert_eq!(r.1, "pw\nuser: me\npin: 1234\n\nline1\nline2\n");
}

#[test]
fn history_prints_last_used_and_password() {
    let entries = vec![
        HistoryEntry { last_used: s("2026-01-02T03:04:05Z"), password: secret("new") },
        HistoryEntry { last_used: s("2025-01-01T00:00:00Z"), password: secret("old") },
    ];
    let (r, _) = one(&["history", "n"], Reply::History { entries });
    assert_eq!(r.1, "2026-01-02T03:04:05Z: new\n2025-01-01T00:00:00Z: old\n");
}

#[test]
fn status_prints_one_line_per_profile() {
    let two = Reply::Status {
        agent_version: s("1"),
        profiles: vec![
            ProfileStatus { profile: s("work"), logged_in: true, unlocked: true, last_sync: Some(7) },
            ProfileStatus { profile: s("home"), logged_in: false, unlocked: false, last_sync: None },
        ],
    };
    let (r, _) = one(&["status"], two);
    assert_eq!(r.1, "work\tlogged in\tunlocked\t7\nhome\tnot logged in\tlocked\t-\n");
}

#[test]
fn a_reply_that_does_not_fit_the_request_is_refused() {
    for args in [&["status"][..], &["list"], &["history", "n"], &["unlock"], &["unlocked"]] {
        let (r, _) = one(args, Reply::Raw { json: secret("x") });
        assert_eq!((r.0, r.1.as_str()), (1, ""), "{args:?}");
        assert!(r.2.contains("does not fit"), "{args:?}: {}", r.2);
    }
    let (r, _) = one(&["get", "n"], Reply::Done);
    assert_eq!(r.0, 1);
}

#[test]
fn a_closed_output_is_a_failure() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let f = fake(vec![Act::Reply(Reply::Value { value: secret("v") })]);
    let mut err = vec![];
    let env = env_in(f.base.path(), None, None);
    assert_eq!(run(["dybw", "get", "n"], &env, &mut Broken, &mut err), 1);
    assert!(String::from_utf8(err).unwrap().contains("cannot write the output"));
}

// exit codes and error texts

#[test]
fn unlocked_exits_0_when_unlocked_and_1_when_locked_silently() {
    let f = fake(vec![Act::Reply(status(true)), Act::Reply(status(false))]);
    assert_eq!(f.run(&["unlocked"]), (0, s(""), s("")));
    assert_eq!(f.run(&["unlocked"]), (1, s(""), s("")));
    f.ops();
}

#[test]
fn the_first_listed_profile_decides_unlocked_and_an_empty_list_is_locked() {
    let (r, _) = one(&["unlocked"], Reply::Status { agent_version: s("1"), profiles: vec![] });
    assert_eq!(r.0, 1);
}

#[test]
fn error_replies_become_messages_and_exit_1() {
    let cases = [
        (AgentError::Locked, "dybw: the vault is locked (run `dybw unlock`)\n"),
        (AgentError::NotLoggedIn, "dybw: the profile is not logged in (run `dybw login`)\n"),
        (AgentError::NotFound, "dybw: no item matches\n"),
        (AgentError::NoSuchField(s("pin")), "dybw: the item has no field named \"pin\"\n"),
        (AgentError::Denied, "dybw: denied (see the agent log)\n"),
        (AgentError::Prompt, "dybw: the confirmation prompt could not be shown (pinentry)\n"),
        (
            AgentError::Refused(s("kdf-downgrade")),
            "dybw: the kdf-downgrade check refused the unlock; see the agent log\n",
        ),
        (AgentError::Network, "dybw: the server could not be reached\n"),
        (AgentError::Server, "dybw: the server refused the request\n"),
        (AgentError::Config, "dybw: the configuration is invalid (see the agent log)\n"),
        (AgentError::Internal, "dybw: internal agent error\n"),
    ];
    for (error, text) in cases {
        let (r, _) = one(&["get", "n"], Reply::Error { error });
        assert_eq!((r.0, r.1.as_str(), r.2.as_str()), (1, "", text));
    }
}

#[test]
fn an_ambiguous_lookup_lists_its_candidates_on_stderr() {
    let candidates = vec![
        Candidate { id: s("id1"), name: s("mail"), user: Some(s("a")) },
        Candidate { id: s("id2"), name: s("mail"), user: None },
    ];
    let (r, _) = one(&["get", "mail"], Reply::Error { error: AgentError::Ambiguous { candidates } });
    assert_eq!((r.0, r.1.as_str()), (1, ""));
    assert_eq!(r.2, "dybw: several items match\nid1\tmail\ta\nid2\tmail\t\n");
}

#[test]
fn an_agent_that_closes_without_a_reply_is_named() {
    let f = fake(vec![Act::Close]);
    let (code, out, err) = f.run(&["get", "n"]);
    f.ops();
    assert_eq!((code, out.as_str()), (1, ""));
    assert_eq!(err, "dybw: the agent closed the connection (is it a different version? try `dybw agent stop`)\n");
}

#[test]
fn a_reply_cut_short_in_the_body_counts_as_closed() {
    let f = fake(vec![Act::Raw([&100u32.to_be_bytes()[..], b"{}"].concat())]);
    let (code, _, err) = f.run(&["status"]);
    f.ops();
    assert_eq!(code, 1);
    assert!(err.contains("closed the connection"), "{err}");
}

#[test]
fn an_invalid_or_oversize_or_foreign_reply_is_refused_without_its_text() {
    let body = |b: &[u8]| [&(b.len() as u32).to_be_bytes()[..], b].concat();
    let cases = [
        (body(b"{\"version\":1,\"reply\":{\"hunter2\":1}}"), "invalid reply"),
        (body(b"{\"version\":9,\"reply\":\"done\"}"), "not supported"),
        ((dybw_proto::MAX_FRAME as u32 + 1).to_be_bytes().to_vec(), "exceeds"),
    ];
    for (bytes, text) in cases {
        let f = fake(vec![Act::Raw(bytes)]);
        let (code, _, err) = f.run(&["status"]);
        f.ops();
        assert_eq!(code, 1);
        assert!(err.contains(text) && !err.contains("hunter2"), "{err}");
    }
}

#[test]
fn a_socket_that_cannot_be_opened_is_not_taken_for_a_missing_agent() {
    let base = base();
    let path = base.path().join("dybw/agent.sock");
    let _listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, PermissionsExt::from_mode(0o000)).unwrap();
    let (code, _, err) = run_in(&env_in(base.path(), None, None), &["unlocked"]);
    assert_eq!(code, 1);
    assert!(err.contains("cannot connect to"), "{err}");
}

// no agent, and autostart

/// A directory holding a `dybw-agent` that records its start, then does `body`.
fn agent_script(body: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("dybw-agent");
    std::fs::write(&bin, format!("#!/bin/sh\ntouch \"$(dirname \"$0\")/started\"\n{body}\n")).unwrap();
    std::fs::set_permissions(&bin, PermissionsExt::from_mode(0o755)).unwrap();
    dir
}

fn started(dir: &tempfile::TempDir) -> bool {
    dir.path().join("started").exists()
}

#[test]
fn commands_that_need_no_agent_do_not_start_one() {
    let bin = agent_script("sleep 1");
    for (args, code) in [(&["unlocked"][..], 1), (&["lock"], 0), (&["lock", "--all"], 0), (&["agent", "stop"], 0)] {
        let env = env_in(base().path(), None, Some(bin.path().into()));
        assert_eq!(run_in(&env, args), (code, s(""), s("")), "{args:?}");
    }
    assert!(!started(&bin));
}

#[test]
fn agent_stop_asks_a_running_agent_to_stop() {
    let (r, op) = one(&["agent", "stop"], Reply::Done);
    assert_eq!((r.0, op), (0, Op::StopAgent));
}

#[test]
fn a_missing_agent_is_started_from_next_to_the_executable_and_awaited() {
    let bin = agent_script("sleep 2");
    let base = base();
    let sock = base.path().join("dybw/agent.sock");
    let marker = bin.path().join("started");
    // The fake binds only once the script has run, as a real agent would.
    let agent = std::thread::spawn(move || {
        while !marker.exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(150));
        serve(UnixListener::bind(sock).unwrap(), vec![Act::Reply(Reply::Value { value: secret("v") })])
    });
    let env = env_in(base.path(), None, Some(bin.path().into()));
    let (code, out, _) = run_in(&env, &["get", "n"]);
    assert_eq!((code, out.as_str()), (0, "v\n"));
    assert_eq!(agent.join().unwrap().join().unwrap().len(), 1);
    assert!(started(&bin));
}

#[test]
fn a_start_that_fails_is_reported() {
    let base = base();
    let run = |exe_dir: Option<PathBuf>, wait: Duration, expect: &str| {
        let mut env = env_in(base.path(), None, exe_dir);
        env.start_wait = wait;
        let (code, out, err) = run_in(&env, &["unlock"]);
        assert_eq!((code, out.as_str()), (1, ""));
        assert!(err.starts_with("dybw: cannot start the agent: ") && err.contains(expect), "{err}");
        if expect.contains("exited") || expect.contains("no answer") {
            let log = base.path().join("dybw/agent.log");
            assert!(err.trim_end().ends_with(&format!("see {}", log.display())), "{err}");
        }
    };
    run(None, Duration::from_secs(1), "cannot locate the dybw executable");
    let empty = tempfile::tempdir().unwrap();
    // PATH is never searched: a binary missing next to dybw is a hint, not a lookup.
    run(Some(empty.path().into()), Duration::from_secs(1), "install dybw-agent next to dybw");
    run(Some(agent_script("exit 3").path().into()), Duration::from_secs(5), "exited at start");
    run(Some(agent_script("sleep 2").path().into()), Duration::from_millis(200), "no answer");
}

#[test]
fn a_second_agent_that_loses_the_race_still_gets_the_answer() {
    // The started binary exits at once because another agent already answers: that is a success.
    let bin = agent_script("exit 1");
    let base = base();
    let back = base.path().join("dybw/agent.sock");
    let listener = UnixListener::bind(&back).unwrap();
    // Take the path out of sight for the first connect, then restore it while the script runs.
    let hidden = base.path().join("dybw/hidden");
    std::fs::rename(&back, &hidden).unwrap();
    let marker = bin.path().join("started");
    let f = std::thread::spawn(move || {
        while !marker.exists() {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::fs::rename(hidden, back).unwrap();
        serve(listener, vec![Act::Reply(Reply::Done)]).join().unwrap()
    });
    let env = env_in(base.path(), None, Some(bin.path().into()));
    assert_eq!(run_in(&env, &["unlock"]).0, 0);
    assert_eq!(f.join().unwrap(), [Op::Unlock { profile: None }]);
}

#[test]
fn the_real_environment_reads_the_process() {
    let env = Env::real();
    assert!(env.exe_dir.is_some());
    assert_eq!(env.start_wait, START_WAIT);
    assert_eq!((env.var)("PATH"), std::env::var_os("PATH"));
}

#[test]
fn the_executable_directory_is_the_real_one_behind_a_symlink() {
    let real = tempfile::tempdir().unwrap();
    let links = tempfile::tempdir().unwrap();
    std::fs::write(real.path().join("dybw"), "").unwrap();
    let link = links.path().join("rbw");
    std::os::unix::fs::symlink(real.path().join("dybw"), &link).unwrap();
    assert_eq!(client::exe_dir_of(Ok(link)), Some(std::fs::canonicalize(real.path()).unwrap()));
    assert_eq!(client::exe_dir_of(Err(std::io::ErrorKind::NotFound.into())), None);
    assert_eq!(client::exe_dir_of(Ok(real.path().join("missing"))), None);
}

#[test]
fn an_agent_that_exits_but_answers_a_moment_later_is_still_awaited() {
    let bin = agent_script("exit 1");
    let base = base();
    let back = base.path().join("dybw/agent.sock");
    let listener = UnixListener::bind(&back).unwrap();
    let hidden = base.path().join("dybw/hidden");
    std::fs::rename(&back, &hidden).unwrap();
    let marker = bin.path().join("started");
    let f = std::thread::spawn(move || {
        while !marker.exists() {
            std::thread::sleep(Duration::from_millis(1));
        }
        // Well after the script exited, inside the grace.
        std::thread::sleep(Duration::from_millis(500));
        std::fs::rename(hidden, back).unwrap();
        serve(listener, vec![Act::Reply(Reply::Done)]).join().unwrap()
    });
    let env = env_in(base.path(), None, Some(bin.path().into()));
    assert_eq!(run_in(&env, &["unlock"]).0, 0);
    assert_eq!(f.join().unwrap(), [Op::Unlock { profile: None }]);
}

#[test]
fn a_started_agent_logs_to_a_private_file_and_a_refusal_names_it() {
    let bin = agent_script("echo to-stdout; echo to-stderr >&2; sleep 2");
    let base = base();
    let sock = base.path().join("dybw/agent.sock");
    let marker = bin.path().join("started");
    let agent = std::thread::spawn(move || {
        while !marker.exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
        serve(
            UnixListener::bind(sock).unwrap(),
            vec![Act::Reply(Reply::Error { error: AgentError::Refused(s("kdf-downgrade")) })],
        )
    });
    let env = env_in(base.path(), None, Some(bin.path().into()));
    let (code, _, err) = run_in(&env, &["unlock"]);
    agent.join().unwrap().join().unwrap();
    let log = base.path().join("dybw/agent.log");
    assert_eq!(code, 1);
    assert_eq!(err, format!("dybw: the kdf-downgrade check refused the unlock; see {}\n", log.display()));
    assert_eq!(std::fs::metadata(&log).unwrap().permissions().mode() & 0o777, 0o600);
    std::thread::sleep(Duration::from_millis(200));
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("to-stdout") && text.contains("to-stderr"), "{text}");
}

#[test]
fn a_symlinked_log_is_refused_and_no_agent_is_started() {
    let bin = agent_script("sleep 1");
    let base = base();
    let target = base.path().join("elsewhere");
    std::fs::write(&target, "").unwrap();
    std::os::unix::fs::symlink(&target, base.path().join("dybw/agent.log")).unwrap();
    let env = env_in(base.path(), None, Some(bin.path().into()));
    let (code, _, err) = run_in(&env, &["unlock"]);
    assert_eq!(code, 1);
    assert!(err.contains("cannot open the agent log"), "{err}");
    assert!(!started(&bin));
    assert_eq!(std::fs::read_to_string(target).unwrap(), "");
}

#[test]
fn an_unsafe_socket_directory_is_refused_before_anything_is_sent() {
    let bin = agent_script("sleep 1");
    for autostart in [&["unlock"][..], &["unlocked"]] {
        let base = base();
        let dir = base.path().join("dybw");
        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o755)).unwrap();
        let env = env_in(base.path(), None, Some(bin.path().into()));
        let (code, _, err) = run_in(&env, autostart);
        assert_eq!(code, 1);
        assert!(err.contains("unsafe socket directory") && err.contains("open to other users"), "{err}");

        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o700)).unwrap();
        let mut other = env_in(base.path(), None, Some(bin.path().into()));
        other.uid = euid() + 1;
        assert!(run_in(&other, autostart).2.contains("not owned by this user"));

        std::fs::remove_dir(&dir).unwrap();
        std::os::unix::fs::symlink(base.path(), &dir).unwrap();
        assert!(run_in(&env, autostart).2.contains("symbolic link"));
    }
    assert!(!started(&bin));
}

#[test]
fn a_missing_socket_directory_means_no_agent_and_is_made_for_a_start() {
    let base = tempfile::Builder::new().prefix("d").tempdir_in("/tmp").unwrap();
    let env = env_in(base.path(), None, None);
    assert_eq!(run_in(&env, &["unlocked"]).0, 1);
    assert!(!base.path().join("dybw").exists());
    // A start makes it 0700 (then fails here for want of an executable).
    assert!(run_in(&env, &["unlock"]).2.contains("cannot locate"));
    assert_eq!(std::fs::metadata(base.path().join("dybw")).unwrap().permissions().mode() & 0o777, 0o700);
}

#[test]
fn text_output_escapes_control_characters_but_get_and_raw_do_not() {
    let nasty = ItemSummary { name: Some(s("a\tb\nc\x1b[31m")), user: Some(s("u\r")), ..item("1", "x", None) };
    let (r, _) = one(&["list", "--fields", "name,user"], Reply::Items { items: vec![nasty.clone()] });
    assert_eq!(r.1, "a\\x09b\\x0ac\\x1b[31m\tu\\x0d\n");
    let (r, _) = one(&["list", "--raw", "--fields", "name"], Reply::Items { items: vec![nasty] });
    assert!(r.1.contains("\\u001b") && r.1.contains("\\n"), "{}", r.1);
    let (r, _) = one(&["get", "n"], Reply::Value { value: secret("p\tw") });
    assert_eq!(r.1, "p\tw\n");
    let c = Candidate { id: s("i\td"), name: s("n\nm"), user: Some(s("\x1bu")) };
    let (r, _) = one(&["get", "n"], Reply::Error { error: AgentError::Ambiguous { candidates: vec![c] } });
    assert_eq!(r.2, "dybw: several items match\ni\\x09d\tn\\x0am\t\\x1bu\n");
}

#[test]
fn a_connection_the_agent_cut_off_reads_as_closed() {
    use std::io::ErrorKind::*;
    for kind in [UnexpectedEof, BrokenPipe, ConnectionReset] {
        assert!(matches!(client::gone(kind.into()), ClientError::Closed), "{kind:?}");
    }
    assert!(matches!(client::gone(PermissionDenied.into()), ClientError::Io(_)));
}

#[test]
fn an_existing_directory_without_a_socket_is_no_agent() {
    let base = base();
    let env = env_in(base.path(), None, None);
    assert_eq!(run_in(&env, &["unlocked"]), (1, s(""), s("")));
    assert_eq!(run_in(&env, &["agent", "stop"]), (0, s(""), s("")));
}

#[test]
fn field_names_are_escaped_but_their_values_are_not() {
    let (r, _) = one(&["get", "n", "-l"], Reply::FieldNames { names: vec![s("a\x1b[2Jb")] });
    assert_eq!(r.1, "a\\x1b[2Jb\n");
    let entries = vec![
        Entry { name: s("password"), value: secret("pw") },
        Entry { name: s("f\nake: x"), value: secret("v\tal") },
    ];
    let (r, _) = one(&["get", "n", "--full"], Reply::Full { entries });
    assert_eq!(r.1, "pw\nf\\x0aake: x: v\tal\n");
}

// policy

#[test]
fn policy_show_prints_one_escaped_row_per_entry() {
    let entries = vec![
        PolicyEntry { exe: s("/bin/sh"), script: Some(s("/opt/a\nb.sh")), hash: s("ab12"), rule: PolicyRule::Allow },
        PolicyEntry { exe: s("/usr/bin/x"), script: None, hash: s(""), rule: PolicyRule::Deny },
    ];
    let ((code, out, _), op) = one(&["policy", "show"], Reply::Policy { entries });
    assert_eq!(code, 0);
    assert_eq!(out, "allow\t/bin/sh\t/opt/a\\x0ab.sh\tab12\ndeny\t/usr/bin/x\t\t\n");
    assert_eq!(op, Op::Policy { profile: None, action: PolicyAction::Show });
}

#[test]
fn policy_changes_send_their_action_and_succeed_on_done() {
    let dir = tempfile::tempdir().unwrap();
    let dir = std::fs::canonicalize(dir.path()).unwrap();
    let (sh, script, tool) = (dir.join("sh"), dir.join("a.sh"), dir.join("x"));
    for f in [&sh, &script, &tool] {
        std::fs::write(f, "x").unwrap();
    }
    let p = |f: &Path| f.to_string_lossy().into_owned();
    let cases: [(Vec<String>, PolicyAction); 3] = [
        (
            vec![s("policy"), s("allow"), p(&sh), s("--script"), p(&script)],
            PolicyAction::Allow { invoker: p(&sh), script: Some(p(&script)) },
        ),
        (
            vec![s("-p"), s("home"), s("policy"), s("deny"), p(&tool)],
            PolicyAction::Deny { invoker: p(&tool), script: None },
        ),
        (vec![s("policy"), s("forget"), s("/opt/a.sh")], PolicyAction::Forget { invoker: s("/opt/a.sh") }),
    ];
    for (args, action) in cases {
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let ((code, out, _), op) = one(&argv, Reply::Done);
        assert_eq!((code, out.as_str()), (0, ""), "{args:?}");
        let profile = args.contains(&s("home")).then(|| s("home"));
        assert_eq!(op, Op::Policy { profile, action });
    }
}

#[test]
fn policy_allow_sends_canonical_paths_and_a_missing_file_is_a_cli_error() {
    let dir = tempfile::tempdir().unwrap();
    let real = std::fs::canonicalize(dir.path()).unwrap().join("real.sh");
    std::fs::write(&real, "x").unwrap();
    let link = dir.path().join("link.sh");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let (link, real) = (link.to_string_lossy().into_owned(), real.to_string_lossy().into_owned());
    let ((code, _, _), op) = one(&["policy", "allow", "/bin/sh", "--script", &link], Reply::Done);
    assert_eq!(code, 0);
    let Op::Policy { action: PolicyAction::Allow { invoker, script }, .. } = op else { panic!("{op:?}") };
    assert!(Path::new(&invoker).is_absolute());
    assert_eq!(script, Some(real));
    // No agent is running: the command must fail before it looks for one.
    let base = base();
    for args in [["policy", "allow", "no/such/prog"], ["policy", "deny", "no/such/prog"]] {
        let (code, _, err) = run_in(&env_in(base.path(), None, None), &args);
        assert_eq!(code, 1, "{args:?}");
        assert!(err.contains("cannot find no/such/prog"), "{err}");
    }
    let (code, _, err) =
        run_in(&env_in(base.path(), None, None), &["policy", "allow", "/bin/sh", "--script", "gone.sh"]);
    assert!((code, err.contains("cannot find gone.sh")) == (1, true), "{err}");
}

#[test]
fn a_policy_reply_that_does_not_fit_is_unexpected_and_a_refusal_is_denied() {
    let ((code, _, err), _) = one(&["policy", "show"], Reply::Done);
    assert_eq!((code, err.contains("does not fit")), (1, true));
    let ((code, _, err), _) = one(&["policy", "forget", "/x"], Reply::Policy { entries: vec![] });
    assert_eq!((code, err.contains("does not fit")), (1, true));
    let ((code, _, err), _) = one(&["policy", "forget", "/x"], Reply::Error { error: AgentError::Denied });
    assert_eq!((code, err.contains("denied")), (1, true));
}

// audit

fn audit_event(
    caller: dybw_agent::caller::Caller,
    verdict: dybw_agent::policy::Verdict,
) -> dybw_agent::policy::AuditEvent {
    dybw_agent::policy::AuditEvent {
        time: std::time::UNIX_EPOCH + Duration::from_secs(1_794_528_000),
        profile: s("work"),
        caller,
        op: "get",
        kind: Some("password"),
        item: Some(s("id-1")),
        verdict,
    }
}

fn audit_log(base: &Path) -> PathBuf {
    // Under HOME whatever XDG_STATE_HOME says (see `audit_log_ignores_xdg_state_home`).
    base.join(".local/state/dybw/audit.log")
}

/// Three lines: an invoker with a script, an AI harness, an unknown caller.
fn write_audit(base: &Path) {
    use dybw_agent::audit::FileAudit;
    use dybw_agent::caller::{Caller, Via};
    use dybw_agent::policy::{Audit, Verdict};
    let log = FileAudit::new(&audit_log(base), euid());
    let tool = Caller::Invoker {
        exe: "/usr/bin/tool".into(),
        script: Some("/opt/a.sh".into()),
        hash: s("h"),
        relative: false,
    };
    log.record(audit_event(tool, Verdict::Confirmed));
    log.record(audit_event(Caller::Ai { harness: s("claude"), via: Via::Ancestry }, Verdict::Denied));
    log.record(audit_event(Caller::Unknown { why: s("orphan") }, Verdict::Declined));
}

#[test]
fn audit_prints_the_log_as_a_table_and_never_asks_the_agent() {
    let base = base();
    write_audit(base.path());
    // No socket exists: the file is read directly.
    let (code, out, err) = run_in(&env_in(base.path(), None, None), &["audit"]);
    assert_eq!((code, err.as_str()), (0, ""));
    let rows: Vec<Vec<&str>> = out.lines().map(|l| l.split('\t').collect()).collect();
    assert_eq!(rows.len(), 3);
    let t = "2026-11-13T00:00:00Z";
    assert_eq!(rows[0], [t, "work", "invoker", "/usr/bin/tool", "/opt/a.sh", "get", "password", "id-1", "confirmed"]);
    assert_eq!(rows[1], [t, "work", "ai", "claude", "-", "get", "password", "id-1", "denied"]);
    assert_eq!(rows[2], [t, "work", "unknown", "-", "-", "get", "password", "id-1", "declined"]);
}

#[test]
fn audit_can_show_only_ai_callers_and_only_the_latest_lines() {
    let base = base();
    write_audit(base.path());
    let env = env_in(base.path(), None, None);
    let (_, out, _) = run_in(&env, &["audit", "--ai"]);
    assert_eq!(out.lines().count(), 1);
    assert!(out.contains("\tai\tclaude\t"));
    let (_, out, _) = run_in(&env, &["audit", "-n", "1"]);
    assert_eq!(out.lines().count(), 1);
    assert!(out.contains("declined"));
    let (_, out, _) = run_in(&env, &["audit", "-n", "0"]);
    assert_eq!(out, "");
}

#[test]
fn audit_without_a_log_is_empty_and_an_untrusted_or_homeless_one_fails() {
    let base = base();
    let env = env_in(base.path(), None, None);
    assert_eq!(run_in(&env, &["audit"]), (0, s(""), s("")));
    write_audit(base.path());
    std::fs::set_permissions(audit_log(base.path()), PermissionsExt::from_mode(0o644)).unwrap();
    let (code, out, err) = run_in(&env, &["audit"]);
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.contains("cannot read the audit log") && err.contains("chmod 600"), "{err}");
    let mut homeless = env_in(base.path(), None, None);
    homeless.var = Box::new(|_| None);
    let (code, _, err) = run_in(&homeless, &["audit"]);
    assert_eq!(code, 1);
    assert!(err.contains("HOME"), "{err}");
}

// doctor

const CONFIG: &str =
    "default = \"work\"\n[profiles.work]\nserver_url = \"https://w.example.org\"\nemail = \"w@example.org\"\n";

fn write_config(base: &Path) {
    let file = base.join(".config/dybw/config.toml");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, CONFIG).unwrap();
}

fn doctor_with(env: &Env, me: Option<dybw_agent::caller::Caller>, pinentry_ok: bool) -> (u8, String) {
    let pinentry = |p: &str| if pinentry_ok { Ok(format!("/usr/bin/{p}")) } else { Err(s("not found")) };
    let mut out = vec![];
    let code = crate::doctor::run(env, None, me, &pinentry, &mut out).unwrap();
    (code, String::from_utf8(out).unwrap())
}

#[test]
fn doctor_passes_a_healthy_machine_with_no_agent_running() {
    let base = base();
    write_config(base.path());
    write_audit(base.path());
    let (code, out) = doctor_with(&env_in(base.path(), None, None), None, true);
    assert_eq!(code, 0, "{out}");
    for want in [
        "[ok] socket directory: ",
        "[ok] agent: not running",
        "[ok] config: ",
        "[ok] profile: work",
        "[ok] pinentry: /usr/bin/pinentry",
        "[ok] policy: ",
        ", none yet",
        "[ok] audit log: ",
        ", 3 lines",
    ] {
        assert!(out.contains(want), "{want:?} in {out}");
    }
    assert!(!out.contains("warning"));
}

#[test]
fn doctor_warns_under_an_ai_harness_but_a_healthy_machine_still_passes() {
    let base = base();
    write_config(base.path());
    let me = dybw_agent::caller::Caller::Ai { harness: s("claude"), via: dybw_agent::caller::Via::Ancestry };
    let (code, out) = doctor_with(&env_in(base.path(), None, None), Some(me), true);
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("[warning] caller: this runs under the AI harness claude"), "{out}");
    // Any other caller is not remarked on.
    let other = dybw_agent::caller::Caller::Unknown { why: s("x") };
    assert!(!doctor_with(&env_in(base.path(), None, None), Some(other), true).1.contains("warning"));
}

#[test]
fn doctor_reports_the_agent_it_finds() {
    let version = env!("CARGO_PKG_VERSION");
    let status = |v: &str| Reply::Status { agent_version: s(v), profiles: vec![] };
    let cases = [
        (Act::Reply(status(version)), true, "[ok] agent: running, version"),
        (Act::Reply(status("0.0.1")), false, "[problem] agent: version 0.0.1"),
        (
            Act::Reply(Reply::Error { error: AgentError::Config }),
            false,
            "[problem] agent: running, but answers with an error",
        ),
        (Act::Reply(Reply::Done), false, "[problem] agent: running, but the reply does not fit"),
        (Act::Close, false, "[problem] agent: the agent closed the connection"),
    ];
    for (act, healthy, want) in cases {
        let f = fake(vec![act]);
        write_config(f.base.path());
        let (code, out) = doctor_with(&env_in(f.base.path(), None, None), None, true);
        assert_eq!((code == 0, out.contains(want)), (healthy, true), "{want}: {out}");
        f.ops();
    }
}

#[test]
fn doctor_flags_a_socket_directory_others_can_reach() {
    let base = base();
    write_config(base.path());
    std::fs::set_permissions(base.path().join("dybw"), PermissionsExt::from_mode(0o755)).unwrap();
    let (code, out) = doctor_with(&env_in(base.path(), None, None), None, true);
    assert_eq!(code, 1);
    assert!(out.contains("[problem] socket directory: "), "{out}");
    // A directory that is not there yet is fine: the first command makes it.
    let fresh = tempfile::Builder::new().prefix("d").tempdir_in("/tmp").unwrap();
    write_config(fresh.path());
    let (code, out) = doctor_with(&env_in(fresh.path(), None, None), None, true);
    assert!(code == 0 && out.contains("made on first use"), "{out}");
}

#[test]
fn doctor_flags_a_missing_home_a_bad_config_a_bad_profile_and_a_bad_pinentry() {
    let base = base();
    let mut homeless = env_in(base.path(), None, None);
    homeless.var = Box::new(|_| None);
    homeless.uid = euid();
    let (code, out) = doctor_with(&homeless, None, true);
    assert_eq!(code, 1);
    assert!(out.contains("[problem] home: HOME is not set"), "{out}");

    let env = env_in(base.path(), None, None);
    let file = base.path().join(".config/dybw/config.toml");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, "[profiles.work]\nbogus = 1\n").unwrap();
    let (code, out) = doctor_with(&env, None, true);
    assert!(code == 1 && out.contains("[problem] config: "), "{out}");
    // No profile to use: no default, none named.
    std::fs::write(&file, "[profiles.work]\nserver_url = \"https://w.example.org\"\nemail = \"w@example.org\"\n")
        .unwrap();
    let (code, out) = doctor_with(&env, None, true);
    assert!(code == 1 && out.contains("[problem] profile: "), "{out}");
    write_config(base.path());
    let (code, out) = doctor_with(&env, None, false);
    assert!(code == 1 && out.contains("[problem] pinentry: pinentry: not found"), "{out}");
}

#[test]
fn doctor_flags_a_policy_or_audit_file_that_cannot_be_trusted_and_says_how_to_repair_the_policy() {
    let base = base();
    write_config(base.path());
    let env = env_in(base.path(), None, None);
    let policy = base.path().join(".local/state/dybw/profiles/work/policy.json");
    std::fs::create_dir_all(policy.parent().unwrap()).unwrap();
    std::fs::write(&policy, "{\"version\":1,\"entries\":[]}").unwrap();
    std::fs::set_permissions(&policy, PermissionsExt::from_mode(0o600)).unwrap();
    let (code, out) = doctor_with(&env, None, true);
    assert!(code == 0 && out.contains("0 entries"), "{out}");
    std::fs::set_permissions(&policy, PermissionsExt::from_mode(0o644)).unwrap();
    let (code, out) = doctor_with(&env, None, true);
    assert!(code == 1 && out.contains("[problem] policy: ") && out.contains("or remove it"), "{out}");

    write_audit(base.path());
    let log = audit_log(base.path());
    std::fs::OpenOptions::new().append(true).open(&log).unwrap().write_all(b"not json\n").unwrap();
    let (_, out) = doctor_with(&env, None, true);
    assert!(out.contains("[problem] audit log: ") && out.contains("1 lines are not entries"), "{out}");
    std::fs::set_permissions(&log, PermissionsExt::from_mode(0o644)).unwrap();
    let (_, out) = doctor_with(&env, None, true);
    assert!(out.contains("nothing is recorded until it is fixed"), "{out}");
}

#[test]
fn the_doctor_command_runs_the_real_checks() {
    let base = base();
    write_config(base.path());
    let (code, out, _) = run_in(&env_in(base.path(), None, None), &["doctor"]);
    // The pinentry and the harness depend on the machine; the checks themselves always run.
    assert!(code <= 1 && out.contains("[ok] socket directory") && out.contains("] pinentry: "), "{out}");
}

#[test]
fn the_audit_log_is_under_home_whatever_xdg_state_home_says() {
    let base = base();
    write_audit(base.path());
    let mut env = env_in(base.path(), None, None);
    let elsewhere = tempfile::tempdir().unwrap();
    let (home, xdg) = (base.path().to_owned(), elsewhere.path().to_owned());
    env.var = Box::new(move |name| match name {
        "XDG_RUNTIME_DIR" | "HOME" => Some(home.clone().into()),
        "XDG_STATE_HOME" => Some(xdg.clone().into()),
        _ => None,
    });
    let (code, out, _) = run_in(&env, &["audit"]);
    assert_eq!((code, out.lines().count()), (0, 3));
}
