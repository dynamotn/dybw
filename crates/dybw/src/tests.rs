//! Parsing, output per op, exit codes, error texts and autostart, against a fake agent on a real socket.

#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::Duration;

use dybw_proto::{
    AgentError, Candidate, Entry, HistoryEntry, ItemSummary, Op, ProfileStatus, Reply, Request, Response, Secret,
    Select, Target, decode_request, encode,
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
        (AgentError::Denied, "dybw: denied\n"),
        (AgentError::Prompt, "dybw: the confirmation prompt could not be shown (pinentry)\n"),
        (
            AgentError::Refused(s("kdf-downgrade")),
            "dybw: the kdf-downgrade check refused the unlock; see the agent log\n",
        ),
        (AgentError::Network, "dybw: the server could not be reached\n"),
        (AgentError::Server, "dybw: the server refused the request\n"),
        (AgentError::Config, "dybw: the configuration is invalid\n"),
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
    assert_eq!(r.1, "pw\nf\\x0ake: x: v\tal\n");
}
