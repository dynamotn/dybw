#![expect(clippy::unwrap_used, reason = "tests")]

use super::*;
use dybw_peer::{Fake, Token};
use std::os::fd::AsFd;

/// A fake tree plus real files for the executables and scripts the invoker is hashed from.
struct Tree {
    fake: Arc<Fake>,
    dir: tempfile::TempDir,
}

const PEER: u32 = 100;

fn os(s: &str) -> OsString {
    s.into()
}

impl Tree {
    fn new() -> Self {
        let tree = Self { fake: Arc::new(Fake::default()), dir: tempfile::tempdir().unwrap() };
        tree.fake.set_peer(Peer { pid: PEER, uid: 1, token: Token::plain(0, u64::from(PEER)) });
        tree
    }

    /// A real file named `name` holding `content`.
    fn file(&self, name: &str, content: &str) -> PathBuf {
        let path = self.dir.path().canonicalize().unwrap().join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    fn add(&self, pid: u32, exe: &Path, ppid: u32, argv: Option<&[&str]>, env: Option<&[&str]>) {
        self.fake.add(
            pid,
            Process {
                exe: exe.to_path_buf(),
                ppid,
                start: u64::from(pid),
                image: Vec::new(),
                argv: argv.map(|a| a.iter().map(|s| os(s)).collect()),
                env: env.map(|e| e.iter().map(|k| (os(k), os("1"))).collect()),
                cwd: None,
                started: Some(SystemTime::now() + Duration::from_secs(3600)),
            },
        );
    }

    /// The `dybw` peer (pid 100) under `ppid`.
    fn dybw(&self, ppid: u32) {
        self.add(PEER, Path::new("/usr/local/bin/dybw"), ppid, Some(&["dybw", "get"]), Some(&[]));
    }

    fn resolver(&self) -> Resolver {
        Resolver::new(self.fake.clone(), Harnesses::default())
    }

    fn resolve(&self) -> Resolved {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let peer = self.fake.peer_of(a.as_fd()).unwrap();
        self.resolver().resolve(peer)
    }

    fn caller(&self) -> Caller {
        self.resolve().caller
    }
}

fn sha(content: &str) -> String {
    Sha256::digest(content.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn unknown(c: &Caller) -> &str {
    match c {
        Caller::Unknown { why } => why,
        other => panic!("expected unknown, got {other:?}"),
    }
}

#[test]
fn the_invoker_is_the_parent_of_dybw_hashed_by_its_executable() {
    let t = Tree::new();
    let app = t.file("app", "binary");
    t.dybw(50);
    t.add(50, &app, 10, Some(&["app"]), Some(&[]));
    t.add(10, Path::new("/usr/bin/login"), 1, Some(&["login"]), Some(&[]));
    assert_eq!(t.caller(), Caller::Invoker { exe: app, script: None, hash: sha("binary"), relative: false });
}

#[test]
fn an_interpreter_is_looked_through_to_its_script() {
    let t = Tree::new();
    let bash = t.file("bash", "elf");
    let script = t.file("run.sh", "echo hi");
    t.dybw(50);
    t.add(50, &bash, 1, Some(&["bash", "-e", &script.to_string_lossy()]), Some(&[]));
    // `-e` is errexit for a shell, not inline code.
    assert_eq!(t.caller(), Caller::Invoker { exe: bash, script: Some(script), hash: sha("echo hi"), relative: false });
}

#[test]
fn editing_the_script_changes_the_hash() {
    let t = Tree::new();
    let py = t.file("python3.13", "elf");
    let script = t.file("tool.py", "v1");
    t.dybw(50);
    t.add(50, &py, 1, Some(&["python3.13", "-u", &script.to_string_lossy()]), Some(&[]));
    let before = t.caller();
    std::fs::write(&script, "v2").unwrap();
    let after = t.caller();
    assert_ne!(before, after);
    assert!(matches!(after, Caller::Invoker { hash, .. } if hash == sha("v2")));
}

#[test]
fn an_interactive_shell_is_the_shell_itself() {
    let t = Tree::new();
    let fish = t.file("fish", "elf");
    t.dybw(50);
    t.add(50, &fish, 1, Some(&["-fish"]), Some(&[]));
    assert_eq!(t.caller(), Caller::Invoker { exe: fish, script: None, hash: sha("elf"), relative: false });
}

#[test]
fn inline_code_a_module_a_relative_script_or_hidden_argv_is_unknown() {
    let t = Tree::new();
    let sh = t.file("zsh", "elf");
    let py = t.file("python3", "elf");
    let node = t.file("node", "elf");
    t.dybw(50);
    for (exe, argv) in [
        (&sh, vec!["zsh", "-c", "dybw get"]),
        (&sh, vec!["zsh", "-lc", "dybw get"]),
        (&py, vec!["python3", "-m", "http.server"]),
        (&py, vec!["python3", "-c", "x"]),
        (&node, vec!["node", "--eval", "x"]),
        (&node, vec!["node", "-p", "x"]),
        (&sh, vec!["zsh", "--command", "x"]),
        (&sh, vec!["zsh", "./run.sh"]),
        (&sh, vec!["zsh", "--", "run.sh"]),
    ] {
        t.add(50, exe, 1, Some(&argv), Some(&[]));
        assert!(matches!(t.caller(), Caller::Unknown { .. }), "{argv:?}");
    }
    t.add(50, &sh, 1, None, None);
    assert!(unknown(&t.caller()).contains("not visible"));
}

#[test]
fn a_script_after_double_dash_and_clustered_flags_are_handled() {
    let t = Tree::new();
    let sh = t.file("sh", "elf");
    let py = t.file("python3", "elf");
    let script = t.file("s.sh", "x");
    t.dybw(50);
    t.add(50, &sh, 1, Some(&["sh", "--", &script.to_string_lossy()]), Some(&[]));
    assert!(matches!(t.caller(), Caller::Invoker { script: Some(s), .. } if s == script));
    t.add(50, &sh, 1, Some(&["sh", "-eux", &script.to_string_lossy(), "-c", "ignored"]), Some(&[]));
    assert!(matches!(t.caller(), Caller::Invoker { script: Some(s), .. } if s == script));
    t.add(50, &py, 1, Some(&["python3", "-uB", "-I", &script.to_string_lossy()]), Some(&[]));
    assert!(matches!(t.caller(), Caller::Invoker { script: Some(s), .. } if s == script));
    // Only flags, or nothing: an interactive interpreter.
    for argv in [vec!["sh"], vec!["sh", "-l"], vec!["sh", "--"]] {
        t.add(50, &sh, 1, Some(&argv), Some(&[]));
        assert!(matches!(t.caller(), Caller::Invoker { script: None, .. }), "{argv:?}");
    }
}

#[test]
fn a_script_that_does_not_resolve_is_unknown() {
    let t = Tree::new();
    let sh = t.file("sh", "elf");
    t.dybw(50);
    let dir = t.dir.path().to_string_lossy().into_owned();
    for arg in ["/no/such/script", dir.as_str()] {
        t.add(50, &sh, 1, Some(&["sh", arg]), Some(&[]));
        assert!(matches!(t.caller(), Caller::Unknown { .. }), "{arg}");
    }
}

#[test]
fn a_relative_script_resolves_against_the_cwd_of_the_interpreter() {
    let t = Tree::new();
    let sh = t.file("sh", "elf");
    let script = t.file("rel.sh", "x");
    t.dybw(50);
    t.add(50, &sh, 1, Some(&["sh", "rel.sh"]), Some(&[]));
    let with_cwd = Process { cwd: Some(t.dir.path().to_path_buf()), ..t.fake.process(50).unwrap() };
    t.fake.add(50, with_cwd);
    assert!(matches!(t.caller(), Caller::Invoker { script: Some(s), relative: true, .. } if s == script));
    // A script that vanished again.
    t.add(50, &sh, 1, Some(&["sh", "gone.sh"]), Some(&[]));
    t.fake.add(50, Process { cwd: Some(t.dir.path().to_path_buf()), ..t.fake.process(50).unwrap() });
    assert!(unknown(&t.caller()).contains("cannot be found"));
}

#[test]
fn options_that_may_hide_the_script_are_unknown() {
    // Every bypass the review listed: an attacker's /abs/g.* is the existing file a naive scan would take.
    let t = Tree::new();
    let sh = t.file("bash", "elf");
    let py = t.file("python3", "elf");
    let node = t.file("node", "elf");
    let g = |name: &str| t.file(name, "good").to_string_lossy().into_owned();
    let (gsh, gpy, gjs) = (g("g.sh"), g("g.py"), g("g.js"));
    t.dybw(50);
    for (exe, argv) in [
        (&sh, vec!["bash", "-s", &gsh]),
        (&sh, vec!["bash", "-", &gsh]),
        (&sh, vec!["bash", "--rcfile", &gsh, "evil.sh"]),
        (&sh, vec!["bash", "-euxc", "evil"]),
        (&sh, vec!["bash", "-c", "evil", &gsh]),
        (&sh, vec!["bash", "-ic", "evil"]),
        (&sh, vec!["bash", "--command", "evil"]),
        (&sh, vec!["bash", "-o", "pipefail", &gsh]),
        (&py, vec!["python3", "-", &gpy]),
        (&py, vec!["python3", "-W", &gpy, "evil.py"]),
        (&py, vec!["python3", "-c\"import os\"", &gpy]),
        (&py, vec!["python3", "-mpytest", &gpy]),
        (&py, vec!["python3", "-m", "pytest", &gpy]),
        (&py, vec!["python3", "-X", "dev", &gpy]),
        (&node, vec!["node", "--require", &gjs, "evil.js"]),
        (&node, vec!["node", "-e'evil'", &gjs]),
        (&node, vec!["node", "--eval=evil", &gjs]),
        (&node, vec!["node", "-p", "evil", &gjs]),
        (&node, vec!["node", "--inspect", &gjs]),
        (&node, vec!["node", "-r", &gjs, "evil.js"]),
    ] {
        t.add(50, exe, 1, Some(&argv), Some(&[]));
        assert!(matches!(t.caller(), Caller::Unknown { .. }), "{argv:?}");
    }
}

#[test]
fn a_file_changed_after_the_process_started_is_unknown() {
    // The grant must not rest on a hash of content the process never ran.
    let t = Tree::new();
    let sh = t.file("sh", "elf");
    let script = t.file("s.sh", "x");
    t.dybw(50);
    t.add(50, &sh, 1, Some(&["sh", &script.to_string_lossy()]), Some(&[]));
    let long_ago = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    t.fake.add(50, Process { started: Some(long_ago), ..t.fake.process(50).unwrap() });
    assert!(unknown(&t.caller()).contains("changed after"));
    // The same for an executable with no script, and for an unknown start time.
    t.add(50, &sh, 1, Some(&["sh"]), Some(&[]));
    t.fake.add(50, Process { started: Some(long_ago), ..t.fake.process(50).unwrap() });
    assert!(unknown(&t.caller()).contains("changed after"));
    t.fake.add(50, Process { started: None, ..t.fake.process(50).unwrap() });
    assert!(unknown(&t.caller()).contains("start time"));
}

#[test]
fn subreapers_privilege_wrappers_and_other_peers_are_unknown() {
    let t = Tree::new();
    let app = t.file("app", "binary");
    for name in ["systemd", "init", "launchd", "tini", "dumb-init", "containerd-shim-runc-v2"] {
        t.dybw(50);
        t.add(50, Path::new(&format!("/usr/bin/{name}")), 1, Some(&[name]), Some(&[]));
        assert!(unknown(&t.caller()).contains("adopts"), "{name}");
    }
    for name in ["sudo", "doas", "su", "run0", "pkexec"] {
        t.dybw(50);
        t.add(50, &app, 40, Some(&["app"]), Some(&[]));
        t.add(40, Path::new(&format!("/usr/bin/{name}")), 1, Some(&[name]), Some(&[]));
        assert!(unknown(&t.caller()).contains("privilege"), "{name}");
        // The harness above it is still the answer.
        t.add(40, Path::new(&format!("/usr/bin/{name}")), 30, Some(&[name]), Some(&[]));
        t.add(30, Path::new("/opt/claude"), 1, Some(&["claude"]), Some(&[]));
        assert_eq!(ai_via(&t.caller()), ("claude", Via::Ancestry));
    }
    // The peer must be dybw (or rbw).
    t.add(50, &app, 1, Some(&["app"]), Some(&[]));
    t.add(PEER, Path::new("/bin/other"), 50, Some(&["other"]), Some(&[]));
    assert!(unknown(&t.caller()).contains("not dybw"));
}

#[test]
fn resolving_off_the_async_thread_gives_the_same_answer() {
    let t = Tree::new();
    let app = t.file("app", "binary");
    t.dybw(50);
    t.add(50, &app, 1, Some(&["app"]), Some(&[]));
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let peer = t.fake.peer_of(a.as_fd()).unwrap();
    let resolver = Arc::new(t.resolver());
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let resolved = runtime.block_on(resolver.clone().resolve_async(peer));
    assert!(matches!(&resolved.caller, Caller::Invoker { exe, .. } if *exe == app));
    assert!(resolver.recheck(&resolved));
    let failed = Resolved::unknown(resolved.peer.clone(), "the resolver failed");
    assert!(unknown(&failed.caller).contains("failed"));
}

#[test]
fn dybw_run_by_dybw_or_rbw_walks_one_more_level() {
    let t = Tree::new();
    let app = t.file("app", "binary");
    t.dybw(90);
    t.add(90, Path::new("/usr/local/bin/dybw"), 80, Some(&["dybw"]), Some(&[]));
    t.add(80, Path::new("/usr/local/bin/rbw"), 70, Some(&["rbw"]), Some(&[]));
    t.add(70, &app, 1, Some(&["app"]), Some(&[]));
    assert!(matches!(t.caller(), Caller::Invoker { exe, .. } if exe == app));
}

#[test]
fn an_orphan_is_unknown() {
    // Review Focus 4: launchd, cron or nohup after the parent exited.
    let t = Tree::new();
    t.dybw(1);
    assert!(unknown(&t.caller()).contains("orphan"));
    t.dybw(0);
    assert!(unknown(&t.caller()).contains("orphan"));
    // Only `dybw` above, then launchd.
    t.dybw(90);
    t.add(90, Path::new("/usr/local/bin/dybw"), 1, Some(&["dybw"]), Some(&[]));
    assert!(unknown(&t.caller()).contains("orphan"));
}

#[test]
fn a_replaced_or_missing_peer_is_unknown() {
    let t = Tree::new();
    assert!(unknown(&t.caller()).contains("gone")); // not in the table at all
    // Same pid, other program started later: the token no longer fits.
    t.dybw(50);
    t.add(50, Path::new("/bin/x"), 1, None, None);
    let resolver = t.resolver();
    let peer = Peer { pid: PEER, uid: 1, token: Token::plain(0, 999) };
    assert!(matches!(resolver.resolve(peer).caller, Caller::Unknown { .. }));
}

#[test]
fn a_peer_whose_pid_is_reused_fails_the_recheck() {
    // Review Focus 1.
    let t = Tree::new();
    let app = t.file("app", "binary");
    t.dybw(50);
    t.add(50, &app, 1, Some(&["app"]), Some(&[]));
    let resolved = t.resolve();
    assert!(t.resolver().recheck(&resolved));
    // The peer exits and another program gets its pid.
    t.fake.add(
        PEER,
        Process {
            exe: "/bin/other".into(),
            ppid: 50,
            start: 5000,
            image: vec![],
            argv: None,
            env: None,
            cwd: None,
            started: None,
        },
    );
    assert!(!t.resolver().recheck(&resolved));
    t.fake.kill(PEER);
    assert!(!t.resolver().recheck(&resolved));
}

#[test]
fn an_invoker_that_exits_replaced_or_reparents_the_peer_fails_the_recheck() {
    let t = Tree::new();
    let app = t.file("app", "binary");
    t.dybw(50);
    t.add(50, &app, 10, Some(&["app"]), Some(&[]));
    t.add(10, Path::new("/usr/bin/login"), 1, Some(&["login"]), Some(&[]));
    let resolved = t.resolve();
    assert!(matches!(resolved.caller, Caller::Invoker { .. }));
    // Above the invoker is not part of the answer.
    t.fake.kill(10);
    assert!(t.resolver().recheck(&resolved));
    // The invoker's pid is reused.
    t.add(50, &app, 10, Some(&["app"]), Some(&[]));
    t.fake.add(50, Process { start: 7, ..t.fake.process(50).unwrap() });
    assert!(!t.resolver().recheck(&resolved));
    // The invoker exits and the peer is adopted by launchd.
    t.add(50, &app, 10, Some(&["app"]), Some(&[]));
    assert!(t.resolver().recheck(&resolved));
    t.dybw(1);
    assert!(!t.resolver().recheck(&resolved));
}

fn ai_via(c: &Caller) -> (&str, Via) {
    match c {
        Caller::Ai { harness, via } => (harness, *via),
        other => panic!("expected ai, got {other:?}"),
    }
}

#[test]
fn a_harness_ancestor_classifies_even_with_a_cleared_environment() {
    // Review Focus 3: no marker, empty env at every level.
    let t = Tree::new();
    let sh = t.file("zsh", "elf");
    let script = t.file("s.sh", "x");
    t.dybw(50);
    t.add(50, &sh, 40, Some(&["zsh", &script.to_string_lossy()]), Some(&[]));
    for (exe, argv, harness) in [
        ("/opt/claude", vec!["claude"], "claude"),
        ("/h/.local/share/mise/installs/claude/2.1.0/claude", vec!["x"], "claude"),
        ("/h/.local/share/claude/versions/2.1.0", vec!["2.1.0"], "claude"),
        ("/usr/bin/node", vec!["/home/u/bin/claude", "--resume"], "claude"),
        ("/usr/bin/node", vec!["node", "/h/cursor-agent/index.js"], "cursor"),
        ("/usr/bin/node", vec!["node", "/h/node_modules/@anthropic-ai/claude-code/cli.js"], "claude"),
        ("/usr/bin/node", vec!["node", "/x/@google/gemini-cli/dist/index.js"], "gemini"),
        ("/usr/bin/node", vec!["node", "/x/@openai/codex/bin/codex.js"], "codex"),
        ("/usr/bin/node", vec!["node", "/x/@github/copilot/index.js"], "copilot"),
        ("/usr/bin/node", vec!["node", "/x/opencode.cjs"], "opencode"),
        ("/usr/bin/agy", vec!["agy"], "antigravity"),
        ("/usr/bin/goose", vec!["goose"], "goose"),
        ("/usr/bin/python3.12", vec!["python3.12", "/home/u/.venv/bin/aider"], "aider"),
        ("/usr/bin/python3.12", vec!["python3.12", "/home/u/.venv/bin/hermes-acp"], "hermes"),
        ("/h/.local/share/cursor-agent/versions/1/node", vec!["node"], "cursor"),
        ("/usr/bin/node", vec!["cursor-agent"], "cursor"),
    ] {
        t.add(40, Path::new(exe), 30, Some(&argv), Some(&[]));
        t.add(30, Path::new("/usr/bin/login"), 1, Some(&["login"]), Some(&[]));
        assert_eq!(ai_via(&t.caller()), (harness, Via::Ancestry), "{exe} {argv:?}");
    }
}

#[test]
fn ai_wins_over_an_orphan_an_unreadable_invoker_and_a_broken_walk() {
    let t = Tree::new();
    // The harness is the whole chain above dybw: nothing else is an invoker.
    t.dybw(40);
    t.add(40, Path::new("/opt/claude"), 1, Some(&["claude"]), None);
    assert_eq!(ai_via(&t.caller()), ("claude", Via::Ancestry));
    // An invoker whose file cannot be read, harness further up.
    t.dybw(50);
    t.add(50, Path::new("/no/such/app"), 40, Some(&["app"]), None);
    assert_eq!(ai_via(&t.caller()), ("claude", Via::Ancestry));
    // The walk breaks above the harness: the harness was already found.
    t.add(40, Path::new("/opt/claude"), 30, Some(&["claude"]), None);
    assert_eq!(ai_via(&t.caller()), ("claude", Via::Ancestry));
}

#[test]
fn a_marker_in_the_peer_or_invoker_env_is_ai_and_other_levels_do_not_count() {
    let t = Tree::new();
    let app = t.file("app", "binary");
    t.add(PEER, Path::new("/usr/local/bin/dybw"), 50, Some(&["dybw"]), Some(&["CODEX_SANDBOX"]));
    t.add(50, &app, 1, Some(&["app"]), Some(&[]));
    assert_eq!(ai_via(&t.caller()), ("codex", Via::Marker));
    t.dybw(50);
    t.add(50, &app, 40, Some(&["app"]), Some(&["CLAUDECODE"]));
    t.add(40, Path::new("/bin/tool"), 1, Some(&["tool"]), Some(&["GEMINI_CLI"]));
    assert_eq!(ai_via(&t.caller()), ("claude", Via::Marker));
    // A marker only on a distant ancestor is not read (its ancestry is, though).
    t.add(50, &app, 40, Some(&["app"]), Some(&[]));
    assert!(matches!(t.caller(), Caller::Invoker { .. }));
    for (var, harness) in MARKERS {
        t.add(50, &app, 1, Some(&["app"]), Some(&[var]));
        assert_eq!(ai_via(&t.caller()), (harness, Via::Marker));
    }
}

#[test]
fn hidden_argv_or_env_is_never_taken_as_clean() {
    // No env visible and no ancestry match: not AI, but nothing here loosens anything: the invoker is named
    // only when the rest resolves; a hidden-argv interpreter is unknown.
    let t = Tree::new();
    let node = t.file("node", "elf");
    t.add(PEER, Path::new("/usr/local/bin/dybw"), 50, None, None);
    t.add(50, &node, 1, None, None);
    assert!(matches!(t.caller(), Caller::Unknown { .. }));
}

#[test]
fn a_walk_that_cannot_reach_the_top_is_unknown() {
    let t = Tree::new();
    let app = t.file("app", "binary");
    t.dybw(50);
    t.add(50, &app, 40, Some(&["app"]), Some(&[]));
    // pid 40 is unreadable (exited, or another user's).
    assert!(unknown(&t.caller()).contains("top"));
    // A loop in the parent links.
    t.add(40, &app, 50, Some(&["app"]), Some(&[]));
    assert!(matches!(t.caller(), Caller::Unknown { .. }));
    // Deeper than the cap.
    t.dybw(200);
    for pid in 200..300 {
        t.add(pid, &app, pid + 1, Some(&["app"]), Some(&[]));
    }
    assert!(unknown(&t.caller()).contains("top"));
}

#[test]
fn an_unreadable_invoker_file_is_unknown() {
    let t = Tree::new();
    t.dybw(50);
    t.add(50, Path::new("/no/such/app"), 1, Some(&["app"]), Some(&[]));
    assert!(unknown(&t.caller()).contains("cannot be read"));
}

#[test]
fn reading_is_capped() {
    let t = Tree::new();
    let f = t.file("big", "12345");
    let open = || std::fs::File::open(&f).unwrap();
    assert_eq!(read_capped(open(), 5).unwrap(), b"12345");
    assert!(read_capped(open(), 4).is_err());
    assert!(hash_file(Path::new("/no/such"), None).is_err());
}

#[test]
fn the_harness_list_only_grows() {
    let t = Tree::new();
    let file = t.dir.path().join("harnesses.toml");
    let defaults = Harnesses::default().0.len();
    assert_eq!(Harnesses::load(&file).0.len(), defaults);
    std::fs::write(&file, "[[harness]]\nname = \"mine\"\nexe = [\"my-agent\"]\n[[harness]]\nexe = [\"nameless\"]\n")
        .unwrap();
    let table = Harnesses::load(&file);
    assert_eq!(table.0.len(), defaults + 1);
    let mine = Process {
        exe: "/bin/my-agent".into(),
        ppid: 1,
        start: 0,
        image: vec![],
        argv: None,
        env: None,
        cwd: None,
        started: None,
    };
    assert_eq!(table.find(&mine), Some("mine"));
    let claude = Process { exe: "/bin/claude".into(), ..mine };
    assert_eq!(table.find(&claude), Some("claude"));
    // Empty fragments would match everything: dropped, and an entry left with nothing is dropped.
    std::fs::write(
        &file,
        "[[harness]]\nname = \"a\"\nexe = [\"\"]\n[[harness]]\nname = \"b\"\nexe = [\"b\", \"\"]\nargv_contains = [\"\"]\n",
    )
    .unwrap();
    let table = Harnesses::load(&file);
    assert_eq!(table.0.len(), defaults + 1);
    assert_eq!(table.find(&claude), Some("claude"));
    assert!(table.find(&Process { exe: "/bin/zzz".into(), ..claude.clone() }).is_none());
    for bad in ["not toml [", "[[harness]]\nexe = 3\n"] {
        std::fs::write(&file, bad).unwrap();
        assert_eq!(Harnesses::load(&file).0.len(), defaults);
    }
    std::fs::write(&file, [0xff, 0xfe]).unwrap();
    assert_eq!(Harnesses::load(&file).0.len(), defaults);
    std::fs::write(&file, vec![b' '; 70 << 10]).unwrap();
    assert_eq!(Harnesses::load(&file).0.len(), defaults);
}

#[test]
fn this_process_resolves_to_a_plausible_invoker() {
    // The test binary stands in for `dybw`; its parent is cargo or a shell. Whatever the surroundings (a harness,
    // a container's pid 1), the answer has the right shape.
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let resolver = Resolver::new(Arc::new(dybw_peer::Os), Harnesses::default());
    let resolved = resolver.resolve(dybw_peer::peer_of_stream(&a).unwrap());
    match &resolved.caller {
        Caller::Invoker { exe, script, hash, .. } => {
            assert!(exe.is_absolute());
            assert!(script.as_ref().is_none_or(|s| s.is_absolute()));
            assert_eq!(hash.len(), 64);
        }
        Caller::Ai { harness, .. } => assert!(!harness.is_empty()),
        Caller::Unknown { why } => assert!(!why.is_empty()),
    }
    assert!(resolver.recheck(&resolved));
}

#[test]
fn only_a_named_absolute_invoker_is_rememberable() {
    let t = Tree::new();
    let app = t.file("app", "binary");
    let sh = t.file("sh", "elf");
    let script = t.file("s.sh", "x");
    t.dybw(50);
    let remember = |t: &Tree| t.caller().rememberable();
    t.add(50, &app, 1, Some(&["app"]), Some(&[]));
    assert!(remember(&t));
    t.add(50, &sh, 1, Some(&["sh", &script.to_string_lossy()]), Some(&[]));
    assert!(remember(&t));
    // A bare interpreter: every script it runs would share the grant.
    t.add(50, &sh, 1, Some(&["sh"]), Some(&[]));
    assert!(!remember(&t));
    // A relative script: the cwd may change under it.
    t.add(50, &sh, 1, Some(&["sh", "s.sh"]), Some(&[]));
    t.fake.add(50, Process { cwd: Some(t.dir.path().to_path_buf()), ..t.fake.process(50).unwrap() });
    assert!(matches!(t.caller(), Caller::Invoker { relative: true, .. }));
    assert!(!remember(&t));
    t.add(50, &sh, 1, Some(&["sh", "-c", "x"]), Some(&[]));
    assert!(!remember(&t));
    t.add(50, Path::new("/opt/claude"), 1, Some(&["claude"]), Some(&[]));
    assert!(!remember(&t));
}

#[test]
fn a_file_the_user_names_is_hashed_and_a_missing_or_huge_one_is_refused() {
    let tree = Tree::new();
    let file = tree.file("named", "content");
    assert_eq!(hash_of(&file).unwrap(), sha("content"));
    assert!(hash_of(&file.with_file_name("missing")).is_err());
    let huge = tree.file("huge", "");
    std::fs::OpenOptions::new().write(true).open(&huge).unwrap().set_len(MAX_HASH_BYTES + 1).unwrap();
    assert!(hash_of(&huge).is_err());
}

#[test]
fn the_doctor_can_ask_what_this_process_would_be_taken_for() {
    let tree = Tree::new();
    tree.dybw(1);
    assert!(matches!(tree.resolver().caller_of_self(), Some(Caller::Invoker { .. } | Caller::Unknown { .. })));
    tree.add(2, Path::new("/opt/claude"), 1, Some(&["claude"]), Some(&[]));
    tree.dybw(2);
    assert!(matches!(tree.resolver().caller_of_self(), Some(Caller::Ai { .. })));
    // A process table that does not know the peer: nothing to say.
    assert!(Resolver::new(Arc::new(Fake::default()), Harnesses::default()).caller_of_self().is_none());
    // The real table, whatever this test runs under.
    let _ = this_process(&tree.dir.path().join("no-harnesses.toml"));
}
