//! The rbw shim: argv[0] dispatch, rbw's command line (every command, flag and usage error), the mapping onto
//! `dybw`'s requests, `RBW_PROFILE`, and `config show/set/unset`.

#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use dybw_proto::{AgentError, Field, Op, Reply, Select, Target};

use super::*;
use crate::rbw::Opt;
use crate::tests::{Act, base as new_base, env_in, fake, s, secret};

/// `env_in`, with these variables on top.
fn renv(base: &Path, vars: &'static [(&'static str, &'static str)]) -> Env {
    let mut env = env_in(base, None, None);
    let inner = std::mem::replace(&mut env.var, Box::new(|_| None));
    env.var = Box::new(move |n| vars.iter().find(|(k, _)| *k == n).map(|(_, v)| (*v).into()).or_else(|| inner(n)));
    env
}

fn rbw_in(env: &Env, args: &[&str]) -> (u8, String, String) {
    let (mut out, mut err) = (vec![], vec![]);
    let argv: Vec<std::ffi::OsString> = ["rbw"].iter().chain(args).map(Into::into).collect();
    let code = dispatch(argv, env, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

/// One command against a fake agent that gives one reply; the shim runs with `RBW_PROFILE=p`.
fn rone(args: &[&str], reply: Reply) -> ((u8, String, String), Op) {
    let f = fake(vec![Act::Reply(reply)]);
    let result = rbw_in(&renv(f.base.path(), &[("RBW_PROFILE", "p")]), args);
    (result, f.ops().remove(0))
}

/// A run with no agent at all.
fn alone(vars: &'static [(&'static str, &'static str)], args: &[&str]) -> (u8, String, String) {
    let base = crate::tests::fake(vec![]);
    rbw_in(&renv(base.base.path(), vars), args)
}

// dispatch

#[test]
fn argv0_picks_the_personality() {
    let base = fake(vec![]);
    let env = env_in(base.base.path(), None, None);
    let run = |argv0: &str| {
        let (mut out, mut err) = (vec![], vec![]);
        let code = dispatch(vec![argv0.into(), "--version".into()], &env, &mut out, &mut err);
        (code, String::from_utf8(out).unwrap())
    };
    assert_eq!(run("rbw"), (0, "rbw 1.15.0\n".into()));
    assert_eq!(run("/usr/local/bin/rbw"), (0, "rbw 1.15.0\n".into()));
    assert_eq!(run("./bin/rbw"), (0, "rbw 1.15.0\n".into()));
    for other in ["dybw", "/x/rbw-dybw", "rbw.exe", "", "/"] {
        let (code, out) = run(other);
        assert!(code == 0 && !out.starts_with("rbw "), "{other}: {out}");
    }
    // No argv[0] at all is not the shim.
    let (mut out, mut err) = (vec![], vec![]);
    assert_eq!(dispatch(vec![], &env, &mut out, &mut err), 1);
}

// parsing and usage errors

const COMMANDS: &[&str] = &[
    "config",
    "register",
    "login",
    "unlock",
    "unlocked",
    "sync",
    "list",
    "get",
    "search",
    "code",
    "add",
    "generate",
    "edit",
    "remove",
    "history",
    "lock",
    "purge",
    "stop-agent",
    "gen-completions",
];

#[test]
fn help_names_every_command_alias_and_text() {
    let (code, out, err) = alone(&[], &["--help"]);
    assert_eq!((code, err.as_str()), (0, ""));
    assert!(out.starts_with("Unofficial Bitwarden CLI\n\nUsage: rbw <COMMAND>\n"), "{out}");
    for c in COMMANDS {
        assert!(out.contains(&format!("\n  {c}")), "{c}: {out}");
    }
    assert!(out.contains("[alias: ls]") && out.contains("[alias: totp]"), "{out}");
    assert!(out.contains("[alias: gen]") && out.contains("[alias: rm]"), "{out}");
    assert!(out.contains("Terminate the background agent"), "{out}");
    for c in COMMANDS {
        let (code, out, _) = alone(&[], &[c, "--help"]);
        assert_eq!(code, 0, "{c}");
        assert!(out.contains(&format!("Usage: rbw {c}")), "{c}: {out}");
    }
    // The long help of `register` and `add` is rbw's.
    let (_, out, _) = alone(&[], &["register", "--help"]);
    assert!(out.contains("includes bot detection to prevent brute force attacks"), "{out}");
    let (_, out, _) = alone(&[], &["add", "-h"]);
    assert!(out.starts_with("Add a new password to the database\n"), "{out}");
    let (_, out, _) = alone(&[], &["get", "-h"]);
    assert!(out.contains("Usage: rbw get [OPTIONS] <NEEDLE> [USER]"), "{out}");
    assert!(out.contains("-c, --clipboard") && out.contains("-l, --list-fields"), "{out}");
    let (_, out, _) = alone(&[], &["code", "-h"]);
    assert!(out.contains("      --clipboard") && !out.contains("-c, --clipboard"), "{out}");
}

#[test]
fn every_command_line_rbw_accepts_parses() {
    let accepted: &[&[&str]] = &[
        &["config", "show"],
        &["config", "set", "email", "a@b"],
        &["config", "unset", "email"],
        &["register"],
        &["login"],
        &["unlock"],
        &["unlocked"],
        &["sync"],
        &["list"],
        &["ls", "--raw"],
        &["list", "--fields", "id,name", "--raw"],
        &["list", "--fields=id", "--fields", "type"],
        &["get", "n"],
        &["get", "n", "u", "--folder", "f", "-i"],
        &["get", "n", "-f", "totp", "--full", "--raw", "-c", "-l"],
        &["get", "n", "--field", "x", "--clipboard", "--list-fields"],
        &["get", "https://example.org/x", "--", "-dash"],
        &["search", "t"],
        &["search", "t", "--fields", "id,user,folder", "--folder", "f", "--raw"],
        &["code", "n"],
        &["totp", "n", "u", "--folder", "f", "-i", "--clipboard"],
        &["add", "n"],
        &["add", "n", "u", "--uri", "a", "--uri", "b", "--folder", "f"],
        &["generate", "10"],
        &["gen", "10", "n", "u", "--uri", "a", "--folder", "f", "--no-symbols"],
        &["generate", "10", "--only-numbers"],
        &["generate", "10", "--nonconfusables"],
        &["generate", "10", "--diceware"],
        &["edit", "n", "u", "--folder", "f", "-i"],
        &["remove", "n"],
        &["rm", "n", "u"],
        &["history", "n", "u", "--folder", "f"],
        &["lock"],
        &["purge"],
        &["stop-agent"],
        &["gen-completions", "bash"],
        &["gen-completions", "zsh"],
        &["gen-completions", "fish"],
        &["gen-completions", "powershell"],
        &["gen-completions", "elvish"],
        &["gen-completions", "nushell"],
        &["gen-completions", "fig"],
        &["--version"],
        &["-V"],
        &["help"],
        &["help", "get"],
    ];
    for args in accepted {
        let argv = ["rbw"].iter().chain(args.iter());
        match Opt::try_parse_from(argv) {
            Ok(_) => {}
            Err(e) => assert!(matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion), "{args:?}: {e}"),
        }
    }
}

#[test]
fn usage_errors_have_rbws_text_and_exit_code_2() {
    let cases: &[(&[&str], &[&str])] = &[
        (&[], &["Usage: rbw <COMMAND>"]),
        (&["bogus"], &["unrecognized subcommand 'bogus'"]),
        (&["--bogus"], &["unexpected argument '--bogus'"]),
        (&["get"], &["required arguments were not provided", "<NEEDLE>", "Usage: rbw get <NEEDLE> [USER]"]),
        (&["get", "n", "--bogus"], &["unexpected argument '--bogus'"]),
        (&["get", "n", "u", "extra"], &["unexpected argument 'extra'"]),
        (&["code", "n", "-c"], &["unexpected argument '-c'"]),
        (&["list", "--raw", "x"], &["unexpected argument 'x'"]),
        (&["list", "--fields"], &["a value is required for '--fields <FIELDS>'"]),
        (&["search"], &["<TERM>"]),
        (&["add"], &["<NAME>"]),
        (&["add", "n", "u", "--uri"], &["a value is required for '--uri <URI>'"]),
        (&["generate"], &["<LEN>"]),
        (&["generate", "x"], &["invalid value 'x' for '<LEN>'"]),
        (&["generate", "-1"], &["unexpected argument '-1'"]),
        (&["generate", "5", "--no-symbols", "--only-numbers"], &["cannot be used with"]),
        (&["generate", "5", "--diceware", "--nonconfusables"], &["cannot be used with"]),
        (&["generate", "5", "--no-symbol"], &["unexpected argument '--no-symbol'", "--no-symbols"]),
        (&["edit"], &["<NEEDLE>"]),
        (&["remove"], &["<NEEDLE>"]),
        (&["history"], &["<NEEDLE>"]),
        (&["lock", "x"], &["unexpected argument 'x'"]),
        (&["gen-completions"], &["<SHELL>"]),
        (
            &["gen-completions", "tcsh"],
            &["invalid value 'tcsh'", "[possible values: bash, zsh, fish, powershell, elvish, nushell, fig]"],
        ),
        (&["config"], &["Usage: rbw config <COMMAND>"]),
        (&["config", "set", "k"], &["required arguments were not provided", "<VALUE>"]),
        (&["config", "unset"], &["<KEY>"]),
        (&["config", "bogus"], &["unrecognized subcommand 'bogus'"]),
    ];
    for (args, wants) in cases {
        let (code, out, err) = alone(&[], args);
        assert_eq!((code, out.as_str()), (2, ""), "{args:?}: {err}");
        for want in *wants {
            assert!(err.contains(want), "{args:?}: {want} not in {err}");
        }
    }
}

// mapping onto dybw's requests

#[test]
fn every_command_maps_to_its_op() {
    let get = |select| Op::Get {
        profile: Some(s("p")),
        needle: s("n"),
        user: None,
        folder: None,
        ignorecase: false,
        select,
        rbw: true,
    };
    let find = |ignorecase| (s("n"), Some(s("me")), Some(s("f")), ignorecase);
    let (n, u, f, i) = find(true);
    let item = || Reply::RbwItem { item: Box::new(crate::rbw_out_tests::note_item(None)) };
    let cases: Vec<(Vec<&str>, Reply, Op)> = vec![
        (vec!["register"], Reply::Done, Op::Login { profile: Some(s("p")) }),
        (vec!["login"], Reply::Done, Op::Login { profile: Some(s("p")) }),
        (vec!["lock"], Reply::Done, Op::Lock { target: Target::Profile(s("p")) }),
        (vec!["sync"], Reply::Done, Op::Sync { target: Target::Profile(s("p")) }),
        (vec!["stop-agent"], Reply::Done, Op::StopAgent),
        (vec!["purge"], Reply::Done, Op::Purge { profile: Some(s("p")) }),
        (
            vec!["list"],
            Reply::Items { items: vec![] },
            Op::List { profile: Some(s("p")), fields: vec![Field::Name], folder: None },
        ),
        (
            vec!["ls", "--fields", "id,user,folder,type"],
            Reply::Items { items: vec![] },
            Op::List {
                profile: Some(s("p")),
                fields: vec![Field::Id, Field::User, Field::Folder, Field::Type],
                folder: None,
            },
        ),
        (
            vec!["list", "--raw", "--fields", "id"],
            Reply::Items { items: vec![] },
            Op::List {
                profile: Some(s("p")),
                fields: vec![Field::Id, Field::Name, Field::User, Field::Folder, Field::Uri, Field::Type],
                folder: None,
            },
        ),
        (
            vec!["search", "t", "--fields", "id,user", "--folder", "f"],
            Reply::Items { items: vec![] },
            Op::Search {
                profile: Some(s("p")),
                term: s("t"),
                folder: Some(s("f")),
                fields: vec![Field::Id, Field::User],
            },
        ),
        (
            vec!["search", "t", "--raw"],
            Reply::Items { items: vec![] },
            Op::Search {
                profile: Some(s("p")),
                term: s("t"),
                folder: None,
                fields: vec![Field::Id, Field::Name, Field::User, Field::Folder, Field::Uri, Field::Type],
            },
        ),
        (vec!["get", "n"], Reply::Value { value: secret("v") }, get(Select::Password)),
        (vec!["get", "n", "-f", "totp"], Reply::Value { value: secret("v") }, get(Select::Field(s("totp")))),
        (vec!["get", "n", "--full", "-f", "totp"], item(), get(Select::Full)),
        (vec!["get", "n", "--raw", "--full", "-f", "x"], item(), get(Select::Raw)),
        (
            vec!["get", "n", "-l", "--raw", "--full", "-f", "x"],
            Reply::FieldNames { names: vec![] },
            get(Select::ListFields),
        ),
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
                rbw: true,
            },
        ),
        (
            vec!["code", "n", "me", "--folder", "f", "-i"],
            Reply::Code { code: secret("123456"), seconds_left: 9 },
            Op::Code {
                profile: Some(s("p")),
                needle: n.clone(),
                user: u.clone(),
                folder: f.clone(),
                ignorecase: i,
                next: false,
            },
        ),
        (
            vec!["totp", "n"],
            Reply::Code { code: secret("123456"), seconds_left: 9 },
            Op::Code {
                profile: Some(s("p")),
                needle: s("n"),
                user: None,
                folder: None,
                ignorecase: false,
                next: false,
            },
        ),
        (
            vec!["rm", "n", "me", "--folder", "f", "-i"],
            Reply::Done,
            Op::Remove {
                profile: Some(s("p")),
                needle: n.clone(),
                user: u.clone(),
                folder: f.clone(),
                ignorecase: true,
            },
        ),
        (
            vec!["remove", "n", "me", "--folder", "f"],
            Reply::Done,
            Op::Remove {
                profile: Some(s("p")),
                needle: n.clone(),
                user: u.clone(),
                folder: f.clone(),
                ignorecase: false,
            },
        ),
        (
            vec!["history", "n", "me", "--folder", "f", "-i"],
            Reply::History { entries: vec![] },
            Op::History { profile: Some(s("p")), needle: n, user: u, folder: f, ignorecase: true },
        ),
    ];
    for (args, reply, want) in cases {
        let (result, op) = rone(&args, reply);
        assert_eq!((result.0, op), (0, want), "{args:?}: {}", result.2);
    }
}

#[test]
fn a_needle_that_looks_like_a_uri_or_uuid_is_sent_as_typed() {
    for needle in ["https://example.org/login", "6a3b1c52-0f5e-4d8e-9b1a-2f6f1c0d7e11", "-dash"] {
        let (_, op) = rone(&["get", "--", needle], Reply::Value { value: secret("v") });
        let Op::Get { needle: sent, .. } = op else { panic!("{op:?}") };
        assert_eq!(sent, needle);
    }
}

#[test]
fn generate_without_a_name_prints_locally() {
    let (code, out, err) = alone(&[], &["generate", "12", "--only-numbers"]);
    assert_eq!((code, err.as_str()), (0, ""));
    assert!(out.trim_end().len() == 12 && out.trim_end().bytes().all(|b| b.is_ascii_digit()), "{out}");
    let (code, _, err) = alone(&[], &["generate", "0"]);
    assert_eq!(code, 1);
    assert!(err.starts_with("rbw generate: "), "{err}");
}

#[test]
fn list_and_search_refuse_a_field_rbw_does_not_know() {
    for args in [&["list", "--fields", "id,bogus"][..], &["search", "t", "--fields", "uri"]] {
        let (code, out, err) = alone(&[], args);
        let name = args[0];
        assert_eq!((code, out.as_str()), (1, ""), "{args:?}");
        assert!(err.starts_with(&format!("rbw {name}: unknown field ")), "{err}");
    }
    // `--raw` shows every field whatever was asked.
    assert_eq!(alone(&[], &["list", "--raw", "--fields", "bogus"]).0, 1, "the agent is not running, but fields passed");
}

#[test]
fn a_length_too_large_for_the_agent_is_refused() {
    let (code, _, err) = alone(&[], &["generate", "99999999999", "n"]);
    assert_eq!(code, 1);
    assert_eq!(err, "rbw generate: the length is too large\n");
}

#[test]
fn gen_completions_is_clap_output_for_the_model_plus_rbws_scripts() {
    use clap::CommandFactory as _;
    use clap_complete::Shell;
    let render = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut buf = vec![];
        f(&mut buf);
        String::from_utf8(buf).unwrap()
    };
    let cmd = Opt::command();
    let want: Vec<(&str, String)> = vec![
        (
            "bash",
            render(&|b| clap_complete::generate(Shell::Bash, &mut cmd.clone(), "rbw", b))
                + include_str!("rbw_completion/rbw.bash")
                + "\n",
        ),
        (
            "zsh",
            render(&|b| clap_complete::generate(Shell::Zsh, &mut cmd.clone(), "rbw", b))
                + include_str!("rbw_completion/rbw.zsh")
                + "\n",
        ),
        (
            "fish",
            render(&|b| clap_complete::generate(Shell::Fish, &mut cmd.clone(), "rbw", b))
                + include_str!("rbw_completion/rbw.fish")
                + "\n",
        ),
        ("powershell", render(&|b| clap_complete::generate(Shell::PowerShell, &mut cmd.clone(), "rbw", b))),
        ("elvish", render(&|b| clap_complete::generate(Shell::Elvish, &mut cmd.clone(), "rbw", b))),
        ("nushell", render(&|b| clap_complete::generate(clap_complete_nushell::Nushell, &mut cmd.clone(), "rbw", b))),
        ("fig", render(&|b| clap_complete::generate(clap_complete_fig::Fig, &mut Opt::command(), "rbw", b))),
    ];
    for (shell, expected) in want {
        let (code, out, err) = alone(&[], &["gen-completions", shell]);
        assert_eq!((code, err.as_str()), (0, ""), "{shell}");
        assert_eq!(out, expected, "{shell}");
        assert!(out.contains("stop-agent") && out.contains("gen-completions"), "{shell}");
    }
    let (_, fish, _) = alone(&[], &["gen-completions", "fish"]);
    for sub in ["config", "register", "unlocked", "search", "code", "history", "purge"] {
        assert!(fish.contains(&format!("-a \"{sub}\"")), "{sub}");
    }
}

#[test]
fn errors_are_prefixed_with_the_rbw_command() {
    let ((code, out, err), _) = rone(&["get", "n"], Reply::Error { error: AgentError::Denied });
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.starts_with("rbw get: denied"), "{err}");
}

// RBW_PROFILE

#[test]
fn rbw_profile_names_the_profile_and_dybw_profile_is_not_read() {
    let f = fake(vec![Act::Reply(Reply::Done), Act::Reply(Reply::Done), Act::Reply(Reply::Done)]);
    let base = f.base.path();
    assert_eq!(rbw_in(&renv(base, &[("RBW_PROFILE", "work"), ("DYBW_PROFILE", "other")]), &["sync"]).0, 0);
    assert_eq!(rbw_in(&renv(base, &[("DYBW_PROFILE", "other")]), &["purge"]).0, 0);
    assert_eq!(rbw_in(&renv(base, &[("RBW_PROFILE", "")]), &["purge"]).0, 0);
    assert_eq!(
        f.ops(),
        [Op::Sync { target: Target::Profile(s("work")) }, Op::Purge { profile: None }, Op::Purge { profile: None }]
    );
}

#[test]
fn the_dash_p_flag_is_not_an_rbw_flag() {
    let (code, _, err) = alone(&[], &["-p", "x", "unlock"]);
    assert_eq!(code, 2);
    assert!(err.contains("unexpected argument '-p'"), "{err}");
}

// config

fn home_file(base: &Path) -> std::path::PathBuf {
    base.join(".config/dybw/config.toml")
}

fn write_config(base: &Path, text: &str) {
    std::fs::create_dir_all(base.join(".config/dybw")).unwrap();
    std::fs::write(home_file(base), text).unwrap();
}

fn read_config(base: &Path) -> String {
    std::fs::read_to_string(home_file(base)).unwrap()
}

const FILE: &str = "# my settings\n\
    default = \"work\"\n\
    auth = \"api-key\"\n\
    \n\
    [ssh_agent]\n\
    profiles = [\"work\"]\n\
    \n\
    [profiles.work] # the job\n\
    server_url = \"https://w.example.org\"\n\
    email = \"w@example.org\"\n\
    \n\
    [profiles.home]\n\
    server_url = \"https://h.example.org\"\n\
    email = \"h@example.org\"\n";

/// Run `config` commands in a fresh home holding `text` (when there is one).
fn cfg(
    text: Option<&str>,
    vars: &'static [(&'static str, &'static str)],
    args: &[&str],
) -> (tempfile::TempDir, (u8, String, String)) {
    let f = new_base();
    if let Some(text) = text {
        write_config(f.path(), text);
    }
    let result = rbw_in(&renv(f.path(), vars), args);
    (f, result)
}

#[test]
fn config_show_prints_rbws_keys_from_the_profile() {
    let (_, (code, out, err)) = cfg(Some(FILE), &[], &["config", "show"]);
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(
        out,
        "{\n  \"email\": \"w@example.org\",\n  \"sso_id\": null,\n  \"base_url\": \"https://w.example.org\",\n  \
         \"identity_url\": null,\n  \"ui_url\": null,\n  \"notifications_url\": null,\n  \"lock_timeout\": 3600,\n  \
         \"sync_interval\": 300,\n  \"pinentry\": \"pinentry\",\n  \"client_cert_path\": null\n}\n"
    );
    let (_, (code, out, _)) = cfg(Some(FILE), &[("RBW_PROFILE", "home")], &["config", "show"]);
    assert_eq!(code, 0);
    assert!(out.contains("\"email\": \"h@example.org\""), "{out}");
    let (_, (code, out, err)) = cfg(None, &[], &["config", "show"]);
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.starts_with("rbw config show: "), "{err}");
    // A misspelt key anywhere is an error, as for every dybw tool.
    let (_, (code, _, err)) = cfg(Some("bogus = 1\n"), &[], &["config", "show"]);
    assert_eq!(code, 1);
    assert!(err.starts_with("rbw config show: ") && err.contains("bogus"), "{err}");
    let (_, (code, _, err)) = cfg(Some("default = \n"), &[], &["config", "show"]);
    assert_eq!(code, 1);
    assert!(err.starts_with("rbw config show: "), "{err}");
}

#[test]
fn config_show_reports_a_closed_output() {
    struct Closed;
    impl std::io::Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let f = new_base();
    write_config(f.path(), FILE);
    let e = crate::rbw_config::show(&renv(f.path(), &[]), None, &mut Closed).unwrap_err();
    assert!(e.to_string().starts_with("cannot write the output"), "{e}");
}

#[test]
fn config_set_changes_one_line_and_keeps_the_rest() {
    let (base, (code, out, err)) = cfg(Some(FILE), &[], &["config", "set", "email", "new@example.org"]);
    assert_eq!((code, out.as_str()), (0, ""));
    assert_eq!(read_config(base.path()), FILE.replace("w@example.org", "new@example.org"));
    assert!(err.contains("- email = \"w@example.org\"") && err.contains("+ email = \"new@example.org\""), "{err}");
    assert!(err.contains("[profiles.work]"), "{err}");
}

#[test]
fn config_set_maps_every_key() {
    let cases: &[(&str, &str, &str)] = &[
        ("base_url", "https://x.example.org", "server_url = \"https://x.example.org\""),
        ("lock_timeout", "90", "lock_timeout_minutes = 2"),
        ("lock_timeout", "3600", "lock_timeout_minutes = 60"),
        ("lock_timeout", "1", "lock_timeout_minutes = 1"),
        ("sync_interval", "0", "sync_interval_seconds = 0"),
        ("sync_interval", "120", "sync_interval_seconds = 120"),
        ("pinentry", "/bin/sh", "pinentry = \"/bin/sh\""),
    ];
    for (key, value, line) in cases {
        let (base, (code, _, err)) = cfg(Some(FILE), &[("RBW_PROFILE", "home")], &["config", "set", key, value]);
        assert_eq!(code, 0, "{key}: {err}");
        let text = read_config(base.path());
        let home = text.split("[profiles.home]").nth(1).unwrap();
        assert!(home.contains(line), "{key}: {text}");
        assert!(!text.split("[profiles.home]").next().unwrap().contains(line), "{key}: {text}");
    }
}

#[test]
fn config_set_in_an_empty_home_makes_the_file_and_the_default() {
    let (base, (code, _, err)) = cfg(None, &[], &["config", "set", "email", "me@example.org"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(read_config(base.path()), "default = \"default\"\n\n[profiles.default]\nemail = \"me@example.org\"\n");
    assert_eq!(std::fs::metadata(home_file(base.path())).unwrap().permissions().mode() & 0o777, 0o600);
    let f = new_base();
    write_config(f.path(), &read_config(base.path()));
    let (code, _, _) = {
        let r = rbw_in(&renv(f.path(), &[]), &["config", "set", "base_url", "https://v.example.org"]);
        (r.0, r.1, r.2)
    };
    assert_eq!(code, 0);
    assert_eq!(
        read_config(f.path()),
        "default = \"default\"\n\n[profiles.default]\nemail = \"me@example.org\"\nserver_url = \"https://v.example.org\"\n"
    );
    let shown = dybw_agent::config::Config::load(&home_file(f.path())).unwrap().profile(None).unwrap();
    assert_eq!((shown.email.as_str(), shown.server_url.as_str()), ("me@example.org", "https://v.example.org"));
}

#[test]
fn config_set_creates_the_profile_rbw_profile_names() {
    let (base, (code, _, err)) =
        cfg(Some(FILE), &[("RBW_PROFILE", "new")], &["config", "set", "email", "n@example.org"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(read_config(base.path()), format!("{FILE}\n[profiles.new]\nemail = \"n@example.org\"\n"));
    // A file with no profile named and a `default` already: the default is not rewritten.
    let (base, _) = cfg(Some("default = \"a\"\n"), &[("RBW_PROFILE", "b")], &["config", "set", "email", "x"]);
    assert_eq!(read_config(base.path()), "default = \"a\"\n\n[profiles.b]\nemail = \"x\"\n");
}

#[test]
fn config_set_keeps_the_mode_of_an_existing_file() {
    let f = new_base();
    write_config(f.path(), FILE);
    std::fs::set_permissions(home_file(f.path()), PermissionsExt::from_mode(0o640)).unwrap();
    assert_eq!(rbw_in(&renv(f.path(), &[]), &["config", "set", "email", "z"]).0, 0);
    assert_eq!(std::fs::metadata(home_file(f.path())).unwrap().permissions().mode() & 0o777, 0o640);
    assert!(!f.path().join(".config/dybw/config.toml.new").exists());
}

#[test]
fn config_set_with_the_same_value_changes_nothing() {
    let (base, (code, _, err)) = cfg(Some(FILE), &[], &["config", "set", "email", "w@example.org"]);
    assert_eq!(code, 0);
    assert!(err.contains("nothing to change"), "{err}");
    assert_eq!(read_config(base.path()), FILE);
}

#[test]
fn config_set_zero_lock_timeout_is_logged_and_nothing_is_saved() {
    let (base, (code, _, err)) = cfg(Some(FILE), &[], &["config", "set", "lock_timeout", "0"]);
    assert_eq!(code, 0);
    assert_eq!(err, "ERROR: lock_timeout must be greater than 0\n");
    assert_eq!(read_config(base.path()), FILE);
}

#[test]
fn config_set_refuses_what_a_profile_cannot_hold() {
    let cases: &[(&str, &str, &str)] = &[
        ("sso_id", "x", "rbw config set: `sso_id` is not supported: dybw logs in with an API key only"),
        (
            "identity_url",
            "https://i",
            "rbw config set: `identity_url` is not supported: dybw derives the identity URL from `base_url`; set `base_url`",
        ),
        ("ui_url", "https://u", "rbw config set: `ui_url` is not supported: dybw has no web vault URL setting"),
        (
            "notifications_url",
            "https://n",
            "rbw config set: `notifications_url` is not supported: dybw has no notifications URL setting",
        ),
        (
            "client_cert_path",
            "/c",
            "rbw config set: `client_cert_path` is not supported: dybw has no client certificate",
        ),
        ("bogus", "x", "rbw config set: invalid config key: bogus\n"),
        (
            "lock_timeout",
            "soon",
            "rbw config set: failed to parse value for lock_timeout: invalid digit found in string\n",
        ),
        (
            "sync_interval",
            "1.5",
            "rbw config set: failed to parse value for sync_interval: invalid digit found in string\n",
        ),
        // std words this error differently across toolchains.
        ("sync_interval", "18446744073709551615", "rbw config set: "),
    ];
    for (key, value, want) in cases {
        let (base, (code, out, err)) = cfg(Some(FILE), &[], &["config", "set", key, value]);
        assert_eq!((code, out.as_str()), (1, ""), "{key}");
        assert!(err.starts_with(want), "{key}: {err}");
        assert_eq!(read_config(base.path()), FILE, "{key}");
    }
}

#[test]
fn config_set_pinentry_must_be_trusted() {
    let f = new_base();
    write_config(f.path(), FILE);
    let mine = f.path().join("pinentry");
    std::fs::write(&mine, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&mine, PermissionsExt::from_mode(0o755)).unwrap();
    let (code, _, err) = rbw_in(&renv(f.path(), &[]), &["config", "set", "pinentry", mine.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.starts_with("rbw config set: pinentry ") && err.contains("is not trusted"), "{err}");
    assert_eq!(read_config(f.path()), FILE);
}

#[test]
fn config_set_refuses_a_file_it_cannot_parse() {
    let (_, (code, _, err)) = cfg(Some("default = \n"), &[], &["config", "set", "email", "x"]);
    assert_eq!(code, 1);
    assert!(err.starts_with("rbw config set: cannot parse "), "{err}");
}

#[test]
fn config_set_reports_files_it_cannot_read_or_write() {
    let f = new_base();
    std::fs::create_dir_all(home_file(f.path())).unwrap();
    let (code, _, err) = rbw_in(&renv(f.path(), &[]), &["config", "set", "email", "x"]);
    assert_eq!(code, 1);
    assert!(err.starts_with("rbw config set: cannot read "), "{err}");
    let g = new_base();
    std::fs::create_dir_all(g.path().join(".config/dybw")).unwrap();
    std::fs::set_permissions(g.path().join(".config/dybw"), PermissionsExt::from_mode(0o555)).unwrap();
    let h = new_base();
    std::fs::set_permissions(h.path(), PermissionsExt::from_mode(0o555)).unwrap();
    let (code, _, err) = rbw_in(&renv(h.path(), &[]), &["config", "set", "email", "x"]);
    assert_eq!(code, 1);
    assert!(err.starts_with("rbw config set: cannot write "), "{err}");
    std::fs::set_permissions(h.path(), PermissionsExt::from_mode(0o755)).unwrap();
    let (code, _, err) = rbw_in(&renv(g.path(), &[]), &["config", "set", "email", "x"]);
    assert_eq!(code, 1);
    assert!(err.starts_with("rbw config set: cannot write "), "{err}");
}

#[test]
fn config_commands_need_a_home() {
    let f = new_base();
    let mut env = renv(f.path(), &[]);
    env.home = None;
    for args in [&["config", "show"][..], &["config", "set", "email", "x"], &["config", "unset", "pinentry"]] {
        let (code, _, err) = rbw_in(&env, args);
        assert_eq!(code, 1, "{args:?}");
        assert!(err.contains("no home directory"), "{err}");
    }
}

#[test]
fn config_set_and_unset_stop_the_agent() {
    let f = fake(vec![Act::Reply(Reply::Done), Act::Reply(Reply::Done)]);
    write_config(f.base.path(), FILE);
    let env = renv(f.base.path(), &[]);
    assert_eq!(rbw_in(&env, &["config", "set", "email", "x"]).0, 0);
    assert_eq!(rbw_in(&env, &["config", "unset", "email"]).0, 1);
    assert_eq!(rbw_in(&env, &["config", "set", "lock_timeout", "0"]).0, 0);
    assert_eq!(f.ops(), [Op::StopAgent, Op::StopAgent]);
    // An agent that hangs up is an error after the file was saved.
    let f = fake(vec![Act::Close]);
    write_config(f.base.path(), FILE);
    let (code, _, err) = rbw_in(&renv(f.base.path(), &[]), &["config", "set", "email", "x"]);
    assert_eq!(code, 1);
    assert!(err.contains("the agent closed the connection"), "{err}");
}

#[test]
fn config_unset_removes_the_profiles_own_setting() {
    let text = format!("{FILE}lock_timeout_minutes = 5\npinentry = \"/bin/sh\"\n");
    let (base, (code, _, err)) = cfg(Some(&text), &[("RBW_PROFILE", "home")], &["config", "unset", "lock_timeout"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(read_config(base.path()), format!("{FILE}pinentry = \"/bin/sh\"\n"));
    assert!(err.contains("- lock_timeout_minutes = 5"), "{err}");
    let (base, (code, _, _)) = cfg(Some(&text), &[("RBW_PROFILE", "home")], &["config", "unset", "pinentry"]);
    assert_eq!(code, 0);
    assert_eq!(read_config(base.path()), format!("{FILE}lock_timeout_minutes = 5\n"));
    // Nothing set, nothing to do.
    let (base, (code, _, err)) = cfg(Some(FILE), &[], &["config", "unset", "pinentry"]);
    assert_eq!(code, 0);
    assert!(err.contains("nothing to change"), "{err}");
    assert_eq!(read_config(base.path()), FILE);
}

#[test]
fn config_unset_refuses_what_a_profile_needs_or_rbw_cannot_unset() {
    let cases: &[(&str, &str)] = &[
        ("email", "rbw config unset: `email` cannot be unset: a dybw profile needs it"),
        ("base_url", "rbw config unset: `base_url` cannot be unset: a dybw profile needs it"),
        ("sync_interval", "rbw config unset: invalid config key: sync_interval\n"),
        ("bogus", "rbw config unset: invalid config key: bogus\n"),
        ("sso_id", "rbw config unset: `sso_id` is not supported: "),
    ];
    for (key, want) in cases {
        let (base, (code, out, err)) = cfg(Some(FILE), &[], &["config", "unset", key]);
        assert_eq!((code, out.as_str()), (1, ""), "{key}");
        assert!(err.starts_with(want), "{key}: {err}");
        assert_eq!(read_config(base.path()), FILE, "{key}");
    }
}

// the toml_edit based editor

fn set_email(
    text: &str,
    vars: &'static [(&'static str, &'static str)],
    key: &str,
    value: &str,
) -> (u8, String, String) {
    let (base, (code, _, err)) = cfg(Some(text), vars, &["config", "set", key, value]);
    (code, read_config(base.path()), err)
}

#[test]
fn the_editor_keeps_comments_trailing_ones_and_order() {
    let text = "# top\ndefault = \"w\" # which\n\n[profiles.w] # the job\nemail = \"a\" # mine\nserver_url = \"https://w\"\n\n# last\n[bwss]\nprofile = \"w\"\n";
    let (code, new, err) = set_email(text, &[], "email", "b");
    assert_eq!(code, 0, "{err}");
    assert_eq!(new, text.replace("\"a\"", "\"b\""));
    assert!(err.contains("[profiles.w] - email = \"a\"") && err.contains("[profiles.w] + email = \"b\""), "{err}");
    // A new key goes into its section, before the next one.
    let (code, new, _) = set_email(text, &[], "lock_timeout", "120");
    assert_eq!(code, 0);
    assert!(new.contains("server_url = \"https://w\"\nlock_timeout_minutes = 2\n"), "{new}");
    assert!(new.starts_with("# top\ndefault = \"w\" # which\n"), "{new}");
}

#[test]
fn the_editor_edits_inline_table_and_dotted_profiles() {
    let inline = "default = \"w\"\nprofiles = { w = { server_url = \"https://w\", email = \"e\" } }\n";
    let (code, new, err) = set_email(inline, &[], "email", "x");
    assert_eq!(code, 0, "{err}");
    assert_eq!(new, inline.replace("\"e\"", "\"x\""));
    let (_, new, _) = set_email(inline, &[], "lock_timeout", "60");
    assert!(new.contains("lock_timeout_minutes = 1"), "{new}");
    let dotted = "default = \"w\"\nprofiles.w.email = \"e\" # c\nprofiles.w.server_url = \"https://w\"\n";
    let (code, new, err) = set_email(dotted, &[], "email", "x");
    assert_eq!(code, 0, "{err}");
    assert_eq!(new, dotted.replace("\"e\"", "\"x\""));
}

#[test]
fn the_editor_refuses_a_profile_that_is_not_a_table_and_leaves_the_file() {
    for text in ["default = \"w\"\nprofiles = \"x\"\n", "default = \"w\"\n[profiles]\nw = 3\n"] {
        let (base, (code, _, err)) = cfg(Some(text), &[], &["config", "set", "email", "x"]);
        assert_eq!(code, 1);
        assert!(err.starts_with("rbw config set: cannot edit ") && err.contains("is not a table"), "{err}");
        assert_eq!(read_config(base.path()), text);
    }
}

#[test]
fn the_editor_unsets_in_inline_tables_and_keeps_the_rest() {
    let text = "default = \"w\"\nprofiles = { w = { email = \"e\", lock_timeout_minutes = 5 } } # all\n";
    let (base, (code, _, err)) = cfg(Some(text), &[], &["config", "unset", "lock_timeout"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("[profiles.w] - lock_timeout_minutes = 5"), "{err}");
    let new = read_config(base.path());
    assert!(new.contains("email = \"e\"") && new.contains("# all") && !new.contains("lock_timeout"), "{new}");
    // No `profiles` at all: nothing to remove.
    let (_, (code, _, err)) = cfg(Some("default = \"w\"\n"), &[], &["config", "unset", "lock_timeout"]);
    assert_eq!(code, 0);
    assert!(err.contains("nothing to change"), "{err}");
}

#[test]
fn gen_completions_keeps_the_fragments_of_rbws_real_scripts() {
    let (_, fish, _) = alone(&[], &["gen-completions", "fish"]);
    for line in [
        "complete -c rbw -n \"__fish_rbw_needs_command\" -f -a \"get\" -d 'Display the password for a given entry'",
        "complete -c rbw -n \"__fish_rbw_using_subcommand get\" -s f -l field -d 'Field to get' -r",
        "complete -c rbw -n \"__fish_rbw_using_subcommand get\" -s c -l clipboard -d 'Copy result to clipboard'",
        "complete -c rbw -n \"__fish_rbw_using_subcommand code\" -l clipboard -d 'Copy result to clipboard'",
        "complete -c rbw -n \"__fish_rbw_using_subcommand totp\" -l clipboard -d 'Copy result to clipboard'",
    ] {
        assert!(fish.lines().any(|l| l == line), "{line}");
    }
    let (_, bash, _) = alone(&[], &["gen-completions", "bash"]);
    assert!(bash.contains("            rbw,get)\n"), "{bash}");
    let (_, zsh, _) = alone(&[], &["gen-completions", "zsh"]);
    assert!(zsh.starts_with("#compdef rbw\n") && zsh.contains("'-f+[Field to get]:FIELD:_default' \\\n"), "{zsh}");
}

// the shim cannot move the server or the prompt from a script

#[test]
fn base_url_and_pinentry_need_a_terminal() {
    for args in [
        &["config", "set", "base_url", "https://x"][..],
        &["config", "set", "pinentry", "/bin/sh"],
        &["config", "unset", "pinentry"],
    ] {
        let f = new_base();
        write_config(f.path(), FILE);
        let mut env = renv(f.path(), &[]);
        env.stdin_tty = false;
        let (code, out, err) = rbw_in(&env, args);
        assert_eq!((code, out.as_str()), (1, ""), "{args:?}");
        assert_eq!(
            err,
            "rbw config set: changing base_url/pinentry needs an interactive terminal\n".replace("set", args[1]),
            "{args:?}"
        );
        assert_eq!(read_config(f.path()), FILE);
    }
    // Other keys are unchanged without a terminal.
    let f = new_base();
    write_config(f.path(), FILE);
    let mut env = renv(f.path(), &[]);
    env.stdin_tty = false;
    assert_eq!(rbw_in(&env, &["config", "set", "email", "x"]).0, 0);
    assert_eq!(rbw_in(&env, &["config", "set", "lock_timeout", "60"]).0, 0);
    assert_eq!(rbw_in(&env, &["config", "unset", "lock_timeout"]).0, 0);
}

// writing the file

#[test]
fn config_set_follows_a_symlinked_file_and_makes_private_directories() {
    let f = new_base();
    let real = f.path().join("managed.toml");
    std::fs::write(&real, FILE).unwrap();
    std::fs::create_dir_all(f.path().join(".config/dybw")).unwrap();
    std::os::unix::fs::symlink(&real, home_file(f.path())).unwrap();
    assert_eq!(rbw_in(&renv(f.path(), &[]), &["config", "set", "email", "z"]).0, 0);
    assert!(std::fs::symlink_metadata(home_file(f.path())).unwrap().file_type().is_symlink());
    assert_eq!(std::fs::read_to_string(&real).unwrap(), FILE.replace("w@example.org", "z"));
    assert!(!f.path().join("managed.toml.new").exists());
    // A fresh home: the directories are 0700, the file 0600.
    let g = new_base();
    assert_eq!(rbw_in(&renv(g.path(), &[]), &["config", "set", "email", "z"]).0, 0);
    for d in [".config", ".config/dybw"] {
        assert_eq!(std::fs::metadata(g.path().join(d)).unwrap().permissions().mode() & 0o777, 0o700, "{d}");
    }
}

#[test]
fn a_failed_write_leaves_no_temporary_file() {
    let f = new_base();
    write_config(f.path(), FILE);
    // The target is replaced by a directory only after it was read, so the rename fails.
    let dir = f.path().join(".config/dybw");
    let tmp = dir.join("config.toml.new");
    std::fs::create_dir(&tmp).unwrap();
    std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o555)).unwrap();
    let (code, _, err) = rbw_in(&renv(f.path(), &[]), &["config", "set", "email", "x"]);
    std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o755)).unwrap();
    assert_eq!(code, 1);
    assert!(err.contains("cannot write "), "{err}");
    assert_eq!(read_config(f.path()), FILE);
}
