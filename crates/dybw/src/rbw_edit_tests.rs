//! rbw's `$EDITOR` flow for `add` and `edit`, with fake editors (shell scripts): the private file and directory, what
//! the editor is given, what is sent, and that nothing is left behind in any case (Review Focus 5). The texts and the
//! parse are rbw 1.15.0's (`src/edit.rs`, `src/bin/rbw/commands.rs:1219-1228`, `2629-2648`).

#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use dybw_proto::{Op, Reply, Sealed};
use zeroize::Zeroizing;

use super::*;
use crate::rbw_edit::{HELP_NOTES, HELP_PW, parse};
use crate::rbw_out_tests::{card_for_edit, edit_reply, login_for_edit, note_item, raw_get, rbw_run};
use crate::tests::{Act, s};

/// A scratch place for the editors' notes, on the file system of the scratch directory (hard links work).
fn work() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("w").tempdir_in("/tmp").unwrap()
}

/// An executable `#!/bin/sh` script `name` in `dir`; `$f` is the file it is given (the last argument), `$W` is `dir`.
fn editor(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    let script = format!("#!/bin/sh\nW='{}'\nfor f; do :; done\n{body}\n", dir.display());
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, PermissionsExt::from_mode(0o755)).unwrap();
    path
}

/// Records what the editor was given: its arguments, the directory's and the file's modes, the text, and a hard link.
const RECORD: &str = r#"echo "$@" > "$W/args"
dirname "$f" > "$W/dir"
ls -ld "$(dirname "$f")" | cut -c1-10 > "$W/dirmode"
ls -l "$f" | cut -c1-10 > "$W/filemode"
cp "$f" "$W/seen"
ln "$f" "$W/link""#;

fn read(w: &Path, name: &str) -> String {
    std::fs::read_to_string(w.join(name)).unwrap()
}

/// The scratch directories left under `dir`.
fn leftovers(dir: &Path) -> Vec<String> {
    let names = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned());
    names.filter(|n| n.starts_with("rbw-edit")).collect()
}

/// Run `args` with `VISUAL=visual`; also checks no scratch directory is left where the editor said it was.
fn with_editor(acts: Vec<Act>, visual: &Path, args: &[&str]) -> ((u8, String, String), Vec<Op>) {
    rbw_run(acts, &[("VISUAL", visual.display().to_string())], args, |_| {})
}

fn left_where_the_editor_was(w: &Path) -> bool {
    std::fs::read_to_string(w.join("dir")).is_ok_and(|d| Path::new(d.trim()).exists())
}

fn sealed(v: &str) -> Option<Sealed> {
    Some(Sealed::new(s(v)))
}

#[test]
fn add_edits_in_a_private_file_sends_the_text_and_wipes_and_removes_the_file() {
    let w = work();
    let body = format!("{RECORD}\nprintf 'new pw\\n\\n\\nnote 1\\n# not a note\\nnote 2\\n\\n' > \"$f\"");
    let ed = editor(w.path(), "ed", &body);
    let args = ["add", "n", "me", "--uri", "https://a", "--folder", "f"];
    let (result, ops) = with_editor(vec![Act::Reply(Reply::Done)], &ed, &args);
    assert_eq!(result, (0, s(""), s("")));
    assert_eq!(
        ops,
        [Op::Add {
            profile: None,
            name: s("n"),
            user: Some(s("me")),
            uris: vec![s("https://a")],
            folder: Some(s("f")),
            ask: vec![],
            password: sealed("new pw"),
            notes: sealed("note 1\nnote 2"),
        }]
    );
    assert_eq!(read(w.path(), "seen"), HELP_PW, "an empty text and rbw's help");
    assert_eq!(read(w.path(), "dirmode").trim(), "drwx------");
    assert_eq!(read(w.path(), "filemode").trim(), "-rw-------");
    assert_eq!(read(w.path(), "args").trim(), format!("{}/rbw", read(w.path(), "dir").trim()), "the file, no flag");
    let link = std::fs::read(w.path().join("link")).unwrap();
    assert_eq!(link.len(), "new pw\n\n\nnote 1\n# not a note\nnote 2\n\n".len());
    assert!(link.iter().all(|b| *b == 0), "the file was overwritten with zeros in place");
    assert!(!left_where_the_editor_was(w.path()), "the directory is gone");
}

#[test]
fn edit_starts_from_the_current_password_and_notes_and_sends_the_new_ones() {
    let w = work();
    let ed = editor(w.path(), "ed", &format!("{RECORD}\nprintf 'pw2\\n\\nnew notes\\n' > \"$f\""));
    let (result, ops) =
        with_editor(vec![edit_reply(login_for_edit()), Act::Reply(Reply::Done)], &ed, &["edit", "n", "-i"]);
    assert_eq!(result, (0, s(""), s("")));
    assert_eq!(read(w.path(), "seen"), format!("pw\n\nline 1\nline 2\n{HELP_PW}"));
    let edit = |password, notes| Op::Edit {
        profile: None,
        needle: s("n"),
        user: None,
        folder: None,
        ask: vec![],
        ignorecase: true,
        password,
        notes,
    };
    assert_eq!(ops, [raw_get("n", true), edit(sealed("pw2"), sealed("new notes"))]);
    assert!(std::fs::read(w.path().join("link")).unwrap().iter().all(|b| *b == 0));
    assert!(!left_where_the_editor_was(w.path()));
    // Notes removed: sent empty, which clears them, as rbw's `None` does.
    let ed = editor(w.path(), "ed", "printf 'pw\\n' > \"$f\"");
    let (_, ops) = with_editor(vec![edit_reply(login_for_edit()), Act::Reply(Reply::Done)], &ed, &["edit", "n", "-i"]);
    assert_eq!(ops[1], edit(sealed("pw"), sealed("")));
    // A note: only its notes, read after a blank first line as rbw does; its old text and rbw's help to start from.
    let ed = editor(w.path(), "ed", &format!("{RECORD}\nprintf 'new 1\\n\\nnew 2\\n# c\\n' > \"$f\""));
    let (result, ops) =
        with_editor(vec![edit_reply(note_item(Some("old"))), Act::Reply(Reply::Done)], &ed, &["edit", "n", "-i"]);
    assert_eq!(result.0, 0);
    assert_eq!(read(w.path(), "seen"), format!("old\n{HELP_NOTES}"));
    assert_eq!(ops[1], edit(None, sealed("new 1\n\nnew 2")));
    let (_, ops) = with_editor(vec![edit_reply(note_item(None)), Act::Reply(Reply::Done)], &ed, &["edit", "n", "-i"]);
    assert_eq!(read(w.path(), "seen"), format!("\n{HELP_NOTES}"), "no notes: an empty line");
    assert_eq!(ops.len(), 2);
}

#[test]
fn edit_of_another_type_refuses_before_any_editor_runs() {
    let w = work();
    let ed = editor(w.path(), "ed", "touch \"$W/ran\"");
    let (result, ops) = with_editor(vec![edit_reply(card_for_edit())], &ed, &["edit", "n"]);
    assert_eq!(result, (1, s(""), s("rbw edit: modifications are only supported for login and note entries\n")));
    assert_eq!(ops, [raw_get("n", false)]);
    assert!(!w.path().join("ran").exists());
}

#[test]
fn a_failing_empty_or_unreadable_edit_writes_nothing_and_leaves_nothing_behind() {
    let w = work();
    let nothing = "the editor left nothing to save; nothing was changed";
    // (what the editor does, the error, whether `edit` fails too: an unchanged login is a change of nothing, sent)
    let cases = [
        ("exit 3", "failed to run editor", true),
        (": > \"$f\"", nothing, true),
        ("true", nothing, false),
        ("printf '\\n\\n# only comments\\n' > \"$f\"", nothing, true),
        ("rm \"$f\"", "cannot read ", true),
        ("printf 'pw\\377\\n' > \"$f\"", "is not UTF-8 text", true),
    ];
    for (action, why, edit_too) in cases {
        let ed = editor(w.path(), "ed", &format!("{RECORD}\n{action}"));
        let edit = (&["edit", "n"][..], vec![edit_reply(login_for_edit())]);
        for (args, acts) in [(&["add", "n"][..], vec![])].into_iter().chain(edit_too.then_some(edit)) {
            let reads = acts.len();
            let ((code, out, err), ops) = with_editor(acts, &ed, args);
            assert_eq!((code, out.as_str()), (1, ""), "{action}");
            assert!(err.starts_with(&format!("rbw {}: ", args[0])) && err.contains(why), "{action}: {err}");
            assert_eq!(ops.len(), reads, "{action}: nothing written");
            assert!(!left_where_the_editor_was(w.path()), "{action}");
            // A file the editor removed is not there to wipe (its link keeps it).
            if !action.starts_with("rm") {
                assert!(std::fs::read(w.path().join("link")).unwrap().iter().all(|b| *b == 0), "{action}: wiped");
            }
            let _ = std::fs::remove_file(w.path().join("link"));
        }
    }
    // rbw's text for a failed editor: the program, its arguments and the status.
    let ed = editor(w.path(), "ed", &format!("{RECORD}\nexit 3"));
    let (_, _, err) = with_editor(vec![], &ed, &["add", "n"]).0;
    let file = format!("{}/rbw", read(w.path(), "dir").trim());
    assert_eq!(
        err,
        format!("rbw add: failed to run editor {} {file}: ExitStatus(unix_wait_status(768))\n", ed.display())
    );
}

#[test]
fn an_editor_that_keeps_the_file_open_or_leaves_more_files_still_leaves_nothing_behind() {
    let w = work();
    let body = format!(
        "{RECORD}\nd=$(dirname \"$f\")\nmkdir \"$d/sub\"\nprintf 'secret' > \"$d/sub/backup\"\nln \"$d/sub/backup\" \
         \"$W/sublink\"\nln -s /etc/hosts \"$d/hosts\"\nprintf 'secret' > \"$d/rbw~\"\nprintf 'pw\\n' > \"$f\"\n( sleep 2 \
         < \"$f\" > /dev/null 2>&1 & )"
    );
    let ed = editor(w.path(), "ed", &body);
    let (result, ops) = with_editor(vec![Act::Reply(Reply::Done)], &ed, &["add", "n"]);
    assert_eq!(result.0, 0, "{}", result.2);
    assert_eq!(ops.len(), 1);
    assert!(!left_where_the_editor_was(w.path()), "removed while the editor's child still holds the file");
    assert!(std::fs::read(w.path().join("sublink")).unwrap().iter().all(|b| *b == 0), "files below are wiped too");
    assert!(std::fs::read_to_string("/etc/hosts").is_ok_and(|h| !h.is_empty()), "a link is removed, not followed");
}

#[test]
fn the_editor_is_run_as_rbw_runs_it() {
    let w = work();
    // vim and nvim get no swap file or viminfo.
    for name in ["vim", "nvim"] {
        let ed = editor(w.path(), name, &format!("{RECORD}\nexit 1"));
        with_editor(vec![], &ed, &["add", "n"]);
        let file = format!("{}/rbw", read(w.path(), "dir").trim());
        assert_eq!(read(w.path(), "args").trim(), format!("-ni NONE {file}"), "{name}");
    }
    // A value with a space or a quote is run by the shell, the file appended.
    let ed = editor(w.path(), "ed", &format!("{RECORD}\nexit 1"));
    let (_, _, err) = rbw_run(vec![], &[("VISUAL", format!("{} --wait", ed.display()))], &["add", "n"], |_| {}).0;
    let file = format!("{}/rbw", read(w.path(), "dir").trim());
    assert_eq!(read(w.path(), "args").trim(), format!("--wait {file}"));
    assert!(
        err.starts_with(&format!("rbw add: failed to run editor /bin/sh -c {} --wait {file}: ", ed.display())),
        "{err}"
    );
    // `$EDITOR` when `$VISUAL` is not set.
    let marker = editor(w.path(), "other", "touch \"$W/editor-ran\"\nexit 1");
    rbw_run(vec![], &[("EDITOR", marker.display().to_string())], &["add", "n"], |_| {});
    assert!(w.path().join("editor-ran").exists());
    // A value with no file name, or a program that does not exist.
    let (_, _, err) = rbw_run(vec![], &[("VISUAL", s("/"))], &["add", "n"], |_| {}).0;
    assert_eq!(err, "rbw add: invalid value for $VISUAL: /\n");
    let (_, _, err) = rbw_run(vec![], &[("EDITOR", s("/nonexistent/ed"))], &["add", "n"], |_| {}).0;
    assert_eq!(err, "rbw add: failed to run editor /nonexistent/ed: No such file or directory (os error 2)\n");
    assert_eq!(
        crate::rbw_edit::editor_of(&crate::tests::env_in(w.path(), None, None)),
        ("EDITOR", std::ffi::OsString::from("/usr/bin/vim")),
        "rbw's default"
    );
}

#[test]
fn the_private_directory_is_made_under_the_runtime_dir_else_tmpdir_else_tmp() {
    let w = work();
    let ed = editor(w.path(), "ed", &format!("{RECORD}\nexit 1"));
    let visual = ed.display().to_string();
    let only = |vars: Vec<(&'static str, String)>| {
        let visual = visual.clone();
        move |env: &mut Env| {
            env.var = Box::new(move |n| {
                if n == "VISUAL" {
                    return Some(visual.clone().into());
                }
                vars.iter().find(|(k, _)| *k == n).map(|(_, v)| v.into())
            });
        }
    };
    let tmpdir = w.path().join("t");
    std::fs::create_dir(&tmpdir).unwrap();
    rbw_run(vec![], &[], &["add", "n"], only(vec![("TMPDIR", tmpdir.display().to_string())]));
    assert!(read(w.path(), "dir").starts_with(&tmpdir.display().to_string()), "{}", read(w.path(), "dir"));
    assert!(leftovers(&tmpdir).is_empty());
    rbw_run(vec![], &[], &["add", "n"], only(vec![("TMPDIR", s("relative")), ("XDG_RUNTIME_DIR", s("rel"))]));
    assert!(read(w.path(), "dir").starts_with("/tmp/rbw-edit."), "{}", read(w.path(), "dir"));
    let (code, _, err) = rbw_run(vec![], &[], &["add", "n"], only(vec![("XDG_RUNTIME_DIR", s("/nonexistent/x"))])).0;
    assert_eq!(code, 1);
    assert!(err.starts_with("rbw add: cannot make a private directory under /nonexistent/x: "), "{err}");
}

#[test]
fn piped_text_is_read_from_stdin_with_no_editor() {
    let w = work();
    let ed = editor(w.path(), "ed", "touch \"$W/ran\"");
    let piped = |env: &mut Env| {
        env.stdin_tty = false;
        env.stdin = Box::new(|| Ok(Zeroizing::new(s("pw\n\nnotes\n"))));
    };
    let (result, ops) =
        rbw_run(vec![Act::Reply(Reply::Done)], &[("VISUAL", ed.display().to_string())], &["add", "n"], piped);
    assert_eq!(result, (0, s(""), s("")));
    let Op::Add { password, notes, .. } = &ops[0] else { panic!() };
    assert_eq!((password, notes), (&sealed("pw"), &sealed("notes")));
    assert!(!w.path().join("ran").exists());
    let broken = |env: &mut Env| {
        env.stdin_tty = false;
        env.stdin = Box::new(|| Err(std::io::ErrorKind::BrokenPipe.into()));
    };
    let (code, _, err) = rbw_run(vec![], &[], &["add", "n"], broken).0;
    assert_eq!((code, err.as_str()), (1, "rbw add: failed to read from stdin: broken pipe\n"));
}

#[test]
fn the_text_is_parsed_as_rbw_parses_it() {
    let parsed = |t: &str| {
        let (p, n) = parse(t);
        (p.map(|p| p.to_string()), n.map(|n| n.to_string()))
    };
    let some = |v: &str| Some(s(v));
    assert_eq!(parsed(""), (None, None));
    assert_eq!(parsed("pw"), (some("pw"), None));
    assert_eq!(parsed("# pw\n"), (some("# pw"), None), "the first line is the password, even a comment");
    assert_eq!(parsed("pw\n\n\na\n\nb\n# c\n\n"), (some("pw"), some("a\n\nb")));
    assert_eq!(parsed("pw\nnotes right after\r\n"), (some("pw"), some("notes right after")));
    assert_eq!(parsed(&format!("pw\n{HELP_PW}")), (some("pw"), None), "rbw's help is not kept");
}
