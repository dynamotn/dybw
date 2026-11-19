//! Linux: the clipboard through `wl-copy`/`wl-paste`, `xclip` or `xsel`, found in [`PATH`] only. The value goes on
//! stdin, never in argv; the check before clearing compares SHA-256 digests.

use std::ffi::OsString;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{Error, Token, Tool};

/// Where the tools are looked for, and the `PATH` they run with: never the caller's.
pub(crate) const PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Runs the tools; tests swap it.
pub(crate) trait Runner {
    fn exists(&self, path: &Path) -> bool;
    /// Run with `input` on stdin and stdout discarded (`wl-copy` and `xclip` fork and keep serving it); `true` when
    /// it exited 0.
    fn run(&self, program: &Path, args: &[&str], input: &[u8]) -> std::io::Result<bool>;
    /// Run and keep stdout; `None` when it exited non-zero.
    fn read(&self, program: &Path, args: &[&str]) -> std::io::Result<Option<Zeroizing<Vec<u8>>>>;
}

pub(crate) struct System;

impl System {
    fn command(program: &Path, args: &[&str]) -> Command {
        let mut command = Command::new(program);
        command.args(args).env("PATH", PATH).stderr(Stdio::null());
        command
    }
}

impl Runner for System {
    fn exists(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn run(&self, program: &Path, args: &[&str], input: &[u8]) -> std::io::Result<bool> {
        let mut child = Self::command(program, args).stdin(Stdio::piped()).stdout(Stdio::null()).spawn()?;
        // Dropping stdin after the write is the end of the value.
        let wrote = child.stdin.take().map_or(Ok(()), |mut stdin| stdin.write_all(input));
        let ok = child.wait()?.success();
        // A tool that refused its arguments may exit before reading: its status says so, not the broken pipe.
        wrote.or_else(|e| if e.kind() == ErrorKind::BrokenPipe { Ok(()) } else { Err(e) })?;
        Ok(ok)
    }

    fn read(&self, program: &Path, args: &[&str]) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
        let out = Self::command(program, args).stdin(Stdio::null()).output()?;
        let text = Zeroizing::new(out.stdout);
        Ok(out.status.success().then_some(text))
    }
}

impl Tool {
    /// The argument lists for a copy, tried in order: `--sensitive` (the KDE hint) needs wl-clipboard 2.2.
    fn copy_args(self) -> &'static [&'static [&'static str]] {
        match self {
            Tool::WlCopy => &[&["--type", "text/plain", "--sensitive"], &["--type", "text/plain"]],
            Tool::Xclip => &[&["-selection", "clipboard", "-in"]],
            Tool::Xsel => &[&["--clipboard", "--input"]],
        }
    }

    fn paste(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Tool::WlCopy => ("wl-paste", &["--no-newline"]),
            Tool::Xclip => ("xclip", &["-selection", "clipboard", "-out"]),
            Tool::Xsel => ("xsel", &["--clipboard", "--output"]),
        }
    }

    /// The clear command; `xclip` has none and copies the empty text instead.
    fn clear(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Tool::WlCopy => ("wl-copy", &["--clear"]),
            Tool::Xclip => ("xclip", &["-selection", "clipboard", "-in"]),
            Tool::Xsel => ("xsel", &["--clipboard", "--clear"]),
        }
    }
}

fn find(runner: &dyn Runner, name: &str) -> Option<PathBuf> {
    PATH.split(':').map(|dir| Path::new(dir).join(name)).find(|p| runner.exists(p))
}

fn digest(text: &[u8]) -> [u8; 32] {
    Sha256::digest(text).into()
}

/// Wayland when `WAYLAND_DISPLAY` is set and `wl-copy` is installed, else X11 (`xclip`, then `xsel`) when `DISPLAY`
/// is set.
fn pick(runner: &dyn Runner, var: &dyn Fn(&str) -> Option<OsString>) -> Result<(Tool, PathBuf), Error> {
    let set = |name| var(name).is_some_and(|v| !v.is_empty());
    let tools: &[Tool] = match (set("WAYLAND_DISPLAY"), set("DISPLAY")) {
        (true, true) => &Tool::ALL,
        (true, false) => &[Tool::WlCopy],
        (false, true) => &[Tool::Xclip, Tool::Xsel],
        (false, false) => &[],
    };
    tools.iter().find_map(|&t| find(runner, t.name()).map(|p| (t, p))).ok_or(Error::Unavailable)
}

pub(crate) fn copy(runner: &dyn Runner, var: &dyn Fn(&str) -> Option<OsString>, value: &[u8]) -> Result<Token, Error> {
    let (tool, path) = pick(runner, var)?;
    for args in tool.copy_args() {
        if runner.run(&path, args, value)? {
            return Ok(Token::Hash(tool, digest(value)));
        }
    }
    Err(Error::Refused)
}

pub(crate) fn clear_if_unchanged(runner: &dyn Runner, token: &Token) -> Result<bool, Error> {
    let Token::Hash(tool, hash) = token else { return Err(Error::BadToken) };
    let program = |name| find(runner, name).ok_or(Error::Unavailable);
    let (paste, args) = tool.paste();
    // An empty or unreadable clipboard is not the copy either.
    let current = runner.read(&program(paste)?, args)?;
    if current.is_none_or(|text| digest(&text) != *hash) {
        return Ok(false);
    }
    let (clear, args) = tool.clear();
    if runner.run(&program(clear)?, args, b"")? { Ok(true) } else { Err(Error::Refused) }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;

    /// Program, arguments, stdin.
    type Call = (String, Vec<String>, Vec<u8>);

    /// Tools at the given paths; `run` answers from `runs` in order, `read` gives `clipboard`.
    #[derive(Default)]
    struct Fake {
        installed: Vec<&'static str>,
        runs: RefCell<VecDeque<std::io::Result<bool>>>,
        clipboard: Option<&'static [u8]>,
        calls: RefCell<Vec<Call>>,
    }

    impl Fake {
        fn with(installed: &[&'static str], runs: Vec<bool>) -> Fake {
            Fake {
                installed: installed.to_vec(),
                runs: RefCell::new(runs.into_iter().map(Ok).collect()),
                ..Fake::default()
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }

        fn record(&self, program: &Path, args: &[&str], input: &[u8]) {
            let args = args.iter().map(|a| a.to_string()).collect();
            self.calls.borrow_mut().push((program.display().to_string(), args, input.to_vec()));
        }
    }

    impl Runner for Fake {
        fn exists(&self, path: &Path) -> bool {
            self.installed.iter().any(|p| Path::new(p) == path)
        }

        fn run(&self, program: &Path, args: &[&str], input: &[u8]) -> std::io::Result<bool> {
            self.record(program, args, input);
            self.runs.borrow_mut().pop_front().unwrap()
        }

        fn read(&self, program: &Path, args: &[&str]) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
            self.record(program, args, b"");
            Ok(self.clipboard.map(|c| Zeroizing::new(c.to_vec())))
        }
    }

    fn vars(set: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        move |name| set.iter().find(|(k, _)| *k == name).map(|(_, v)| v.into())
    }

    const WAYLAND: &[(&str, &str)] = &[("WAYLAND_DISPLAY", "wayland-0"), ("DISPLAY", ":0")];
    const X11: &[(&str, &str)] = &[("DISPLAY", ":0")];
    const VALUE: &[u8] = b"hunter2 secret";

    #[test]
    fn wayland_copy_sends_the_value_on_stdin_with_the_hint() {
        let fake = Fake::with(&["/usr/bin/wl-copy", "/usr/bin/xclip"], vec![true]);
        let token = copy(&fake, &vars(WAYLAND), VALUE).unwrap();
        assert_eq!(token, Token::Hash(Tool::WlCopy, digest(VALUE)));
        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        let (program, args, input) = &calls[0];
        assert_eq!((program.as_str(), input.as_slice()), ("/usr/bin/wl-copy", VALUE));
        assert_eq!(args, &["--type", "text/plain", "--sensitive"]);
        // The value is in no argument, and the token does not hold it.
        assert!(args.iter().all(|a| !a.contains("hunter2")));
        assert!(!token.encode().contains("hunter2"));
    }

    #[test]
    fn an_old_wl_copy_without_sensitive_still_copies() {
        let fake = Fake::with(&["/usr/local/bin/wl-copy"], vec![false, true]);
        let vars = vars(&[("WAYLAND_DISPLAY", "w")]);
        assert_eq!(copy(&fake, &vars, VALUE).unwrap(), Token::Hash(Tool::WlCopy, digest(VALUE)));
        let calls = fake.calls();
        assert_eq!(calls[1].1, ["--type", "text/plain"]);
        assert_eq!(calls[1].2, VALUE);
        // Both refuse: an error, not a silent no-op.
        let fake = Fake::with(&["/usr/local/bin/wl-copy"], vec![false, false]);
        assert!(matches!(copy(&fake, &vars, VALUE), Err(Error::Refused)));
    }

    #[test]
    fn x11_takes_xclip_then_xsel_and_wayland_without_wl_copy_falls_back() {
        let fake = Fake::with(&["/bin/xclip", "/bin/xsel"], vec![true]);
        assert_eq!(copy(&fake, &vars(WAYLAND), VALUE).unwrap(), Token::Hash(Tool::Xclip, digest(VALUE)));
        assert_eq!(fake.calls()[0].1, ["-selection", "clipboard", "-in"]);
        let fake = Fake::with(&["/usr/bin/xsel"], vec![true]);
        assert_eq!(copy(&fake, &vars(X11), VALUE).unwrap(), Token::Hash(Tool::Xsel, digest(VALUE)));
        assert_eq!(fake.calls()[0], (s("/usr/bin/xsel"), vec![s("--clipboard"), s("--input")], VALUE.to_vec()));
    }

    #[test]
    fn no_display_or_no_tool_in_the_fixed_path_is_unavailable() {
        let everywhere = ["/usr/bin/wl-copy", "/usr/bin/xclip", "/usr/bin/xsel"];
        for vars in [vars(&[]), vars(&[("WAYLAND_DISPLAY", ""), ("DISPLAY", "")])] {
            let fake = Fake::with(&everywhere, vec![]);
            assert!(matches!(copy(&fake, &vars, VALUE), Err(Error::Unavailable)));
        }
        // A tool only in the caller's PATH is never run.
        let fake = Fake::with(&["/home/u/bin/wl-copy", "/home/u/bin/xclip"], vec![]);
        let vars = vars(&[("WAYLAND_DISPLAY", "w"), ("DISPLAY", ":0"), ("PATH", "/home/u/bin")]);
        assert!(matches!(copy(&fake, &vars, VALUE), Err(Error::Unavailable)));
        assert!(fake.calls().is_empty());
        // X11 only, and only wl-copy installed.
        let fake = Fake::with(&["/usr/bin/wl-copy"], vec![]);
        assert!(matches!(copy(&fake, &super::tests::vars(X11), VALUE), Err(Error::Unavailable)));
    }

    #[test]
    fn a_tool_that_cannot_start_is_an_error() {
        let fake = Fake::with(&["/usr/bin/xsel"], vec![]);
        fake.runs.borrow_mut().push_back(Err(std::io::Error::from(ErrorKind::PermissionDenied)));
        assert!(matches!(copy(&fake, &vars(X11), VALUE), Err(Error::Io(_))));
    }

    fn s(v: &str) -> String {
        v.into()
    }

    #[test]
    fn clear_runs_only_while_the_clipboard_still_holds_the_copy() {
        let installed = ["/usr/bin/wl-copy", "/usr/bin/wl-paste", "/usr/bin/xclip", "/usr/bin/xsel"];
        for (tool, paste, clear) in [
            (Tool::WlCopy, ("/usr/bin/wl-paste", vec!["--no-newline"]), ("/usr/bin/wl-copy", vec!["--clear"])),
            (
                Tool::Xclip,
                ("/usr/bin/xclip", vec!["-selection", "clipboard", "-out"]),
                ("/usr/bin/xclip", vec!["-selection", "clipboard", "-in"]),
            ),
            (
                Tool::Xsel,
                ("/usr/bin/xsel", vec!["--clipboard", "--output"]),
                ("/usr/bin/xsel", vec!["--clipboard", "--clear"]),
            ),
        ] {
            let token = Token::Hash(tool, digest(VALUE));
            let fake = Fake { clipboard: Some(VALUE), ..Fake::with(&installed, vec![true]) };
            assert!(clear_if_unchanged(&fake, &token).unwrap());
            let strs = |v: Vec<&str>| v.into_iter().map(s).collect::<Vec<_>>();
            let expected = vec![(s(paste.0), strs(paste.1), vec![]), (s(clear.0), strs(clear.1), vec![])];
            assert_eq!(fake.calls(), expected);
        }
    }

    /// Review focus 5: the user copied something else (or emptied the clipboard) before the timer.
    #[test]
    fn a_changed_or_empty_clipboard_is_left_alone() {
        let token = Token::Hash(Tool::WlCopy, digest(VALUE));
        let installed = ["/usr/bin/wl-copy", "/usr/bin/wl-paste"];
        for clipboard in [Some(&b"what the user copied"[..]), Some(&b"hunter2 secre"[..]), None] {
            let fake = Fake { clipboard, ..Fake::with(&installed, vec![]) };
            assert!(!clear_if_unchanged(&fake, &token).unwrap());
            assert_eq!(fake.calls().len(), 1, "only the paste ran");
        }
    }

    #[test]
    fn clear_errors_are_reported() {
        let token = Token::Hash(Tool::Xsel, digest(VALUE));
        let fake = Fake { clipboard: Some(VALUE), ..Fake::with(&["/bin/xsel"], vec![false]) };
        assert!(matches!(clear_if_unchanged(&fake, &token), Err(Error::Refused)));
        let fake = Fake::with(&[], vec![]);
        assert!(matches!(clear_if_unchanged(&fake, &token), Err(Error::Unavailable)));
        assert!(matches!(clear_if_unchanged(&fake, &Token::Count(1)), Err(Error::BadToken)));
    }

    #[test]
    fn the_system_runner_feeds_stdin_and_reads_stdout_with_the_fixed_path() {
        let sh = Path::new("/bin/sh");
        assert!(System.exists(sh) && !System.exists(Path::new("/bin")));
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let script = format!("cat > '{}'; printf %s \"$PATH\" >> '{}'", out.display(), out.display());
        assert!(System.run(sh, &["-c", &script], VALUE).unwrap());
        assert_eq!(std::fs::read(&out).unwrap(), [VALUE, PATH.as_bytes()].concat());
        // A tool that exits without reading: its status, not a broken pipe.
        assert!(!System.run(sh, &["-c", "exit 1"], &[0u8; 1 << 20]).unwrap());
        let read = System.read(sh, &["-c", "printf 'a b'"]).unwrap();
        assert_eq!(read.as_deref().map(Vec::as_slice), Some(&b"a b"[..]));
        assert_eq!(System.read(sh, &["-c", "exit 3"]).unwrap(), None);
        assert!(System.run(Path::new("/nonexistent/tool"), &[], b"").is_err());
    }
}
