//! rbw's `$VISUAL`/`$EDITOR` input for `add` and `edit` (rbw 1.15.0 `src/edit.rs`, MIT; `parse_editor` and the help
//! texts from `src/bin/rbw/commands.rs:1219-1228` and `2629-2648`). The owner's rule (P4.4): the text is edited in this
//! process, in a file of its own in a fresh 0700 directory, and the file is overwritten with zeros, then it and the
//! directory are removed whatever happens (a failed editor, an empty file, an error reading it back, a panic).

use std::ffi::OsString;
use std::fs::{DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use zeroize::Zeroizing;

use crate::{Env, Fail};

pub(crate) const HELP_PW: &str = r"
# The first line of this file will be the password, and the remainder of the
# file (after any blank lines after the password) will be stored as a note.
# Lines with leading # will be ignored.
";

pub(crate) const HELP_NOTES: &str = r"
# The content of this file will be stored as a note.
# Lines with leading # will be ignored.
";

/// A directory of this process only, wiped and removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    /// A new 0700 directory under `XDG_RUNTIME_DIR`, else `TMPDIR`, else `/tmp`. Made with `mkdir`, which never reuses
    /// a path that exists (another user's directory or link included).
    fn new(env: &Env) -> Result<Scratch, Fail> {
        let base = ["XDG_RUNTIME_DIR", "TMPDIR"]
            .into_iter()
            .filter_map(|v| (env.var)(v))
            .map(PathBuf::from)
            .find(|p| p.is_absolute())
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        let mut last = None;
        for n in 0..16 {
            let dir = base.join(format!("rbw-edit.{}.{stamp}.{n}", std::process::id()));
            match DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(Scratch(dir)),
                Err(e) => last = Some(e),
            }
        }
        let why = last.map(|e| e.to_string()).unwrap_or_default();
        Err(Fail::Log(format!("cannot make a private directory under {}: {why}", base.display())))
    }
}

/// Overwrite every regular file under `dir` with zeros, in place (a hard link elsewhere sees the zeros too); links
/// are not followed.
fn wipe(dir: &Path) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.is_dir() => wipe(&path),
            Ok(m) if m.is_file() => {
                let zeros = |mut f: std::fs::File| -> std::io::Result<()> {
                    let mut left = m.len();
                    let block = [0u8; 4096];
                    while left > 0 {
                        let n = usize::try_from(left.min(4096)).unwrap_or(4096);
                        f.write_all(block.get(..n).unwrap_or(&block))?;
                        left -= n as u64;
                    }
                    f.sync_all()
                };
                let _ = OpenOptions::new().write(true).custom_flags(libc_nofollow()).open(&path).and_then(zeros);
            }
            _ => {}
        }
    }
}

/// `O_NOFOLLOW`: a file swapped for a link between the look and the open is not written through.
fn libc_nofollow() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits() as i32
}

impl Drop for Scratch {
    fn drop(&mut self) {
        wipe(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An I/O error on `path` as a failure of the command.
fn failed<'a>(what: &'static str, path: &'a Path) -> impl FnOnce(std::io::Error) -> Fail + 'a {
    move |e| Fail::Log(format!("{what} {}: {e}", path.display()))
}

/// rbw's test for an editor value that needs a shell.
fn needs_shell(editor: &std::ffi::OsStr) -> bool {
    editor.to_str().is_some_and(|s| s.contains([' ', '$', '\'', '"']))
}

/// The editor and the variable that named it: `$VISUAL`, else `$EDITOR`, else `/usr/bin/vim`.
pub(crate) fn editor_of(env: &Env) -> (&'static str, OsString) {
    match ((env.var)("VISUAL"), (env.var)("EDITOR")) {
        (Some(v), _) => ("VISUAL", v),
        (None, Some(e)) => ("EDITOR", e),
        (None, None) => ("EDITOR", OsString::from("/usr/bin/vim")),
    }
}

/// The text to save: from stdin when it is not a terminal (as rbw, no editor), else `contents` and `help` edited in
/// [`editor_of`] (vim and nvim with no swap or viminfo file).
pub(crate) fn edit(env: &Env, contents: &str, help: &str) -> Result<Zeroizing<String>, Fail> {
    if !env.stdin_tty {
        return (env.stdin)().map_err(|e| Fail::Log(format!("failed to read from stdin: {e}")));
    }
    let (var, editor) = editor_of(env);
    let scratch = Scratch::new(env)?;
    let file = scratch.0.join("rbw");
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file)
        .and_then(|mut f| f.write_all(contents.as_bytes()).and_then(|()| f.write_all(help.as_bytes())));
    written.map_err(failed("cannot write", &file))?;
    let (cmd, args) = if needs_shell(&editor) {
        let mut line = editor.clone();
        line.push(" ");
        line.push(&file);
        (PathBuf::from("/bin/sh"), vec![OsString::from("-c"), line])
    } else {
        let path = PathBuf::from(&editor);
        let name = path
            .file_name()
            .ok_or_else(|| Fail::Log(format!("invalid value for ${var}: {}", editor.to_string_lossy())))?;
        let mut args = vec![];
        if name == "vim" || name == "nvim" {
            args.extend([OsString::from("-ni"), OsString::from("NONE")]);
        }
        args.push(file.clone().into_os_string());
        (path, args)
    };
    let shown = || args.iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ");
    let status = Command::new(&cmd)
        .args(&args)
        .status()
        .map_err(|e| Fail::Log(format!("failed to run editor {}: {e}", cmd.display())))?;
    if !status.success() {
        return Err(Fail::Log(format!("failed to run editor {} {}: {status:?}", cmd.display(), shown())));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    let read = std::fs::File::open(&file).and_then(|mut f| {
        let size = f.metadata()?.len();
        bytes.reserve_exact(usize::try_from(size).unwrap_or_default());
        f.read_to_end(&mut bytes)
    });
    read.map_err(failed("cannot read", &file))?;
    let text = String::from_utf8(std::mem::take(&mut *bytes)).map_err(|e| {
        drop(Zeroizing::new(e.into_bytes()));
        Fail::Log(format!("{} is not UTF-8 text", file.display()))
    })?;
    Ok(Zeroizing::new(text))
}

/// rbw's `parse_editor`: the first line is the password; the rest, after the blank lines that follow it and without
/// the lines starting with `#`, is the notes (`None` when empty).
pub(crate) fn parse(contents: &str) -> (Option<Zeroizing<String>>, Option<Zeroizing<String>>) {
    let mut lines = contents.lines();
    let password = lines.next().map(|l| Zeroizing::new(l.to_owned()));
    // Sized once: the notes are never longer than the text, so they are never moved while they grow.
    let mut notes = Zeroizing::new(String::with_capacity(contents.len() + 1));
    for line in lines.skip_while(|l| l.is_empty()).filter(|l| !l.starts_with('#')) {
        notes.push_str(line);
        notes.push('\n');
    }
    while notes.ends_with('\n') {
        notes.pop();
    }
    (password, (!notes.is_empty()).then_some(notes))
}
