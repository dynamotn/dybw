//! Pure parsers for what the kernel hands back. They run on every OS so the
//! odd-buffer tests do too; none of them panics on short or garbage input.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

pub(crate) type Env = Vec<(OsString, OsString)>;

fn os(bytes: &[u8]) -> OsString {
    OsString::from_vec(bytes.to_vec())
}

/// `KEY=value` entries; entries without `=` and empty ones are dropped.
fn env_pairs<'a>(entries: impl Iterator<Item = &'a [u8]>) -> Env {
    entries
        .filter_map(|e| {
            let eq = e.iter().position(|b| *b == b'=')?;
            Some((os(e.get(..eq)?), os(e.get(eq + 1..)?)))
        })
        .collect()
}

/// macOS `KERN_PROCARGS2`: native-endian `argc`, the exec path, NUL padding,
/// `argc` argv strings, then the environment. A truncated tail is tolerated.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn procargs2(buf: &[u8]) -> Option<(Vec<OsString>, Env)> {
    let (head, rest) = buf.split_first_chunk::<4>()?;
    let argc = usize::try_from(i32::from_ne_bytes(*head)).ok()?;
    let path_end = rest.iter().position(|b| *b == 0)?;
    let rest = rest.get(path_end..)?;
    let rest = rest.get(rest.iter().position(|b| *b != 0).unwrap_or(rest.len())..)?;
    let mut parts = rest.split(|b| *b == 0);
    let argv = parts.by_ref().take(argc).map(os).collect();
    Some((argv, env_pairs(parts)))
}

/// `/proc/<pid>/cmdline`: NUL-terminated strings.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(crate) fn cmdline(buf: &[u8]) -> Vec<OsString> {
    let buf = buf.strip_suffix(&[0]).unwrap_or(buf);
    if buf.is_empty() {
        return Vec::new();
    }
    buf.split(|b| *b == 0).map(os).collect()
}

/// `/proc/<pid>/environ`.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(crate) fn environ(buf: &[u8]) -> Env {
    env_pairs(buf.split(|b| *b == 0))
}

/// `/proc/<pid>/stat` → (ppid, start time in clock ticks since boot). The
/// command name sits in parentheses and may hold spaces or `)`, so parse from
/// the last `)`.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(crate) fn proc_stat(buf: &[u8]) -> Option<(u32, u64)> {
    let close = buf.iter().rposition(|b| *b == b')')?;
    let text = std::str::from_utf8(buf.get(close + 1..)?).ok()?;
    let mut fields = text.split_ascii_whitespace();
    // fields after the name: state, ppid, ... (field 22 overall is index 19).
    let ppid = fields.nth(1)?.parse().ok()?;
    let start = fields.nth(17)?.parse().ok()?;
    Some((ppid, start))
}

/// macOS audit token: eight `u32`s; euid is word 1, pid word 5, pidversion 7.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn audit_token(buf: &[u8]) -> Option<(u32, u32, u32)> {
    let word = |i: usize| -> Option<u32> { Some(u32::from_ne_bytes(*buf.get(i * 4..)?.first_chunk::<4>()?)) };
    if buf.len() != 32 {
        return None;
    }
    Some((word(5)?, word(1)?, word(7)?))
}

/// Linux `struct ucred` → (pid, uid).
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
pub(crate) fn ucred(buf: &[u8]) -> Option<(u32, u32)> {
    let (pid, rest) = buf.split_first_chunk::<4>()?;
    let (uid, _) = rest.split_first_chunk::<4>()?;
    Some((u32::from_ne_bytes(*pid), u32::from_ne_bytes(*uid)))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    fn s(v: &str) -> OsString {
        OsString::from(v)
    }

    fn args2(argc: i32, tail: &[u8]) -> Vec<u8> {
        let mut b = argc.to_ne_bytes().to_vec();
        b.extend_from_slice(tail);
        b
    }

    #[test]
    fn procargs2_splits_argv_and_env() {
        let b = args2(2, b"/bin/x\0\0\0x\0-a\0A=1\0B=\0noeq\0\0");
        let (argv, env) = procargs2(&b).unwrap();
        assert_eq!(argv, vec![s("x"), s("-a")]);
        assert_eq!(env, vec![(s("A"), s("1")), (s("B"), s(""))]);
    }

    #[test]
    fn procargs2_tolerates_odd_input() {
        assert!(procargs2(&[]).is_none());
        assert!(procargs2(&[1, 0, 0]).is_none());
        assert!(procargs2(&args2(-1, b"/x\0")).is_none());
        assert!(procargs2(&args2(1, b"/no-nul")).is_none());
        // no args at all, then an argc larger than the data.
        assert_eq!(procargs2(&args2(0, b"/x\0")).unwrap(), (vec![], vec![]));
        let (argv, env) = procargs2(&args2(i32::MAX, b"/x\0\0a\0b")).unwrap();
        assert_eq!(argv, vec![s("a"), s("b")]);
        assert!(env.is_empty());
        // a path with nothing after it, and truncation at every length.
        assert_eq!(procargs2(&args2(1, b"/x")), None);
        let full = args2(2, b"/bin/x\0\0x\0y\0A=1\0\0");
        for n in 0..=full.len() {
            let _ = procargs2(full.get(..n).unwrap());
        }
    }

    #[test]
    fn cmdline_and_environ() {
        assert_eq!(cmdline(b"a\0b c\0"), vec![s("a"), s("b c")]);
        assert_eq!(cmdline(b"a\0\0b"), vec![s("a"), s(""), s("b")]);
        assert!(cmdline(b"").is_empty());
        assert!(cmdline(b"\0").is_empty());
        assert_eq!(environ(b"A=1\0B=x=y\0junk\0\0"), vec![(s("A"), s("1")), (s("B"), s("x=y"))]);
        assert!(environ(b"").is_empty());
    }

    #[test]
    fn proc_stat_handles_odd_names() {
        let line = b"42 (a b) c) S 7 42 42 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 987654 1 2 3";
        assert_eq!(proc_stat(line), Some((7, 987654)));
        assert_eq!(proc_stat(b"42 (x) S 7"), None);
        assert_eq!(proc_stat(b"no paren"), None);
        assert_eq!(proc_stat(b"1 (x) S notanumber 1"), None);
        assert_eq!(proc_stat(b"1 (x) \xff\xfe"), None);
        assert_eq!(proc_stat(b"1 (x)"), None);
        assert_eq!(proc_stat(b"1 (x) S 3 0 0 0"), None);
    }

    #[test]
    fn tokens() {
        let words: [u32; 8] = [0, 501, 20, 501, 20, 4242, 100000, 9];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
        assert_eq!(audit_token(&bytes), Some((4242, 501, 9)));
        assert_eq!(audit_token(&bytes[..31]), None);
        assert_eq!(audit_token(&[]), None);
        let mut cred = 7u32.to_ne_bytes().to_vec();
        cred.extend(1000u32.to_ne_bytes());
        cred.extend(1000u32.to_ne_bytes());
        assert_eq!(ucred(&cred), Some((7, 1000)));
        assert_eq!(ucred(&cred[..7]), None);
        assert_eq!(ucred(&[]), None);
    }
}
