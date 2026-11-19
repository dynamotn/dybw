//! The clipboard, for a secret: the copy is marked so clipboard managers skip it, and [`clear_if_unchanged`] clears
//! it only while it still holds that copy (the user may have copied something else since).
//!
//! macOS writes the general pasteboard with `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType`
//! (nspasteboard.org); its [`Token`] is the pasteboard's change count. Linux runs `wl-copy --sensitive` (which adds
//! `x-kde-passwordManagerHint: secret`), else `xclip` or `xsel`, which cannot add the hint; the tools come from
//! [`tools::PATH`] only, take the value on stdin, and the [`Token`] keeps a SHA-256 of the text, never the text.

#[cfg(target_os = "macos")]
mod mac;
#[cfg(any(target_os = "linux", test))]
mod tools;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No pasteboard (macOS without a window server), or no display or no clipboard tool (Linux).
    #[error("no clipboard here: no display, or no wl-copy, xclip or xsel in /usr/local/bin, /usr/bin or /bin")]
    Unavailable,
    /// macOS pastes text only, and the value is not UTF-8.
    #[error("the value is not text")]
    NotText,
    /// The pasteboard or the tool did not take the value, or did not clear.
    #[error("the clipboard did not take the change")]
    Refused,
    /// A token from another platform, or garbled.
    #[error("not a clipboard token of this system")]
    BadToken,
    #[error("cannot run the clipboard tool: {0}")]
    Io(#[from] std::io::Error),
}

/// A Linux clipboard tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    WlCopy,
    Xclip,
    Xsel,
}

impl Tool {
    const ALL: [Tool; 3] = [Tool::WlCopy, Tool::Xclip, Tool::Xsel];

    fn name(self) -> &'static str {
        match self {
            Tool::WlCopy => "wl-copy",
            Tool::Xclip => "xclip",
            Tool::Xsel => "xsel",
        }
    }
}

/// What a later [`clear_if_unchanged`] compares with: never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// macOS: the pasteboard's change count right after the copy.
    Count(isize),
    /// Linux: the tool that copied, and the SHA-256 of the text.
    Hash(Tool, [u8; 32]),
}

impl Token {
    /// One line of text, for the clearer process: `count:<n>` or `<tool>:<hex sha-256>`.
    pub fn encode(&self) -> String {
        match self {
            Token::Count(n) => format!("count:{n}"),
            Token::Hash(tool, hash) => hash.iter().fold(format!("{}:", tool.name()), |s, b| s + &format!("{b:02x}")),
        }
    }

    pub fn decode(text: &str) -> Option<Token> {
        let (kind, rest) = text.split_once(':')?;
        if kind == "count" {
            return rest.parse().ok().map(Token::Count);
        }
        let tool = Tool::ALL.into_iter().find(|t| t.name() == kind)?;
        let hex = rest.as_bytes();
        let mut hash = [0u8; 32];
        if hex.len() != 64 {
            return None;
        }
        for (byte, pair) in hash.iter_mut().zip(hex.chunks(2)) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(Token::Hash(tool, hash))
    }
}

/// Put `value` on the clipboard, marked as secret.
#[cfg(target_os = "macos")]
pub fn copy(value: &[u8]) -> Result<Token, Error> {
    mac::copy(value)
}

/// Clear the clipboard if it still holds the copy `token` stands for; `true` when it was cleared.
#[cfg(target_os = "macos")]
pub fn clear_if_unchanged(token: &Token) -> Result<bool, Error> {
    mac::clear_if_unchanged(token)
}

/// Put `value` on the clipboard, marked as secret.
#[cfg(target_os = "linux")]
pub fn copy(value: &[u8]) -> Result<Token, Error> {
    tools::copy(&tools::System, &|name| std::env::var_os(name), value)
}

/// Clear the clipboard if it still holds the copy `token` stands for; `true` when it was cleared.
#[cfg(target_os = "linux")]
pub fn clear_if_unchanged(token: &Token) -> Result<bool, Error> {
    tools::clear_if_unchanged(&tools::System, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_round_trip_and_garbage_is_refused() {
        for token in [Token::Count(-3), Token::Count(41), Token::Hash(Tool::Xsel, [0xa5; 32])] {
            assert_eq!(Token::decode(&token.encode()), Some(token));
        }
        let hex = "ab".repeat(32);
        assert_eq!(Token::decode(&format!("wl-copy:{hex}")), Some(Token::Hash(Tool::WlCopy, [0xab; 32])));
        let bad = ["", "count", "count:x", "pbcopy:00", "xclip:00", &format!("xclip:{}", "zz".repeat(32))];
        for text in bad {
            assert_eq!(Token::decode(text), None, "{text}");
        }
        assert_eq!(Token::decode(&format!("xclip:é{}", "0".repeat(62))), None);
    }
}
