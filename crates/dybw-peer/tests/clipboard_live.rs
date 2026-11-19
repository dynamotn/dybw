//! The live clipboard through the public API: copy a marker, clear it; a copy the user replaced is left alone.
//! It writes the real clipboard (macOS: the general pasteboard). Skipped where there is none (CI has no display).

#![expect(clippy::unwrap_used, reason = "tests")]

use dybw_peer::clipboard::{Error, Token, Tool, clear_if_unchanged, copy};

#[test]
fn live_copy_is_cleared_only_while_unchanged() {
    // A token of the other platform is refused before the clipboard is read.
    let foreign = if cfg!(target_os = "macos") { Token::Hash(Tool::Xsel, [0; 32]) } else { Token::Count(1) };
    assert!(matches!(clear_if_unchanged(&foreign), Err(Error::BadToken)));
    let marker = b"dybw-clipboard-test-marker";
    let token = match copy(marker) {
        Err(Error::Unavailable | Error::Refused) => return eprintln!("no clipboard here: skipped"),
        other => other.unwrap(),
    };
    assert!(clear_if_unchanged(&token).unwrap());
    // Review focus 5: something else was copied before the timer.
    let token = copy(marker).unwrap();
    let user = copy(b"dybw-clipboard-test-user").unwrap();
    assert!(!clear_if_unchanged(&token).unwrap());
    assert!(clear_if_unchanged(&user).unwrap());
}
