//! The clipboard through the public API. A plain `cargo test` never writes the user's clipboard: the round trip on
//! the real one is `#[ignore]`d, run it with `cargo test -p dybw-peer --test clipboard_live -- --ignored`.

#![expect(clippy::unwrap_used, reason = "tests")]

use dybw_peer::clipboard::{Error, Token, Tool, clear_if_unchanged, copy};

/// Only paths that cannot write the clipboard.
#[test]
fn refusals_leave_the_clipboard_alone() {
    // A token of the other platform is refused before the clipboard is read.
    let foreign = if cfg!(target_os = "macos") { Token::Hash(Tool::Xsel, [0; 32]) } else { Token::Count(1) };
    assert!(matches!(clear_if_unchanged(&foreign), Err(Error::BadToken)));
    if cfg!(target_os = "macos") {
        // A count the pasteboard never had: read, not cleared; non-UTF-8 is refused before the pasteboard.
        assert!(!clear_if_unchanged(&Token::Count(isize::MIN)).unwrap());
        assert!(matches!(copy(&[0xff]), Err(Error::NotText)));
    } else if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("DISPLAY").is_none() {
        // No display (CI): nothing to write to.
        assert!(matches!(copy(b"x"), Err(Error::Unavailable)));
        assert!(matches!(clear_if_unchanged(&Token::Hash(Tool::Xsel, [0; 32])), Err(Error::Unavailable) | Ok(false)));
    }
}

/// Copy a marker, clear it; a copy replaced by another is left alone.
#[test]
#[ignore = "writes the real clipboard: run with --ignored"]
fn live_copy_is_cleared_only_while_unchanged() {
    let marker = b"dybw-clipboard-test-marker";
    let token = match copy(marker) {
        Err(Error::Unavailable | Error::Refused) => return eprintln!("no clipboard here: skipped"),
        other => other.unwrap().token,
    };
    assert!(clear_if_unchanged(&token).unwrap());
    // Review focus 5: something else was copied before the timer.
    let token = copy(marker).unwrap().token;
    let user = copy(b"dybw-clipboard-test-user").unwrap().token;
    assert!(!clear_if_unchanged(&token).unwrap());
    assert!(clear_if_unchanged(&user).unwrap());
}
