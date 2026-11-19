//! macOS: the general pasteboard through objc2's typed AppKit bindings (no `unsafe` needed). One pasteboard item
//! carries the text and the nspasteboard.org markers, written at once so no reader sees the text unmarked.

use objc2::rc::autoreleasepool;
use objc2::runtime::ProtocolObject;
use objc2_app_kit::{NSPasteboard, NSPasteboardItem};
use objc2_foundation::{NSArray, NSData, NSString};

use super::{Error, Token};

const TEXT: &str = "public.utf8-plain-text";
/// Clipboard managers do not show or store it.
const CONCEALED: &str = "org.nspasteboard.ConcealedType";
/// Clipboard managers do not keep it in their history.
const TRANSIENT: &str = "org.nspasteboard.TransientType";

pub(super) fn copy(value: &[u8]) -> Result<Token, Error> {
    copy_on(&NSPasteboard::generalPasteboard(), value)
}

pub(super) fn clear_if_unchanged(token: &Token) -> Result<bool, Error> {
    clear_on(&NSPasteboard::generalPasteboard(), token)
}

fn copy_on(pasteboard: &NSPasteboard, value: &[u8]) -> Result<Token, Error> {
    let text = std::str::from_utf8(value).map_err(|_| Error::NotText)?;
    autoreleasepool(|_| {
        let item = NSPasteboardItem::new();
        let empty = NSData::new();
        let marked = item.setString_forType(&NSString::from_str(text), &NSString::from_str(TEXT))
            && [CONCEALED, TRANSIENT].into_iter().all(|t| item.setData_forType(&empty, &NSString::from_str(t)));
        pasteboard.clearContents();
        let items = NSArray::from_retained_slice(&[ProtocolObject::from_retained(item)]);
        // The count after the write: a later copy by anyone bumps it.
        let written = marked && pasteboard.writeObjects(&items);
        written.then(|| Token::Count(pasteboard.changeCount())).ok_or(Error::Refused)
    })
}

/// Review focus 5: the change count moves with every write to the pasteboard, so another copy since ours is left
/// alone. (A copy landing between the check and `clearContents` is lost: the window is two calls wide.)
fn clear_on(pasteboard: &NSPasteboard, token: &Token) -> Result<bool, Error> {
    let Token::Count(count) = token else { return Err(Error::BadToken) };
    if pasteboard.changeCount() != *count {
        return Ok(false);
    }
    pasteboard.clearContents();
    Ok(true)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use objc2::rc::Retained;

    use super::*;

    /// A named pasteboard of the test's own (one per test: they run in parallel); the user's is not touched.
    fn own(name: &str) -> Retained<NSPasteboard> {
        NSPasteboard::pasteboardWithName(&NSString::from_str(&format!("org.dybw.test.{name}")))
    }

    fn text(pasteboard: &NSPasteboard) -> Option<String> {
        pasteboard.stringForType(&NSString::from_str(TEXT)).map(|s| s.to_string())
    }

    fn types(pasteboard: &NSPasteboard) -> Vec<String> {
        pasteboard.types().map(|t| t.to_vec().iter().map(|s| s.to_string()).collect()).unwrap_or_default()
    }

    /// Skipped where no pasteboard server answers (a sandbox, a session without a window server).
    fn copied(pasteboard: &NSPasteboard, value: &[u8]) -> Option<Token> {
        // Text values only: the one error left is `Refused`.
        copy_on(pasteboard, value).ok()
    }

    #[test]
    fn the_copy_is_readable_text_marked_concealed_and_transient() {
        let pb = own("marked");
        let Some(token) = copied(&pb, "pässword 🔑".as_bytes()) else { return eprintln!("no pasteboard: skipped") };
        assert_eq!(token, Token::Count(pb.changeCount()));
        assert_eq!(text(&pb).as_deref(), Some("pässword 🔑"));
        let types = types(&pb);
        assert!(types.iter().any(|t| t == CONCEALED) && types.iter().any(|t| t == TRANSIENT), "{types:?}");
        assert!(clear_on(&pb, &token).unwrap());
        assert_eq!(text(&pb), None);
    }

    /// Review focus 5.
    #[test]
    fn a_copy_replaced_by_the_user_is_not_cleared() {
        let pb = own("replaced");
        let Some(token) = copied(&pb, b"secret") else { return eprintln!("no pasteboard: skipped") };
        pb.clearContents();
        pb.setString_forType(&NSString::from_str("the user's"), &NSString::from_str(TEXT));
        assert!(!clear_on(&pb, &token).unwrap());
        assert_eq!(text(&pb).as_deref(), Some("the user's"));
    }

    #[test]
    fn non_text_and_foreign_tokens_are_refused_without_touching_the_pasteboard() {
        let pb = own("refused");
        let before = pb.changeCount();
        assert!(matches!(copy_on(&pb, &[0xff, 0xfe]), Err(Error::NotText)));
        assert!(matches!(clear_on(&pb, &Token::Hash(super::super::Tool::Xsel, [0; 32])), Err(Error::BadToken)));
        assert_eq!(pb.changeCount(), before);
    }
}
