//! Termination signals held off for a span of code: while a [`Deferred`] lives, SIGINT, SIGQUIT, SIGHUP and SIGTERM
//! are only noted, so the span can clean up (wipe a file) before the process acts on them. The old dispositions come
//! back when it is dropped. Dispositions are process-wide: one `Deferred` exists at a time (the others wait).

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, MutexGuard};

/// The signals held off.
pub const SIGNALS: [i32; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP, libc::SIGTERM];

/// The last signal noted since the current `Deferred` began; 0 for none.
static CAUGHT: AtomicI32 = AtomicI32::new(0);
/// Held by the live `Deferred`.
static ONE: Mutex<()> = Mutex::new(());

extern "C" fn note(sig: libc::c_int) {
    // Async-signal-safe: an atomic store only.
    CAUGHT.store(sig, Ordering::SeqCst);
}

/// The held-off span; dropping it restores what was there before.
pub struct Deferred {
    old: Vec<(i32, libc::sigaction)>,
    _one: MutexGuard<'static, ()>,
}

/// Set `sig`'s action to `new`; the previous one.
fn swap(sig: i32, new: &libc::sigaction) -> std::io::Result<libc::sigaction> {
    // SAFETY: an all-zero `sigaction` is a valid value of this plain C struct; it is only an out-parameter here.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are to live, properly aligned `sigaction` values for the duration of the call.
    if unsafe { libc::sigaction(sig, new, &mut old) } == 0 { Ok(old) } else { Err(std::io::Error::last_os_error()) }
}

impl Deferred {
    /// Note the signals from now on instead of acting on them. Waits while another `Deferred` lives.
    pub fn new() -> std::io::Result<Deferred> {
        let one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        CAUGHT.store(0, Ordering::SeqCst);
        // SAFETY: as in `swap`, all-zero is a valid `sigaction`; every field that matters is set below.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = note as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: `sa_mask` is a live `sigset_t` inside `action`.
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        // Restart interrupted calls (the wait for the editor goes on).
        action.sa_flags = libc::SA_RESTART;
        let mut held = Deferred { old: Vec::with_capacity(SIGNALS.len()), _one: one };
        for sig in SIGNALS {
            // A failure drops `held`, which puts back the ones already swapped.
            let old = swap(sig, &action)?;
            held.old.push((sig, old));
        }
        Ok(held)
    }

    /// The signal noted while this lived, if any (the last one).
    pub fn caught(&self) -> Option<i32> {
        Some(CAUGHT.load(Ordering::SeqCst)).filter(|s| *s != 0)
    }
}

impl Drop for Deferred {
    fn drop(&mut self) {
        for (sig, old) in self.old.drain(..).rev() {
            // Restoring what was there cannot fail for these signals; there is nothing else to do if it did.
            let _ = swap(sig, &old);
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn handler(sig: i32) -> libc::sighandler_t {
        // SAFETY: a null new action only reads the current one into `old`, a live out-parameter.
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        assert_eq!(unsafe { libc::sigaction(sig, std::ptr::null(), &mut old) }, 0);
        old.sa_sigaction
    }

    #[test]
    fn signals_are_noted_while_deferred_and_the_old_actions_come_back() {
        let before: Vec<_> = SIGNALS.iter().map(|s| handler(*s)).collect();
        let held = Deferred::new().unwrap();
        assert_eq!(held.caught(), None);
        for sig in SIGNALS {
            assert_eq!(handler(sig), note as extern "C" fn(libc::c_int) as libc::sighandler_t, "noted");
            // SAFETY: raising a signal whose handler is `note` only stores an atomic.
            assert_eq!(unsafe { libc::raise(sig) }, 0);
            assert_eq!(held.caught(), Some(sig), "the process is still here");
        }
        drop(held);
        let after: Vec<_> = SIGNALS.iter().map(|s| handler(*s)).collect();
        assert_eq!(after, before);
        assert_eq!(Deferred::new().unwrap().caught(), None, "a new span starts clean");
    }

    #[test]
    fn a_signal_that_cannot_be_caught_is_refused() {
        // SAFETY: as in `swap`.
        let action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert!(swap(libc::SIGKILL, &action).is_err());
    }
}
