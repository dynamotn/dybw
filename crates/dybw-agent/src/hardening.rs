//! Process hardening at start: no core dump anywhere, no ptrace attach (Linux `PR_SET_DUMPABLE`, macOS
//! `PT_DENY_ATTACH` through `dybw-peer`, a no-op elsewhere). Running the agent under a debugger on macOS kills it.
//! A failure is reported and the agent keeps running.

use rustix::io::Errno;
use rustix::process::{Resource, Rlimit, setrlimit};

/// What could not be set, for the caller to report.
pub fn harden() -> Vec<String> {
    harden_with(dybw_peer::deny_attach)
}

/// `harden` with the attach denial injected. It goes first: a debugger gets the least time to attach.
fn harden_with(deny_attach: impl FnOnce() -> Result<(), dybw_peer::Error>) -> Vec<String> {
    let none = Rlimit { current: Some(0), maximum: Some(0) };
    let denied = deny_attach().err().map(|e| format!("PT_DENY_ATTACH: {e}"));
    [denied, failure("RLIMIT_CORE", setrlimit(Resource::Core, none)), dumpable()].into_iter().flatten().collect()
}

#[cfg(target_os = "linux")]
fn dumpable() -> Option<String> {
    use rustix::process::{DumpableBehavior, set_dumpable_behavior};
    failure("PR_SET_DUMPABLE", set_dumpable_behavior(DumpableBehavior::NotDumpable))
}

#[cfg(not(target_os = "linux"))]
fn dumpable() -> Option<String> {
    None
}

/// The text to print for what `harden` could not set: nothing when all went well.
pub fn report(failed: &[String]) -> String {
    failed.iter().map(|f| format!("dybw-agent: hardening: {f}\n")).collect()
}

/// What to report when the call `what` returned `result`; nothing on success.
fn failure(what: &str, result: Result<(), Errno>) -> Option<String> {
    result.err().map(|e| format!("{what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_call_is_named_and_a_successful_one_is_silent() {
        assert_eq!(failure("RLIMIT_CORE", Ok(())), None);
        assert_eq!(failure("RLIMIT_CORE", Err(Errno::PERM)), Some(format!("RLIMIT_CORE: {}", Errno::PERM)));
    }

    #[test]
    fn the_report_is_empty_on_success_and_one_line_per_failure() {
        assert_eq!(report(&[]), "");
        assert_eq!(report(&["a".into(), "b".into()]), "dybw-agent: hardening: a\ndybw-agent: hardening: b\n");
    }

    #[test]
    fn the_attach_denial_runs_first_and_a_failure_is_reported_not_fatal() {
        let called = std::cell::Cell::new(0);
        let failed = harden_with(|| {
            called.set(called.get() + 1);
            Err(dybw_peer::Error::Gone)
        });
        assert_eq!(called.get(), 1);
        assert!(failed.first().is_some_and(|f| f.starts_with("PT_DENY_ATTACH: ")), "{failed:?}");
        assert!(harden_with(|| Ok(())).is_empty());
    }

    #[test]
    fn hardening_lowers_the_core_limit() {
        // Lowering the limit of the test process is harmless and idempotent.
        assert!(harden().is_empty());
        let limit = rustix::process::getrlimit(Resource::Core);
        assert_eq!((limit.current, limit.maximum), (Some(0), Some(0)));
    }
}
