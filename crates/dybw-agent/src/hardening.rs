//! Process hardening at start: no core dump anywhere, no ptrace attach on Linux. macOS `PT_DENY_ATTACH` needs
//! `unsafe` and waits for P4.2. A failure is reported and the agent keeps running.

use rustix::io::Errno;
use rustix::process::{Resource, Rlimit, setrlimit};

/// What could not be set, for the caller to report.
pub fn harden() -> Vec<String> {
    let none = Rlimit { current: Some(0), maximum: Some(0) };
    [failure("RLIMIT_CORE", setrlimit(Resource::Core, none)), dumpable()].into_iter().flatten().collect()
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
    fn hardening_lowers_the_core_limit() {
        // Lowering the limit of the test process is harmless and idempotent.
        assert!(harden().is_empty());
        let limit = rustix::process::getrlimit(Resource::Core);
        assert_eq!((limit.current, limit.maximum), (Some(0), Some(0)));
    }
}
