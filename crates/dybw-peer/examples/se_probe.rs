//! The Secure Enclave prototype gate (P4.6 Task 3), run by hand on a Mac:
//!
//!     cargo run -p dybw-peer --example se_probe            # all steps; (c) and (d) show the Touch ID sheet
//!     cargo run -p dybw-peer --example se_probe -- --no-prompt   # (a) and (b) only
//!
//! (a) create a Secure Enclave key, (b) wrap a secret to it, (c) derive it back after Touch ID and compare,
//! (d) a Touch ID confirmation from a background thread. Each step prints PASS or FAIL; the exit code is the
//! number of failures. Nothing is stored: the key lives only as its handle in this process.

use dybw_peer::enclave::{self, Policy};

fn main() {
    let prompt = !std::env::args().any(|a| a == "--no-prompt");
    let mut failures = 0;
    let mut report = |step: &str, result: Result<String, String>| match result {
        Ok(note) => println!("PASS {step}: {note}"),
        Err(note) => {
            failures += 1;
            println!("FAIL {step}: {note}");
        }
    };
    println!("pid {} uid {} enclave available: {}", std::process::id(), uid(), enclave::available());

    let created = enclave::create(Policy::CurrentSet, false);
    report(
        "(a) create",
        created
            .as_ref()
            .map(|c| format!("handle {} bytes, public key {} bytes", c.handle.len(), c.public.len()))
            .map_err(|e| format!("{e} ({e:?})")),
    );
    let Ok(created) = created else { std::process::exit(failures) };

    let wrapped = enclave::wrap(&created.public);
    report(
        "(b) wrap",
        wrapped.as_ref().map(|_| "32-byte secret and an ephemeral key".to_owned()).map_err(|e| format!("{e} ({e:?})")),
    );
    let Ok(wrapped) = wrapped else { std::process::exit(failures) };

    if !prompt {
        println!("SKIP (c) derive and (d) confirm: --no-prompt");
        std::process::exit(failures);
    }
    let derived = enclave::derive(&created.handle, &wrapped.ephemeral, "test the dybw Secure Enclave probe");
    report(
        "(c) derive",
        match derived {
            Ok(secret) if *secret == *wrapped.secret => Ok("the secret matches".to_owned()),
            Ok(_) => Err("a different secret came back".to_owned()),
            Err(e) => Err(format!("{e} ({e:?})")),
        },
    );

    // The agent asks from a worker thread, never a main run loop: do the same.
    let answer = std::thread::spawn(|| enclave::confirm("confirm the dybw probe (touch to allow)")).join();
    report(
        "(d) confirm",
        match answer {
            Ok(enclave::Confirm::Allowed) => Ok("allowed".to_owned()),
            Ok(other) => Err(format!("{other:?}")),
            Err(_) => Err("the thread panicked".to_owned()),
        },
    );
    std::process::exit(failures);
}

/// The uid, through `id` (no libc call in an example).
fn uid() -> String {
    std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}
