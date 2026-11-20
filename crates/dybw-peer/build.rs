//! macOS: build `src/enclave/secure_enclave.swift` into a static library with `xcrun swiftc` and link it with the
//! frameworks and the Swift runtime it needs. Other systems build nothing (the enclave is a stub there).

use std::env;
use std::path::PathBuf;
use std::process::Command;

const SOURCE: &str = "src/enclave/secure_enclave.swift";

fn main() {
    println!("cargo:rerun-if-changed={SOURCE}");
    for var in ["MACOSX_DEPLOYMENT_TARGET", "DEVELOPER_DIR", "SDKROOT"] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    #[expect(clippy::expect_used, reason = "a build script with no OUT_DIR cannot do anything useful")]
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR for build scripts"));
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        _ => "x86_64",
    };
    // CryptoKit's Secure Enclave keys need 10.15; 11.0 is Rust's own floor on Apple silicon.
    let version = env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "11.0".to_owned());
    let library = out.join("libdybw_enclave.a");
    let status = Command::new("xcrun")
        .args(["swiftc", "-parse-as-library", "-emit-library", "-static", "-O", "-module-name", "DybwEnclave"])
        .args(["-target", &format!("{arch}-apple-macosx{version}")])
        .arg("-module-cache-path")
        .arg(out.join("module-cache"))
        .arg(SOURCE)
        .arg("-o")
        .arg(&library)
        .status();
    if !matches!(status, Ok(s) if s.success()) {
        panic!("xcrun swiftc failed to build {SOURCE}: {status:?}");
    }
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=dybw_enclave");
    for framework in ["CryptoKit", "LocalAuthentication", "Security", "Foundation"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
    // The Swift runtime ships with macOS (/usr/lib/swift); the toolchain holds the compatibility shims it autolinks.
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    let swiftc = Command::new("xcrun").args(["--find", "swiftc"]).output();
    if let Ok(found) = swiftc {
        let path = PathBuf::from(String::from_utf8_lossy(&found.stdout).trim());
        if let Some(bin) = path.parent() {
            println!("cargo:rustc-link-search=native={}", bin.join("../lib/swift/macosx").display());
        }
    }
}
