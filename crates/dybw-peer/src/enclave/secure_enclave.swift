// The Secure Enclave and LocalAuthentication behind a C ABI, for `enclave/mac.rs`.
//
// Every function returns a status code (see STATUS_* below and `Error` in enclave.rs) and writes the raw error code
// it saw into `detail`. No Swift error crosses the ABI; every buffer is the caller's, of a size the caller states.
//
// The key wrap is ECIES in CryptoKit terms: an ephemeral P-256 key agrees with the Secure Enclave key (ECDH), and
// HKDF-SHA256 turns the shared secret into 32 bytes, with
//   salt = "" (none), info = "dybw-unlock:biometric-se" || ephemeral public (X9.63) || enclave public (X9.63).
// Those 32 bytes are the core's hardware KEK input, which adds its own HKDF and the authenticated EncString.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

private let STATUS_OK: Int32 = 0
private let STATUS_UNAVAILABLE: Int32 = 1
private let STATUS_CANCELLED: Int32 = 2
private let STATUS_FAILED: Int32 = 3
private let STATUS_LOCKED_OUT: Int32 = 4
private let STATUS_INVALIDATED: Int32 = 5
private let STATUS_OTHER: Int32 = 6

private let INFO = Data("dybw-unlock:biometric-se".utf8)
private let PUBLIC_LEN = 65
/// How long a Touch ID sheet may wait for a finger before it is withdrawn.
private let PROMPT_SECONDS = 60.0

/// Withdraw the sheet after the deadline: `invalidate` makes the pending call fail with `appCancel` (cancelled).
/// The caller still waits for that answer, so nothing returns while the shim may write into its buffers.
/// Cancel the returned item once the call is over.
private func deadline(_ context: LAContext) -> DispatchWorkItem {
    let timer = DispatchWorkItem { [weak context] in context?.invalidate() }
    DispatchQueue.global().asyncAfter(deadline: .now() + PROMPT_SECONDS, execute: timer)
    return timer
}

/// Map an error to a status. LAError covers the prompt; CryptoTokenKit (the Secure Enclave token) reports a key whose
/// biometry set changed as corrupted data or a missing object.
private func status(_ error: Error, _ detail: UnsafeMutablePointer<Int64>) -> Int32 {
    let ns = error as NSError
    detail.pointee = Int64(ns.code)
    if ns.domain == LAErrorDomain {
        switch ns.code {
        case -2, -4, -9: return STATUS_CANCELLED  // userCancel, systemCancel, appCancel
        case -1: return STATUS_FAILED  // authenticationFailed
        case -8: return STATUS_LOCKED_OUT  // biometryLockout
        // passcodeNotSet, biometryNotAvailable (lid closed, no sensor), biometryNotEnrolled, userFallback,
        // companionNotAvailable, biometryNotPaired, biometryDisconnected, notInteractive
        case -5, -6, -7, -3, -11, -12, -13, -1004: return STATUS_UNAVAILABLE
        default: return STATUS_OTHER
        }
    }
    if ns.domain == "CryptoTokenKit" {
        switch ns.code {
        case -4: return STATUS_CANCELLED  // canceledByUser
        case -5: return STATUS_FAILED  // authenticationFailed
        case -3, -6: return STATUS_INVALIDATED  // corruptedData, objectNotFound
        default: return STATUS_OTHER
        }
    }
    return STATUS_OTHER
}

private func copy(_ data: Data, _ out: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Bool {
    guard data.count <= cap else { return false }
    data.copyBytes(to: out, count: data.count)
    return true
}

private func secret(
    _ shared: SharedSecret, _ ephemeral: Data, _ enclave: Data, _ out: UnsafeMutablePointer<UInt8>
) {
    let key = shared.hkdfDerivedSymmetricKey(
        using: SHA256.self, salt: Data(), sharedInfo: INFO + ephemeral + enclave, outputByteCount: 32)
    key.withUnsafeBytes { raw in
        for (i, byte) in raw.enumerated() { out[i] = byte }
    }
}

@_cdecl("dybw_se_available")
public func seAvailable() -> Bool {
    SecureEnclave.isAvailable
}

/// A new key in the Secure Enclave, usable after Touch ID (`any`: any enrolled finger, else the set enrolled now;
/// `watch`: or an Apple Watch). Writes its `dataRepresentation` (`*data_len` bytes, at most `data_cap`) and its
/// public key (65 bytes, X9.63).
@_cdecl("dybw_se_create")
public func seCreate(
    _ any: Bool, _ watch: Bool, _ data: UnsafeMutablePointer<UInt8>, _ dataCap: Int,
    _ dataLen: UnsafeMutablePointer<Int>, _ publicOut: UnsafeMutablePointer<UInt8>,
    _ detail: UnsafeMutablePointer<Int64>
) -> Int32 {
    detail.pointee = 0
    guard SecureEnclave.isAvailable else { return STATUS_UNAVAILABLE }
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage, any ? .biometryAny : .biometryCurrentSet]
    if watch {
        if #available(macOS 15, *) { flags.formUnion([.or, .companion]) } else { flags.formUnion([.or, .watch]) }
    }
    var cfError: Unmanaged<CFError>?
    guard
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &cfError)
    else {
        return cfError.map { status($0.takeRetainedValue() as Error, detail) } ?? STATUS_OTHER
    }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let handle = key.dataRepresentation
        guard copy(handle, data, dataCap) else { return STATUS_OTHER }
        dataLen.pointee = handle.count
        _ = copy(key.publicKey.x963Representation, publicOut, PUBLIC_LEN)
        return STATUS_OK
    } catch {
        return status(error, detail)
    }
}

/// The wrapping side, no Touch ID: an ephemeral key agrees with `enclave` (65 bytes, X9.63). Writes the ephemeral
/// public key (65 bytes) and the 32-byte secret.
@_cdecl("dybw_se_wrap")
public func seWrap(
    _ enclave: UnsafePointer<UInt8>, _ ephemeralOut: UnsafeMutablePointer<UInt8>,
    _ out: UnsafeMutablePointer<UInt8>, _ detail: UnsafeMutablePointer<Int64>
) -> Int32 {
    detail.pointee = 0
    let enclaveData = Data(bytes: enclave, count: PUBLIC_LEN)
    do {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: enclaveData)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let ephemeralData = ephemeral.publicKey.x963Representation
        secret(try ephemeral.sharedSecretFromKeyAgreement(with: peer), ephemeralData, enclaveData, out)
        _ = copy(ephemeralData, ephemeralOut, PUBLIC_LEN)
        return STATUS_OK
    } catch {
        return status(error, detail)
    }
}

/// The unwrapping side: reload the key from its `dataRepresentation` and agree with `ephemeral` (65 bytes). The Touch
/// ID sheet shows `reason`; a fresh context each time, so no earlier match is reused. Writes the 32-byte secret.
@_cdecl("dybw_se_derive")
public func seDerive(
    _ data: UnsafePointer<UInt8>, _ dataLen: Int, _ ephemeral: UnsafePointer<UInt8>,
    _ reason: UnsafePointer<CChar>, _ out: UnsafeMutablePointer<UInt8>, _ detail: UnsafeMutablePointer<Int64>
) -> Int32 {
    detail.pointee = 0
    let text = String(cString: reason)
    guard !text.isEmpty else { return STATUS_OTHER }  // the sheet must say what it is for
    guard SecureEnclave.isAvailable else { return STATUS_UNAVAILABLE }
    let context = LAContext()
    context.localizedReason = text
    context.localizedFallbackTitle = ""
    let timer = deadline(context)
    defer { timer.cancel() }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: data, count: dataLen), authenticationContext: context)
        let ephemeralData = Data(bytes: ephemeral, count: PUBLIC_LEN)
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralData)
        secret(try key.sharedSecretFromKeyAgreement(with: peer), ephemeralData, key.publicKey.x963Representation, out)
        return STATUS_OK
    } catch {
        return status(error, detail)
    }
}

/// A yes or no by Touch ID, blocking the calling thread (never the main one: the reply comes on a private queue).
@_cdecl("dybw_la_confirm")
public func laConfirm(_ reason: UnsafePointer<CChar>, _ detail: UnsafeMutablePointer<Int64>) -> Int32 {
    detail.pointee = 0
    let text = String(cString: reason)
    guard !text.isEmpty else { return STATUS_OTHER }  // the sheet must say what it is for
    let context = LAContext()
    context.localizedFallbackTitle = ""
    var canError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &canError) else {
        return canError.map { status($0, detail) } ?? STATUS_UNAVAILABLE
    }
    let done = DispatchSemaphore(value: 0)
    var result = STATUS_OTHER
    let timer = deadline(context)
    defer { timer.cancel() }
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: text) {
        ok, error in
        result = ok ? STATUS_OK : error.map { status($0, detail) } ?? STATUS_OTHER
        done.signal()
    }
    done.wait()  // bounded by the deadline: invalidate answers the callback
    return result
}

/// Test hook: the unwrapping side with a software key (32-byte scalar), to check `dybw_se_wrap` without an enclave.
/// Writes the key's public half first, whatever `ephemeral` is.
@_cdecl("dybw_se_test_derive")
public func seTestDerive(
    _ scalar: UnsafePointer<UInt8>, _ ephemeral: UnsafePointer<UInt8>, _ publicOut: UnsafeMutablePointer<UInt8>,
    _ out: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: Data(bytes: scalar, count: 32)) else {
        return STATUS_OTHER
    }
    let publicData = key.publicKey.x963Representation
    _ = copy(publicData, publicOut, PUBLIC_LEN)
    let ephemeralData = Data(bytes: ephemeral, count: PUBLIC_LEN)
    guard let peer = try? P256.KeyAgreement.PublicKey(x963Representation: ephemeralData),
        let shared = try? key.sharedSecretFromKeyAgreement(with: peer)
    else { return STATUS_OTHER }
    secret(shared, ephemeralData, publicData, out)
    return STATUS_OK
}
