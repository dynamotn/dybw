//! SSH key items (type 5) for the SSH agent (P4.5, `docs/profiles.md` §8). [`keys`] lists the personal SSH keys of a
//! vault from what `item::ssh_public` decrypts (name and public key): never a private key. [`sign`] opens the one
//! item asked for, checks that its private key is the key the client named and the item lists, signs, and wipes the
//! key before it returns. Nothing here prompts: the caller confirms before it calls [`sign`]. Organization items are
//! left out in P4.5.

use std::collections::BTreeMap;

use dybw_core::crypto::SymmetricKey;
use dybw_core::vault::item::{self, Data};
use serde_json::Value;
use signature::Signer;
use ssh_key::encoding::Encode;
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};

use crate::read;

/// The agent protocol's sign flag for `rsa-sha2-256` (draft-miller-ssh-agent).
pub const RSA_SHA2_256: u32 = 0x02;
/// The agent protocol's sign flag for `rsa-sha2-512`.
pub const RSA_SHA2_512: u32 = 0x04;

/// One key the agent can offer: what a listing and a confirmation show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    /// The item's id.
    pub id: String,
    /// The item's name.
    pub name: String,
    /// `SHA256:…`, computed from the public key rather than taken from the item.
    pub fingerprint: String,
    /// The public key in the SSH wire format, as the agent protocol names a key.
    pub blob: Vec<u8>,
}

/// Why a signature was not made. The agent protocol answers every one with its failure reply.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SshError {
    #[error("no personal SSH key item with this id")]
    NotFound,
    #[error("the SSH key item cannot be read")]
    Unreadable,
    #[error("the SSH key item holds no usable OpenSSH private or public key")]
    BadKey,
    #[error("the private key is not the key that was asked for")]
    KeyMismatch,
    #[error("RSA signatures with SHA-1 (ssh-rsa) are refused")]
    Sha1Refused,
    #[error("the key cannot sign")]
    Sign,
}

/// The personal SSH key items of `sync` that are not in the trash, by any type the agent can sign with
/// (Ed25519, RSA, ECDSA P-256/384/521). An item that does not read or holds no such public key is left out.
pub fn keys(sync: &Value, user: &SymmetricKey) -> Vec<Key> {
    let read = |c: &Value| {
        let public = item::ssh_public(c, user, &BTreeMap::new()).ok()?;
        let key = PublicKey::from_openssh(public.public_key.as_deref()?).ok()?;
        matches!(key.algorithm(), Algorithm::Ed25519 | Algorithm::Rsa { .. } | Algorithm::Ecdsa { .. }).then_some(())?;
        Some(Key {
            id: public.summary.id,
            name: public.summary.name.to_string(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            blob: key.to_bytes().ok()?,
        })
    };
    let all: Vec<&Value> = personal_ssh(sync).collect();
    let keys: Vec<Key> = all.iter().copied().filter_map(read).collect();
    if keys.len() < all.len() {
        tracing::info!(skipped = all.len() - keys.len(), "SSH key items that cannot be used are left out");
    }
    keys
}

/// The listed key the agent protocol names by its wire-format public key.
pub fn find<'a>(keys: &'a [Key], blob: &[u8]) -> Option<&'a Key> {
    keys.iter().find(|k| k.blob == blob)
}

/// Sign `data` with the private key of item `id`, which must be `blob` (the key the client asked for) and the item's
/// own public key. RSA signs with SHA-256 or SHA-512 as `flags` ask ([`RSA_SHA2_256`] first, as OpenSSH), never SHA-1;
/// other keys ignore `flags`. The reply is the SSH signature blob (`string` algorithm, `string` signature). Only
/// this one item is opened, and its private key is wiped before this returns.
pub fn sign(
    sync: &Value,
    user: &SymmetricKey,
    id: &str,
    blob: &[u8],
    data: &[u8],
    flags: u32,
) -> Result<Vec<u8>, SshError> {
    let cipher =
        personal_ssh(sync).find(|c| c.get("id").and_then(Value::as_str) == Some(id)).ok_or(SshError::NotFound)?;
    let item = read::open_with(cipher, user, &BTreeMap::new()).map_err(|_| SshError::Unreadable)?;
    let Data::SshKey(k) = &item.data else { return Err(SshError::Unreadable) };
    let pem = k.private_key.as_deref().ok_or(SshError::BadKey)?;
    let private = PrivateKey::from_openssh(pem).map_err(|_| SshError::BadKey)?;
    let stored =
        PublicKey::from_openssh(k.public_key.as_deref().ok_or(SshError::BadKey)?).map_err(|_| SshError::BadKey)?;
    drop(item);
    if private.public_key().key_data() != stored.key_data() || stored.to_bytes().ok().as_deref() != Some(blob) {
        return Err(SshError::KeyMismatch);
    }
    let signature = match private.key_data() {
        KeypairData::Rsa(rsa) => {
            let hash = match flags {
                f if f & RSA_SHA2_256 != 0 => HashAlg::Sha256,
                f if f & RSA_SHA2_512 != 0 => HashAlg::Sha512,
                _ => return Err(SshError::Sha1Refused),
            };
            (rsa, Some(hash)).try_sign(data)
        }
        other => other.try_sign(data),
    };
    signature.map_err(|_| SshError::Sign)?.encode_vec().map_err(|_| SshError::Sign)
}

/// The personal SSH key items not in the trash; organization items are left out in P4.5.
fn personal_ssh(sync: &Value) -> impl Iterator<Item = &Value> {
    read::ciphers(sync)
        .filter(|c| c.get("type").and_then(Value::as_u64) == Some(5))
        .filter(|c| c.get("organizationId").is_none_or(Value::is_null))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use std::convert::Infallible;

    use dybw_core::crypto::SymmetricKey;
    use dybw_native::ports::random::OsRandom;
    use serde_json::{Value, json};
    use signature::Verifier;
    use ssh_key::encoding::Decode;
    use ssh_key::private::{Ed25519Keypair, KeypairData, RsaKeypair, SkEd25519};
    use ssh_key::rand_core::{TryCryptoRng, TryRng};
    use ssh_key::{Algorithm, EcdsaCurve, LineEnding, PrivateKey, Signature, public};

    use super::{Key, RSA_SHA2_256, RSA_SHA2_512, SshError, find, keys, sign};
    use crate::read::OPENS;

    /// The OS random source, as the RNG ssh-key generates keys with.
    struct Os;

    impl TryRng for Os {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            let mut b = [0; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }
        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            let mut b = [0; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            dybw_core::ports::Random::fill(&OsRandom, dst).unwrap();
            Ok(())
        }
    }

    impl TryCryptoRng for Os {}

    fn generate(algorithm: Algorithm) -> PrivateKey {
        match algorithm {
            // ssh-key's default is 4096 bits: slow to generate, and 2048 says the same.
            Algorithm::Rsa { .. } => {
                PrivateKey::new(KeypairData::from(RsaKeypair::random(&mut Os, 2048).unwrap()), "").unwrap()
            }
            other => PrivateKey::random(&mut Os, other).unwrap(),
        }
    }

    fn ecdsa(curve: EcdsaCurve) -> Algorithm {
        Algorithm::Ecdsa { curve }
    }

    struct World {
        user: SymmetricKey,
        sync: Value,
    }

    impl World {
        fn new() -> World {
            World { user: SymmetricKey::generate(&OsRandom).unwrap(), sync: json!({ "ciphers": [] }) }
        }

        fn enc(&self, text: &str) -> Value {
            json!(self.user.encrypt_str(text, &OsRandom).unwrap())
        }

        /// A personal SSH key item `id` holding `private` and, as its public key, `public` (an OpenSSH line).
        fn item(&mut self, id: &str, private: Option<&str>, public: Option<&str>) -> &mut Value {
            let ssh = json!({
                "privateKey": private.map(|p| self.enc(p)),
                "publicKey": public.map(|p| self.enc(p)),
                "keyFingerprint": self.enc("SHA256:whatever the item says"),
            });
            let cipher = json!({ "id": id, "type": 5, "name": self.enc(&format!("key {id}")), "sshKey": ssh });
            let all = self.sync["ciphers"].as_array_mut().unwrap();
            all.push(cipher);
            all.last_mut().unwrap()
        }

        /// A personal SSH key item `id` of `key`, as Bitwarden stores one.
        fn key(&mut self, id: &str, key: &PrivateKey) -> &mut Value {
            let private = key.to_openssh(LineEnding::LF).unwrap();
            let public = key.public_key().to_openssh().unwrap();
            self.item(id, Some(&private), Some(&public))
        }

        fn keys(&self) -> Vec<Key> {
            keys(&self.sync, &self.user)
        }

        fn sign(&self, id: &str, blob: &[u8], flags: u32) -> Result<Vec<u8>, SshError> {
            sign(&self.sync, &self.user, id, blob, b"data to sign", flags)
        }
    }

    fn blob(key: &PrivateKey) -> Vec<u8> {
        key.public_key().to_bytes().unwrap()
    }

    fn opens() -> usize {
        OPENS.with(std::cell::Cell::get)
    }

    /// The signature blob decoded, checked against `key` over the signed data.
    fn verified(key: &PrivateKey, reply: &[u8]) -> Signature {
        let signature = Signature::decode(&mut &reply[..]).unwrap();
        Verifier::verify(key.public_key(), b"data to sign", &signature).unwrap();
        signature
    }

    #[test]
    fn keys_lists_every_signing_type_without_opening_an_item() {
        let mut world = World::new();
        let types = [
            Algorithm::Ed25519,
            Algorithm::Rsa { hash: None },
            ecdsa(EcdsaCurve::NistP256),
            ecdsa(EcdsaCurve::NistP384),
            ecdsa(EcdsaCurve::NistP521),
        ];
        let generated: Vec<PrivateKey> = types.into_iter().map(generate).collect();
        for (n, key) in generated.iter().enumerate() {
            world.key(&format!("k{n}"), key);
        }
        let before = opens();
        let listed = world.keys();
        assert_eq!(opens(), before, "listing opens nothing");
        let want: Vec<Key> = generated
            .iter()
            .enumerate()
            .map(|(n, key)| Key {
                id: format!("k{n}"),
                name: format!("key k{n}"),
                fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                blob: blob(key),
            })
            .collect();
        assert_eq!(listed, want);
        assert!(listed[0].fingerprint.starts_with("SHA256:"));
        assert_eq!(find(&listed, &blob(&generated[2])).unwrap().id, "k2");
        assert_eq!(find(&listed, b"no such key"), None);
    }

    #[test]
    fn keys_leaves_out_what_the_agent_cannot_offer() {
        let mut world = World::new();
        let key = generate(Algorithm::Ed25519);
        world.key("ok", &key);
        world.key("org", &key)["organizationId"] = json!("o1");
        world.key("trashed", &key)["deletedDate"] = json!("2026-01-01T00:00:00Z");
        world.key("login", &key)["type"] = json!(1);
        world.key("unreadable", &key)["name"] = json!("2.not|a|cipher");
        world.item("no public key", None, None);
        world.item("bad public key", None, Some("ssh-ed25519 not-base64"));
        let sk = security_key(&key);
        world.key("security key", &sk);
        assert_eq!(world.keys().iter().map(|k| k.id.as_str()).collect::<Vec<_>>(), ["ok"]);
    }

    #[test]
    fn sign_makes_a_signature_the_public_key_verifies_for_every_type() {
        let mut world = World::new();
        for (n, curve) in [EcdsaCurve::NistP256, EcdsaCurve::NistP384, EcdsaCurve::NistP521].into_iter().enumerate() {
            let key = generate(ecdsa(curve));
            world.key(&format!("e{n}"), &key);
            let signature = verified(&key, &world.sign(&format!("e{n}"), &blob(&key), 0).unwrap());
            assert_eq!(signature.algorithm(), ecdsa(curve));
        }
        let key = generate(Algorithm::Ed25519);
        world.key("ed", &key);
        let before = opens();
        let reply = world.sign("ed", &blob(&key), RSA_SHA2_512).unwrap();
        assert_eq!(opens(), before + 1, "only the one item is opened");
        assert_eq!(verified(&key, &reply).algorithm(), Algorithm::Ed25519, "flags are for RSA only");
    }

    #[test]
    fn rsa_signs_with_the_sha2_the_flags_ask_for_and_never_sha1() {
        let mut world = World::new();
        let key = generate(Algorithm::Rsa { hash: None });
        world.key("rsa", &key);
        let algorithm = |flags| verified(&key, &world.sign("rsa", &blob(&key), flags).unwrap()).algorithm();
        let rsa = |hash| Algorithm::Rsa { hash: Some(hash) };
        assert_eq!(algorithm(RSA_SHA2_256), rsa(ssh_key::HashAlg::Sha256));
        assert_eq!(algorithm(RSA_SHA2_512), rsa(ssh_key::HashAlg::Sha512));
        assert_eq!(algorithm(RSA_SHA2_256 | RSA_SHA2_512), rsa(ssh_key::HashAlg::Sha256), "as OpenSSH");
        assert_eq!(world.sign("rsa", &blob(&key), 0), Err(SshError::Sha1Refused));
        assert_eq!(world.sign("rsa", &blob(&key), 0x01 | 0x08), Err(SshError::Sha1Refused));
    }

    #[test]
    fn sign_refuses_an_item_that_is_not_a_personal_ssh_key() {
        let mut world = World::new();
        let key = generate(Algorithm::Ed25519);
        world.key("org", &key)["organizationId"] = json!("o1");
        world.key("trashed", &key)["deletedDate"] = json!("2026-01-01T00:00:00Z");
        world.key("login", &key)["type"] = json!(1);
        let before = opens();
        for id in ["org", "trashed", "login", "missing"] {
            assert_eq!(world.sign(id, &blob(&key), 0), Err(SshError::NotFound), "{id}");
        }
        assert_eq!(opens(), before, "nothing opened");
    }

    #[test]
    fn sign_refuses_an_item_without_a_usable_key() {
        let mut world = World::new();
        let key = generate(Algorithm::Ed25519);
        let public = key.public_key().to_openssh().unwrap();
        let private = key.to_openssh(LineEnding::LF).unwrap();
        world.key("unreadable", &key)["sshKey"]["privateKey"] = json!("2.not|a|cipher");
        world.item("no private key", None, Some(&public));
        world.item("bad private key", Some("-----BEGIN OPENSSH PRIVATE KEY-----"), Some(&public));
        world.item("no public key", Some(&private), None);
        world.item("bad public key", Some(&private), Some("ssh-ed25519 not-base64"));
        assert_eq!(world.sign("unreadable", &blob(&key), 0), Err(SshError::Unreadable));
        for id in ["no private key", "bad private key", "no public key", "bad public key"] {
            assert_eq!(world.sign(id, &blob(&key), 0), Err(SshError::BadKey), "{id}");
        }
    }

    #[test]
    fn sign_uses_only_the_key_that_was_asked_for_and_listed() {
        let mut world = World::new();
        let (key, other) = (generate(Algorithm::Ed25519), generate(Algorithm::Ed25519));
        let private = key.to_openssh(LineEnding::LF).unwrap();
        world.item("swapped", Some(&private), Some(&other.public_key().to_openssh().unwrap()));
        world.key("k", &key);
        // The item lists `other`, its private key is `key`: neither blob signs.
        assert_eq!(world.sign("swapped", &blob(&key), 0), Err(SshError::KeyMismatch));
        assert_eq!(world.sign("swapped", &blob(&other), 0), Err(SshError::KeyMismatch));
        // The client asked for another key than this item's.
        assert_eq!(world.sign("k", &blob(&other), 0), Err(SshError::KeyMismatch));
    }

    #[test]
    fn a_key_ssh_key_cannot_sign_with_is_refused() {
        let mut world = World::new();
        let sk = security_key(&generate(Algorithm::Ed25519));
        world.key("sk", &sk);
        assert_eq!(world.sign("sk", &blob(&sk), 0), Err(SshError::Sign));
    }

    #[test]
    fn errors_say_what_went_wrong_and_nothing_more() {
        assert_eq!(SshError::Sha1Refused.to_string(), "RSA signatures with SHA-1 (ssh-rsa) are refused");
        assert_eq!(SshError::KeyMismatch.to_string(), "the private key is not the key that was asked for");
    }

    #[test]
    fn the_test_random_source_gives_every_width() {
        assert_ne!((Os.try_next_u32().unwrap(), Os.try_next_u64().unwrap()), (0, 0));
    }

    /// A FIDO security key (`sk-ssh-ed25519`) on `key`'s public half: the agent has no way to sign with one.
    fn security_key(key: &PrivateKey) -> PrivateKey {
        let KeypairData::Ed25519(Ed25519Keypair { public, .. }) = key.key_data() else { panic!() };
        let sk = SkEd25519::new(public::SkEd25519::new(*public, "ssh:"), 0, vec![1]).unwrap();
        PrivateKey::new(KeypairData::from(sk), "").unwrap()
    }
}
