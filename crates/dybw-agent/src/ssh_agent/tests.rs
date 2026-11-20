//! The SSH agent protocol, against the scripted host and a real Unix socket pair (a Rust client), and once on the
//! real `ssh-agent.sock` served by `serve`.
#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dybw_proto::{Op, Target};
use serde_json::{Value, json};
use signature::{Signer, Verifier};
use ssh_key::encoding::{Decode, Encode};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{Algorithm, LineEnding, PrivateKey, Signature};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream as Tokio;

use super::*;
use crate::agent::testing::{Rig, process, rig};
use crate::ssh::tests::generate;
use crate::write_tests::{REV, enc};

fn ed25519(seed: u8) -> PrivateKey {
    PrivateKey::new(KeypairData::from(Ed25519Keypair::from_seed(&[seed; 32])), "").unwrap()
}

fn blob(key: &PrivateKey) -> Vec<u8> {
    key.public_key().to_bytes().unwrap()
}

/// A personal SSH key item of `key`, as Bitwarden stores one, under the vector account's user key.
fn ssh_item(id: &str, name: &str, key: &PrivateKey) -> Value {
    json!({
        "id": id, "type": 5, "name": enc(name), "notes": null, "folderId": null, "organizationId": null,
        "reprompt": 0, "revisionDate": REV, "fields": [], "passwordHistory": [],
        "sshKey": {
            "privateKey": enc(&key.to_openssh(LineEnding::LF).unwrap()),
            "publicKey": enc(&key.public_key().to_openssh().unwrap()),
            "keyFingerprint": enc("SHA256:whatever"),
        },
    })
}

/// Says yes or no as told, records every context it was asked about, and can lock `work` while it is asked.
#[derive(Default)]
struct Double {
    refuse: AtomicBool,
    asked: Mutex<Vec<SignContext>>,
    lock_on_ask: Mutex<Option<Arc<Agent>>>,
    /// Run once while asked.
    on_ask: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Double {
    fn asked(&self) -> Vec<SignContext> {
        self.asked.lock().unwrap().clone()
    }
}

impl Authorize for Double {
    fn authorize_sign<'a>(
        &'a self,
        _: &'a Resolved,
        _: &'a Key,
        ctx: &'a SignContext,
    ) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>> {
        self.asked.lock().unwrap().push(ctx.clone());
        if let Some(f) = self.on_ask.lock().unwrap().take() {
            f();
        }
        let lock = self.lock_on_ask.lock().unwrap().take();
        Box::pin(async move {
            if let Some(agent) = lock {
                agent.dispatch(Op::Lock { target: Target::Profile("work".into()) }).await;
            }
            if self.refuse.load(Ordering::SeqCst) { Decision::Refuse } else { Decision::Allow }
        })
    }
}

struct World {
    _dir: tempfile::TempDir,
    rig: Rig,
    ssh: Arc<SshAgent>,
    auth: Arc<Double>,
    /// `alpha` (item sa) and `beta` (item sb), on `work`.
    alpha: PrivateKey,
    beta: PrivateKey,
}

/// `work` unlocked with the fixture vault plus `alpha` and `beta` and `extra` items; the SSH agent offers `work`,
/// then `home` (locked), and this test process is a peer the fake process table knows.
async fn world(extra: Vec<Value>) -> World {
    let (alpha, beta) = (ed25519(1), ed25519(2));
    let mut items = vec![ssh_item("sa", "alpha", &alpha), ssh_item("sb", "beta", &beta)];
    items.extend(extra);
    let (dir, rig) = crate::write_tests::setup(|v| {
        v["ciphers"].as_array_mut().unwrap().extend(items);
    })
    .await;
    trust_self(&rig);
    let auth = Arc::new(Double::default());
    let ssh = Arc::new(SshAgent::new(rig.agent.clone(), vec!["work".into(), "home".into()], auth.clone()));
    World { _dir: dir, rig, ssh, auth, alpha, beta }
}

/// Put this very process in the fake process table, as the peer of every test connection.
fn trust_self(rig: &Rig) -> u32 {
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let me = dybw_peer::peer_of_stream(&a).unwrap();
    rig.tree.add(me.pid, dybw_peer::Process { image: me.token.image.clone(), ..process(me.token.start) });
    me.pid
}

struct Client {
    stream: Tokio,
    task: tokio::task::JoinHandle<()>,
}

impl Client {
    async fn send(&mut self, message: &[u8]) {
        let mut frame = Vec::new();
        put_string(&mut frame, message);
        self.stream.write_all(&frame).await.unwrap();
    }

    async fn recv(&mut self) -> Option<Vec<u8>> {
        let mut len = [0; 4];
        self.stream.read_exact(&mut len).await.ok()?;
        let mut out = vec![0; u32::from_be_bytes(len) as usize];
        self.stream.read_exact(&mut out).await.ok()?;
        Some(out)
    }

    async fn ask(&mut self, message: &[u8]) -> Vec<u8> {
        self.send(message).await;
        self.recv().await.unwrap()
    }

    /// The agent closed the connection: no reply, and the handler has ended.
    async fn closed(mut self) -> bool {
        // Bounded: a connection the agent keeps open would otherwise wait out the idle timeout.
        let none = tokio::time::timeout(Duration::from_secs(5), self.recv()).await.is_ok_and(|r| r.is_none());
        tokio::time::timeout(Duration::from_secs(5), self.task).await.is_ok() && none
    }

    async fn keys(&mut self) -> Vec<(Vec<u8>, String)> {
        identities(&self.ask(&[REQUEST_IDENTITIES]).await)
    }

    async fn sign(&mut self, key: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        self.ask(&sign_request(key, data, flags)).await
    }
}

async fn connect(ssh: &Arc<SshAgent>) -> Client {
    let (stream, server) = Tokio::pair().unwrap();
    Client { stream, task: tokio::spawn(handle(ssh.clone(), server)) }
}

fn message(kind: u8, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![kind];
    for f in fields {
        put_string(&mut out, f);
    }
    out
}

fn sign_request(key: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut out = message(SIGN_REQUEST, &[key, data]);
    out.extend_from_slice(&flags.to_be_bytes());
    out
}

fn identities(reply: &[u8]) -> Vec<(Vec<u8>, String)> {
    let mut r = Reader(reply);
    assert_eq!(r.u8(), Some(IDENTITIES_ANSWER));
    let n = r.u32().unwrap();
    let keys = (0..n).map(|_| (r.string().unwrap().to_vec(), String::from_utf8(r.string().unwrap().to_vec()).unwrap()));
    let keys = keys.collect();
    assert!(r.0.is_empty());
    keys
}

/// The signature of a SIGN_RESPONSE, checked against `key` over `data`.
fn verified(key: &PrivateKey, data: &[u8], reply: &[u8]) -> Signature {
    let mut r = Reader(reply);
    assert_eq!(r.u8(), Some(SIGN_RESPONSE), "{reply:?}");
    let signature = Signature::decode(&mut r.string().unwrap()).unwrap();
    Verifier::verify(key.public_key(), data, &signature).unwrap();
    signature
}

const FAIL: [u8; 1] = [FAILURE];
const OK: [u8; 1] = [SUCCESS];

/// `session-bind@openssh.com` for `host` over `session_id`, signed by `signer`.
fn bind_request(host: &PrivateKey, signer: &PrivateKey, session_id: &[u8], forwarded: bool) -> Vec<u8> {
    bind_signed(host, &Signer::<Signature>::try_sign(signer, session_id).unwrap(), session_id, forwarded)
}

/// `session-bind@openssh.com` for `host` over `session_id` with `signature`.
fn bind_signed(host: &PrivateKey, signature: &Signature, session_id: &[u8], forwarded: bool) -> Vec<u8> {
    let signature = signature.encode_vec().unwrap();
    let mut out = message(EXTENSION, &[SESSION_BIND, &blob(host), session_id, &signature]);
    out.push(u8::from(forwarded));
    out
}

/// The fields of a userauth request, to build good and bad ones.
#[derive(Clone)]
struct Userauth<'a> {
    session_id: &'a [u8],
    kind: u8,
    user: &'a [u8],
    service: &'a [u8],
    method: &'a [u8],
    follows: u8,
    algorithm: &'a [u8],
    key: Vec<u8>,
    host: Option<Vec<u8>>,
    tail: &'a [u8],
}

impl<'a> Userauth<'a> {
    fn new(key: &PrivateKey) -> Userauth<'a> {
        Userauth {
            session_id: b"sid-1",
            kind: USERAUTH_REQUEST,
            user: b"git",
            service: b"ssh-connection",
            method: b"publickey",
            follows: 1,
            algorithm: b"ssh-ed25519",
            key: blob(key),
            host: None,
            tail: b"",
        }
    }

    fn hostbound(key: &PrivateKey, host: &PrivateKey) -> Userauth<'a> {
        Userauth { method: b"publickey-hostbound-v00@openssh.com", host: Some(blob(host)), ..Userauth::new(key) }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, self.session_id);
        out.push(self.kind);
        for f in [self.user, self.service, self.method] {
            put_string(&mut out, f);
        }
        out.push(self.follows);
        put_string(&mut out, self.algorithm);
        put_string(&mut out, &self.key);
        if let Some(host) = &self.host {
            put_string(&mut out, host);
        }
        out.extend_from_slice(self.tail);
        out
    }
}

#[test]
fn the_reader_refuses_what_is_cut_short() {
    let mut r = Reader(&[0, 0, 0, 3, b'a', b'b']);
    assert_eq!(r.string(), None, "three bytes announced, two there");
    assert_eq!(Reader(&[0, 0, 1]).u32(), None);
    assert_eq!(Reader(&[]).u8(), None);
    let mut r = Reader(&[0, 0, 0, 2, b'a', b'b', 7]);
    assert_eq!((r.string(), r.u8(), r.u8()), (Some(&b"ab"[..]), Some(7), None));
}

#[test]
fn a_userauth_request_is_told_from_other_data_as_openssh_does() {
    let (key, host) = (ed25519(1), ed25519(9));
    let good = Userauth::new(&key);
    let login = Login { user: "git".into(), session_id: b"sid-1", host_key: None };
    assert_eq!(userauth(&good.bytes(), &blob(&key)), Some(login));
    let hostbound = Userauth::hostbound(&key, &host).bytes();
    let parsed = userauth(&hostbound, &blob(&key)).unwrap();
    assert_eq!(parsed.host_key, Some(&blob(&host)[..]));
    let rsa = Userauth { algorithm: b"rsa-sha2-512", ..good.clone() };
    assert!(userauth(&rsa.bytes(), &blob(&key)).is_some(), "any known algorithm name");
    let other = ed25519(2);
    let bad = [
        ("empty session id", Userauth { session_id: b"", ..good.clone() }),
        ("not a userauth request", Userauth { kind: 51, ..good.clone() }),
        ("user not UTF-8", Userauth { user: &[0xff], ..good.clone() }),
        ("another service", Userauth { service: b"ssh-userauth", ..good.clone() }),
        ("another method", Userauth { method: b"password", ..good.clone() }),
        ("no signature follows", Userauth { follows: 0, ..good.clone() }),
        ("unknown algorithm", Userauth { algorithm: b"ssh-nope", ..good.clone() }),
        ("algorithm not UTF-8", Userauth { algorithm: &[0xff], ..good.clone() }),
        ("another key", Userauth { key: blob(&other), ..good.clone() }),
        ("trailing data", Userauth { tail: b"x", ..good.clone() }),
        ("hostbound without its host key", Userauth { method: b"publickey-hostbound-v00@openssh.com", ..good }),
    ];
    for (name, case) in bad {
        assert_eq!(userauth(&case.bytes(), &blob(&key)), None, "{name}");
    }
    assert_eq!(userauth(b"arbitrary data", &blob(&key)), None);
    let mut cut = Userauth::new(&key).bytes();
    cut.truncate(cut.len() - 3);
    assert_eq!(userauth(&cut, &blob(&key)), None, "cut short");
}

fn bind(conn: &mut Conn, request: &[u8]) -> Option<bool> {
    let mut r = Reader(request);
    assert_eq!((r.u8(), r.string()), (Some(EXTENSION), Some(SESSION_BIND)));
    conn.bind(&mut r)
}

#[test]
fn session_bind_verifies_the_host_key_signature_over_the_session_id() {
    let (host, other) = (ed25519(9), ed25519(8));
    let mut conn = Conn::default();
    assert_eq!(bind(&mut conn, &bind_request(&host, &other, b"sid", false)), Some(false), "signed by another key");
    assert!(conn.bind_refused && conn.binds.is_empty());
    let mut conn = Conn::default();
    assert_eq!(bind(&mut conn, &bind_request(&host, &host, b"sid", false)), Some(true));
    assert!(!conn.bind_refused);
    assert_eq!((conn.binds.len(), conn.binds[0].forwarded), (1, false));
}

#[test]
fn session_bind_refuses_bad_fields_and_closes_on_cut_ones() {
    let host = ed25519(9);
    let good = bind_request(&host, &host, b"sid", false);
    let parts = |r: &[u8]| {
        let mut r = Reader(r);
        r.u8();
        r.string();
        (r.string().unwrap().to_vec(), r.string().unwrap().to_vec(), r.string().unwrap().to_vec())
    };
    let (key, sid, sig) = parts(&good);
    let with = |key: &[u8], sid: &[u8], sig: &[u8]| {
        let mut out = message(EXTENSION, &[SESSION_BIND, key, sid, sig]);
        out.push(0);
        bind(&mut Conn::default(), &out)
    };
    assert_eq!(with(&key, &sid, &sig), Some(true));
    assert_eq!(with(b"not a key", &sid, &sig), Some(false));
    assert_eq!(with(&key, &sid, b"not a signature"), Some(false));
    assert_eq!(with(&key, &sid, &[sig.as_slice(), b"x"].concat()), Some(false), "trailing signature bytes");
    let long = vec![7; MAX_SESSION_ID + 1];
    let signed = parts(&bind_request(&host, &host, &long, false)).2;
    assert_eq!(with(&key, &long, &signed), Some(false), "a session id over 128 bytes");
    assert_eq!(bind(&mut Conn::default(), &good[..good.len() - 1]), None, "no forwarding flag");
}

#[test]
fn session_bind_follows_openssh_rules_for_a_second_bind() {
    let (hop1, hop2, other) = (ed25519(9), ed25519(8), ed25519(7));
    // Bound for its own login: nothing more, not even the same bind again.
    let mut login = Conn::default();
    assert_eq!(bind(&mut login, &bind_request(&hop1, &hop1, b"s1", false)), Some(true));
    assert_eq!(bind(&mut login, &bind_request(&hop1, &hop1, b"s1", false)), Some(false));
    assert_eq!(bind(&mut login, &bind_request(&hop2, &hop2, b"s2", false)), Some(false));
    assert!(login.bind_refused);
    // Forwarded: a hop per bind; the same session again is fine with its own host key and refused with another.
    let mut fwd = Conn::default();
    assert_eq!(bind(&mut fwd, &bind_request(&hop1, &hop1, b"s1", true)), Some(true));
    assert_eq!(bind(&mut fwd, &bind_request(&hop1, &hop1, b"s1", true)), Some(true));
    assert_eq!(fwd.binds.len(), 1, "recorded once");
    assert_eq!(bind(&mut fwd, &bind_request(&other, &other, b"s1", true)), Some(false));
    assert_eq!(bind(&mut fwd, &bind_request(&hop2, &hop2, b"s2", false)), Some(true));
    assert_eq!(fwd.binds.len(), 2);
    // At most 16.
    let mut many = Conn::default();
    for n in 0..MAX_BINDS {
        assert_eq!(bind(&mut many, &bind_request(&hop1, &hop1, &[u8::try_from(n).unwrap()], true)), Some(true));
    }
    assert_eq!(bind(&mut many, &bind_request(&hop1, &hop1, b"one more", true)), Some(false));
}

#[test]
fn the_sign_context_says_what_is_signed_and_where_it_goes() {
    let (key, hop1, hop2) = (ed25519(1), ed25519(9), ed25519(8));
    let k = blob(&key);
    let mut conn = Conn::default();
    let unbound = conn.context("work".into(), &Userauth::new(&key).bytes(), &k);
    let login = |bound| Data::Login { user: "git".into(), bound };
    assert_eq!(unbound, SignContext { profile: "work".into(), data: login(false), bound: None, bind_refused: false });
    assert_eq!(conn.context("work".into(), b"a git commit", &k).data, Data::Other);

    assert_eq!(bind(&mut conn, &bind_request(&hop1, &hop1, b"sid-1", false)), Some(true));
    let ctx = conn.context("work".into(), &Userauth::new(&key).bytes(), &k);
    assert_eq!(ctx.data, login(true));
    assert_eq!(ctx.bound, Some(Binding { host_key: hop1.public_key().clone(), forwarded: false }));
    let hostbound = |host: &PrivateKey| conn.context("work".into(), &Userauth::hostbound(&key, host).bytes(), &k).data;
    assert_eq!(hostbound(&hop1), login(true));
    assert_eq!(hostbound(&hop2), login(false), "the request names another host than the bound one");
    let other_session = Userauth { session_id: b"sid-2", ..Userauth::new(&key) }.bytes();
    assert_eq!(conn.context("work".into(), &other_session, &k).data, login(false));
    let mut bad_host = Userauth::hostbound(&key, &hop1);
    bad_host.host = Some(b"not a key".to_vec());
    assert_eq!(conn.context("work".into(), &bad_host.bytes(), &k).data, login(false));

    // Forwarded: the last hop is the destination, and the request is marked forwarded.
    let mut fwd = Conn::default();
    bind(&mut fwd, &bind_request(&hop1, &hop1, b"s1", true));
    bind(&mut fwd, &bind_request(&hop2, &hop2, b"s2", false));
    bind(&mut fwd, &bind_request(&hop2, &hop1, b"s3", false));
    let ctx = fwd.context("work".into(), b"x", &k);
    assert_eq!(ctx.bound, Some(Binding { host_key: hop2.public_key().clone(), forwarded: true }));
    assert!(ctx.bind_refused);
}

#[tokio::test]
async fn identities_are_the_keys_of_the_unlocked_profiles_by_name() {
    let w = world(vec![]).await;
    let mut c = connect(&w.ssh).await;
    assert_eq!(c.keys().await, [(blob(&w.alpha), "alpha".into()), (blob(&w.beta), "beta".into())]);
    // Locked: nothing, on the same connection; a profile never started offers nothing either (`home`).
    w.rig.agent.dispatch(Op::Lock { target: Target::All }).await;
    assert_eq!(c.keys().await, []);
    assert_eq!(w.rig.agent.worker_count(), 1, "listing starts no worker");
}

#[tokio::test]
async fn a_key_held_by_two_profiles_is_offered_once_as_the_first() {
    let w = world(vec![]).await;
    w.rig.host.vault(&json!({ "ciphers": [ssh_item("h1", "alpha at home", &w.alpha)] }).to_string());
    crate::agent::testing::unlock(&w.rig.agent, &w.rig.host, "home").await;
    let ssh = Arc::new(SshAgent::new(w.rig.agent.clone(), vec!["home".into(), "work".into()], w.auth.clone()));
    let names: Vec<String> = connect(&ssh).await.keys().await.into_iter().map(|(_, n)| n).collect();
    assert_eq!(names, ["alpha at home", "beta"]);
}

#[tokio::test]
async fn sign_returns_a_signature_the_key_verifies_once_authorized() {
    let w = world(vec![]).await;
    let mut c = connect(&w.ssh).await;
    let reply = c.sign(&blob(&w.beta), b"a git commit", 0).await;
    assert_eq!(verified(&w.beta, b"a git commit", &reply).algorithm(), Algorithm::Ed25519);
    let asked = w.auth.asked();
    assert_eq!(asked, [SignContext { profile: "work".into(), data: Data::Other, bound: None, bind_refused: false }]);
    // Refused: the failure reply, and the connection stays open.
    w.auth.refuse.store(true, Ordering::SeqCst);
    assert_eq!(c.sign(&blob(&w.beta), b"x", 0).await, FAIL);
    assert_eq!(c.keys().await.len(), 2);
}

#[tokio::test]
async fn a_login_on_a_bound_connection_is_marked_with_its_destination() {
    let w = world(vec![]).await;
    let host = ed25519(9);
    let mut c = connect(&w.ssh).await;
    assert_eq!(c.ask(&bind_request(&host, &host, b"sid-1", false)).await, OK);
    let data = Userauth::hostbound(&w.alpha, &host).bytes();
    verified(&w.alpha, &data, &c.sign(&blob(&w.alpha), &data, 0).await);
    let ctx = w.auth.asked().pop().unwrap();
    assert_eq!(ctx.data, Data::Login { user: "git".into(), bound: true });
    assert_eq!(ctx.bound, Some(Binding { host_key: host.public_key().clone(), forwarded: false }));
    // A second bind of a login connection is refused, and the connection is told so.
    assert_eq!(c.ask(&bind_request(&host, &host, b"sid-2", false)).await, FAIL);
}

#[tokio::test]
async fn nothing_signs_with_a_key_that_is_not_offered() {
    let w = world(vec![]).await;
    let mut c = connect(&w.ssh).await;
    assert_eq!(c.sign(&blob(&ed25519(5)), b"x", 0).await, FAIL);
    assert!(w.auth.asked().is_empty(), "not even asked");
}

#[tokio::test]
async fn a_connection_kept_open_across_a_lock_does_not_sign_with_the_locked_key() {
    let w = world(vec![]).await;
    let mut c = connect(&w.ssh).await;
    verified(&w.alpha, b"x", &c.sign(&blob(&w.alpha), b"x", 0).await);
    w.rig.agent.dispatch(Op::Lock { target: Target::Profile("work".into()) }).await;
    assert_eq!(c.sign(&blob(&w.alpha), b"x", 0).await, FAIL);
    assert_eq!(w.auth.asked().len(), 1, "the locked key is not offered, so nobody is asked");
    // Locked while the user was being asked: nothing is signed either.
    let w = world(vec![]).await;
    *w.auth.lock_on_ask.lock().unwrap() = Some(w.rig.agent.clone());
    let mut c = connect(&w.ssh).await;
    assert_eq!(c.sign(&blob(&w.alpha), b"x", 0).await, FAIL);
    assert_eq!(w.auth.asked().len(), 1);
}

#[tokio::test]
async fn rsa_without_a_sha2_flag_is_refused_and_signs_with_one() {
    let rsa = generate(Algorithm::Rsa { hash: None });
    let w = world(vec![ssh_item("r1", "rsa", &rsa)]).await;
    let mut c = connect(&w.ssh).await;
    assert_eq!(c.sign(&blob(&rsa), b"x", 0).await, FAIL, "legacy ssh-rsa (SHA-1)");
    assert!(w.auth.asked().is_empty(), "refused before anyone is asked");
    let signature = verified(&rsa, b"x", &c.sign(&blob(&rsa), b"x", crate::ssh::RSA_SHA2_512).await);
    assert_eq!(signature.algorithm(), Algorithm::Rsa { hash: Some(ssh_key::HashAlg::Sha512) });
}

#[tokio::test]
async fn a_client_that_changed_while_it_was_asked_gets_no_signature() {
    let w = world(vec![]).await;
    let mut c = connect(&w.ssh).await;
    c.keys().await;
    w.rig.tree.kill(trust_self(&w.rig));
    assert_eq!(c.sign(&blob(&w.alpha), b"x", 0).await, FAIL);
    assert_eq!(w.auth.asked().len(), 1);
}

#[tokio::test]
async fn remove_changes_only_the_agents_view() {
    let w = world(vec![]).await;
    let mut c = connect(&w.ssh).await;
    assert_eq!(c.ask(&message(REMOVE_IDENTITY, &[&blob(&w.alpha)])).await, OK);
    assert_eq!(c.ask(&message(REMOVE_IDENTITY, &[&blob(&w.alpha)])).await, FAIL, "no longer offered");
    assert_eq!(c.ask(&message(REMOVE_IDENTITY, &[&blob(&ed25519(5))])).await, FAIL);
    // Another connection sees the same view, and the removed key does not sign.
    let mut other = connect(&w.ssh).await;
    assert_eq!(other.keys().await, [(blob(&w.beta), "beta".into())]);
    assert_eq!(other.sign(&blob(&w.alpha), b"x", 0).await, FAIL);
    assert_eq!(c.ask(&[REMOVE_ALL_IDENTITIES]).await, OK);
    assert_eq!(c.keys().await, []);
    // The vault still holds both.
    let listed = w.rig.agent.dispatch(Op::List { profile: Some("work".into()), fields: vec![], folder: None }).await;
    let ids = format!("{listed:?}");
    assert!(ids.contains("\"sa\"") && ids.contains("\"sb\""), "{ids}");
}

#[tokio::test]
async fn adding_keys_smartcards_locks_and_unknown_messages_fail_and_the_connection_stays() {
    let w = world(vec![]).await;
    let mut c = connect(&w.ssh).await;
    let private = w.alpha.to_bytes().unwrap();
    for kind in [17, 25, 20, 21, 22, 23, 26, 1, 9, 200] {
        assert_eq!(c.ask(&message(kind, &[b"ssh-ed25519", &private])).await, FAIL, "{kind}");
    }
    assert_eq!(c.ask(&message(EXTENSION, &[b"query"])).await, FAIL, "an unknown extension");
    assert_eq!(c.keys().await.len(), 2, "still serving");
}

#[tokio::test]
async fn a_malformed_or_oversized_message_closes_the_connection_and_the_agent_keeps_serving() {
    let w = world(vec![]).await;
    let cut_sign = sign_request(&blob(&w.alpha), b"x", 0);
    let host = ed25519(9);
    let cut_bind = bind_request(&host, &host, b"sid", false);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("sign cut short", cut_sign[..cut_sign.len() - 1].to_vec()),
        ("remove cut short", vec![REMOVE_IDENTITY, 0, 0, 0, 9, 1]),
        ("extension without a name", vec![EXTENSION, 0, 0]),
        ("session-bind cut short", cut_bind[..cut_bind.len() - 1].to_vec()),
    ];
    for (name, body) in cases {
        let mut c = connect(&w.ssh).await;
        c.send(&body).await;
        assert!(c.closed().await, "{name}");
    }
    let frames: Vec<(&str, Vec<u8>)> = vec![
        ("empty message", vec![0, 0, 0, 0]),
        ("oversized", u32::try_from(MAX_MESSAGE + 1).unwrap().to_be_bytes().to_vec()),
        ("huge", vec![0xff; 4]),
    ];
    for (name, frame) in frames {
        let mut c = connect(&w.ssh).await;
        c.stream.write_all(&frame).await.unwrap();
        assert!(c.closed().await, "{name}");
    }
    // The largest message is still read (and refused as unknown).
    let mut c = connect(&w.ssh).await;
    let mut big = vec![200];
    big.resize(MAX_MESSAGE, 0);
    assert_eq!(c.ask(&big).await, FAIL);
    assert_eq!(connect(&w.ssh).await.keys().await.len(), 2, "the agent serves on");
}

#[tokio::test]
async fn a_frame_cut_short_closes_and_an_idle_connection_is_reaped() {
    let mut w = world(vec![]).await;
    let ssh = Arc::get_mut(&mut w.ssh).unwrap();
    ssh.idle_timeout = Duration::from_millis(100);
    let mut c = connect(&w.ssh).await;
    assert_eq!(c.keys().await.len(), 2);
    assert!(c.closed().await, "idle past the idle timeout");
    let mut c = connect(&w.ssh).await;
    c.stream.write_all(&[0, 0]).await.unwrap();
    c.stream.shutdown().await.unwrap();
    assert!(c.closed().await, "EOF in the header");
    let mut c = connect(&w.ssh).await;
    c.stream.write_all(&[0, 0, 0, 9, REQUEST_IDENTITIES]).await.unwrap();
    c.stream.shutdown().await.unwrap();
    assert!(c.closed().await, "EOF in the message");
}

#[tokio::test]
async fn a_message_begun_must_finish_within_the_read_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let mut rig = rig(dir.path());
    Arc::get_mut(&mut rig.agent).unwrap().read_timeout = Duration::from_millis(100);
    trust_self(&rig);
    let ssh = Arc::new(SshAgent::new(rig.agent.clone(), vec![], Arc::new(RefuseAll)));
    let mut c = connect(&ssh).await;
    c.stream.write_all(&[0, 0, 0, 9, REQUEST_IDENTITIES]).await.unwrap();
    assert!(c.closed().await);
}

#[tokio::test]
async fn a_client_gone_before_its_reply_ends_the_connection() {
    let w = world(vec![]).await;
    let mut c = connect(&w.ssh).await;
    assert_eq!(c.keys().await.len(), 2, "identified and served");
    // A second request, and the client is gone before the reply: the write fails and the handler ends.
    c.send(&[REQUEST_IDENTITIES]).await;
    drop(c.stream);
    assert!(tokio::time::timeout(Duration::from_secs(5), c.task).await.is_ok());
}

#[tokio::test]
async fn a_peer_of_another_uid_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let mut rig = rig(dir.path());
    Arc::get_mut(&mut rig.agent).unwrap().uid += 1;
    let ssh = Arc::new(SshAgent::new(rig.agent.clone(), vec!["work".into()], Arc::new(RefuseAll)));
    let mut c = connect(&ssh).await;
    c.send(&[REQUEST_IDENTITIES]).await;
    assert!(c.closed().await);
}

#[tokio::test]
async fn refuse_all_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    let resolved = crate::caller::Resolved::fixed(crate::agent::testing::invoker(), crate::agent::testing::peer());
    let key = Key { id: "k".into(), name: "n".into(), fingerprint: "f".into(), blob: vec![] };
    let ctx = SignContext { profile: "work".into(), data: Data::Other, bound: None, bind_refused: false };
    assert_eq!(RefuseAll.authorize_sign(&resolved, &key, &ctx).await, Decision::Refuse);
    drop(rig);
}

#[tokio::test]
async fn listing_is_no_use_of_the_profile_but_signing_is() {
    let w = world(vec![]).await;
    let min = Duration::from_secs(60);
    let mut c = connect(&w.ssh).await;
    w.rig.clock.advance(4 * min, 4 * min);
    verified(&w.alpha, b"x", &c.sign(&blob(&w.alpha), b"x", 0).await);
    w.rig.clock.advance(4 * min, 4 * min);
    assert_eq!(c.keys().await.len(), 2, "4 minutes since the signature");
    w.rig.clock.advance(2 * min, 2 * min);
    assert_eq!(c.keys().await, [], "6 minutes since the signature: the listings did not count");
}

/// The agent's real `ssh-agent.sock` under `serve`, with a Rust client on a std socket.
#[tokio::test(flavor = "multi_thread")]
async fn serve_answers_on_the_ssh_socket_until_it_stops() {
    let w = world(vec![]).await;
    let dir = tempfile::Builder::new().prefix("d").tempdir_in("/tmp").unwrap();
    let run = dir.path().join("run");
    let (listener, lock) = crate::socket::bind(&run, crate::agent::testing::me()).unwrap();
    let ssh_listener = crate::socket::bind_ssh(&run, crate::agent::testing::me(), &lock).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(crate::server::serve(
        w.rig.agent.clone(),
        listener,
        Some((ssh_listener, w.ssh.clone())),
        async move { stopped.await.map_err(std::io::Error::other) },
    ));
    let path = run.join("ssh-agent.sock");
    let (alpha, data) = (blob(&w.alpha), Userauth::new(&w.alpha).bytes());
    let (keys, signed) = tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut s = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let mut ask = |m: &[u8]| {
            let mut frame = Vec::new();
            put_string(&mut frame, m);
            s.write_all(&frame).unwrap();
            let mut len = [0; 4];
            s.read_exact(&mut len).unwrap();
            let mut out = vec![0; u32::from_be_bytes(len) as usize];
            s.read_exact(&mut out).unwrap();
            out
        };
        (ask(&[REQUEST_IDENTITIES]), ask(&sign_request(&alpha, &data, 0)))
    })
    .await
    .unwrap();
    assert_eq!(identities(&keys).len(), 2);
    verified(&w.alpha, &Userauth::new(&w.alpha).bytes(), &signed);
    // An idle SSH connection does not hold the shutdown.
    let _idle = std::os::unix::net::UnixStream::connect(run.join("ssh-agent.sock")).unwrap();
    stop.send(()).unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(5), served).await;
    assert!(ended.unwrap().unwrap().is_ok());
    assert_eq!(w.rig.agent.worker_count(), 0);
}

/// OpenSSH's own client on the socket: `ssh-add -L` lists the keys, `ssh-keygen -Y sign` signs through the agent,
/// `ssh-add -d` removes one from the view. Needs OpenSSH 8.9+ on PATH; run with `--ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs OpenSSH's ssh-add and ssh-keygen on PATH"]
async fn openssh_clients_list_sign_and_remove() {
    let dir = tempfile::Builder::new().prefix("d").tempdir_in("/tmp").unwrap();
    let rig = crate::agent::testing::rig_with(dir.path(), |_| Arc::new(dybw_peer::Os));
    let alpha = ed25519(1);
    let mut vault: Value = serde_json::from_str(crate::read_tests::VAULT).unwrap();
    vault["ciphers"].as_array_mut().unwrap().push(ssh_item("sa", "alpha", &alpha));
    rig.host.vault(&vault.to_string());
    crate::agent::testing::unlock(&rig.agent, &rig.host, "work").await;
    let auth = Arc::new(Double::default());
    let ssh = Arc::new(SshAgent::new(rig.agent.clone(), vec!["work".into()], auth.clone()));
    let run = dir.path().join("run");
    let (listener, lock) = crate::socket::bind(&run, crate::agent::testing::me()).unwrap();
    let ssh_listener = crate::socket::bind_ssh(&run, crate::agent::testing::me(), &lock).unwrap();
    let served = tokio::spawn(crate::server::serve(
        rig.agent.clone(),
        listener,
        Some((ssh_listener, ssh)),
        std::future::pending::<std::io::Result<()>>(),
    ));
    let sock = run.join("ssh-agent.sock");
    let public = alpha.public_key().to_openssh().unwrap();
    let pub_file = dir.path().join("alpha.pub");
    std::fs::write(&pub_file, format!("{public}\n")).unwrap();
    std::fs::write(dir.path().join("msg"), "hello").unwrap();
    let out = tokio::task::spawn_blocking({
        let (sock, dir, pub_file) = (sock.clone(), dir.path().to_owned(), pub_file.clone());
        move || {
            let run = |cmd: &str, args: &[&std::ffi::OsStr]| {
                std::process::Command::new(cmd)
                    .args(args)
                    .env("SSH_AUTH_SOCK", &sock)
                    .current_dir(&dir)
                    .output()
                    .unwrap()
            };
            let listed = run("ssh-add", &["-L".as_ref()]);
            let signed = run(
                "ssh-keygen",
                &[
                    "-Y".as_ref(),
                    "sign".as_ref(),
                    "-n".as_ref(),
                    "file".as_ref(),
                    "-U".as_ref(),
                    "-f".as_ref(),
                    pub_file.as_os_str(),
                    "msg".as_ref(),
                ],
            );
            let removed = run("ssh-add", &["-d".as_ref(), pub_file.as_os_str()]);
            let after = run("ssh-add", &["-l".as_ref()]);
            (listed, signed, removed, after)
        }
    })
    .await
    .unwrap();
    let (listed, signed, removed, after) = out;
    assert_eq!(String::from_utf8_lossy(&listed.stdout).trim(), format!("{public} alpha").trim(), "{listed:?}");
    assert!(signed.status.success(), "{signed:?}");
    assert!(dir.path().join("msg.sig").exists());
    assert_eq!(auth.asked().len(), 1);
    assert_eq!(auth.asked()[0].data, Data::Other);
    assert!(removed.status.success(), "{removed:?}");
    assert!(!after.status.success(), "no identities left: {after:?}");
    served.abort();
}

#[test]
fn session_bind_verifies_rsa_sha2_512_and_ecdsa_host_keys() {
    let rsa = generate(Algorithm::Rsa { hash: None });
    let KeypairData::Rsa(pair) = rsa.key_data() else { panic!() };
    let signature = Signer::<Signature>::try_sign(&(pair, Some(ssh_key::HashAlg::Sha512)), b"sid").unwrap();
    assert_eq!(signature.algorithm(), Algorithm::Rsa { hash: Some(ssh_key::HashAlg::Sha512) });
    assert_eq!(bind(&mut Conn::default(), &bind_signed(&rsa, &signature, b"sid", false)), Some(true));
    assert_eq!(bind(&mut Conn::default(), &bind_signed(&rsa, &signature, b"other sid", false)), Some(false));
    let ecdsa = generate(Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP256 });
    assert_eq!(bind(&mut Conn::default(), &bind_request(&ecdsa, &ecdsa, b"sid", false)), Some(true));
    assert_eq!(bind(&mut Conn::default(), &bind_request(&ecdsa, &ed25519(3), b"sid", false)), Some(false));
}

#[tokio::test]
async fn a_connection_whose_session_bind_failed_signs_nothing() {
    let w = world(vec![]).await;
    let (host, other) = (ed25519(9), ed25519(8));
    let mut c = connect(&w.ssh).await;
    assert_eq!(c.ask(&bind_request(&host, &other, b"sid", false)).await, FAIL);
    assert_eq!(c.sign(&blob(&w.alpha), b"x", 0).await, FAIL);
    assert!(w.auth.asked().is_empty(), "refused before anyone is asked");
    // A forwarded connection with a good bind and a refused one still signs (the refusal is on record).
    let mut fwd = connect(&w.ssh).await;
    assert_eq!(fwd.ask(&bind_request(&host, &host, b"s1", true)).await, OK);
    assert_eq!(fwd.ask(&bind_request(&other, &host, b"s2", false)).await, FAIL);
    verified(&w.alpha, b"x", &fwd.sign(&blob(&w.alpha), b"x", 0).await);
    assert!(w.auth.asked()[0].bind_refused);
}

#[tokio::test]
async fn a_key_removed_while_the_user_was_asked_does_not_sign() {
    let w = world(vec![]).await;
    let (ssh, alpha) = (w.ssh.clone(), blob(&w.alpha));
    *w.auth.on_ask.lock().unwrap() = Some(Box::new(move || {
        ssh.removed.lock().unwrap().insert(alpha);
    }));
    let mut c = connect(&w.ssh).await;
    assert_eq!(c.sign(&blob(&w.alpha), b"x", 0).await, FAIL);
    assert_eq!(w.auth.asked().len(), 1, "asked, then refused");
}

#[tokio::test]
async fn connections_past_the_cap_are_closed_at_once() {
    let mut w = world(vec![]).await;
    Arc::get_mut(&mut w.ssh).unwrap().slots = Arc::new(tokio::sync::Semaphore::new(1));
    let mut first = connect(&w.ssh).await;
    assert_eq!(first.keys().await.len(), 2);
    assert!(connect(&w.ssh).await.closed().await, "over the cap");
    drop(first.stream);
    first.task.await.unwrap();
    assert_eq!(connect(&w.ssh).await.keys().await.len(), 2, "its slot is free again");
}

#[tokio::test]
async fn an_item_whose_private_key_does_not_parse_signs_nothing() {
    let broken = ed25519(4);
    let mut item = ssh_item("sx", "broken", &broken);
    item["sshKey"]["privateKey"] = json!(enc("-----BEGIN OPENSSH PRIVATE KEY-----"));
    let w = world(vec![item]).await;
    let mut c = connect(&w.ssh).await;
    assert_eq!(c.keys().await.len(), 3, "listed from its public key");
    assert_eq!(c.sign(&blob(&broken), b"x", 0).await, FAIL);
    assert_eq!(w.auth.asked().len(), 1, "asked, then the key failed");
}
