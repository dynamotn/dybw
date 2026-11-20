//! What a profile worker needs from the machine: an HTTP client and the pinentry. The real host is the one in
//! `dybw-native`; tests plug in a fake, so no test touches the network or a screen.

use std::time::Duration;

use dybw_core::ports::{Http, PortError};
use dybw_native::config::Trust;
use dybw_native::ports::http::HttpPort;
use dybw_native::prompter::{Confirm, PromptError, Prompter, SESSION_ENV};
use zeroize::Zeroizing;

/// How long the user has to answer one pinentry question.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);
/// The title of every pinentry window.
pub const TITLE: &str = "dybw";

#[expect(async_fn_in_trait, reason = "the worker is single-threaded: its futures are never sent anywhere")]
pub trait Host: Send + 'static {
    type Http: Http + 'static;

    /// A fresh HTTP client (redirects refused), one per login or sync.
    fn http(&self) -> Result<Self::Http, PortError>;
    /// Ask for a secret (`prompt` is the field label); `None` is the user's cancel.
    async fn password(
        &self,
        prompt: &str,
        description: &str,
        error: Option<&str>,
    ) -> Result<Option<Zeroizing<String>>, PromptError>;
    /// Ask the user to allow something; "always" is offered only when `offer_always`.
    async fn confirm(&self, description: &str, offer_always: bool) -> Result<Confirm, PromptError>;
    /// The machine's name, for the device name the server shows.
    fn hostname(&self) -> String;
    /// The machine fingerprint local unlock protectors are bound to (ADR 0006); `None` when it cannot be read.
    fn machine(&self) -> Option<String>;
}

/// The real host: `HttpPort` and a trusted pinentry. A pinentry that fails the trust rule is kept as text and
/// reported when the first question is asked, so one profile's bad `pinentry` does not stop the agent.
pub struct RealHost {
    prompter: Result<Prompter, String>,
}

impl RealHost {
    pub fn new(trust: Trust, pinentry: &str) -> Self {
        let prompter = Prompter::trusted(trust, pinentry, PROMPT_TIMEOUT, SESSION_ENV).map_err(|e| format!("{e:#}"));
        RealHost { prompter }
    }
}

impl Host for RealHost {
    type Http = HttpPort;

    fn http(&self) -> Result<HttpPort, PortError> {
        HttpPort::new()
    }

    async fn password(
        &self,
        prompt: &str,
        description: &str,
        error: Option<&str>,
    ) -> Result<Option<Zeroizing<String>>, PromptError> {
        match &self.prompter {
            Ok(p) => p.ask_password(TITLE, prompt, description, error).await,
            Err(why) => Err(PromptError::Untrusted(why.clone())),
        }
    }

    async fn confirm(&self, description: &str, offer_always: bool) -> Result<Confirm, PromptError> {
        match &self.prompter {
            Ok(p) => p.ask_confirm(TITLE, description, offer_always).await,
            Err(why) => Err(PromptError::Untrusted(why.clone())),
        }
    }

    fn hostname(&self) -> String {
        rustix::system::uname().nodename().to_string_lossy().chars().filter(|c| !c.is_control()).collect()
    }

    fn machine(&self) -> Option<String> {
        // Why it cannot be read is `dybw doctor`'s to say.
        dybw_peer::machine_id().ok()
    }
}

/// A scripted host for tests: no network, no pinentry. The vector is the public `pbkdf2` account of dybw-core's
/// test vectors (source 2: the email is the salt, the KDF comes from prelogin).
#[cfg(test)]
pub(crate) mod fake {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use dybw_core::ports::{HttpRequest, HttpResponse};
    use serde_json::Value;

    use super::*;

    pub const PASSWORD: &str = "vectors-pbkdf2-password";
    const PROFILE_KEY: &str = "2.i8kWlJpkBIlQNEsIQHe7yg==|gVpFnvKEofwA3e7PrRWtB/Xilo7/RYG87RVpyPU89Mss9OttJttG1KuxyzKd6n8zeBc6/5Z/9Cs8N5ZZU91yerrvhpPiln3pDNdNi9Vg/5Y=|o4JKGpcG33gTOxKljcHzzOqQRzWvtvJzohdxuiHv5Dk=";

    /// What the pinentry does with one question.
    pub enum Answer {
        Text(&'static str),
        Cancel,
        Fail,
        Timeout,
        /// Never answers: the user has walked away.
        Hang,
        /// A confirmation that says yes once `World::release` is notified.
        Held,
        /// A confirmation that says yes and "always".
        Always,
        /// `Held`, then "always".
        HeldAlways,
        /// A secret typed once `World::release` is notified.
        HeldText(&'static str),
    }

    pub struct World {
        pub answers: VecDeque<Answer>,
        /// Every question: the description and the error line.
        pub asked: Vec<(String, Option<String>)>,
        /// The prompt (field label) of every question, in the same order.
        pub prompts: Vec<String>,
        /// False: every request fails like a dead network.
        pub online: bool,
        /// The status of `/connect/token`: 200 logs in, 400 is a refused key.
        pub token_status: u16,
        /// The HTTP client cannot be built.
        pub http_fails: bool,
        /// The machine's name.
        pub hostname: String,
        /// `/sync` answers 500.
        pub sync_fails: bool,
        /// `/sync` never answers.
        pub sync_hangs: bool,
        /// Shows in the `/sync` body, so a test can tell one sync from another.
        pub sync_marker: u32,
        /// `METHOD path` of every request.
        pub requests: Vec<String>,
        /// The `deviceName` of every login.
        pub device_names: Vec<String>,
        /// The `Bitwarden-Client-Version` header of every request.
        pub client_versions: Vec<String>,
        /// The `ciphers` and `folders` JSON lists the `/sync` answer carries.
        pub ciphers: String,
        pub folders: String,
        /// The `profile` object of `/sync`; the pbkdf2 account's when `None`.
        pub profile: Option<String>,
        /// What the user does with each confirmation (`Text` allows; none left means no).
        pub confirms: VecDeque<Answer>,
        /// Every confirmation asked.
        pub confirmed: Vec<String>,
        /// Whether "always" was offered, per confirmation.
        pub offered: Vec<bool>,
        /// What an `Answer::Held` confirmation waits for.
        pub release: Arc<tokio::sync::Notify>,
        /// The server answers every cipher write "out of date".
        pub out_of_date: bool,
        /// Each cipher write so far: it dates what it writes.
        pub writes: u32,
        /// The body of every cipher write.
        pub bodies: Vec<Value>,
        /// `/sync` answers 500 once a cipher write went through.
        pub sync_fails_after_write: bool,
        /// What `POST /api/folders` answers instead of making the folder.
        pub folder_reply: Option<u16>,
        /// The machine fingerprint; `None` cannot be read.
        pub machine: Option<String>,
    }

    impl World {
        pub fn count(&self, what: &str) -> usize {
            self.requests.iter().filter(|r| r.ends_with(what)).count()
        }

        /// The server's side of a create (`POST /api/ciphers`), an update (`PUT /api/ciphers/<id>`) and a trash
        /// (`PUT /api/ciphers/<id>/delete`), on the ciphers the next `/sync` sends.
        #[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
        fn cipher_write(&mut self, method: &str, path: &str, body: Option<&[u8]>) -> (u16, String) {
            let body: Value = body.and_then(|b| serde_json::from_slice(b).ok()).unwrap_or_default();
            self.bodies.push(body.clone());
            if self.out_of_date {
                let message = "The client copy of this cipher is out of date. Resync the client and try again.";
                return (400, serde_json::json!({ "message": message }).to_string());
            }
            self.writes += 1;
            let date = serde_json::json!(format!("2026-11-18T00:00:{:02}.000Z", self.writes));
            let mut list: Vec<Value> = serde_json::from_str(&self.ciphers).unwrap();
            let id = path.trim_start_matches("/api/ciphers").trim_start_matches('/');
            let reply = if method == "Post" {
                let mut c = body;
                c["id"] = serde_json::json!(format!("new{}", self.writes));
                c["revisionDate"] = date;
                list.push(c.clone());
                c
            } else if let Some(id) = id.strip_suffix("/delete") {
                list.iter_mut().filter(|c| c["id"] == id).for_each(|c| c["deletedDate"] = date.clone());
                serde_json::json!({})
            } else {
                let mut c = body;
                c["id"] = serde_json::json!(id);
                c["revisionDate"] = date;
                list.iter_mut().filter(|x| x["id"] == id).for_each(|x| *x = c.clone());
                c
            };
            self.ciphers = Value::Array(list).to_string();
            (200, reply.to_string())
        }
    }

    #[derive(Clone)]
    pub struct FakeHost(pub Arc<Mutex<World>>);

    impl FakeHost {
        pub fn new() -> Self {
            FakeHost(Arc::new(Mutex::new(World {
                answers: VecDeque::new(),
                asked: Vec::new(),
                prompts: Vec::new(),
                online: true,
                token_status: 200,
                http_fails: false,
                hostname: "testhost".into(),
                sync_fails: false,
                sync_hangs: false,
                sync_marker: 0,
                requests: Vec::new(),
                device_names: Vec::new(),
                client_versions: Vec::new(),
                ciphers: "[]".into(),
                folders: "[]".into(),
                profile: None,
                confirms: VecDeque::new(),
                confirmed: Vec::new(),
                offered: Vec::new(),
                release: Arc::new(tokio::sync::Notify::new()),
                out_of_date: false,
                writes: 0,
                bodies: Vec::new(),
                sync_fails_after_write: false,
                folder_reply: None,
                machine: Some("fake-machine".into()),
            })))
        }

        #[expect(clippy::unwrap_used, reason = "tests")]
        pub fn world(&self) -> std::sync::MutexGuard<'_, World> {
            self.0.lock().unwrap()
        }

        pub fn answer(&self, answer: Answer) {
            self.world().answers.push_back(answer);
        }

        pub fn allow(&self) {
            self.world().confirms.push_back(Answer::Text("yes"));
        }

        /// The user says yes and ticks "always" (which only counts when it was offered).
        pub fn allow_always(&self) {
            self.world().confirms.push_back(Answer::Always);
        }

        /// The `ciphers` and `folders` of `/sync`, from a `{ciphers, folders}` JSON text.
        #[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
        pub fn vault(&self, json: &str) {
            let v: serde_json::Value = serde_json::from_str(json).unwrap();
            let mut w = self.world();
            w.ciphers = v["ciphers"].to_string();
            w.folders = v["folders"].to_string();
            w.profile = v.get("profile").map(Value::to_string);
        }
    }

    pub struct FakeHttp(Arc<Mutex<World>>);

    impl Http for FakeHttp {
        fn refuses_redirects(&self) -> bool {
            true
        }

        #[expect(clippy::unwrap_used, reason = "tests")]
        async fn send(&self, req: HttpRequest) -> Result<HttpResponse, PortError> {
            let path = req.url.split_once("example.org").map_or(req.url.as_str(), |(_, p)| p).to_owned();
            let (status, body, hang) = {
                let mut w = self.0.lock().unwrap();
                w.requests.push(format!("{:?} {path}", req.method));
                w.client_versions.extend(
                    req.headers.iter().filter(|(k, _)| k == "Bitwarden-Client-Version").map(|(_, v)| v.clone()),
                );
                if !w.online {
                    return Err(PortError("network: connection refused".into()));
                }
                match path.as_str() {
                    "/identity/connect/token" => {
                        let form =
                            String::from_utf8_lossy(req.body.as_deref().map_or(&[][..], |b| b.as_slice())).into_owned();
                        let name = form.split('&').find_map(|p| p.strip_prefix("deviceName="));
                        w.device_names.extend(name.map(str::to_owned));
                        let body = if w.token_status == 200 {
                            r#"{"access_token":"tok","expires_in":3600}"#
                        } else {
                            r#"{"error":"invalid_client"}"#
                        };
                        (w.token_status, body.to_owned(), false)
                    }
                    "/api/sync?excludeDomains=true" => {
                        let marker = w.sync_marker;
                        let profile =
                            w.profile.clone().unwrap_or_else(|| format!(r#"{{"id":"u1","key":"{PROFILE_KEY}"}}"#));
                        let body = format!(
                            r#"{{"profile":{profile},"ciphers":{},"folders":{},"marker":{marker}}}"#,
                            w.ciphers, w.folders
                        );
                        let fails = w.sync_fails || (w.sync_fails_after_write && w.writes > 0);
                        (if fails { 500 } else { 200 }, body, w.sync_hangs)
                    }
                    // A new folder, in what the next `/sync` sends.
                    "/api/folders" if w.folder_reply.is_some() => (w.folder_reply.unwrap(), "{}".to_owned(), false),
                    "/api/folders" => {
                        let mut folders: Vec<Value> = serde_json::from_str(&w.folders).unwrap();
                        let name = req.body.as_deref().and_then(|b| serde_json::from_slice::<Value>(b).ok());
                        let folder = serde_json::json!({
                            "id": format!("made-{}", folders.len()),
                            "name": name.and_then(|n| n.get("name").cloned()),
                        });
                        folders.push(folder.clone());
                        w.folders = Value::Array(folders).to_string();
                        (200, folder.to_string(), false)
                    }
                    p if p.starts_with("/api/ciphers") => {
                        let (status, body) =
                            w.cipher_write(&format!("{:?}", req.method), p, req.body.as_deref().map(|b| b.as_slice()));
                        (status, body, false)
                    }
                    // The only other request an unlock makes: `/identity/accounts/prelogin`.
                    _ => (200, r#"{"kdf":0,"kdfIterations":600000}"#.to_owned(), false),
                }
            };
            if hang {
                std::future::pending::<()>().await;
            }
            Ok(HttpResponse { status, body: Zeroizing::new(body.into_bytes()) })
        }
    }

    impl Host for FakeHost {
        type Http = FakeHttp;

        fn http(&self) -> Result<FakeHttp, PortError> {
            #[expect(clippy::unwrap_used, reason = "tests")]
            let fails = self.0.lock().unwrap().http_fails;
            if fails { Err(PortError("http client: scripted".into())) } else { Ok(FakeHttp(self.0.clone())) }
        }

        #[expect(clippy::unwrap_used, reason = "tests")]
        async fn password(
            &self,
            prompt: &str,
            description: &str,
            error: Option<&str>,
        ) -> Result<Option<Zeroizing<String>>, PromptError> {
            let (answer, release) = {
                let mut w = self.0.lock().unwrap();
                w.asked.push((description.to_owned(), error.map(str::to_owned)));
                w.prompts.push(prompt.to_owned());
                (w.answers.pop_front().unwrap_or(Answer::Cancel), w.release.clone())
            };
            match answer {
                Answer::Text(t) => Ok(Some(Zeroizing::new(t.to_owned()))),
                Answer::Cancel => Ok(None),
                Answer::Fail => Err(PromptError::Protocol("scripted".into())),
                Answer::Timeout => Err(PromptError::Timeout),
                Answer::Hang => std::future::pending().await,
                Answer::HeldText(t) => {
                    release.notified().await;
                    Ok(Some(Zeroizing::new(t.to_owned())))
                }
                // The user types the right password once the test lets them.
                Answer::Held | Answer::Always | Answer::HeldAlways => {
                    release.notified().await;
                    Ok(Some(Zeroizing::new(PASSWORD.to_owned())))
                }
            }
        }

        #[expect(clippy::unwrap_used, reason = "tests")]
        async fn confirm(&self, description: &str, offer_always: bool) -> Result<Confirm, PromptError> {
            let (answer, release) = {
                let mut w = self.0.lock().unwrap();
                w.confirmed.push(description.to_owned());
                w.offered.push(offer_always);
                (w.confirms.pop_front().unwrap_or(Answer::Cancel), w.release.clone())
            };
            match answer {
                Answer::Text(_) => Ok(Confirm::Once),
                // The pinentry only returns "always" when it was offered.
                Answer::Always => Ok(if offer_always { Confirm::Always } else { Confirm::Once }),
                Answer::Cancel => Ok(Confirm::Deny),
                Answer::Fail => Err(PromptError::Protocol("scripted".into())),
                Answer::Timeout => Err(PromptError::Timeout),
                Answer::Hang => std::future::pending().await,
                Answer::Held | Answer::HeldAlways | Answer::HeldText(_) => {
                    release.notified().await;
                    Ok(if matches!(answer, Answer::HeldAlways) && offer_always {
                        Confirm::Always
                    } else {
                        Confirm::Once
                    })
                }
            }
        }

        #[expect(clippy::unwrap_used, reason = "tests")]
        fn hostname(&self) -> String {
            self.0.lock().unwrap().hostname.clone()
        }

        #[expect(clippy::unwrap_used, reason = "tests")]
        fn machine(&self) -> Option<String> {
            self.0.lock().unwrap().machine.clone()
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn me() -> dybw_native::fsutil::User {
        dybw_native::fsutil::User { uid: rustix::process::geteuid().as_raw(), groups: None }
    }

    fn trust() -> Trust {
        Trust { search: Some("/usr/bin:/bin".into()), user: me(), exe: None, home: None }
    }

    #[tokio::test]
    async fn the_real_host_builds_a_client_names_the_machine_and_refuses_an_untrusted_pinentry() {
        let host = RealHost::new(trust(), "/nonexistent/pinentry");
        assert!(host.http().is_ok());
        assert!(!host.hostname().is_empty() && !host.hostname().chars().any(char::is_control));
        assert!(host.machine().is_some_and(|m| !m.is_empty()));
        let e = host.password("p", "x", None).await.err().unwrap();
        assert!(matches!(e, PromptError::Untrusted(_)), "{e}");
        let e = host.confirm("x", false).await.err().unwrap();
        assert!(matches!(e, PromptError::Untrusted(_)), "{e}");
    }

    #[tokio::test]
    async fn the_real_host_runs_a_trusted_pinentry() {
        // `true` is not a pinentry: it says nothing, which is a protocol error, and that proves it was run.
        let host = RealHost::new(trust(), "/usr/bin/true");
        let e = host.password("p", "x", None).await.err().unwrap();
        assert!(!matches!(e, PromptError::Untrusted(_)), "{e}");
        let e = host.confirm("x", false).await.err().unwrap();
        assert!(!matches!(e, PromptError::Untrusted(_)), "{e}");
    }
}
