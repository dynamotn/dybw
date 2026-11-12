//! The accept loop and one connection: peer check, one request under a read timeout, one reply.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use dybw_proto::{AgentError, MAX_FRAME, Reply, Request, Response, decode_request, encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

use crate::agent::{Agent, TICK};

/// Serve until `shutdown` resolves or `StopAgent` arrives, ticking the idle and sleep checks. Every worker is
/// stopped, and its keys wiped, before this returns.
pub async fn serve(
    agent: Arc<Agent>,
    listener: std::os::unix::net::UnixListener,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let listener = UnixListener::from_std(listener)?;
    let ticker = tokio::spawn(ticker(agent.clone()));
    let out = tokio::select! {
        () = shutdown => Ok(()),
        () = agent.stop.notified() => Ok(()),
        out = accept_loop(&agent, &listener) => out,
    };
    ticker.abort();
    agent.shutdown().await;
    out
}

async fn ticker(agent: Arc<Agent>) {
    let mut tick = tokio::time::interval(TICK);
    loop {
        tick.tick().await;
        agent.tick().await;
    }
}

/// Ends only on an accept error (out of descriptors, a dead socket): better to stop than to spin.
// The closing brace of a loop that never ends is a line no test can reach, so the loop's own closes it.
#[rustfmt::skip]
async fn accept_loop(agent: &Arc<Agent>, listener: &UnixListener) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(handle(agent.clone(), stream)); } }

/// One connection. A peer of another uid, a slow or oversize or malformed or wrong-version request is dropped
/// without a reply and before any worker is touched.
pub async fn handle(agent: Arc<Agent>, mut stream: UnixStream) {
    if !matches!(stream.peer_cred(), Ok(cred) if cred.uid() == agent.uid) {
        return;
    }
    let Some(request) = read_request(&mut stream, agent.read_timeout).await else { return };
    let reply = agent.dispatch(request.op).await;
    let _ = stream.write_all(&reply_frame(reply)).await;
    let _ = stream.shutdown().await;
}

/// A reply too large for a frame is an agent fault, answered as `Internal`, never dropped silently.
fn reply_frame(reply: Reply) -> Zeroizing<Vec<u8>> {
    encode(&Response::new(reply)).unwrap_or_else(|_| {
        let internal = Response::new(Reply::Error { error: AgentError::Internal });
        // Fixed and tiny: it always fits.
        encode(&internal).unwrap_or_default()
    })
}

/// The request on `stream`, or `None` on timeout, EOF, a read error, or a frame `decode_request` refuses.
/// The buffer is allocated once at its largest, so no unwiped copy is left behind, and wiped on drop.
async fn read_request(stream: &mut UnixStream, limit: Duration) -> Option<Request> {
    let read = async {
        let mut buf = Zeroizing::new(Vec::with_capacity(4 + MAX_FRAME));
        loop {
            if let Some((request, _)) = decode_request(&buf).ok()? {
                return Some(request);
            }
            if stream.read_buf(&mut *buf).await.ok()? == 0 {
                return None;
            }
        }
    };
    tokio::time::timeout(limit, read).await.ok().flatten()
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::agent::testing::{agent, me};
    use dybw_proto::{Op, Secret, decode_response};
    use tokio::net::UnixStream as Tokio;

    fn frame(json: &str) -> Vec<u8> {
        let mut out = (json.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(json.as_bytes());
        out
    }

    /// Send `bytes` over a connected pair, close the write side, and return what the agent answers.
    async fn answer(agent: &Arc<Agent>, bytes: &[u8], close: bool) -> Option<Reply> {
        let (mut client, server) = Tokio::pair().unwrap();
        let task = tokio::spawn(handle(agent.clone(), server));
        client.write_all(bytes).await.unwrap();
        if close {
            client.shutdown().await.unwrap();
        }
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap();
        decode_response(&out).unwrap().map(|(r, _)| r.reply)
    }

    fn status() -> Vec<u8> {
        frame(r#"{"version":1,"op":"status","profile":null}"#)
    }

    #[tokio::test]
    async fn a_good_request_is_answered_once() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, _) = agent(dir.path());
        let reply = answer(&agent, &status(), false).await.unwrap();
        assert!(matches!(reply, Reply::Status { .. }));
    }

    #[tokio::test]
    async fn a_peer_of_another_uid_is_dropped_before_any_worker() {
        let dir = tempfile::tempdir().unwrap();
        let (mut agent, _) = agent(dir.path());
        Arc::get_mut(&mut agent).unwrap().uid = me() + 1;
        assert_eq!(answer(&agent, &status(), false).await, None);
        assert_eq!(agent.worker_count(), 0);
    }

    #[tokio::test]
    async fn bad_frames_are_dropped_before_any_vault_work() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, _) = agent(dir.path());
        let oversize = ((dybw_proto::MAX_FRAME + 1) as u32).to_be_bytes();
        let cases: Vec<(&str, Vec<u8>, bool)> = vec![
            ("oversize", oversize.to_vec(), false),
            ("unknown version", frame(r#"{"version":9,"op":"status","profile":null}"#), false),
            ("unknown op", frame(r#"{"version":1,"op":"decrypt"}"#), false),
            ("not json", frame("not json"), false),
            ("eof mid frame", status().get(..10).unwrap().to_vec(), true),
            ("nothing", vec![], true),
        ];
        for (name, bytes, close) in cases {
            assert_eq!(answer(&agent, &bytes, close).await, None, "{name}");
        }
        assert_eq!(agent.worker_count(), 0, "no worker started for any of them");
    }

    #[tokio::test]
    async fn a_silent_client_is_cut_off_after_the_read_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let (mut agent, _) = agent(dir.path());
        Arc::get_mut(&mut agent).unwrap().read_timeout = Duration::from_millis(50);
        // The client sends half a header and then waits; the agent closes on it.
        assert_eq!(answer(&agent, &[0, 0], false).await, None);
        assert_eq!(agent.worker_count(), 0);
    }

    #[test]
    fn a_reply_too_large_for_a_frame_becomes_internal() {
        let huge = Reply::Value { value: Secret::new("x".repeat(MAX_FRAME + 1)) };
        let (r, _) = decode_response(&reply_frame(huge)).unwrap().unwrap();
        assert_eq!(r.reply, Reply::Error { error: AgentError::Internal });
        let (r, _) = decode_response(&reply_frame(Reply::Done)).unwrap().unwrap();
        assert_eq!(r.reply, Reply::Done);
    }

    fn ask(path: &std::path::Path, op: Op) -> Reply {
        use std::io::{Read, Write};
        let mut s = std::os::unix::net::UnixStream::connect(path).unwrap();
        s.write_all(&encode(&dybw_proto::Request::new(op)).unwrap()).unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        decode_response(&buf).unwrap().unwrap().0.reply
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_agent_is_refused_while_the_first_answers_and_stop_ends_serve() {
        let dir = tempfile::Builder::new().prefix("d").tempdir_in("/tmp").unwrap();
        let (agent, _) = agent(dir.path());
        let sock_dir = dir.path().join("run");
        let listener = crate::socket::bind(&sock_dir, me()).unwrap();
        let served = tokio::spawn(serve(agent.clone(), listener, std::future::pending()));
        let path = sock_dir.join("agent.sock");

        assert!(crate::socket::bind(&sock_dir, me()).is_err(), "the live socket is not replaced");
        let first = {
            let path = path.clone();
            tokio::task::spawn_blocking(move || ask(&path, Op::Status { profile: None })).await.unwrap()
        };
        assert!(matches!(first, Reply::Status { .. }), "the first agent still answers");

        let stopped = tokio::task::spawn_blocking(move || ask(&path, Op::StopAgent)).await.unwrap();
        assert_eq!(stopped, Reply::Done);
        served.await.unwrap().unwrap();
        assert_eq!(agent.worker_count(), 0, "workers are stopped on the way out");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn serve_also_ends_on_its_shutdown_signal() {
        let dir = tempfile::Builder::new().prefix("d").tempdir_in("/tmp").unwrap();
        let (agent, _) = agent(dir.path());
        let listener = crate::socket::bind(&dir.path().join("run"), me()).unwrap();
        serve(agent, listener, async {}).await.unwrap();
    }
}
