//! The accept loop and one connection: peer check, one request under a read timeout, one reply.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use dybw_proto::{AgentError, MAX_FRAME, Op, Reply, Request, Response, decode_request, encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use crate::agent::{Agent, TICK};

/// Serve until `shutdown` resolves (or fails) or a `StopAgent` reply has been delivered, ticking the idle and sleep
/// checks. Connections in flight are given `drain_timeout` to finish, then cancelled; then every worker is stopped
/// and its keys wiped before this returns.
pub async fn serve(
    agent: Arc<Agent>,
    listener: std::os::unix::net::UnixListener,
    shutdown: impl Future<Output = std::io::Result<()>>,
) -> std::io::Result<()> {
    let listener = UnixListener::from_std(listener)?;
    let ticker = tokio::spawn(ticker(agent.clone()));
    let mut handlers = JoinSet::new();
    let out = tokio::select! {
        out = shutdown => out,
        () = agent.stop.notified() => Ok(()),
        out = accept_loop(&agent, &listener, &mut handlers) => out,
    };
    ticker.abort();
    wind_down(&agent, handlers).await;
    out
}

/// A request may wait on a pinentry for minutes: finish what is quick, cancel the rest, then lock and end every
/// worker. Not generic, so the agent's real `serve` and the tests' share one body.
async fn wind_down(agent: &Agent, mut handlers: JoinSet<()>) {
    if tokio::time::timeout(agent.drain_timeout, drain(&mut handlers)).await.is_err() {
        tracing::warn!("cancelling requests still waiting at shutdown");
        handlers.shutdown().await;
    }
    agent.shutdown().await;
}

async fn drain(handlers: &mut JoinSet<()>) {
    while handlers.join_next().await.is_some() {}
}

async fn ticker(agent: Arc<Agent>) {
    let mut tick = tokio::time::interval(TICK);
    loop {
        tick.tick().await;
        agent.tick().await;
    }
}

/// Ends only on an accept error (out of descriptors, a dead socket): better to stop than to spin.
// rustfmt::skip: coverage counts the closing brace of an endless loop as a line no test reaches, so it shares a line.
#[rustfmt::skip]
async fn accept_loop(agent: &Arc<Agent>, listener: &UnixListener, handlers: &mut JoinSet<()>) -> std::io::Result<()> {
    loop {
        while handlers.try_join_next().is_some() {}
        let (stream, _) = listener.accept().await?;
        let agent = agent.clone();
        handlers.spawn(async move { if handle(agent.clone(), stream).await { agent.stop.notify_one(); } }); } }

/// One connection. A peer of another uid, a slow or oversize or malformed or wrong-version request is dropped
/// without a reply and before any worker is touched. Returns true when the request was `StopAgent`, whose `Done`
/// has by then been written and the connection closed: only then may the agent stop.
pub async fn handle(agent: Arc<Agent>, mut stream: UnixStream) -> bool {
    if !matches!(stream.peer_cred(), Ok(cred) if cred.uid() == agent.uid) {
        tracing::warn!("refused a connection from another user");
        return false;
    }
    let Some(request) = read_request(&mut stream, agent.read_timeout).await else { return false };
    let stop = request.op == Op::StopAgent;
    let reply = agent.dispatch(request.op).await;
    respond(&mut stream, reply, agent.read_timeout).await;
    stop
}

/// Write the reply and close, within `limit`: a client that never reads cannot hold the connection open.
async fn respond(stream: &mut UnixStream, reply: Reply, limit: Duration) {
    let write = async {
        let _ = stream.write_all(&reply_frame(reply)).await;
        let _ = stream.shutdown().await;
    };
    if tokio::time::timeout(limit, write).await.is_err() {
        tracing::warn!("a client did not take its reply in time");
    }
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
            match decode_request(&buf) {
                Ok(Some((request, _))) => return Some(request),
                Ok(None) => {}
                Err(e) => {
                    // The error names a position or a version, never frame text.
                    tracing::warn!(%e, "refused a request frame");
                    return None;
                }
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
    use dybw_proto::{Secret, decode_response};
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
        let (listener, _lock) = crate::socket::bind(&sock_dir, me()).unwrap();
        let served = tokio::spawn(serve(agent.clone(), listener, std::future::pending::<std::io::Result<()>>()));
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
        let (listener, _lock) = crate::socket::bind(&dir.path().join("run"), me()).unwrap();
        serve(agent, listener, async { Ok(()) }).await.unwrap();
    }

    #[tokio::test]
    async fn only_a_delivered_stop_agent_asks_the_agent_to_stop() {
        let dir = tempfile::tempdir().unwrap();
        let (agent, _) = agent(dir.path());
        for (op, stops) in [("status", false), ("stop_agent", true)] {
            let (mut client, server) = Tokio::pair().unwrap();
            let task = tokio::spawn(handle(agent.clone(), server));
            let json = if op == "status" {
                r#"{"version":1,"op":"status","profile":null}"#
            } else {
                r#"{"version":1,"op":"stop_agent"}"#
            };
            client.write_all(&frame(json)).await.unwrap();
            let mut out = Vec::new();
            client.read_to_end(&mut out).await.unwrap();
            // The reply and the close come first; the flag is what tells `serve` to stop afterwards.
            assert_eq!(task.await.unwrap(), stops, "{op}");
            assert!(!out.is_empty());
        }
    }

    #[tokio::test]
    async fn a_client_that_never_reads_cannot_hold_the_reply_open() {
        let (_client, mut server) = Tokio::pair().unwrap();
        let big = Reply::Value { value: Secret::new("x".repeat(MAX_FRAME - 100)) };
        // Far more than a socket buffer holds, and nobody reads it.
        let done = tokio::time::timeout(Duration::from_secs(10), respond(&mut server, big, Duration::from_millis(50)));
        assert!(done.await.is_ok(), "the write must give up at the timeout");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn serve_answers_connections_in_flight_before_it_stops_the_workers() {
        let dir = tempfile::Builder::new().prefix("d").tempdir_in("/tmp").unwrap();
        let (mut agent, _) = agent(dir.path());
        Arc::get_mut(&mut agent).unwrap().read_timeout = Duration::from_secs(5);
        let (listener, _lock) = crate::socket::bind(&dir.path().join("run"), me()).unwrap();
        let path = dir.path().join("run/agent.sock");
        let served = tokio::spawn(serve(agent.clone(), listener, std::future::pending::<std::io::Result<()>>()));
        // A connects first and is slow; B stops the agent meanwhile.
        let slow = {
            let (path, ready) = (path.clone(), tokio::sync::oneshot::channel::<()>());
            let (tx, rx) = ready;
            let reply = tokio::task::spawn_blocking(move || {
                use std::io::{Read, Write};
                let mut s = std::os::unix::net::UnixStream::connect(&path).unwrap();
                tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(400));
                s.write_all(&encode(&dybw_proto::Request::new(Op::Status { profile: None })).unwrap()).unwrap();
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).unwrap();
                decode_response(&buf).unwrap().unwrap().0.reply
            });
            rx.await.unwrap();
            reply
        };
        let stopped = {
            let path = path.clone();
            tokio::task::spawn_blocking(move || ask(&path, Op::StopAgent)).await.unwrap()
        };
        assert_eq!(stopped, Reply::Done);
        assert!(matches!(slow.await.unwrap(), Reply::Status { .. }), "the connection in flight was served, not cut");
        served.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_waiting_on_the_user_does_not_hold_the_shutdown_for_ever() {
        use crate::agent::testing::{agent_world, seed_credentials};
        use crate::host::fake::Answer;
        let dir = tempfile::Builder::new().prefix("d").tempdir_in("/tmp").unwrap();
        let (mut agent, _, host) = agent_world(dir.path());
        Arc::get_mut(&mut agent).unwrap().drain_timeout = Duration::from_millis(100);
        seed_credentials(&agent, "work");
        host.answer(Answer::Hang);
        let (listener, _lock) = crate::socket::bind(&dir.path().join("run"), me()).unwrap();
        let path = dir.path().join("run/agent.sock");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let served =
            tokio::spawn(serve(agent.clone(), listener, async move { stopped.await.map_err(std::io::Error::other) }));
        // An unlock that waits on a pinentry nobody answers.
        let waiting = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write};
            let mut s = std::os::unix::net::UnixStream::connect(&path).unwrap();
            s.write_all(&encode(&dybw_proto::Request::new(Op::Unlock { profile: None })).unwrap()).unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).unwrap();
            buf
        });
        while host.world().asked.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        stop.send(()).unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(5), served).await;
        assert!(ended.unwrap().unwrap().is_ok());
        assert!(waiting.await.unwrap().is_empty(), "the cancelled request got no reply");
        assert_eq!(agent.worker_count(), 0, "and the workers are stopped");
    }
}
