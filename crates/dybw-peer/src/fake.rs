//! A scripted [`ProcessSource`] for tests of the crates above this one.

use std::collections::HashMap;
use std::os::fd::BorrowedFd;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::{Error, Peer, Process, ProcessSource};

#[derive(Default)]
struct State {
    peer: Option<Peer>,
    procs: HashMap<u32, Process>,
}

/// Answers from a table: `set_peer` is who every socket connects to, `add`
/// puts a process in the table, `kill` takes it out again.
#[derive(Default)]
pub struct Fake(Mutex<State>);

impl Fake {
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn set_peer(&self, peer: Peer) {
        self.state().peer = Some(peer);
    }

    pub fn add(&self, pid: u32, process: Process) {
        self.state().procs.insert(pid, process);
    }

    pub fn kill(&self, pid: u32) {
        self.state().procs.remove(&pid);
    }
}

impl ProcessSource for Fake {
    fn peer_of(&self, _sock: BorrowedFd<'_>) -> Result<Peer, Error> {
        self.state().peer.clone().ok_or(Error::Gone)
    }

    fn process(&self, pid: u32) -> Result<Process, Error> {
        self.state().procs.get(&pid).cloned().ok_or(Error::Gone)
    }

    /// Same pid, still in the table, same start time and image (an exec changes it).
    fn still_same(&self, peer: &Peer) -> bool {
        self.state().procs.get(&peer.pid).is_some_and(|p| p.start == peer.token.start && p.image == peer.token.image)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::Token;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    fn proc(start: u64) -> Process {
        Process { exe: PathBuf::from("/bin/x"), ppid: 1, start, image: vec![], argv: None, env: None }
    }

    #[test]
    fn scripted_answers() {
        let (a, _b) = UnixStream::pair().unwrap();
        let fake = Fake::default();
        assert_eq!(fake.peer_of(a.as_fd()).unwrap_err(), Error::Gone);
        let peer = Peer { pid: 7, uid: 1, token: Token::plain(0, 5) };
        fake.set_peer(peer.clone());
        assert_eq!(fake.peer_of(a.as_fd()).unwrap().pid, 7);
        assert!(!fake.still_same(&peer));
        fake.add(7, proc(5));
        assert_eq!(fake.process(7).unwrap(), proc(5));
        assert!(fake.still_same(&peer));
        fake.add(7, proc(6));
        assert!(!fake.still_same(&peer));
        fake.add(7, Process { image: vec![1], ..proc(5) });
        assert!(!fake.still_same(&peer));
        fake.kill(7);
        assert_eq!(fake.process(7), Err(Error::Gone));
    }
}
