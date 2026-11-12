"""dybw and dybw-agent against a real Vaultwarden: login, unlock, reads behind the confirmation, lock, offline.

The tests run in file order and share one agent. The agent reaches Vaultwarden through a small TCP proxy so the
offline test can switch the server off. Pinentry answers come from /tmp/fake-pinentry.json (see fake_pinentry.py).
"""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlparse

import pytest

from conftest import URL

CTL = Path("/tmp/fake-pinentry.json")
PROXY_PORT = 8099
FOLDER = "e2e"
HISTORY = [("old-pw-1", "2024-01-02T03:04:05.000Z"), ("old-pw-2", "2024-05-06T07:08:09.000Z")]
PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-body\n-----END OPENSSH PRIVATE KEY-----"


class Proxy:
    """Forwards 127.0.0.1:PROXY_PORT to Vaultwarden; stop() makes the server unreachable."""

    def __init__(self, target):
        u = urlparse(target)
        self.target = (u.hostname, u.port or 80)
        self.conns = []

    def start(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", PROXY_PORT))
        self.sock.listen(16)
        threading.Thread(target=self._accept, args=(self.sock,), daemon=True).start()

    def _accept(self, sock):
        while True:
            try:
                c, _ = sock.accept()
                up = socket.create_connection(self.target)
            except OSError:
                return
            self.conns += [c, up]
            for a, b in ((c, up), (up, c)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    @staticmethod
    def _pipe(a, b):
        try:
            while data := a.recv(65536):
                b.sendall(data)
        except OSError:
            pass
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def stop(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)  # wakes the accept thread; close() alone does not
        except OSError:
            pass
        self.sock.close()
        for c in self.conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
                c.close()
            except OSError:
                pass
        self.conns = []


def pinentry(**ctl):
    CTL.write_text(json.dumps(ctl))


@pytest.fixture(scope="module")
def world(account, dybw_bin):
    """Seed the vault, write the profile config, and return a runner for dybw commands."""
    guard = account.add_login(
        FOLDER, "guarded", "guard-pw", username="guser", reprompt=1,
    )
    seeded = {
        "login": account.add_login(
            FOLDER, "login-item", "login-pw", username="luser", uri="https://login.example",
            notes="login notes", fields={"api-token": "field-v1", "other": "field-v2"}, history=HISTORY,
        ),
        "note": account.add_note(FOLDER, "note-item", "the note body"),
        "card": account.add_typed(
            FOLDER, 3, "card-item", "card",
            {"cardholderName": "Card Holder", "brand": "Visa", "number": "4111111111111111",
             "expMonth": "12", "expYear": "2030", "code": "737"},
        ),
        "identity": account.add_typed(
            FOLDER, 4, "identity-item", "identity", {"firstName": "Ida", "lastName": "Lovelace"},
        ),
        "ssh": account.add_typed(
            FOLDER, 5, "ssh-item", "sshKey",
            {"privateKey": PRIVATE_KEY, "publicKey": "ssh-ed25519 AAAAFAKEKEY e2e", "keyFingerprint": "SHA256:fake"},
        ),
        "guarded": guard,
    }
    seeded = {k: v["id"] for k, v in seeded.items()}
    ssh = next((c for c in account.sync()["ciphers"] if c["id"] == seeded["ssh"]), None)
    assert ssh and ssh["type"] == 5 and ssh.get("sshKey"), f"Vaultwarden does not return the SSH key item: {ssh}"
    root = Path(tempfile.mkdtemp(prefix="d", dir="/tmp"))
    for d in ("config/dybw", "state", "cache", "run"):
        (root / d).mkdir(parents=True)
    (root / "run").chmod(0o700)
    (root / "config/dybw/config.toml").write_text(
        f'default = "e2e"\n[profiles.e2e]\nserver_url = "http://127.0.0.1:{PROXY_PORT}"\n'
        f'email = "{account.email}"\npinentry = "/usr/local/bin/fake-pinentry"\nlock_timeout_minutes = 0\n'
    )
    env = {
        **os.environ,
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_STATE_HOME": str(root / "state"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "XDG_RUNTIME_DIR": str(root / "run"),
    }
    env.pop("DYBW_PROFILE", None)
    proxy = Proxy(URL)
    proxy.start()
    CTL.unlink(missing_ok=True)

    def run(*args, pins=(), confirm="deny"):
        pinentry(pins=list(pins), confirm=confirm)
        try:
            return subprocess.run([dybw_bin, *args], env=env, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired as e:
            agent_log = run.log.read_text() if run.log.exists() else ""
            pytest.fail(f"dybw {args} hung; agent log:\n{agent_log}\nstderr: {e.stderr}", pytrace=False)

    run.ids = seeded
    run.proxy = proxy
    run.log = root / "run/dybw/agent.log"
    yield run
    run("agent", "stop")
    proxy.stop()
    shutil.rmtree(root, ignore_errors=True)


def ensure_unlocked(world, account):
    if world("unlocked").returncode != 0:
        r = world("unlock", pins=[account.password])
        assert r.returncode == 0, r.stderr


def get(world, *args, confirm="once"):
    r = world("get", *args, confirm=confirm)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_login_stores_the_api_key(world, account):
    r = world("login", pins=[account.client_id, account.client_secret])
    assert r.returncode == 0, (r.stderr, world.log.read_text() if world.log.exists() else "")
    status = world("status").stdout.split("\t")
    assert status[:3] == ["e2e", "logged in", "locked"]


def test_unlock_online(world, account):
    assert world("unlocked").returncode == 1
    r = world("unlock", pins=[account.password])
    assert r.returncode == 0, r.stderr
    assert world("unlocked").returncode == 0
    assert world("status").stdout.split("\t")[:3] == ["e2e", "logged in", "unlocked"]


def test_list_and_search_need_no_confirmation(world, account):
    ensure_unlocked(world, account)
    names = world("list").stdout.splitlines()
    for n in ("login-item", "note-item", "card-item", "identity-item", "guarded"):
        assert n in names, (n, names, world.log.read_text())
    r = world("list", "--fields", "name,user,folder,type", "--folder", FOLDER)
    assert "login-item\tluser\te2e\tLogin" in r.stdout.splitlines()
    rows = json.loads(world("list", "--raw", "--fields", "name").stdout)
    assert {"id": world.ids["note"], "name": "note-item"} in rows
    assert world("search", "luser").stdout.splitlines() == ["login-item"]
    assert "the note body" not in world("list", "--raw").stdout
    assert world("search", "no-such-thing").stdout == ""


def test_get_each_type(world, account):
    ensure_unlocked(world, account)
    assert get(world, "login-item") == "login-pw\n"
    assert get(world, "note-item") == "the note body\n"
    assert get(world, "card-item") == "4111111111111111\n"
    assert get(world, "identity-item") == "Ida Lovelace\n"
    assert get(world, world.ids["login"]) == "login-pw\n"
    assert get(world, "LOGIN-ITEM", "-i") == "login-pw\n"


def test_ssh_key_item(world, account):
    ensure_unlocked(world, account)
    assert world("search", "ssh").stdout.splitlines() == ["ssh-item"]
    assert get(world, "ssh-item") == "ssh-ed25519 AAAAFAKEKEY e2e\n"
    assert get(world, "ssh-item", "-f", "private-key") == PRIVATE_KEY + "\n"


def test_get_fields(world, account):
    ensure_unlocked(world, account)
    assert get(world, "login-item", "-f", "user") == "luser\n"
    assert get(world, "login-item", "-f", "notes") == "login notes\n"
    assert get(world, "login-item", "-f", "api-token") == "field-v1\n"
    assert get(world, "card-item", "-f", "cvv") == "737\n"


def test_get_full(world, account):
    ensure_unlocked(world, account)
    lines = get(world, "login-item", "--full").splitlines()
    assert lines[0] == "login-pw"
    assert "login notes" in lines
    assert "api-token: field-v1" in lines and "other: field-v2" in lines


def test_get_raw(world, account):
    ensure_unlocked(world, account)
    text = get(world, "login-item", "--raw")
    item = json.loads(text)
    assert item["name"] == "login-item"
    assert "login-pw" in text and "luser" in text


def test_get_list_fields(world, account):
    ensure_unlocked(world, account)
    assert get(world, "login-item", "-l").splitlines() == ["api-token", "other"]


def test_history(world, account):
    ensure_unlocked(world, account)
    r = world("history", "login-item", confirm="once")
    assert r.returncode == 0, r.stderr
    lines = r.stdout.splitlines()
    assert len(lines) == 2
    assert sorted(line.split(": ", 1)[1] for line in lines) == ["old-pw-1", "old-pw-2"]


def test_refused_confirmation_is_denied(world, account):
    ensure_unlocked(world, account)
    for args in (("get", "login-item"), ("get", "login-item", "--full"), ("get", "login-item", "-l"), ("history", "login-item")):
        r = world(*args, confirm="deny")
        assert r.returncode == 1 and r.stdout == "" and "denied" in r.stderr, (args, r)
    assert "login-pw" not in r.stderr


def test_reprompt_item_is_denied_without_a_prompt(world, account):
    ensure_unlocked(world, account)
    Path("/tmp/fake-pinentry.log").unlink(missing_ok=True)
    r = world("get", "guarded", confirm="always")
    assert r.returncode == 1 and r.stdout == "" and "denied" in r.stderr
    assert "guarded" in world("list").stdout.splitlines()
    log = Path("/tmp/fake-pinentry.log")  # absent: no pinentry was started at all
    assert not log.exists() or "CONFIRM" not in log.read_text()


def test_lock(world, account):
    ensure_unlocked(world, account)
    assert world("lock").returncode == 0
    assert world("unlocked").returncode == 1
    # A read on a locked profile unlocks first (profiles.md section 4); the user cancels the password question:
    # a denial, nothing confirmed, still locked.
    Path("/tmp/fake-pinentry.log").unlink(missing_ok=True)
    r = world("get", "login-item", confirm="always")
    assert r.returncode == 1 and "denied" in r.stderr and r.stdout == ""
    assert "CONFIRM" not in Path("/tmp/fake-pinentry.log").read_text()
    assert world("unlocked").returncode == 1
    assert world("list").returncode == 1


def test_locked_profile_get_unlocks_first(world, account):
    world("lock")
    Path("/tmp/fake-pinentry.log").unlink(missing_ok=True)
    r = world("get", "login-item", pins=[account.password], confirm="once")
    assert r.returncode == 0 and r.stdout == "login-pw\n", (r.stderr, world.log.read_text())
    log = Path("/tmp/fake-pinentry.log").read_text()
    assert log.count("GETPIN") == 1 and "CONFIRM" in log
    assert world("unlocked").returncode == 0


def test_offline_unlock_from_the_cache(world, account):
    world.proxy.stop()
    try:
        r = world("unlock", pins=[account.password])
        assert r.returncode == 0, (r.stderr, world.log.read_text())
        assert world("unlocked").returncode == 0
        assert "login-item" in world("list").stdout.splitlines()
        assert get(world, "login-item") == "login-pw\n"
        assert world("sync").returncode == 1
    finally:
        world.proxy.start()
