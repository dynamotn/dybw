"""P4.5 end to end: dybw-agent as the SSH agent of real OpenSSH clients, logging in to a real sshd.

The vault holds one SSH key item of each type (Ed25519, RSA, ECDSA P-256/384/521), made with ssh-keygen and
uploaded through bwclient; sshd (run as the test user on 127.0.0.1, in this container) trusts the public keys read
back from those items, and the private key files are deleted, so a login can only sign through the agent.
Every login names the agent with `-o IdentityAgent` and the key with `IdentitiesOnly` + its public key file. The
fake pinentry log tells what the user was asked (prompts() of test_policy: `always` means "always" was offered).

"Always" is per client process (pid, start time, image) and one `ssh` makes one signature per login, so it is
tested with a real single-process double sign: `ssh-keygen -Y sign -U` over two files. The locked profile is
tested at the protocol level (ssh_agent_client.py), because no OpenSSH client asks an agent to sign with a key the
agent does not list. The tests run in file order and share one agent; `ssh-add -d`/`-D` run last, since a removal
lasts until the agent restarts.
"""

import base64
import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from test_cli import FOLDER, ensure_unlocked, pinentry, world  # noqa: F401  (world is a fixture)
from test_policy import LOG, prompts, script_in, via

PORT = 2222
SSHD = "/usr/sbin/sshd"
SSH = os.path.realpath(shutil.which("ssh") or "/usr/bin/ssh")
CLIENT = Path(__file__).with_name("ssh_agent_client.py")
KEYS = {"ed25519": ["-t", "ed25519"], "rsa": ["-t", "rsa", "-b", "3072"], "p256": ["-t", "ecdsa", "-b", "256"],
        "p384": ["-t", "ecdsa", "-b", "384"], "p521": ["-t", "ecdsa", "-b", "521"]}
USER = getpass.getuser()


def fingerprint(pub):
    return subprocess.run(["ssh-keygen", "-lf", str(pub)], capture_output=True, text=True, check=True).stdout.split()[1]


@pytest.fixture(scope="module")
def keys(account):
    """{kind: {"id", "name", "pub": path of the public key read back from the vault, "fp"}}; no private key file."""
    d = Path(tempfile.mkdtemp(prefix="k", dir="/tmp"))
    out = {}
    for kind, args in KEYS.items():
        path = d / kind
        name = f"ssh-{kind}"
        subprocess.run(["ssh-keygen", "-q", *args, "-N", "", "-C", name, "-f", str(path)], check=True)
        item = account.add_typed(FOLDER, 5, name, "sshKey", {
            "privateKey": path.read_text(), "publicKey": path.with_suffix(".pub").read_text().strip(),
            "keyFingerprint": fingerprint(path.with_suffix(".pub")),
        })
        path.unlink()
        pub = d / f"{kind}.pub"
        pub.write_text(account.ssh_public(item["id"]) + "\n")
        out[kind] = {"id": item["id"], "name": name, "pub": pub, "fp": fingerprint(pub)}
    yield out
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="module")
def sshd(keys):
    """sshd on 127.0.0.1:PORT run as this user, trusting the vault's SSH keys; a known_hosts file for its host key."""
    if not os.path.exists(SSHD):
        pytest.skip("no sshd: run the suite in its container (scripts/e2e.sh)")
    d = Path(tempfile.mkdtemp(prefix="s", dir="/tmp"))
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(d / "host")], check=True)
    (d / "authorized_keys").write_text("".join(k["pub"].read_text() for k in keys.values()))
    (d / "sshd_config").write_text(
        f"Port {PORT}\nListenAddress 127.0.0.1\nHostKey {d}/host\nPidFile {d}/sshd.pid\n"
        f"AuthorizedKeysFile {d}/authorized_keys\nStrictModes no\nUsePAM no\nPasswordAuthentication no\n"
        # A refused login must not get 127.0.0.1 penalized for the next tests; DEBUG2 logs each key's algorithm.
        "KbdInteractiveAuthentication no\nPerSourcePenalties no\nLogLevel DEBUG2\n"
    )
    host = (d / "host.pub").read_text().split()
    (d / "known_hosts").write_text(f"[127.0.0.1]:{PORT} {host[0]} {host[1]}\n")
    log = d / "sshd.log"
    proc = subprocess.Popen([SSHD, "-D", "-f", str(d / "sshd_config"), "-E", str(log)])
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=1).close()
            break
        except OSError:
            assert proc.poll() is None, log.read_text() if log.exists() else "sshd exited"
            time.sleep(0.1)
    proc.dir, proc.log, proc.known = d, log, d / "known_hosts"
    proc.host_fp = fingerprint(d / "host.pub")
    yield proc
    proc.terminate()
    proc.wait(10)
    shutil.rmtree(d, ignore_errors=True)


def agent_sock(world):
    return str(world.root / "run/dybw/ssh-agent.sock")


def env_of(world, ai=False):
    env = {k: v for k, v in world.env.items() if k != "SSH_AUTH_SOCK"}
    return {**env, "CLAUDECODE": "1"} if ai else env


def ssh(world, sshd, key, confirm="once", ai=False):
    """Log in and run `echo logged-in`, the fake pinentry answering `confirm`."""
    LOG.unlink(missing_ok=True)
    pinentry(pins=[], confirm=confirm)
    cmd = [SSH, "-F", "/dev/null", "-p", str(PORT), "-o", f"IdentityAgent={agent_sock(world)}",
           "-o", "IdentitiesOnly=yes", "-o", f"IdentityFile={key['pub']}", "-o", f"UserKnownHostsFile={sshd.known}",
           "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
           "-o", "KbdInteractiveAuthentication=no", f"{USER}@127.0.0.1", "echo", "logged-in"]
    return subprocess.run(cmd, env=env_of(world, ai), capture_output=True, text=True, timeout=90)


def sign_files(world, key, *files, confirm="once", ai=False):
    """`ssh-keygen -Y sign -U` over `files` in one process (one signature per file), through the agent."""
    LOG.unlink(missing_ok=True)
    pinentry(pins=[], confirm=confirm)
    for f in files:
        Path(f"{f}.sig").unlink(missing_ok=True)
    env = {**env_of(world, ai), "SSH_AUTH_SOCK": agent_sock(world)}
    cmd = ["ssh-keygen", "-Y", "sign", "-U", "-n", "file", "-f", str(key["pub"]), *map(str, files)]
    return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=90)


def verifies(key, path):
    with open(path, "rb") as data:
        r = subprocess.run(["ssh-keygen", "-Y", "check-novalidate", "-n", "file", "-f", str(key["pub"]),
                            "-s", f"{path}.sig"], stdin=data, capture_output=True, text=True)
    return r.returncode == 0


def ssh_add(world, *args):
    env = {**env_of(world), "SSH_AUTH_SOCK": agent_sock(world)}
    return subprocess.run(["ssh-add", *args], env=env, capture_output=True, text=True, timeout=30)


def raw_sign(world, key, data, pins=(), confirm="once", ai=False):
    """A sign request from ssh_agent_client.py (a separate process, so CLAUDECODE is in its own environment)."""
    LOG.unlink(missing_ok=True)
    pinentry(pins=list(pins), confirm=confirm)
    f = world.root / "raw.data"
    f.write_bytes(data)
    cmd = [sys.executable, str(CLIENT), agent_sock(world), str(key["pub"]), str(f)]
    return subprocess.run(cmd, env=env_of(world, ai), capture_output=True, text=True, timeout=90)


def log_text():
    return LOG.read_text() if LOG.exists() else ""


def test_login_and_unlock(world, account, keys, sshd):
    config = Path(world.env["HOME"]) / ".config/dybw/config.toml"
    config.write_text(config.read_text() + '[ssh_agent]\nprofiles = ["e2e"]\n')
    r = world("login", pins=[account.client_id, account.client_secret])
    assert r.returncode == 0, r.stderr
    ensure_unlocked(world, account)
    assert world("sync").returncode == 0


def test_ssh_add_lists_every_key_by_item_name(world, keys):
    r = ssh_add(world, "-l")
    assert r.returncode == 0, r.stderr
    listed = {line.split()[1]: line.split()[2] for line in r.stdout.splitlines()}
    assert listed == {k["fp"]: k["name"] for k in keys.values()}, r.stdout


@pytest.mark.parametrize("kind", list(KEYS))
def test_each_key_type_logs_in_after_a_yes_naming_the_destination(world, keys, sshd, kind):
    key = keys[kind]
    mark = sshd.log.stat().st_size
    r = ssh(world, sshd, key, confirm="once")
    assert (r.returncode, r.stdout) == (0, "logged-in\n"), (r.stderr, world.log.read_text())
    (p,) = prompts()
    for part in (f"dybw profile e2e: allow the SSH client {SSH}", f'log in as "{USER}"',
                 f"to the host whose key is {sshd.host_fp}", f'with the SSH key "{key["name"]}" ({key["fp"]})'):
        assert part in p["text"], (part, p["text"])
    # `ssh` is a launcher: never offered "always" (the main socket's rule).
    assert not p["always"] and "NOT an SSH login" not in p["text"], p
    if kind == "rsa":
        # The signature sshd checked: an RSA key signs with SHA-2 (rsa-sha2-256/512), never ssh-rsa (SHA-1).
        # sshd's auth2-pubkey.c logs `debug2_f("%s user %s %s public key %s %s", valid, user, "attempting", pkalg,
        # keystring)`: the word after "attempting public key " is the signature algorithm the client used.
        log = sshd.log.read_text()[mark:]
        algs = {line.split("attempting public key ")[1].split()[0] for line in log.splitlines()
                if "attempting public key " in line}
        assert algs and algs <= {"rsa-sha2-256", "rsa-sha2-512"}, log


def test_a_no_refuses_the_login(world, keys, sshd):
    r = ssh(world, sshd, keys["ed25519"], confirm="deny")
    assert r.returncode == 255 and "logged-in" not in r.stdout
    assert len(prompts()) == 1


def test_always_lasts_for_that_process_only(world, keys):
    key = keys["ed25519"]
    files = [world.root / "one.txt", world.root / "two.txt"]
    for f in files:
        f.write_text(f"{f.name}\n")
    r = sign_files(world, key, *files, confirm="always")
    assert r.returncode == 0, r.stderr
    (p,) = prompts()  # the second signature of the same process was not asked about
    assert p["always"] and "sign data that is NOT an SSH login" in p["text"], p
    assert "ssh-keygen" in p["text"], p
    assert all(verifies(key, f) for f in files)
    # Another process of the same program is asked again.
    r = sign_files(world, key, files[0], confirm="deny")
    assert r.returncode != 0 and len(prompts()) == 1


def test_two_ssh_logins_are_two_processes_and_asked_twice(world, keys, sshd):
    for _ in range(2):
        r = ssh(world, sshd, keys["p256"], confirm="always")
        assert r.returncode == 0, r.stderr
        assert len(prompts()) == 1


def test_an_ai_marked_client_is_confirmed_every_time(world, keys, sshd):
    key = keys["ed25519"]
    files = [world.root / "ai1.txt", world.root / "ai2.txt"]
    for f in files:
        f.write_text("ai\n")
    r = sign_files(world, key, *files, confirm="always", ai=True)
    assert r.returncode == 0, r.stderr
    asked = prompts()
    assert len(asked) == 2 and not any(p["always"] for p in asked), asked
    for p in asked:
        assert "of the AI agent" in p["text"] and "(asked every time for this client)" in p["text"], p
    r = ssh(world, sshd, key, confirm="always", ai=True)
    assert r.returncode == 0, r.stderr
    (p,) = prompts()
    assert not p["always"] and f"to the host whose key is {sshd.host_fp}" in p["text"], p


def test_a_policy_deny_refuses_signs_without_a_question(world, keys, sshd):
    s = script_in(world, "p.sh")
    r = via(world, s, "policy", "deny", SSH, confirm="once")
    assert r.returncode == 0, r.stderr
    r = ssh(world, sshd, keys["ed25519"], confirm="always")
    assert r.returncode == 255 and prompts() == [], r.stderr
    r = via(world, s, "policy", "forget", SSH, confirm="once")
    assert r.returncode == 0, r.stderr
    r = ssh(world, sshd, keys["ed25519"], confirm="once")
    assert r.returncode == 0 and len(prompts()) == 1, r.stderr


def ed25519_verifies(key, data, hexsig):
    blob = bytes.fromhex(hexsig)
    alg_len = int.from_bytes(blob[:4], "big")
    assert blob[4:4 + alg_len] == b"ssh-ed25519"
    sig = blob[8 + alg_len:]
    pub = base64.b64decode(key["pub"].read_text().split()[1])
    Ed25519PublicKey.from_public_bytes(pub[-32:]).verify(sig, data)  # raises when it does not verify
    return True


def test_a_locked_profile_offers_no_key_and_a_sign_unlocks_then_confirms(world, account, keys):
    assert world("lock").returncode == 0
    r = ssh_add(world, "-l")
    assert r.returncode == 1 and "no identities" in r.stdout, (r.stdout, r.stderr)
    r = raw_sign(world, keys["ed25519"], b"challenge", pins=[account.password], confirm="once")
    assert r.returncode == 0, (r.stderr, world.log.read_text())
    assert ed25519_verifies(keys["ed25519"], b"challenge", r.stdout.strip())
    log = log_text()
    assert log.index("GETPIN") < log.index("CONFIRM") and "an SSH signature asked by" in log, log
    (p,) = prompts()
    assert "NOT an SSH login" in p["text"], p
    assert world("unlocked").returncode == 0


def test_an_ai_marked_client_is_never_asked_to_unlock(world, account, keys):
    assert world("lock").returncode == 0
    r = raw_sign(world, keys["ed25519"], b"challenge", pins=[account.password], confirm="once", ai=True)
    assert r.returncode == 1 and r.stdout == "", r
    assert "GETPIN" not in log_text() and prompts() == []
    assert world("unlocked").returncode == 1
    ensure_unlocked(world, account)


def test_ssh_add_d_and_capital_d_change_only_the_agents_view(world, account, keys, sshd):
    gone = keys["p384"]
    r = ssh_add(world, "-d", str(gone["pub"]))
    assert r.returncode == 0, r.stderr
    listed = ssh_add(world, "-l").stdout
    assert gone["fp"] not in listed and keys["ed25519"]["fp"] in listed, listed
    # No OpenSSH client asks for a key the agent does not list: the protocol client does, and gets a failure with no
    # question.
    r = raw_sign(world, gone, b"challenge", confirm="once")
    assert r.returncode == 1 and r.stdout == "", r
    assert prompts() == [] and "GETPIN" not in log_text()
    r = ssh_add(world, "-D")
    assert r.returncode == 0, r.stderr
    r = ssh_add(world, "-l")
    assert r.returncode == 1 and "no identities" in r.stdout
    # The vault still holds every key.
    assert all(account.ssh_public(k["id"]) for k in keys.values())
    assert "ssh-p384" in world("list").stdout.splitlines()


def test_the_audit_log_records_each_signature_decision(world, keys, sshd):
    raw = (Path(world.env["HOME"]) / ".local/state/dybw/audit.log").read_text()
    lines = [json.loads(line) for line in raw.splitlines()]
    signs = [e for e in lines if e["op"] == "ssh-sign"]
    assert {"confirmed", "remembered", "granted", "declined", "denied"} <= {e["verdict"] for e in signs}, signs
    assert {e["key"] for e in signs} == {k["fp"] for k in keys.values()}
    assert {e.get("item") for e in signs} - {None} == {k["id"] for k in keys.values()}
    logins = [e for e in signs if e["kind"] == "login"]
    assert logins and {e.get("dest") for e in logins} == {sshd.host_fp}, logins
    assert not any(e.get("forwarded") for e in signs)
    assert {e.get("kind") for e in signs} - {None} == {"login", "data"}
    assert {"ai", "invoker"} <= {e["class"] for e in signs}
    assert {e["exe"] for e in signs if e["kind"] == "login"} == {SSH}
    # The AI-marked client refused an unlock: audited as denied, with no question.
    (refused,) = [e for e in signs if e["class"] == "ai" and e["verdict"] == "denied"]
    assert refused["key"] == keys["ed25519"]["fp"] and refused.get("item") is None, refused
    # The removed key's sign was refused before any item of ours: denied, with no item.
    gone = [e for e in signs if e["key"] == keys["p384"]["fp"] and e["verdict"] == "denied"]
    assert gone and all(e.get("item") is None for e in gone), gone
    # Every removal is audited: the key's fingerprint for `-d`, "all" for `-D`.
    removes = [e for e in lines if e["op"] == "ssh-remove"]
    assert [(e["key"], e["verdict"]) for e in removes] == [(keys["p384"]["fp"], "granted"), ("all", "granted")], removes
    r = world("audit", "-n", "500")
    assert r.returncode == 0 and "ssh-sign" in r.stdout, r.stderr
