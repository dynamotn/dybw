"""The caller policy and the AI-agent class, end to end on Linux (so dybw-peer's /proc code runs for real).

Callers are made with small scripts: `bash /abs/s.sh` is an invoker the policy can remember, `./s.sh` is not
rememberable, `CLAUDECODE=1` or a binary under `.../claude/versions/` is an AI agent, and `setsid -f ... exec dybw`
leaves dybw with no parent. The fake pinentry log tells what the user was asked. The tests run in file order and
share one agent and one policy file.
"""

import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from test_cli import ensure_unlocked, pinentry, world  # noqa: F401  (world is a fixture)

LOG = Path("/tmp/fake-pinentry.log")
BASH = os.path.realpath(shutil.which("bash"))
SCRIPT = '#!/bin/bash\n"$DYBW" "$@"\nexit $?\n'


def via(world, script, *args, confirm="deny", cwd=None, extra=None):
    """Run `bash <script> args` (the script runs dybw with the args) after the pinentry answers `confirm`."""
    LOG.unlink(missing_ok=True)
    pinentry(pins=[], confirm=confirm)
    env = {**world.env, "DYBW": world.bin, **(extra or {})}
    return subprocess.run(["bash", str(script), *args], env=env, cwd=cwd, capture_output=True, text=True, timeout=60)


def prompts():
    """The confirmations the fake pinentry was asked since the log was last removed."""
    found, cur = [], None
    for line in LOG.read_text().splitlines() if LOG.exists() else []:
        cmd, _, arg = line.partition(" ")
        if cmd == "SETTITLE":
            cur = {"title": arg, "desc": [], "confirms": 0}
        elif cur and cmd == "SETDESC":
            cur["desc"].append(arg)
        elif cur and cmd == "CONFIRM":
            cur["confirms"] += 1
            if cur["confirms"] == 1:
                found.append(cur)
    for p in found:
        p["text"] = p["desc"][0]
        p["always"] = p["confirms"] > 1  # "Remember this decision" is a second CONFIRM
    return found


def write(path, text):
    """Write a script and let a second pass: on Linux a process start is only known to the second (the boot time in
    /proc/stat), so a file written less than a second before the run looks changed after the start (Unknown)."""
    path.write_text(text)
    time.sleep(1.2)


def script_in(world, name, subdir="scripts"):
    d = world.root / subdir
    d.mkdir(exist_ok=True)
    path = d / name
    write(path, SCRIPT)
    return path


def test_login_and_unlock(world, account):
    r = world("login", pins=[account.client_id, account.client_secret])
    assert r.returncode == 0, r.stderr
    ensure_unlocked(world, account)


def test_a_script_read_is_confirmed_remembered_and_asked_again_when_edited(world):
    s = script_in(world, "a.sh")
    r = via(world, s, "get", "login-item", confirm="always")
    assert (r.returncode, r.stdout) == (0, "login-pw\n"), r.stderr
    (p,) = prompts()
    assert p["title"] == "dybw" and p["always"]
    for part in (BASH, str(s), "login-item", "dybw get"):
        assert part in p["text"], (part, p["text"])
    # Remembered: a "deny" pinentry would refuse, but it is never asked.
    r = via(world, s, "get", "login-item", confirm="deny")
    assert (r.returncode, r.stdout) == (0, "login-pw\n"), r.stderr
    assert prompts() == []
    # The script changed: the grant no longer applies.
    write(s, SCRIPT + "# edited\n")
    r = via(world, s, "get", "login-item", confirm="once")
    assert (r.returncode, r.stdout) == (0, "login-pw\n"), r.stderr
    (p,) = prompts()
    assert p["always"] and str(s) in p["text"]
    # "Once" stored nothing: still asked.
    via(world, s, "get", "login-item", confirm="deny")
    assert len(prompts()) == 1


def test_a_relative_script_is_asked_every_time_and_never_offered_always(world):
    s = script_in(world, "r.sh", "rel")
    for _ in range(2):
        r = via(world, "./r.sh", "get", "login-item", confirm="always", cwd=s.parent)
        assert (r.returncode, r.stdout) == (0, "login-pw\n"), r.stderr
        (p,) = prompts()
        assert not p["always"] and str(s) in p["text"], p
    r = via(world, "./r.sh", "get", "login-item", confirm="deny", cwd=s.parent)
    assert r.returncode == 1 and "denied" in r.stderr and r.stdout == ""
    assert len(prompts()) == 1


def test_claudecode_env_is_denied_a_value_but_can_list(world):
    LOG.unlink(missing_ok=True)
    pinentry(pins=[], confirm="always")
    env = {**world.env, "CLAUDECODE": "1"}
    for args in (("get", "login-item"), ("get", "login-item", "--full"), ("history", "login-item")):
        r = subprocess.run([world.bin, *args], env=env, capture_output=True, text=True, timeout=60)
        assert r.returncode == 1 and r.stdout == "" and "denied" in r.stderr, (args, r)
        assert "login-pw" not in r.stderr
    r = subprocess.run([world.bin, "list"], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "login-item" in r.stdout.splitlines()
    assert prompts() == []


def test_a_harness_ancestor_is_denied_a_value_even_with_a_cleared_env(world):
    fake = world.root / "fake/claude/versions/9.9.9"
    fake.parent.mkdir(parents=True)
    shutil.copy(BASH, fake)
    fake.chmod(0o755)
    keep = [f"{k}={v}" for k, v in world.env.items() if k.startswith("XDG_") or k == "HOME"]
    clean = f"env -i {shlex.join(keep)} {shlex.quote(world.bin)}"
    LOG.unlink(missing_ok=True)
    pinentry(pins=[], confirm="always")
    # Two commands: bash must fork for the first, so the fake stays dybw's ancestor.
    r = subprocess.run([str(fake), "-c", f"{clean} get login-item; echo rc=$?"], capture_output=True, text=True, timeout=60)
    assert r.stdout == "rc=1\n" and "denied" in r.stderr, (r.stdout, r.stderr)
    r = subprocess.run([str(fake), "-c", f"{clean} list; echo rc=$?"], capture_output=True, text=True, timeout=60)
    assert "login-item" in r.stdout.splitlines() and r.stdout.endswith("rc=0\n"), (r.stdout, r.stderr)
    assert prompts() == []


def orphan(world, confirm):
    """dybw exec'd by a shell that is not its parent any more (setsid -f; the shell's parent exits at once)."""
    out, err = world.root / "orphan.out", world.root / "orphan.err"
    out.unlink(missing_ok=True)
    err.unlink(missing_ok=True)
    LOG.unlink(missing_ok=True)
    pinentry(pins=[], confirm=confirm)
    cmd = ["setsid", "-f", "sh", "-c", 'sleep 1; exec "$0" get login-item > "$1" 2> "$2"', world.bin, str(out), str(err)]
    subprocess.run(cmd, env=world.env, check=True, timeout=30)
    for _ in range(300):
        if (out.exists() and out.stat().st_size) or (err.exists() and err.stat().st_size):
            break
        time.sleep(0.1)
    return out.read_text(), err.read_text()


def test_an_orphaned_caller_is_asked_every_time_and_never_offered_always(world):
    for _ in range(2):
        out, err = orphan(world, "always")
        assert (out, err) == ("login-pw\n", ""), (out, err)
        (p,) = prompts()
        assert not p["always"] and "unknown caller" in p["text"], p
    out, err = orphan(world, "deny")
    assert out == "" and "denied" in err
    assert len(prompts()) == 1


def policy_rows(world):
    r = world("policy", "show")
    assert r.returncode == 0, r.stderr
    return [line.split("\t") for line in r.stdout.splitlines()]


def test_policy_show_deny_and_forget_round_trip(world):
    s = world.root / "scripts/a.sh"
    # The "always" in the first test left one remembered grant for bash running a.sh.
    assert [row[:3] for row in policy_rows(world)] == [["allow", BASH, str(s)]]
    r = via(world, s, "policy", "deny", BASH, "--script", str(s), confirm="once")
    assert r.returncode == 0, r.stderr
    (p,) = prompts()
    assert p["title"] == "dybw" and "refuse" in p["text"] and str(s) in p["text"]
    assert [row[:3] for row in policy_rows(world)] == [["deny", BASH, str(s)]]
    # A deny wins without a question.
    r = via(world, s, "get", "login-item", confirm="always")
    assert r.returncode == 1 and r.stdout == "" and "denied" in r.stderr and prompts() == []
    # An AI-class caller cannot change the policy.
    r = via(world, s, "policy", "forget", str(s), confirm="once", extra={"CLAUDECODE": "1"})
    assert r.returncode == 1 and "denied" in r.stderr and prompts() == []
    assert len(policy_rows(world)) == 1
    r = via(world, s, "policy", "forget", str(s), confirm="once")
    assert r.returncode == 0, r.stderr
    assert policy_rows(world) == []
    r = via(world, s, "get", "login-item", confirm="once")
    assert (r.returncode, r.stdout) == (0, "login-pw\n") and len(prompts()) == 1


def test_the_audit_log_records_the_requests_without_a_value_or_a_name(world):
    r = world("audit", "-n", "500")
    assert r.returncode == 0, r.stderr
    rows = [line.split("\t") for line in r.stdout.splitlines()]
    assert rows and all(len(row) == 9 for row in rows), r.stdout
    assert {"ai", "unknown", "invoker"} <= {row[2] for row in rows}
    verdicts = {row[8] for row in rows}
    assert {"remembered", "granted", "confirmed", "declined", "denied", "listed"} <= verdicts, verdicts
    assert {row[7] for row in rows if row[5] == "get" and row[2] == "invoker"} == {world.ids["login"]}
    raw = (Path.home() / ".local/state/dybw/audit.log").read_text()
    for text in (r.stdout, raw):
        for secret in ("login-pw", "login-item", "login notes", "luser", "field-v1"):
            assert secret not in text, secret
    ai = [line.split("\t") for line in world("audit", "--ai").stdout.splitlines()]
    assert ai and {row[2] for row in ai} == {"ai"}
    assert {"denied", "listed"} <= {row[8] for row in ai}


def test_doctor_is_healthy(world):
    r = world("doctor")
    assert r.returncode == 0, (r.stdout, r.stderr)
    env = {**world.env, "CLAUDECODE": "1"}
    r = subprocess.run([world.bin, "doctor"], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "warning" in r.stdout.lower(), (r.stdout, r.stderr)
