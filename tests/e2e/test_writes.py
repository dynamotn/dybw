"""P4.3 end to end: TOTP codes, the writes (add, edit, remove, generate) and the reprompt, against Vaultwarden.

Every write is confirmed once in the fake pinentry; its new values come from the pinentry's GETPIN answers. The
tests run in file order and share one agent (the `world` fixture of test_cli). Writes are refused to an unknown
caller, and `python3 -m pytest` cannot be named, so the writes run from a script (`bash /abs/w.sh`), as a user's
would.
"""

import base64
import hashlib
import hmac
import struct
import subprocess
import time
from pathlib import Path

from test_cli import ensure_unlocked, pinentry, world  # noqa: F401  (world is a fixture)
from test_policy import script_in

LOG = Path("/tmp/fake-pinentry.log")
SECRET = "JBSWY3DPEHPK3PXP"


def totp(at):
    """RFC 6238 SHA-1, 6 digits, 30 s: the code of the period holding `at`."""
    key = base64.b32decode(SECRET)
    mac = hmac.new(key, struct.pack(">Q", int(at) // 30), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return f"{(struct.unpack('>I', mac[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def write(world, *args, pins=(), confirm="deny"):
    """`dybw args` run by `bash w.sh`: a caller the policy can name."""
    pinentry(pins=list(pins), confirm=confirm)
    env = {**world.env, "DYBW": world.bin}
    return subprocess.run(["bash", str(world.root / "scripts/w.sh"), *args], env=env, capture_output=True, text=True,
                          timeout=60)


def test_login_and_seed(world, account):
    script_in(world, "w.sh")
    r = world("login", pins=[account.client_id, account.client_secret])
    assert r.returncode == 0, r.stderr
    account.add_login("e2e", "otp-item", "otp-pw", username="ouser", totp=f"otpauth://totp/e2e?secret={SECRET}")
    account.add_login("e2e", "otp-guarded", "og-pw", reprompt=1, totp=SECRET)
    ensure_unlocked(world, account)
    assert world("sync").returncode == 0


def test_code(world, account):
    ensure_unlocked(world, account)
    before = time.time()
    r = world("code", "otp-item", confirm="once")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() in {totp(before), totp(time.time())}, r.stdout
    # --next: a code that is still valid for a few seconds, whenever the test runs.
    r = world("code", "otp-item", "--next", confirm="once")
    after = time.time()
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() in {totp(after), totp(after - 30)}, r.stdout
    r = world("code", "login-item", confirm="once")
    assert r.returncode == 1 and "totp" in r.stderr


def test_code_of_a_reprompt_item_needs_the_master_password(world, account):
    ensure_unlocked(world, account)
    r = world("code", "otp-guarded", pins=["wrong-password"], confirm="once")
    assert (r.returncode, r.stdout) == (1, ""), r
    assert "denied" in r.stderr
    LOG.unlink(missing_ok=True)
    r = world("code", "otp-guarded", pins=[account.password], confirm="once")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() in {totp(time.time()), totp(time.time() - 30)}
    log = LOG.read_text()
    assert log.index("CONFIRM") < log.index("GETPIN")


def test_add_into_a_new_folder(world, account):
    ensure_unlocked(world, account)
    assert account.folder_named("brand-new") is None
    r = write(world, "add", "new-item", "nuser", "--uri", "https://new.example", "--folder", "brand-new",
              pins=["typed-pw"], confirm="once")
    assert (r.returncode, r.stdout) == (0, ""), r.stderr
    folder = account.folder_named("brand-new")
    assert folder
    (item,) = [i for i in account.items("brand-new").values() if i["name"] == "new-item"]
    assert (item["password"], item["username"], item["folder"]) == ("typed-pw", "nuser", folder)
    assert world("list", "--folder", "brand-new").stdout.splitlines() == ["new-item"]
    # A declined add writes nothing.
    r = write(world, "add", "never-item", pins=["pw"], confirm="deny")
    assert r.returncode == 1 and "denied" in r.stderr
    assert "never-item" not in world("list").stdout.splitlines()


def test_edit_password_keeps_the_old_one_in_the_history(world, account):
    ensure_unlocked(world, account)
    r = write(world, "edit", "login-item", pins=["login-pw-2"], confirm="once")
    assert (r.returncode, r.stdout) == (0, ""), r.stderr
    item = account.item(world.ids["login"])
    assert item["password"] == "login-pw-2" and "login-pw" in item["history"]
    assert item["fields"] == {"api-token": "field-v1", "other": "field-v2"}, "the rest is kept"
    r = world("get", "login-item", confirm="once")
    assert r.stdout == "login-pw-2\n", r.stderr


def test_an_out_of_date_edit_is_refused_and_nothing_is_lost(world, account):
    ensure_unlocked(world, account)
    # Changed on the server after the agent's last sync.
    account.set_password(world.ids["login"], "changed-elsewhere")
    r = write(world, "edit", "login-item", pins=["mine"], confirm="once")
    assert r.returncode == 1 and "changed on the server" in r.stderr, r.stderr
    assert account.item(world.ids["login"])["password"] == "changed-elsewhere"


def test_remove_moves_to_the_trash(world, account):
    ensure_unlocked(world, account)
    r = write(world, "remove", "note-item", confirm="once")
    assert (r.returncode, r.stdout) == (0, ""), r.stderr
    assert account.item(world.ids["note"])["deleted"]
    assert "note-item" not in world("list").stdout.splitlines()


def test_generate_local_and_generate_and_save(world, account):
    r = world("generate", "24", "--no-symbols")
    assert r.returncode == 0 and len(r.stdout.strip()) == 24 and r.stdout.strip().isalnum(), r
    assert len(world("generate", "5", "--diceware").stdout.split()) == 5
    ensure_unlocked(world, account)
    LOG.unlink(missing_ok=True)
    r = write(world, "generate", "20", "gen-item", "guser", "--folder", "e2e", confirm="once")
    assert (r.returncode, r.stdout) == (0, ""), r.stderr
    assert "GETPIN" not in LOG.read_text(), "the agent asks for no value"
    (item,) = [i for i in account.items("e2e").values() if i["name"] == "gen-item"]
    assert len(item["password"]) == 20 and item["username"] == "guser"
    assert item["password"] not in r.stderr
    assert world("get", "gen-item", confirm="once").stdout == item["password"] + "\n"


def test_edit_of_a_reprompt_item_needs_the_master_password(world, account):
    ensure_unlocked(world, account)
    r = write(world, "edit", "guarded", pins=["wrong-password", "nope"], confirm="once")
    assert r.returncode == 1 and "denied" in r.stderr
    assert account.item(world.ids["guarded"])["password"] == "guard-pw"
    r = write(world, "edit", "guarded", pins=[account.password, "guard-pw-2"], confirm="once")
    assert r.returncode == 0, r.stderr
    assert account.item(world.ids["guarded"])["password"] == "guard-pw-2"


def test_an_ai_caller_writes_nothing_and_is_not_asked(world, account):
    ensure_unlocked(world, account)
    LOG.unlink(missing_ok=True)
    pinentry(pins=["x"], confirm="once")
    env = {**world.env, "CLAUDECODE": "1"}
    for args in (("add", "ai-item"), ("edit", "login-item"), ("remove", "login-item"), ("generate", "8", "ai-gen"),
                 ("code", "otp-item")):
        r = subprocess.run([world.bin, *args], env=env, capture_output=True, text=True, timeout=60)
        assert r.returncode == 1 and r.stdout == "" and "denied" in r.stderr, (args, r)
    assert not LOG.exists() or "CONFIRM" not in LOG.read_text()
    names = world("list").stdout.splitlines()
    assert "ai-item" not in names and "ai-gen" not in names and "login-item" in names
