"""The P4.4 conformance run: rbw 1.15.0 and the rbw shim (dybw invoked as `rbw`) on the same Vaultwarden vault.

Both clients log in to one account seeded by bwclient (the fixture vault of the phase 4 map, section 6), each in its
own HOME and XDG directories, both on the fake pinentry with the same answers. rbw lives in /opt/rbw (the image's rbw
stage) and is put on PATH for its own runs only; the shim is a symlink named `rbw` in a directory of its own
(`rbw-dybw/rbw`). Every command runs from one `bash` script for both, so the shim's caller is a script invoker, as a
user's would be.

- Tier A: each case runs rbw, then the shim, and compares stdout bytes, stderr bytes and the exit code. A case may
  name a normalizer, only for something non-deterministic; `code` cases retry until both ran in one TOTP period.
- Tier B: the exit codes, then the vault state through bwclient (and the editor's template for add/edit).
- Tier C: not compared; `test_tier_c_*` runs the accepted divergences to record what each side does.

Every case appends one JSON line to /tmp/rbw-conformance.jsonl, printed at the end of the run by conftest.py, which
is where docs/rbw-conformance.md takes its results from. The tests run in file order and share both agents.
"""

import json
import os
import pty
import pwd
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from bwclient import decrypt
from conftest import URL
from test_policy import write as write_script

RBW = os.environ.get("RBW_BIN", "/opt/rbw/bin/rbw")
CTL = Path("/tmp/fake-pinentry.json")
RESULTS = Path("/tmp/rbw-conformance.jsonl")
SECRET = "JBSWY3DPEHPK3PXP"
UUID_NAME = "2f1a4f8e-6a3b-4c7d-9e0f-123456789abc"
UNICODE = "Ünïcødé ✓ 名前"
TAB = "tab\there"
SCRIPT = '#!/bin/bash\n"$RBW_UNDER_TEST" "$@"\n'
EDITOR = '#!/bin/sh\ncp "$1" "$FAKE_EDITOR_SEEN"\ncat "$FAKE_EDITOR_TEXT" > "$1"\n'
FIVE = [(f"h5-old-{i}", f"2024-0{i}-0{i}T0{i}:00:00.000Z") for i in range(1, 6)]
PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-body\nsecond-line\n-----END OPENSSH PRIVATE KEY-----"


RBW_PROXY_PORT = 8098


class EncryptedFor(BaseHTTPRequestHandler):
    """rbw's way to Vaultwarden: forwards every request and adds the `encryptedFor` that Vaultwarden 1.37.4 requires
    on a cipher create or update and rbw 1.15 does not send (without it the server answers 422 and rbw cannot write
    at all). Nothing else is changed; `rewritten` counts the requests it touched."""

    user_id = None
    rewritten = 0

    def _forward(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)) or None
        if body and self.command in ("POST", "PUT") and self.path.split("?")[0].startswith("/api/ciphers"):
            data = json.loads(body)
            target = data.get("cipher", data)
            if isinstance(target, dict) and "type" in target and "encryptedFor" not in target:
                target["encryptedFor"] = EncryptedFor.user_id
                EncryptedFor.rewritten += 1
                body = json.dumps(data).encode()
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection")}
        req = urllib.request.Request(URL.rstrip("/") + self.path, data=body, method=self.command, headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                status, rheaders, rbody = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, rheaders, rbody = e.code, e.headers, e.read()
        self.send_response(status)
        for k, v in rheaders.items():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(rbody)))
        self.end_headers()
        self.wfile.write(rbody)

    do_GET = do_POST = do_PUT = do_DELETE = _forward

    def log_message(self, *args):
        pass


def record(**entry):
    with RESULTS.open("a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


class Side:
    """One client (rbw or the shim): its binary, its environment, run through the shared script."""

    def __init__(self, name, binary, env, script):
        self.name, self.binary, self.env, self.script = name, binary, env, script

    def run(self, args, pins=(), confirm="once", stdin=b"", tty=False, extra=None):
        CTL.write_text(json.dumps({"pins": list(pins), "confirm": confirm}))
        env = {**self.env, "RBW_UNDER_TEST": self.binary, **(extra or {})}
        cmd = ["bash", str(self.script), *args]
        if not tty:
            r = subprocess.run(cmd, env=env, input=stdin, capture_output=True, timeout=90)
            return r.returncode, r.stdout, r.stderr
        # stdin a terminal: both clients then open $EDITOR instead of reading stdin.
        primary, secondary = pty.openpty()
        try:
            r = subprocess.run(cmd, env=env, stdin=secondary, capture_output=True, timeout=90)
        finally:
            os.close(secondary)
            os.close(primary)
        return r.returncode, r.stdout, r.stderr

    def direct(self, *args, pins=(), confirm="once"):
        """Run a setup command outside the script (rbw config, logins)."""
        CTL.write_text(json.dumps({"pins": list(pins), "confirm": confirm}))
        r = subprocess.run([self.binary, *args], env={**self.env}, capture_output=True, timeout=90)
        assert r.returncode == 0, (self.name, args, r.stdout, r.stderr)
        return r


def seed(account):
    """The fixture vault (map section 6). Returns {key: item id}."""
    a = account
    ids = {}

    def add(key, item):
        ids[key] = item["id"]

    otp = f"otpauth://totp/e2e:me?secret={SECRET}&issuer=e2e"
    add("gh_alice", a.add_login("Work", "GitHub", "gh-alice-pw", username="alice", uri="https://github.com",
                                notes="GitHub notes"))
    add("gh_bob", a.add_login("Work", "GitHub", "gh-bob-pw", username="bob"))
    add("mail_work", a.add_login("Work", "Mail", "mail-work-pw", username="me@example.com"))
    add("mail_personal", a.add_login("Personal", "Mail", "mail-personal-pw", username="me@example.com"))
    add("plain", a.add_login(None, "Plain", "plain-pw"))
    add("plain_carol", a.add_login(None, "Plain", "plain-carol-pw", username="carol"))
    add("loose", a.add_login(None, "Loose", "loose-pw", username="dave"))
    for key, uris in {
        "uri_domain": [("https://domain.example", 0)],
        "uri_default": [("https://default.example/x", None)],
        "uri_host": [("https://host.example:8443", 1)],
        "uri_starts": [("https://starts.example/app/", 2)],
        "uri_exact": [("https://exact.example/login", 3)],
        "uri_regex": [(r"^https://re\.example/(a|b)$", 4)],
        "uri_never": [("https://never.example", 5)],
        "uri_ip": [("http://192.168.1.10:8080", 0)],
        "uri_bare": [("10.0.0.5", None)],
        "uri_multi": [("https://one.example", 0), ("https://two.example:444", 1)],
    }.items():
        add(key, a.add_login("URIs", key.replace("_", "-"), f"{key}-pw", uris=uris))
    for key, totp in {
        "totp_sha1": otp + "&algorithm=SHA1",
        "totp_sha256": otp + "&algorithm=SHA256",
        "totp_sha512": otp + "&algorithm=SHA512",
        "totp_d8": otp + "&digits=8",
        "totp_p60": otp + "&period=60",
        "totp_steam": f"steam://{SECRET}",
        "totp_bare": "jbsw y3dp ehpk 3pxp",
    }.items():
        add(key, a.add_login("TOTP", key.replace("_", "-"), f"{key}-pw", username="otp", totp=totp))
    add("fields", a.add_login("Work", "Fields", "fields-pw", username="fuser", notes="fields notes", fields=[
        (0, "text-field", "text value", None),
        (1, "hidden-field", "hidden value", None),
        (2, "bool-field", "true", None),
        (3, "linked-field", None, 100),
        (0, "password", "field-named-password", None),
        (0, "Notes", "field-named-Notes", None),
    ]))
    add("proton", a.add_login(None, "Proton", "proton-pw", username="me@proton.example",
                              fields={"Pass via IMAP bridge": "imap-bridge-pw"}))
    add("age", a.add_note(None, "Age Dotfiles", "AGE-SECRET-KEY-1FAKEFAKEFAKE",
                          fields={"public key": "age1fakepublickey"}))
    add("multiline", a.add_login(None, "Multiline", "ml-pw", notes="line one\nline two\n\n  indented four zebra\n"))
    add("hist1", a.add_login(None, "Hist-1", "h1-now", history=[("h1-old", "2024-01-02T03:04:05.000Z")]))
    add("hist5", a.add_login(None, "Hist-5", "h5-now", history=FIVE))
    add("note", a.add_note("Personal", "Secure Note", "first line\nsecond line", fields={"note-field": "nv"}))
    add("card", a.add_typed("Personal", 3, "Card", "card", {
        "cardholderName": "Card Holder", "brand": "Visa", "number": "4111111111111111", "expMonth": "12",
        "expYear": "2030", "code": "737"}, notes="card notes"))
    add("identity", a.add_typed("Personal", 4, "Identity", "identity", {
        "title": "Dr", "firstName": "Ada", "middleName": "B", "lastName": "Lovelace", "address1": "1 Analytical St",
        "address2": "Floor 2", "address3": "Room 3", "city": "London", "state": "LDN", "postalCode": "N1",
        "country": "UK", "company": "Engines Ltd", "email": "ada@example.com", "phone": "+44 1", "ssn": "123-45",
        "username": "ada", "passportNumber": "P123", "licenseNumber": "L456"}))
    add("ssh", a.add_typed("Personal", 5, "SSH Key", "sshKey", {
        "privateKey": PRIVATE_KEY, "publicKey": "ssh-ed25519 AAAAFAKEKEY e2e", "keyFingerprint": "SHA256:fake"}))
    add("keyed", a.add_login("Work", "Keyed", "keyed-pw", username="kuser", notes="keyed notes",
                             fields={"kf": "kv"}, item_key=os.urandom(64)))
    add("guarded", a.add_login(None, "Guarded", "guarded-pw", username="guser", reprompt=1))
    add("uuid_name", a.add_login(None, UUID_NAME, "uuid-named-pw"))
    add("unicode", a.add_login(None, UNICODE, "uni-pw", username="üser"))
    add("tab", a.add_login(None, TAB, "tab-pw", username="tab\tuser"))
    add("marked", a.add_login(None, "Marked", "marked-pw", fields={"bwss:id": "b-1", "obsidian:id": "o-1",
                                                                  "plain": "kept"}))
    add("trashed", a.add_login(None, "Trashed", "trashed-pw"))
    a.trash(ids["trashed"])
    org = a.create_org("Conformance Org")
    coll = a.add_collection(org, "Shared")
    ids["org"] = a.add_org_login(org, coll, "Org Item", "org-pw", username="ouser")
    ssh = a.cipher(ids["ssh"])
    assert ssh["type"] == 5 and ssh.get("sshKey"), "Vaultwarden does not return the SSH key item"
    return ids


@pytest.fixture(scope="module")
def pair(account, dybw_bin):
    """Seed the vault; set up and log in rbw and the shim; return the two sides and the item ids."""
    if not os.environ.get("DYBW_E2E_CONTAINER"):
        pytest.skip("the conformance run needs its container (scripts/e2e.sh)")
    if not os.access(RBW, os.X_OK):
        pytest.skip(f"no rbw 1.15 at {RBW}")
    RESULTS.unlink(missing_ok=True)
    ids = seed(account)
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    for d in (".config/dybw", ".local/state/dybw", ".cache/dybw"):
        shutil.rmtree(home / d, ignore_errors=True)
    root = Path(tempfile.mkdtemp(prefix="c", dir="/tmp"))
    for d in ("run-d", "run-r", "rbw-home", "rbw-dybw"):
        (root / d).mkdir(mode=0o700)
    (home / ".config/dybw").mkdir(parents=True)
    (home / ".config/dybw/config.toml").write_text(
        f'default = "conf"\n[profiles.conf]\nserver_url = "{URL}"\n'
        f'email = "{account.email}"\npinentry = "/usr/local/bin/fake-pinentry"\n'
    )
    shim = root / "rbw-dybw/rbw"
    shim.symlink_to(dybw_bin)
    editor = root / "editor.sh"
    editor.write_text(EDITOR)
    editor.chmod(0o755)
    script = root / "run.sh"
    write_script(script, SCRIPT)
    base = {k: v for k, v in os.environ.items() if k not in ("RBW_PROFILE", "DYBW_PROFILE", "VISUAL", "EDITOR")}
    rhome = root / "rbw-home"
    renv = {**base, "HOME": str(rhome), "XDG_CONFIG_HOME": str(rhome / ".config"),
            "XDG_CACHE_HOME": str(rhome / ".cache"), "XDG_DATA_HOME": str(rhome / ".local/share"),
            "XDG_RUNTIME_DIR": str(root / "run-r"), "PATH": f"{Path(RBW).parent}:{base['PATH']}"}
    denv = {**base, "HOME": str(home), "XDG_RUNTIME_DIR": str(root / "run-d")}
    rbw = Side("rbw", RBW, renv, script)
    dybw = Side("shim", str(shim), denv, script)
    dybw.dybw = dybw_bin

    EncryptedFor.user_id = account.user_id
    proxy = ThreadingHTTPServer(("127.0.0.1", RBW_PROXY_PORT), EncryptedFor)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    rbw_url = f"http://127.0.0.1:{RBW_PROXY_PORT}"
    for key, value in (("email", account.email), ("base_url", rbw_url),
                       ("notifications_url", f"{URL.rstrip('/')}/notifications"),
                       ("pinentry", "/usr/local/bin/fake-pinentry")):
        rbw.direct("config", "set", key, value)
    rbw.direct("register", pins=[account.client_id, account.client_secret])
    rbw.direct("login", pins=[account.password])
    rbw.direct("unlock", pins=[account.password])
    rbw.direct("sync")
    for args, pins in ((["login"], [account.client_id, account.client_secret]), (["unlock"], [account.password]),
                       (["sync"], [])):
        CTL.write_text(json.dumps({"pins": pins, "confirm": "deny"}))
        r = subprocess.run([dybw_bin, *args], env=denv, capture_output=True, timeout=90)
        assert r.returncode == 0, (args, r.stderr)

    class Pair:
        pass

    p = Pair()
    p.rbw, p.shim, p.ids, p.account, p.root, p.editor = rbw, dybw, ids, account, root, editor
    p.sides = (rbw, dybw)
    p.rbw_url = rbw_url
    yield p
    record(tier="note", case="encryptedFor added to rbw requests", result=str(EncryptedFor.rewritten))
    proxy.shutdown()
    subprocess.run([RBW, "stop-agent"], env=renv, capture_output=True, timeout=30)
    subprocess.run([dybw_bin, "agent", "stop"], env=denv, capture_output=True, timeout=30)
    shutil.rmtree(root, ignore_errors=True)


def resolve(pair, arg):
    if arg.startswith("@U:"):
        return pair.ids[arg[3:]].upper()
    if arg.startswith("@"):
        return pair.ids[arg[1:]]
    return arg


def compare(pair, cid, args, tier="A", pins=None, confirm="once", period=None, norm=None):
    """Run one tier A case on both sides; return (rbw, shim) results after the normalizer."""
    args = [resolve(pair, a) for a in args]
    pins = [pair.account.password] if pins is None else pins
    for _ in range(4):
        t0 = time.time()
        r = pair.rbw.run(args, pins=pins, confirm=confirm)
        s = pair.shim.run(args, pins=pins, confirm=confirm)
        if period is None or int(t0 // period) == int(time.time() // period):
            break
    if norm:
        r, s = NORMALIZERS[norm](r), NORMALIZERS[norm](s)
    entry = {"tier": tier, "case": cid, "args": args, "result": "pass" if r == s else "fail", "norm": norm,
             "exit": r[0], "out": r[1][:120].decode(errors="replace"), "err": r[2][:160].decode(errors="replace")}
    if r != s:
        entry["rbw"] = [r[0], r[1].decode(errors="replace"), r[2].decode(errors="replace")]
        entry["shim"] = [s[0], s[1].decode(errors="replace"), s[2].decode(errors="replace")]
    record(**entry)
    return r, s


# Normalizers: only for non-determinism. None is needed so far; each one added must say what it hides.
NORMALIZERS = {}

FIELDS = ["id", "name", "user", "folder", "type"]


def subsets():
    out = []
    for mask in range(1, 32):
        chosen = [f for i, f in enumerate(FIELDS) if mask & (1 << i)]
        out.append(chosen)
        if len(chosen) > 1:
            out.append(chosen[::-1])
    return out


TIER_A = [
    # Section 3 callers.
    ("unlocked", ["unlocked"], {}),
    ("rbw-pick list", ["list", "--fields", "id,name,user,folder"], {}),
    ("fish list", ["list", "--fields", "name,folder,user"], {}),
    ("fish -l", ["get", "GitHub", "alice", "--list-fields"], {}),
    ("himalaya --field", ["get", "Proton", "--field", "Pass via IMAP bridge"], {}),
    ("docker.sh get", ["get", "Age Dotfiles"], {}),
    ("docker.sh --field", ["get", "Age Dotfiles", "--field", "public key"], {}),
]
for key in ("gh_alice", "gh_bob", "plain", "note", "card", "identity", "ssh", "keyed", "org", "uuid_name", "unicode",
            "tab", "marked", "fields", "multiline", "age"):
    TIER_A.append((f"rbw-pick get id {key}", ["get", f"@{key}"], {}))
for key, period in (("totp_sha1", 30), ("totp_p60", 60), ("totp_steam", 30)):
    TIER_A.append((f"rbw-pick code id {key}", ["code", f"@{key}"], {"period": period}))
# list
TIER_A += [("list", ["list"], {}), ("ls", ["ls"], {}), ("list --raw", ["list", "--raw"], {}),
           ("list --raw --fields name", ["list", "--raw", "--fields", "name"], {}),
           ("list --fields name,name", ["list", "--fields", "name,name"], {}),
           ("list --fields unknown", ["list", "--fields", "name,bogus"], {})]
for chosen in subsets():
    TIER_A.append((f"list --fields {','.join(chosen)}", ["list", "--fields", ",".join(chosen)], {}))
# search (terms found in a name or a user only: the shim's accepted difference, see tier C)
for term in ("GitHub", "github", "alice", "Mail", "me@example.com", UNICODE, "tab", "Plain", "nomatch-xyz", "uri-",
             "Hist"):
    TIER_A.append((f"search {term}", ["search", term], {}))
TIER_A += [
    ("search --folder Work", ["search", "GitHub", "--folder", "Work"], {}),
    ("search --folder Personal", ["search", "Mail", "--folder", "Personal"], {}),
    ("search --fields id,name,user,folder", ["search", "Mail", "--fields", "id,name,user,folder"], {}),
    ("search --fields folder,name", ["search", "Mail", "--fields", "folder,name"], {}),
    ("search --fields type", ["search", "Mail", "--fields", "type"], {}),
    ("search --raw", ["search", "GitHub", "--raw"], {}),
    ("search --raw card", ["search", "Card", "--raw"], {}),
]
# get: names, users, folders, ids, URLs
for cid, args in {
    "get Plain (no user wins)": ["get", "Plain"],
    "get Plain carol": ["get", "Plain", "carol"],
    "get GitHub ambiguous": ["get", "GitHub"],
    "get GitHub alice": ["get", "GitHub", "alice"],
    "get GitHub bob": ["get", "GitHub", "bob"],
    "get GitHub nobody": ["get", "GitHub", "nobody"],
    "get Mail ambiguous": ["get", "Mail"],
    "get Mail --folder Work": ["get", "Mail", "--folder", "Work"],
    "get Mail --folder Personal": ["get", "Mail", "--folder", "Personal"],
    "get GitHub --folder Work ambiguous": ["get", "GitHub", "--folder", "Work"],
    "get Loose --folder Work not found": ["get", "Loose", "--folder", "Work"],
    "get Loose": ["get", "Loose"],
    "get Hub (part, ambiguous)": ["get", "Hub"],
    "get Multi (part)": ["get", "Multi"],
    "get -i github alice": ["get", "-i", "github", "alice"],
    "get -i PLAIN": ["get", "-i", "PLAIN"],
    "get plain (case, not found)": ["get", "plain"],
    "get not found": ["get", "nonexistent"],
    "get Trashed": ["get", "Trashed"],
    "get UUID-like name": ["get", UUID_NAME],
    "get id uppercase": ["get", "@U:gh_alice"],
    "get unicode": ["get", UNICODE],
    "get unicode user": ["get", UNICODE, "üser"],
    "get tab name": ["get", TAB],
    "get Guarded (reprompt)": ["get", "Guarded"],
    "get Org Item": ["get", "Org Item"],
    "get Keyed": ["get", "Keyed"],
    "get Secure Note": ["get", "Secure Note"],
    "get Card": ["get", "Card"],
    "get Identity": ["get", "Identity"],
    "get SSH Key": ["get", "SSH Key"],
    "get Multiline": ["get", "Multiline"],
    "get Marked": ["get", "Marked"],
    "get url github": ["get", "https://github.com/x"],
    "get url domain path": ["get", "https://domain.example/path"],
    "get url domain sub": ["get", "https://sub.domain.example"],
    "get url default match": ["get", "https://default.example"],
    "get url host": ["get", "https://host.example:8443/x"],
    "get url host other port": ["get", "https://host.example/x"],
    "get url starts": ["get", "https://starts.example/app/page"],
    "get url starts miss": ["get", "https://starts.example/other"],
    "get url exact": ["get", "https://exact.example/login"],
    "get url exact slash": ["get", "https://exact.example/login/"],
    "get url regex": ["get", "https://re.example/a"],
    "get url regex miss": ["get", "https://re.example/c"],
    "get url never": ["get", "https://never.example"],
    "get url ip port": ["get", "http://192.168.1.10:8080/"],
    "get url ip other port": ["get", "http://192.168.1.10/"],
    "get url bare host": ["get", "http://10.0.0.5"],
    "get url multi host": ["get", "https://two.example:444/"],
    "get url multi domain": ["get", "https://www.one.example"],
    "get url none": ["get", "https://nothing.example"],
}.items():
    TIER_A.append((cid, args, {}))
# get --field, per type
for item, names in {
    "Fields": ["username", "user", "password", "totp", "notes", "uris", "name", "text-field", "hidden-field",
               "bool-field", "linked-field", "Notes", "TEXT", "field", "nosuch"],
    "Secure Note": ["notes", "note-field", "password", "nosuch"],
    "Card": ["number", "cardholder", "cardholder_name", "brand", "exp_month", "exp_year", "expiration", "code",
             "cvv", "notes", "nosuch"],
    "Identity": ["title", "first_name", "middle_name", "last_name", "name", "address", "address1", "city", "state",
                 "postal_code", "country", "phone", "email", "ssn", "license", "license_number", "passport",
                 "passport_number", "username", "company", "nosuch"],
    "SSH Key": ["public_key", "private_key", "fingerprint", "key_fingerprint", "nosuch"],
    "Keyed": ["username", "kf", "notes"],
    "Org Item": ["username", "password"],
}.items():
    for name in names:
        TIER_A.append((f"get {item} --field {name}", ["get", item, "--field", name], {}))
TIER_A.append(("get totp-sha1 --field totp", ["get", "totp-sha1", "--field", "totp"], {"period": 30}))
TIER_A.append(("get -f short", ["get", "Fields", "-f", "text-field"], {}))
# --full, --raw, -l per type
for item in ("Fields", "GitHub", "Multiline", "Keyed", "Org Item", "Secure Note", "Card", "Identity", "SSH Key",
             "Hist-5", "totp-sha1", "uri-multi", "Marked", "Plain", "Guarded"):
    extra = ["alice"] if item == "GitHub" else []
    period = {"period": 30} if item == "totp-sha1" else {}
    TIER_A.append((f"get {item} --full", ["get", item, *extra, "--full"], period))
    TIER_A.append((f"get {item} --raw", ["get", item, *extra, "--raw"], {}))
    TIER_A.append((f"get {item} -l", ["get", item, *extra, "-l"], {}))
# code
for key, period in (("totp_sha1", 30), ("totp_sha256", 30), ("totp_sha512", 30), ("totp_d8", 30), ("totp_p60", 60),
                    ("totp_steam", 30), ("totp_bare", 30)):
    TIER_A.append((f"code {key}", ["code", key.replace("_", "-")], {"period": period}))
TIER_A += [
    ("totp alias", ["totp", "totp-sha1"], {"period": 30}),
    ("code no TOTP", ["code", "Plain"], {}),
    ("code note", ["code", "Secure Note"], {}),
    ("code ambiguous", ["code", "GitHub"], {}),
    ("code not found", ["code", "nonexistent"], {}),
    ("code -i", ["code", "-i", "TOTP-SHA1"], {"period": 30}),
    ("code --folder", ["code", "totp-sha1", "--folder", "TOTP"], {"period": 30}),
]
# history
for cid, args in {
    "history Hist-1": ["history", "Hist-1"],
    "history Hist-5": ["history", "Hist-5"],
    "history Plain (none)": ["history", "Plain"],
    "history Secure Note": ["history", "Secure Note"],
    "history ambiguous": ["history", "GitHub"],
    "history not found": ["history", "nonexistent"],
    "history -i": ["history", "-i", "hist-1"],
}.items():
    TIER_A.append((cid, args, {}))
TIER_A.append(("--version", ["--version"], {}))


@pytest.mark.parametrize("case", TIER_A, ids=[c[0] for c in TIER_A])
def test_tier_a(pair, case):
    cid, args, opts = case
    r, s = compare(pair, cid, args, **opts)
    assert r == s, (cid, r, s)


# --- tier B -------------------------------------------------------------------------------------------------------


def by_name(account, name):
    """Decrypted views of every item called `name`, trashed ones included."""
    out = []
    for c in account.sync()["ciphers"]:
        if c.get("organizationId"):
            continue
        v = account.item(c["id"])
        if v["name"] == name:
            out.append(v)
    return out


def only(account, name):
    """The one item called `name` (trashed or not), or None when there is none or several."""
    found = by_name(account, name)
    return shape(account, found[0]) if len(found) == 1 else None


def folder_name(account, folder_id):
    for f in account.sync()["folders"]:
        if f["id"] == folder_id:
            return decrypt(f["name"], account.user_key).decode()
    return None


def shape(account, view):
    """What a write left in the vault, without the parts that differ on purpose (id, name)."""
    return {"type": view["type"], "password": view["password"], "username": view["username"], "uris": view["uris"],
            "notes": view["notes"], "folder": folder_name(account, view["folder"]), "fields": view["field_list"],
            "history": view["history"], "deleted": view["deleted"]}


def tier_b(cid, ok, detail=""):
    record(tier="B", case=cid, result="pass" if ok else "fail", detail=detail)
    assert ok, (cid, detail)


def sync_both(pair):
    for side in pair.sides:
        rc, _, err = side.run(["sync"])
        assert rc == 0, (side.name, err)


def test_b_add_from_stdin(pair):
    acc = pair.account
    got = {}
    for side in pair.sides:
        name = f"added-{side.name}"
        rc, out, err = side.run(["add", name, "auser", "--uri", "https://added.example", "--folder", "Added"],
                                stdin=b"added-pw\n\nnote 1\n# not a note\nnote 2\n")
        got[side.name] = (rc, out, err, only(acc, name))
    tier_b("add (stdin)", got["rbw"] == got["shim"] and got["rbw"][0] == 0, repr(got))


def test_b_add_with_editor(pair):
    acc = pair.account
    got = {}
    text = pair.root / "editor-text"
    text.write_bytes(b"ed-pw\ned note\n")
    for side in pair.sides:
        name = f"edited-add-{side.name}"
        seen = pair.root / f"seen-add-{side.name}"
        rc, out, err = side.run(["add", name], tty=True,
                                extra={"EDITOR": str(pair.editor), "FAKE_EDITOR_SEEN": str(seen),
                                       "FAKE_EDITOR_TEXT": str(text)})
        got[side.name] = (rc, out, err, seen.read_bytes() if seen.exists() else None, only(acc, name))
    tier_b("add ($EDITOR, template and result)", got["rbw"] == got["shim"] and got["rbw"][0] == 0, repr(got))


def test_b_edit_from_stdin(pair):
    acc = pair.account
    got = {}
    for side in pair.sides:
        name = f"edit-{side.name}"
        acc.add_login(None, name, "e-old", username="euser", notes="old notes")
    sync_both(pair)
    for side in pair.sides:
        name = f"edit-{side.name}"
        rc, out, err = side.run(["edit", name], stdin=b"e-new\nnew notes\nmore\n")
        got[side.name] = (rc, out, err, only(acc, name))
    tier_b("edit (stdin)", got["rbw"] == got["shim"] and got["rbw"][0] == 0, repr(got))


def test_b_edit_with_editor(pair):
    acc = pair.account
    got = {}
    text = pair.root / "editor-text"
    text.write_bytes(b"ee-new\nedited notes\n")
    for side in pair.sides:
        acc.add_login(None, f"edit-ed-{side.name}", "ee-old", notes="ee notes")
        acc.add_note(None, f"edit-note-{side.name}", "note body")
    sync_both(pair)
    for side in pair.sides:
        name = f"edit-ed-{side.name}"
        seen = pair.root / f"seen-edit-{side.name}"
        env = {"EDITOR": str(pair.editor), "FAKE_EDITOR_SEEN": str(seen), "FAKE_EDITOR_TEXT": str(text)}
        rc, out, err = side.run(["edit", name], tty=True, extra=env)
        view = only(acc, name)
        nseen = pair.root / f"seen-note-{side.name}"
        nrc, nout, nerr = side.run(["edit", f"edit-note-{side.name}"], tty=True,
                                   extra={**env, "FAKE_EDITOR_SEEN": str(nseen)})
        nview = only(acc, f"edit-note-{side.name}")
        got[side.name] = (rc, out, err, seen.read_bytes() if seen.exists() else None, view,
                          nrc, nout, nerr, nseen.read_bytes() if nseen.exists() else None, nview)
    tier_b("edit ($EDITOR, login and note)", got["rbw"] == got["shim"] and got["rbw"][0] == 0, repr(got))


def test_b_edit_refuses_other_types(pair):
    got = {side.name: side.run(["edit", "Card"], stdin=b"x\n") for side in pair.sides}
    tier_b("edit of a card is refused", got["rbw"] == got["shim"] and got["rbw"][0] == 1, repr(got))


ALPHABETS = {
    (): re.compile(r"[\x21-\x7e]+"),
    ("--no-symbols",): re.compile(r"[A-Za-z0-9]+"),
    ("--only-numbers",): re.compile(r"[0-9]+"),
    ("--nonconfusables",): re.compile(r"[A-Za-z0-9!-/:-@\[-`{-~]+"),
}


def test_b_generate(pair):
    acc = pair.account
    detail = {}
    ok = True
    for flags, alphabet in ALPHABETS.items():
        for side in pair.sides:
            rc, out, err = side.run(["generate", "24", *flags])
            pw = out.decode().rstrip("\n")
            good = rc == 0 and err == b"" and out.endswith(b"\n") and len(pw) == 24 and alphabet.fullmatch(pw)
            ok &= bool(good)
            detail[f"{side.name} {flags}"] = (rc, len(pw), err)
    for side in pair.sides:
        rc, out, err = side.run(["generate", "--diceware", "5"])
        words = out.decode().rstrip("\n").split(" ")
        good = rc == 0 and len(words) == 5 and all(re.fullmatch(r"[a-z-]+", w) for w in words)
        ok &= bool(good)
        detail[f"{side.name} diceware"] = (rc, len(words), err)
    shapes = {}
    for side in pair.sides:
        name = f"gen-{side.name}"
        rc, out, err = side.run(["generate", "20", name, "guser", "--uri", "https://gen.example", "--folder", "Gen"])
        s = only(acc, name)
        ok &= bool(rc == 0 and s and out.decode().rstrip("\n") == s["password"] and len(s["password"]) == 20)
        if s:
            s["password"] = len(s["password"] or "")
        shapes[side.name] = (rc, err, s)
    ok &= shapes["rbw"] == shapes["shim"]
    tier_b("generate (alphabets, diceware, NAME saved)", ok, repr((detail, shapes)))


def test_b_remove(pair):
    acc = pair.account
    for side in pair.sides:
        acc.add_login(None, f"rm-{side.name}", "rm-pw")
    sync_both(pair)
    got = {}
    for side in pair.sides:
        rc, out, err = side.run(["remove", f"rm-{side.name}"])
        view = only(acc, f"rm-{side.name}")
        got[side.name] = (rc, out, err, "trashed" if view and view["deleted"] else "live" if view else "gone")
    # Same exit code and output; rbw deletes the item for good (DELETE), the shim moves it to the trash (tier C).
    tier_b("remove (exit code and output; rbw: gone, shim: trashed)",
           got["rbw"] == (0, b"", b"", "gone") and got["shim"] == (0, b"", b"", "trashed"), repr(got))


def test_b_sync(pair):
    pair.account.add_login("Work", "Synced Later", "synced-pw", username="late")
    got = {side.name: side.run(["sync"]) for side in pair.sides}
    tier_b("sync", got["rbw"] == got["shim"] == (0, b"", b""), repr(got))
    # After every write above, both see the same vault.
    for args in (["list", "--fields", "id,name,user,folder,type"], ["get", "Synced Later"]):
        r, s = compare(pair, f"after sync: {' '.join(args)}", args)
        assert r == s


def test_b_lock_and_unlock(pair):
    got = {side.name: side.run(["lock"]) for side in pair.sides}
    tier_b("lock", got["rbw"] == got["shim"] == (0, b"", b""), repr(got))
    r, s = compare(pair, "unlocked (locked)", ["unlocked"])
    assert r == s
    # A read on a locked agent asks for the master password first, in both.
    r, s = compare(pair, "list while locked (unlocks first)", ["list"])
    assert r == s
    for side in pair.sides:
        side.run(["lock"])
    got = {side.name: side.run(["unlock"], pins=[pair.account.password]) for side in pair.sides}
    tier_b("unlock", got["rbw"] == got["shim"] == (0, b"", b""), repr(got))
    r, s = compare(pair, "unlocked (after unlock)", ["unlocked"])
    assert r == s


def config_show(side):
    rc, out, err = side.run(["config", "show"])
    return rc, json.loads(out) if rc == 0 else out, err


def unlock_both(pair):
    for side in pair.sides:
        rc, _, err = side.run(["unlock"], pins=[pair.account.password])
        assert rc == 0, (side.name, err)


def test_b_config(pair):
    try:
        shows = {side.name: config_show(side) for side in pair.sides}
        keys = {n: set(s[1]) for n, s in shows.items()}
        picked = {n: {k: s[1].get(k) for k in ("email", "pinentry")} for n, s in shows.items()}
        # rbw's base_url is the encryptedFor proxy; the defaults of lock_timeout and sync_interval are each tool's own
        # (recorded in the detail, see the report).
        tier_b("config show (keys; email, base_url, pinentry)",
               keys["rbw"] == keys["shim"] and picked["rbw"] == picked["shim"]
               and shows["rbw"][1]["base_url"] == pair.rbw_url and shows["shim"][1]["base_url"] == URL, repr(shows))
        for key, value, want in (("lock_timeout", "7200", 7200), ("sync_interval", "0", 0),
                                 ("sync_interval", "600", 600)):
            sets = {side.name: side.run(["config", "set", key, value]) for side in pair.sides}
            after = {side.name: config_show(side)[1][key] for side in pair.sides}
            tier_b(f"config set {key} {value}", {s[0] for s in sets.values()} == {0}
                   and after == {"rbw": want, "shim": want}, repr((sets, after)))
        unsets = {side.name: side.run(["config", "unset", "lock_timeout"]) for side in pair.sides}
        after = {side.name: config_show(side)[1]["lock_timeout"] for side in pair.sides}
        tier_b("config unset lock_timeout (back to each default)", {u[0] for u in unsets.values()} == {0},
               repr((unsets, after)))
        zero = {side.name: side.run(["config", "set", "lock_timeout", "0"]) for side in pair.sides}
        tier_b("config set lock_timeout 0 (refused, exit 0)", zero["rbw"] == zero["shim"], repr(zero))
        bad = {side.name: side.run(["config", "set", "nosuchkey", "x"]) for side in pair.sides}
        tier_b("config set unknown key", bad["rbw"] == bad["shim"], repr(bad))
    finally:
        # A config change stops both agents; unlock again for what follows.
        unlock_both(pair)


def test_b_stop_agent(pair):
    try:
        got = {side.name: side.run(["stop-agent"]) for side in pair.sides}
        tier_b("stop-agent", got["rbw"] == got["shim"] == (0, b"", b""), repr(got))
        r, s = compare(pair, "unlocked (agent stopped)", ["unlocked"])
        assert r == s
    finally:
        unlock_both(pair)


def test_b_purge(pair):
    try:
        got = {side.name: side.run(["purge"]) for side in pair.sides}
        tier_b("purge", got["rbw"] == got["shim"] == (0, b"", b""), repr(got))
        # rbw's purge stops its agent; the shim's locks the profile and leaves the agent running (tier C).
        after = observe(pair, "unlocked after purge (rbw: agent stopped; shim: profile locked)", ["unlocked"])
        tier_b("purge leaves nothing unlocked", after["rbw"][0] == after["shim"][0] == 1, repr(after))
    finally:
        # rbw logs in again (its tokens went with the database); dybw keeps its API key.
        unlock_both(pair)
    for side in pair.sides:
        assert side.run(["sync"])[0] == 0
    r, s = compare(pair, "after purge: list", ["list", "--fields", "id,name,user,folder,type"])
    assert r == s


# --- tier C: accepted divergences, run to record what each side does -------------------------------------------------


def observe(pair, cid, args, **kw):
    got = {side.name: side.run(args, **kw) for side in pair.sides}
    record(tier="C", case=cid, args=args, result="same" if got["rbw"] == got["shim"] else "differs",
           rbw=[got["rbw"][0], got["rbw"][1].decode(errors="replace"), got["rbw"][2].decode(errors="replace")],
           shim=[got["shim"][0], got["shim"][1].decode(errors="replace"), got["shim"][2].decode(errors="replace")])
    return got


def test_tier_c_observed(pair):
    observe(pair, "search in notes (shim: names and users only)", ["search", "zebra"])
    observe(pair, "search in a URI (shim: names and users only)", ["search", "domain.example"])
    observe(pair, "search in a field value (shim: names and users only)", ["search", "imap-bridge"])
    observe(pair, "add with an empty text (shim writes nothing)", ["add", "empty-add"], stdin=b"")
    observe(pair, "config set identity_url (shim refuses)", ["config", "set", "identity_url", f"{URL}/identity"])
    observe(pair, "config set base_url without a terminal (shim refuses)", ["config", "set", "base_url", URL])
    observe(pair, "config set pinentry without a terminal (shim refuses)",
            ["config", "set", "pinentry", "/usr/local/bin/fake-pinentry"])
    for shell in ("bash", "zsh", "fish", "powershell", "elvish", "nushell", "fig"):
        observe(pair, f"gen-completions {shell}", ["gen-completions", shell])
