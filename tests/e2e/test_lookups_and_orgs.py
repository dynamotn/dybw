"""P4.4 end to end, against Vaultwarden: rbw's URI lookup, organization items (read, edit, a read-only collection's
edit refused), a TOTP key of 12 digits refused, and an edit that keeps another tool's markers byte for byte.

The dybw account is a plain member of an organization another account owns: an owner can edit every collection, so
only a member can be given a read-only one. The tests run in file order and share one agent (the `world` fixture of
test_cli); writes run from a script, as in test_writes.
"""

from test_cli import ensure_unlocked, world  # noqa: F401  (world is a fixture)
from test_policy import script_in
from test_writes import SECRET, write

from bwclient import Account
from conftest import URL


def test_login_and_seed(world, account):
    script_in(world, "w.sh")
    r = world("login", pins=[account.client_id, account.client_secret])
    assert r.returncode == 0, r.stderr
    owner = Account(URL)
    org = owner.create_org("e2e org")
    rw, ro = owner.add_collection(org, "rw"), owner.add_collection(org, "ro")
    owner.add_member(org, account, [(rw, False), (ro, True)])
    world.ids["org-item"] = owner.add_org_login(org, rw, "org-item", "org-pw", username="ouser")
    world.ids["ro-item"] = owner.add_org_login(org, ro, "ro-item", "ro-pw")
    world.ids["otp-12"] = account.add_login("e2e", "otp-12", "o12-pw",
                                            totp=f"otpauth://totp/e2e?secret={SECRET}&digits=12")["id"]
    world.ids["marked"] = account.add_login("e2e", "marked-item", "m-pw",
                                            fields={"bwss:id": "b-1", "obsidian:id": "o-1", "plain": "kept"})["id"]
    world.owner = owner
    ensure_unlocked(world, account)
    assert world("sync").returncode == 0
    names = world("list").stdout.splitlines()
    assert {"org-item", "ro-item", "otp-12", "marked-item"} <= set(names), names


def test_a_url_finds_the_login_by_its_uri(world, account):
    ensure_unlocked(world, account)
    # login-item's URI is https://login.example with the default match (domain).
    for url in ("https://login.example/some/path", "https://www.login.example"):
        r = world("get", url, confirm="once")
        assert (r.returncode, r.stdout) == (0, "login-pw\n"), (url, r.stderr)
    for url in ("http://login.example", "https://other.example"):
        r = world("get", url, confirm="once")
        assert r.returncode == 1 and r.stdout == "" and "no item matches" in r.stderr, (url, r)


def test_an_organization_item_reads_and_edits(world, account):
    ensure_unlocked(world, account)
    r = world("get", "org-item", confirm="once")
    assert (r.returncode, r.stdout) == (0, "org-pw\n"), r.stderr
    r = write(world, "edit", "org-item", pins=["org-pw-2"], confirm="once")
    assert (r.returncode, r.stdout) == (0, ""), r.stderr
    item = world.owner.item(world.ids["org-item"])
    assert (item["password"], item["username"]) == ("org-pw-2", "ouser")
    assert "org-pw" in item["history"]


def test_an_edit_in_a_read_only_collection_is_refused(world, account):
    ensure_unlocked(world, account)
    before = world.owner.cipher(world.ids["ro-item"])
    r = write(world, "edit", "ro-item", pins=["ro-pw-2"], confirm="once")
    assert r.returncode == 1 and "read-only" in r.stderr, r
    assert world.owner.cipher(world.ids["ro-item"]) == before, "nothing was written"
    assert world.owner.item(world.ids["ro-item"])["password"] == "ro-pw"


def test_a_totp_key_of_12_digits_is_refused_with_a_clear_error(world, account):
    ensure_unlocked(world, account)
    r = world("code", "otp-12", confirm="once")
    assert r.returncode == 1 and r.stdout == "", r
    assert "the TOTP key is not usable: the TOTP digits 12 is outside 1..=10" in r.stderr, r.stderr
    assert SECRET not in r.stderr


def test_an_edit_keeps_the_markers_of_other_tools_byte_for_byte(world, account):
    ensure_unlocked(world, account)
    before = account.cipher(world.ids["marked"])["fields"]
    r = write(world, "edit", "marked-item", pins=["m-pw-2"], confirm="once")
    assert (r.returncode, r.stdout) == (0, ""), r.stderr
    assert account.cipher(world.ids["marked"])["fields"] == before, "the encrypted fields are the same strings"
    item = account.item(world.ids["marked"])
    assert item["password"] == "m-pw-2"
    assert item["fields"] == {"bwss:id": "b-1", "obsidian:id": "o-1", "plain": "kept"}


def test_list_fields_needs_no_confirmation_also_for_an_organization_item(world, account):
    ensure_unlocked(world, account)
    r = world("get", "marked-item", "-l", confirm="deny")
    assert (r.returncode, r.stdout.splitlines()) == (0, ["bwss:id", "obsidian:id", "plain"]), r.stderr
    r = world("get", "org-item", "-l", confirm="deny")
    assert (r.returncode, r.stdout) == (0, ""), r.stderr
