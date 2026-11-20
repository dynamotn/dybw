# rbw 1.15 conformance of the rbw shim

The shim is `dybw` invoked as `rbw` (a symlink). This run checks that it answers like rbw 1.15.0 on the same vault,
so the scripts on this machine keep working when `rbw` points at it (phase 4 map, sections 3 and 6; P4.4 Task 5).

**Result** (run of 2026-11-20, `scripts/e2e.sh`, branch `feat/p44-rbw-shim` at 9d7e3fe plus the harness commit):

- Tier A, byte-identical stdout, stderr and exit code: **296 of 296 identical**, with no normalizer.
- Tier B, the same exit code and the same vault state: **20 of 20 equivalent**. One of them, `remove`, checks a
  known difference: rbw deletes the item for good and the shim moves it to the trash (see Divergences).
- Tier C: not compared, listed below with the reason for each. 15 of them were run to record what each side does.
- The whole e2e suite (`scripts/e2e.sh`): 347 passed. That is 45 earlier tests plus this module's 302.

Still to do (owner): run the five section 3 callers on this Mac against the shim by hand (`rbw-pick` from
Hammerspoon, himalaya, `scripts/docker.sh`, `scz`, fish completion). The `rbw` symlink ships only after that (D14).

## Setup

- Container: `tests/e2e/Dockerfile`. rbw 1.15.0 is built in its own stage with
  `cargo install rbw --version 1.15.0 --locked --root /opt/rbw`: crates.io, rbw's own `Cargo.lock`, every crate
  checked against its registry checksum, default features (clipboard on). It is installed in `/opt/rbw`, never on
  `PATH`; the tests put `/opt/rbw/bin` on the `PATH` of rbw's own runs only. A build from source works on any runner
  architecture; the runner here is arm64 (lima).
- Vaultwarden 1.37.4, pinned by digest, started fresh by `scripts/e2e.sh`. The vault is seeded by `bwclient.py`, an
  independent client.
- Two clients on one account, each in its own directories:
  - **rbw**: `HOME` and `XDG_{CONFIG,CACHE,DATA}_HOME` under a temporary directory, its own `XDG_RUNTIME_DIR`.
    Set up with `rbw config set email|base_url|notifications_url|pinentry`, then `rbw register` (the API key), then
    `rbw login` and `rbw unlock` (the master password), then `rbw sync`.
  - **shim**: `<tmp>/rbw-dybw/rbw`, a symlink to the release `dybw`, in a directory of its own. It uses the tester's
    home in the password database (the agent requires that) and its own `XDG_RUNTIME_DIR`. Set up with
    `dybw login` (the API key), then `dybw unlock`, then `dybw sync`.
- Both use `fake_pinentry.py` with the same answers in each case: the master password as the PIN, and "once" to a
  confirmation. rbw never asks for a confirmation; the shim asks for one on each value read. Every command runs from
  one `bash` script for both, so the shim's caller is a script invoker, as it is for a user's script.
- **rbw talks to Vaultwarden through a small proxy** (`EncryptedFor` in the test module). The proxy adds
  `encryptedFor` (the account's user id) to cipher create and update bodies. Vaultwarden 1.37.4 requires that field,
  and rbw 1.15 does not send it. Without it, every rbw write fails with `api request returned error: 422`
  (Vaultwarden logs `missing field encryptedFor`), so rbw cannot write to this server at all. The proxy changes
  nothing else. 7 requests were rewritten in this run. This is a fix for the server environment, not for the
  comparison: reads go through the proxy unchanged. rbw's `notifications_url` points straight at Vaultwarden.
- **Tier A procedure**: rbw runs first, then the shim, with the same arguments. The test compares the stdout bytes,
  the stderr bytes and the exit code. The `code` cases, and the cases that print a TOTP code, repeat both runs until
  they fall in one TOTP period (30 s, or 60 s for the period-60 key), at most 4 times.
- **Normalizers**: none. No case needed one. The ids, dates and `--raw` JSON are deterministic for one vault, and the
  two clients read the same vault.
- **Re-running**: `E2E_TESTS=tests/e2e/test_rbw_conformance.py scripts/e2e.sh` runs this module alone. Each case
  appends one JSON line to `/tmp/rbw-conformance.jsonl` in the container. `conftest.py` prints those lines in an
  `rbw conformance` section at the end of the run, and the tables below are made from them. The ids in the tables
  come from this run's fresh account.

## Fixture vault

It follows the map, section 6. Folders: Work, Personal, URIs, TOTP, plus items with no folder.

- **Logins**:
  - with a user (`GitHub`/alice) and without one (`Plain`);
  - the same name with two users (`GitHub` alice and bob; `Plain` with and without a user);
  - the same name in two folders (`Mail` in Work and in Personal).
- **URIs**: one item per match type. Domain (explicit and default), host with a port, starts-with, exact, regex,
  never, an IP with a port, a bare host, and an item with two URIs.
- **TOTP**: otpauth with SHA1, SHA256 and SHA512, digits 8, period 60, `steam://`, and bare lowercase base32 with
  spaces.
- **Custom fields**: text, hidden, boolean, and linked (to the username). Two fields are named like built-ins
  (`password`, `Notes`).
- **Notes**: notes with several lines and a blank line.
- **Password history**: 1 entry and 5 entries.
- **Other item types**: a secure note with a field, a card, an identity with every part, and an SSH key with a
  multi-line private key.
- **Special cases**:
  - an item with its own key (`Keyed`);
  - an organization item in a collection (`Org Item`);
  - `reprompt = 1` (`Guarded`: the shim also gets the master password);
  - a name that looks like a UUID;
  - Unicode (`Ünïcødé ✓ 名前`, user `üser`) and a tab (`tab\there`, user `tab\tuser`) in names and users;
  - a trashed item;
  - an item with marker fields (`bwss:id`, `obsidian:id`);
  - `Proton` with the field `Pass via IMAP bridge` and `Age Dotfiles` with a field, as the callers use them.

## Cases

- **Tier A**:
  - every section 3 caller command: `unlocked`, `list --fields id,name,user,folder`, `get <id>` and `code <id>`, the
    himalaya `--field`, `docker.sh`'s `get`/`--field`, and the fish completion's `list --fields name,folder,user`
    and `get --list-fields`;
  - `list` with every `--fields` subset in both orders, a duplicated field and an unknown field, plus `ls` and
    `--raw`;
  - `search` on name and user terms, with `--folder`, `--fields` (including the refused `type`) and `--raw`;
  - `get`:
    - lookups by name, user, folder, `-i`, part of a name, id and upper-case id, the UUID-like name, URL needles
      (every match type, hits and misses), and Unicode and tab names;
    - the not-found and ambiguous errors and the trashed item;
    - `--field` for every type (built-in names, aliases, custom fields, field name matching by substring, unknown
      fields);
    - `--full`, `--raw` and `-l` for every type;
  - `code`/`totp` for each TOTP variant, with `-i` and `--folder`, and its errors (no TOTP key, a note, ambiguous,
    not found);
  - `history` (1 and 5 entries, none, a note, ambiguous, not found, `-i`);
  - `--version`;
  - `unlocked` while locked, after `stop-agent` and after `unlock`; `list` while locked (both unlock first through
    the pinentry); `list` and `get` after `sync`, and `list` after `purge`.
- **Tier B**:
  - `add` from stdin and with `$EDITOR`: the template the editor is given must be byte-identical too;
  - `edit` from stdin and with `$EDITOR`, for a login and a note (template and result), and `edit` of a card,
    which is refused;
  - `generate`: each alphabet flag and `--diceware` (length and alphabet), and `generate 20 NAME USER --uri
    --folder` (the printed password is the one saved);
  - `remove`;
  - `sync`, `lock` and `unlock`;
  - `config show` (the key set; `email`, `base_url`, `pinentry`), `config set lock_timeout`, `config set
    sync_interval` (`0` and `600`), `config unset lock_timeout`, `config set lock_timeout 0` (refused, exit 0), and
    an unknown key;
  - `stop-agent` and `purge`.

## Divergences

Known differences, each with its reason. None of them breaks a section 3 caller.

| Difference | rbw 1.15 | shim | Reason |
|---|---|---|---|
| `search` | matches names, users, notes, URIs and field values | matches names and users only | Matching the others would decrypt values without a confirmation (Task 4, accepted). Observed: `search zebra` (a note), `search domain.example` (a URI), and `search imap-bridge` (a field value) find an item in rbw and nothing in the shim. |
| `remove` | `DELETE /api/ciphers/<id>`: the item is gone for good | moves the item to the trash | The shim's write path trashes and never purges (map C5, "trash, not purge"), so a mistaken `rm` can be undone. The exit code and output are the same. Not changed: matching rbw here would mean destroying data, a policy decision for the owner. |
| `purge` | stops the agent and deletes its database | locks the profile, deletes `~/.cache/dybw/profiles/<p>`; the agent keeps running for the other profiles | Same family as "`lock` locks the profile" (Task 4, accepted). Observed: after `purge`, `unlocked` prints `agent not running` (rbw) or `agent is locked` (shim). Both exit with 1. |
| Empty editor text | saves an item with an empty password | writes nothing: "the editor left nothing to save; nothing was changed", exit 1 | The owner's rule for `$EDITOR` (Task 4, accepted). |
| `config set identity_url` | saved | refused, names `base_url` | There is no registry key; dybw derives the identity URL from the base URL (Task 3, accepted). |
| `config set\|unset base_url\|pinentry` with stdin not a terminal | saved | refused ("needs an interactive terminal") | A script or an AI harness must not redirect the server or the prompt through the shim (Task 3 review, accepted). |
| Default `sync_interval` in `config show` | 3600 | 300 | dybw's own default periodic sync. `config set`/`unset` map the same way in both (tier B). |
| `unlock` vs other commands | every command logs in first if needed | only `unlock` logs in first | Task 4, accepted. Not reached in this run, because both were logged in. |
| `lock` | locks the single agent | locks the profile | Task 4, accepted. Only one profile here, so the output is identical. |
| `rbw edit` in a terminal | one step | reads the current password and notes first, which needs one confirmation, then writes, which needs a second | The policy: a read of values is confirmed (Task 4). The template and the result are identical (tier B). |

## Tier C (not compared)

| What | Reason |
|---|---|
| `get -c`, `code --clipboard` | The clipboard needs a display; checked by hand. |
| `gen-completions` output equality | Callers only `source` it, and the pinned fragments are covered by unit tests. Observed: powershell, elvish, nushell and fig are byte-identical. bash, zsh and fish differ only in clap_complete's generated helper names and indentation (`rbw__add` vs `rbw__subcmd__add`, tabs vs spaces). The shim uses clap_complete 4.6.12, rbw's lock 4.5.62; the completions behave the same. Pinning clap_complete 4.5.62 would make them identical; left as an option. |
| `register` / `login` flow | By design, dybw logs in with the API key only (`register` and `login` both run `dybw login`); rbw's `login` uses the master password. Both were used in the setup. |
| Two-factor login | dybw has no password login, so it has no 2FA. |
| `--help` and clap usage-error text | No caller parses them. The shim's clap (4.6) and rbw's (4.5.53) may wrap or word some things differently. |
| The accepted divergences above | Each is a decision, listed with its reason. |

## Results

### Tier A results (296 cases, 296 identical)

| # | Case | Command (after `rbw`) | Exit | rbw's stdout, else stderr (first 60 characters) | Result |
|---|---|---|---|---|---|
| 1 | unlocked | `unlocked` | 0 |  | identical |
| 2 | rbw-pick list | `list --fields id,name,user,folder` | 0 | `693af0e5-5b95-4edc-9a82-3e4b7261156d\t2f1a4f8e-6a3b-4c7d-9e0f`… | identical |
| 3 | fish list | `list --fields name,folder,user` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t\t\nAge Dotfiles\t\t\nCard\tP`… | identical |
| 4 | fish -l | `get GitHub alice --list-fields` | 0 | `username\nuris\npassword\nnotes\n` | identical |
| 5 | himalaya --field | `get Proton --field 'Pass via IMAP bridge'` | 0 | `imap-bridge-pw\n` | identical |
| 6 | docker.sh get | `get 'Age Dotfiles'` | 0 | `AGE-SECRET-KEY-1FAKEFAKEFAKE\n` | identical |
| 7 | docker.sh --field | `get 'Age Dotfiles' --field 'public key'` | 0 | `age1fakepublickey\n` | identical |
| 8 | rbw-pick get id gh_alice | `get a8bdccd4-ed0b-4409-944a-ad91d6f7ec22` | 0 | `gh-alice-pw\n` | identical |
| 9 | rbw-pick get id gh_bob | `get 580cc68b-d1dd-409c-a630-5ff3318163e8` | 0 | `gh-bob-pw\n` | identical |
| 10 | rbw-pick get id plain | `get 61e51eb4-dd2f-4850-863d-3ce443246b75` | 0 | `plain-pw\n` | identical |
| 11 | rbw-pick get id note | `get e6d3bfa2-583a-4444-9cac-5e51376d4e27` | 0 | `first line\nsecond line\n` | identical |
| 12 | rbw-pick get id card | `get 4103e4b8-7b43-47b5-a389-096e61a62f4c` | 0 | `4111111111111111\n` | identical |
| 13 | rbw-pick get id identity | `get 4d20d298-3915-45d4-8452-c7a29d86f6d2` | 0 | `Dr Ada B Lovelace\n` | identical |
| 14 | rbw-pick get id ssh | `get e6238af4-8b49-4970-add9-67e54ed17701` | 0 | `ssh-ed25519 AAAAFAKEKEY e2e\n` | identical |
| 15 | rbw-pick get id keyed | `get ea10c6f4-182f-4357-bbd1-2b64d7ec2b0b` | 0 | `keyed-pw\n` | identical |
| 16 | rbw-pick get id org | `get d637d8ba-808d-47d6-9dd3-aa9d957e2b18` | 0 | `org-pw\n` | identical |
| 17 | rbw-pick get id uuid_name | `get 693af0e5-5b95-4edc-9a82-3e4b7261156d` | 0 | `uuid-named-pw\n` | identical |
| 18 | rbw-pick get id unicode | `get 364966a0-37bf-4643-bd04-b52f05ac90b6` | 0 | `uni-pw\n` | identical |
| 19 | rbw-pick get id tab | `get e3f1ab37-31ee-473c-a3bc-531fee65afd2` | 0 | `tab-pw\n` | identical |
| 20 | rbw-pick get id marked | `get 2c76910f-8512-4459-a703-8a0da594ea00` | 0 | `marked-pw\n` | identical |
| 21 | rbw-pick get id fields | `get 3a1b3437-a0a9-4944-83e6-4701cef45f79` | 0 | `fields-pw\n` | identical |
| 22 | rbw-pick get id multiline | `get b4671b67-11c3-4e68-a61d-dc65aa40dadf` | 0 | `ml-pw\n` | identical |
| 23 | rbw-pick get id age | `get 2f97feaa-a8e5-408a-bb54-45305b8fdee8` | 0 | `AGE-SECRET-KEY-1FAKEFAKEFAKE\n` | identical |
| 24 | rbw-pick code id totp_sha1 | `code 4b409fff-50c3-4ce1-bd32-2575e350e1d1` | 0 | `132500\n` | identical |
| 25 | rbw-pick code id totp_p60 | `code 984d260d-c3d4-4724-86b0-01796e54278e` | 0 | `107432\n` | identical |
| 26 | rbw-pick code id totp_steam | `code 039f83b1-d822-494d-81ca-8fb10923225c` | 0 | `XR3XC\n` | identical |
| 27 | list | `list` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\nAge Dotfiles\nCard\nField`… | identical |
| 28 | ls | `ls` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\nAge Dotfiles\nCard\nField`… | identical |
| 29 | list --raw | `list --raw` | 0 | `[\n  {\n    "id": "693af0e5-5b95-4edc-9a82-3e4b7261156d",\n    `… | identical |
| 30 | list --raw --fields name | `list --raw --fields name` | 0 | `[\n  {\n    "id": "693af0e5-5b95-4edc-9a82-3e4b7261156d",\n    `… | identical |
| 31 | list --fields name,name | `list --fields name,name` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t2f1a4f8e-6a3b-4c7d-9e0f`… | identical |
| 32 | list --fields unknown | `list --fields name,bogus` | 1 | `rbw list: unknown field bogus\n` | identical |
| 33 | list --fields id | `list --fields id` | 0 | `039f83b1-d822-494d-81ca-8fb10923225c\n14172753-48e2-4fce-b00e`… | identical |
| 34 | list --fields name | `list --fields name` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\nAge Dotfiles\nCard\nField`… | identical |
| 35 | list --fields id,name | `list --fields id,name` | 0 | `693af0e5-5b95-4edc-9a82-3e4b7261156d\t2f1a4f8e-6a3b-4c7d-9e0f`… | identical |
| 36 | list --fields name,id | `list --fields name,id` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t693af0e5-5b95-4edc-9a82`… | identical |
| 37 | list --fields user | `list --fields user` | 0 | `otp\n\n\n\nüser\nfuser\n\n\n\notp\n\notp\nbob\nme@proton.example\n\n\n\n\n\n\nme`… | identical |
| 38 | list --fields id,user | `list --fields id,user` | 0 | `039f83b1-d822-494d-81ca-8fb10923225c\totp\n14172753-48e2-4fce-`… | identical |
| 39 | list --fields user,id | `list --fields user,id` | 0 | `otp\t039f83b1-d822-494d-81ca-8fb10923225c\n\t14172753-48e2-4fce`… | identical |
| 40 | list --fields name,user | `list --fields name,user` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t\nAge Dotfiles\t\nCard\t\nFi`… | identical |
| 41 | list --fields user,name | `list --fields user,name` | 0 | `\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\n\tAge Dotfiles\n\tCard\nfu`… | identical |
| 42 | list --fields id,name,user | `list --fields id,name,user` | 0 | `693af0e5-5b95-4edc-9a82-3e4b7261156d\t2f1a4f8e-6a3b-4c7d-9e0f`… | identical |
| 43 | list --fields user,name,id | `list --fields user,name,id` | 0 | `\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t693af0e5-5b95-4edc-9a8`… | identical |
| 44 | list --fields folder | `list --fields folder` | 0 | `TOTP\nURIs\n\n\n\nWork\nURIs\nURIs\nPersonal\nTOTP\nPersonal\nTOTP\nWork`… | identical |
| 45 | list --fields id,folder | `list --fields id,folder` | 0 | `039f83b1-d822-494d-81ca-8fb10923225c\tTOTP\n14172753-48e2-4fce`… | identical |
| 46 | list --fields folder,id | `list --fields folder,id` | 0 | `TOTP\t039f83b1-d822-494d-81ca-8fb10923225c\nURIs\t14172753-48e2`… | identical |
| 47 | list --fields name,folder | `list --fields name,folder` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t\nAge Dotfiles\t\nCard\tPer`… | identical |
| 48 | list --fields folder,name | `list --fields folder,name` | 0 | `\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\n\tAge Dotfiles\nPersonal`… | identical |
| 49 | list --fields id,name,folder | `list --fields id,name,folder` | 0 | `693af0e5-5b95-4edc-9a82-3e4b7261156d\t2f1a4f8e-6a3b-4c7d-9e0f`… | identical |
| 50 | list --fields folder,name,id | `list --fields folder,name,id` | 0 | `\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t693af0e5-5b95-4edc-9a8`… | identical |
| 51 | list --fields user,folder | `list --fields user,folder` | 0 | `otp\tTOTP\n\tURIs\n\t\n\t\nüser\t\nfuser\tWork\n\tURIs\n\tURIs\n\tPersonal\not`… | identical |
| 52 | list --fields folder,user | `list --fields folder,user` | 0 | `TOTP\totp\nURIs\t\n\t\n\t\n\tüser\nWork\tfuser\nURIs\t\nURIs\t\nPersonal\t\nTO`… | identical |
| 53 | list --fields id,user,folder | `list --fields id,user,folder` | 0 | `039f83b1-d822-494d-81ca-8fb10923225c\totp\tTOTP\n14172753-48e2-`… | identical |
| 54 | list --fields folder,user,id | `list --fields folder,user,id` | 0 | `TOTP\totp\t039f83b1-d822-494d-81ca-8fb10923225c\nURIs\t\t14172753`… | identical |
| 55 | list --fields name,user,folder | `list --fields name,user,folder` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t\t\nAge Dotfiles\t\t\nCard\t\t`… | identical |
| 56 | list --fields folder,user,name | `list --fields folder,user,name` | 0 | `\t\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\n\t\tAge Dotfiles\nPerson`… | identical |
| 57 | list --fields id,name,user,folder | `list --fields id,name,user,folder` | 0 | `693af0e5-5b95-4edc-9a82-3e4b7261156d\t2f1a4f8e-6a3b-4c7d-9e0f`… | identical |
| 58 | list --fields folder,user,name,id | `list --fields folder,user,name,id` | 0 | `\t\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t693af0e5-5b95-4edc-9a`… | identical |
| 59 | list --fields type | `list --fields type` | 0 | `Login\nLogin\nLogin\nNote\nLogin\nLogin\nLogin\nLogin\nCard\nLogin\nId`… | identical |
| 60 | list --fields id,type | `list --fields id,type` | 0 | `039f83b1-d822-494d-81ca-8fb10923225c\tLogin\n14172753-48e2-4fc`… | identical |
| 61 | list --fields type,id | `list --fields type,id` | 0 | `Login\t039f83b1-d822-494d-81ca-8fb10923225c\nLogin\t14172753-48`… | identical |
| 62 | list --fields name,type | `list --fields name,type` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\tLogin\nAge Dotfiles\tNote`… | identical |
| 63 | list --fields type,name | `list --fields type,name` | 0 | `Login\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\nNote\tAge Dotfiles`… | identical |
| 64 | list --fields id,name,type | `list --fields id,name,type` | 0 | `693af0e5-5b95-4edc-9a82-3e4b7261156d\t2f1a4f8e-6a3b-4c7d-9e0f`… | identical |
| 65 | list --fields type,name,id | `list --fields type,name,id` | 0 | `Login\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t693af0e5-5b95-4ed`… | identical |
| 66 | list --fields user,type | `list --fields user,type` | 0 | `otp\tLogin\n\tLogin\n\tLogin\n\tNote\nüser\tLogin\nfuser\tLogin\n\tLogin\n`… | identical |
| 67 | list --fields type,user | `list --fields type,user` | 0 | `Login\totp\nLogin\t\nLogin\t\nNote\t\nLogin\tüser\nLogin\tfuser\nLogin\t\n`… | identical |
| 68 | list --fields id,user,type | `list --fields id,user,type` | 0 | `039f83b1-d822-494d-81ca-8fb10923225c\totp\tLogin\n14172753-48e2`… | identical |
| 69 | list --fields type,user,id | `list --fields type,user,id` | 0 | `Login\totp\t039f83b1-d822-494d-81ca-8fb10923225c\nLogin\t\t141727`… | identical |
| 70 | list --fields name,user,type | `list --fields name,user,type` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t\tLogin\nAge Dotfiles\t\tNo`… | identical |
| 71 | list --fields type,user,name | `list --fields type,user,name` | 0 | `Login\t\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\nNote\t\tAge Dotfil`… | identical |
| 72 | list --fields id,name,user,type | `list --fields id,name,user,type` | 0 | `693af0e5-5b95-4edc-9a82-3e4b7261156d\t2f1a4f8e-6a3b-4c7d-9e0f`… | identical |
| 73 | list --fields type,user,name,id | `list --fields type,user,name,id` | 0 | `Login\t\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t693af0e5-5b95-4e`… | identical |
| 74 | list --fields folder,type | `list --fields folder,type` | 0 | `TOTP\tLogin\nURIs\tLogin\n\tLogin\n\tNote\n\tLogin\nWork\tLogin\nURIs\tLo`… | identical |
| 75 | list --fields type,folder | `list --fields type,folder` | 0 | `Login\tTOTP\nLogin\tURIs\nLogin\t\nNote\t\nLogin\t\nLogin\tWork\nLogin\tU`… | identical |
| 76 | list --fields id,folder,type | `list --fields id,folder,type` | 0 | `039f83b1-d822-494d-81ca-8fb10923225c\tTOTP\tLogin\n14172753-48e`… | identical |
| 77 | list --fields type,folder,id | `list --fields type,folder,id` | 0 | `Login\tTOTP\t039f83b1-d822-494d-81ca-8fb10923225c\nLogin\tURIs\t1`… | identical |
| 78 | list --fields name,folder,type | `list --fields name,folder,type` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t\tLogin\nAge Dotfiles\t\tNo`… | identical |
| 79 | list --fields type,folder,name | `list --fields type,folder,name` | 0 | `Login\t\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\nNote\t\tAge Dotfil`… | identical |
| 80 | list --fields id,name,folder,type | `list --fields id,name,folder,type` | 0 | `693af0e5-5b95-4edc-9a82-3e4b7261156d\t2f1a4f8e-6a3b-4c7d-9e0f`… | identical |
| 81 | list --fields type,folder,name,id | `list --fields type,folder,name,id` | 0 | `Login\t\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t693af0e5-5b95-4e`… | identical |
| 82 | list --fields user,folder,type | `list --fields user,folder,type` | 0 | `otp\tTOTP\tLogin\n\tURIs\tLogin\n\t\tLogin\n\t\tNote\nüser\t\tLogin\nfuser\t`… | identical |
| 83 | list --fields type,folder,user | `list --fields type,folder,user` | 0 | `Login\tTOTP\totp\nLogin\tURIs\t\nLogin\t\t\nNote\t\t\nLogin\t\tüser\nLogin\t`… | identical |
| 84 | list --fields id,user,folder,type | `list --fields id,user,folder,type` | 0 | `039f83b1-d822-494d-81ca-8fb10923225c\totp\tTOTP\tLogin\n14172753`… | identical |
| 85 | list --fields type,folder,user,id | `list --fields type,folder,user,id` | 0 | `Login\tTOTP\totp\t039f83b1-d822-494d-81ca-8fb10923225c\nLogin\tUR`… | identical |
| 86 | list --fields name,user,folder,type | `list --fields name,user,folder,type` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t\t\tLogin\nAge Dotfiles\t\t\t`… | identical |
| 87 | list --fields type,folder,user,name | `list --fields type,folder,user,name` | 0 | `Login\t\t\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\nNote\t\t\tAge Dotf`… | identical |
| 88 | list --fields id,name,user,folder,type | `list --fields id,name,user,folder,type` | 0 | `693af0e5-5b95-4edc-9a82-3e4b7261156d\t2f1a4f8e-6a3b-4c7d-9e0f`… | identical |
| 89 | list --fields type,folder,user,name,id | `list --fields type,folder,user,name,id` | 0 | `Login\t\t\t2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\t693af0e5-5b95-4`… | identical |
| 90 | search GitHub | `search GitHub` | 0 | `GitHub\nGitHub\n` | identical |
| 91 | search github | `search github` | 0 | `GitHub\nGitHub\n` | identical |
| 92 | search alice | `search alice` | 0 | `GitHub\n` | identical |
| 93 | search Mail | `search Mail` | 0 | `Mail\nMail\n` | identical |
| 94 | search me@example.com | `search me@example.com` | 0 | `Mail\nMail\n` | identical |
| 95 | search Ünïcødé ✓ 名前 | `search 'Ünïcødé ✓ 名前'` | 0 | `Ünïcødé ✓ 名前\n` | identical |
| 96 | search tab | `search tab` | 0 | `tab\there\n` | identical |
| 97 | search Plain | `search Plain` | 0 | `Plain\nPlain\n` | identical |
| 98 | search nomatch-xyz | `search nomatch-xyz` | 0 |  | identical |
| 99 | search uri- | `search uri-` | 0 | `uri-bare\nuri-default\nuri-domain\nuri-exact\nuri-host\nuri-ip\nur`… | identical |
| 100 | search Hist | `search Hist` | 0 | `Hist-1\nHist-5\n` | identical |
| 101 | search --folder Work | `search GitHub --folder Work` | 0 | `GitHub\nGitHub\n` | identical |
| 102 | search --folder Personal | `search Mail --folder Personal` | 0 | `Mail\n` | identical |
| 103 | search --fields id,name,user,folder | `search Mail --fields id,name,user,folder` | 0 | `7dce29ad-f4ff-453d-a581-51513245ff5b\tMail\tme@example.com\tWor`… | identical |
| 104 | search --fields folder,name | `search Mail --fields folder,name` | 0 | `Work\tMail\nPersonal\tMail\n` | identical |
| 105 | search --fields type | `search Mail --fields type` | 0 | `Login\nLogin\n` | identical |
| 106 | search --raw | `search GitHub --raw` | 0 | `[\n  {\n    "id": "580cc68b-d1dd-409c-a630-5ff3318163e8",\n    `… | identical |
| 107 | search --raw card | `search Card --raw` | 0 | `[\n  {\n    "id": "4103e4b8-7b43-47b5-a389-096e61a62f4c",\n    `… | identical |
| 108 | get Plain (no user wins) | `get Plain` | 0 | `plain-pw\n` | identical |
| 109 | get Plain carol | `get Plain carol` | 0 | `plain-carol-pw\n` | identical |
| 110 | get GitHub ambiguous | `get GitHub` | 1 | `rbw get: couldn't find entry for 'GitHub': multiple entries `… | identical |
| 111 | get GitHub alice | `get GitHub alice` | 0 | `gh-alice-pw\n` | identical |
| 112 | get GitHub bob | `get GitHub bob` | 0 | `gh-bob-pw\n` | identical |
| 113 | get GitHub nobody | `get GitHub nobody` | 1 | `rbw get: couldn't find entry for 'nobody@GitHub': no entry f`… | identical |
| 114 | get Mail ambiguous | `get Mail` | 1 | `rbw get: couldn't find entry for 'Mail': multiple entries fo`… | identical |
| 115 | get Mail --folder Work | `get Mail --folder Work` | 0 | `mail-work-pw\n` | identical |
| 116 | get Mail --folder Personal | `get Mail --folder Personal` | 0 | `mail-personal-pw\n` | identical |
| 117 | get GitHub --folder Work ambiguous | `get GitHub --folder Work` | 1 | `rbw get: couldn't find entry for 'GitHub': multiple entries `… | identical |
| 118 | get Loose --folder Work not found | `get Loose --folder Work` | 1 | `rbw get: couldn't find entry for 'Loose': no entry found\n` | identical |
| 119 | get Loose | `get Loose` | 0 | `loose-pw\n` | identical |
| 120 | get Hub (part, ambiguous) | `get Hub` | 1 | `rbw get: couldn't find entry for 'Hub': multiple entries fou`… | identical |
| 121 | get Multi (part) | `get Multi` | 0 | `ml-pw\n` | identical |
| 122 | get -i github alice | `get -i github alice` | 0 | `gh-alice-pw\n` | identical |
| 123 | get -i PLAIN | `get -i PLAIN` | 0 | `plain-pw\n` | identical |
| 124 | get plain (case, not found) | `get plain` | 1 | `rbw get: couldn't find entry for 'plain': no entry found\n` | identical |
| 125 | get not found | `get nonexistent` | 1 | `rbw get: couldn't find entry for 'nonexistent': no entry fou`… | identical |
| 126 | get Trashed | `get Trashed` | 1 | `rbw get: couldn't find entry for 'Trashed': no entry found\n` | identical |
| 127 | get UUID-like name | `get 2f1a4f8e-6a3b-4c7d-9e0f-123456789abc` | 0 | `uuid-named-pw\n` | identical |
| 128 | get id uppercase | `get A8BDCCD4-ED0B-4409-944A-AD91D6F7EC22` | 0 | `gh-alice-pw\n` | identical |
| 129 | get unicode | `get 'Ünïcødé ✓ 名前'` | 0 | `uni-pw\n` | identical |
| 130 | get unicode user | `get 'Ünïcødé ✓ 名前' üser` | 0 | `uni-pw\n` | identical |
| 131 | get tab name | `get 'tab\\there'` | 0 | `tab-pw\n` | identical |
| 132 | get Guarded (reprompt) | `get Guarded` | 0 | `guarded-pw\n` | identical |
| 133 | get Org Item | `get 'Org Item'` | 0 | `org-pw\n` | identical |
| 134 | get Keyed | `get Keyed` | 0 | `keyed-pw\n` | identical |
| 135 | get Secure Note | `get 'Secure Note'` | 0 | `first line\nsecond line\n` | identical |
| 136 | get Card | `get Card` | 0 | `4111111111111111\n` | identical |
| 137 | get Identity | `get Identity` | 0 | `Dr Ada B Lovelace\n` | identical |
| 138 | get SSH Key | `get 'SSH Key'` | 0 | `ssh-ed25519 AAAAFAKEKEY e2e\n` | identical |
| 139 | get Multiline | `get Multiline` | 0 | `ml-pw\n` | identical |
| 140 | get Marked | `get Marked` | 0 | `marked-pw\n` | identical |
| 141 | get url github | `get https://github.com/x` | 0 | `gh-alice-pw\n` | identical |
| 142 | get url domain path | `get https://domain.example/path` | 0 | `uri_domain-pw\n` | identical |
| 143 | get url domain sub | `get https://sub.domain.example` | 0 | `uri_domain-pw\n` | identical |
| 144 | get url default match | `get https://default.example` | 0 | `uri_default-pw\n` | identical |
| 145 | get url host | `get https://host.example:8443/x` | 0 | `uri_host-pw\n` | identical |
| 146 | get url host other port | `get https://host.example/x` | 1 | `rbw get: couldn't find entry for 'https://host.example/x': n`… | identical |
| 147 | get url starts | `get https://starts.example/app/page` | 0 | `uri_starts-pw\n` | identical |
| 148 | get url starts miss | `get https://starts.example/other` | 1 | `rbw get: couldn't find entry for 'https://starts.example/oth`… | identical |
| 149 | get url exact | `get https://exact.example/login` | 0 | `uri_exact-pw\n` | identical |
| 150 | get url exact slash | `get https://exact.example/login/` | 1 | `rbw get: couldn't find entry for 'https://exact.example/logi`… | identical |
| 151 | get url regex | `get https://re.example/a` | 0 | `uri_regex-pw\n` | identical |
| 152 | get url regex miss | `get https://re.example/c` | 1 | `rbw get: couldn't find entry for 'https://re.example/c': no `… | identical |
| 153 | get url never | `get https://never.example` | 1 | `rbw get: couldn't find entry for 'https://never.example/': n`… | identical |
| 154 | get url ip port | `get http://192.168.1.10:8080/` | 0 | `uri_ip-pw\n` | identical |
| 155 | get url ip other port | `get http://192.168.1.10/` | 1 | `rbw get: couldn't find entry for 'http://192.168.1.10/': no `… | identical |
| 156 | get url bare host | `get http://10.0.0.5` | 0 | `uri_bare-pw\n` | identical |
| 157 | get url multi host | `get https://two.example:444/` | 0 | `uri_multi-pw\n` | identical |
| 158 | get url multi domain | `get https://www.one.example` | 0 | `uri_multi-pw\n` | identical |
| 159 | get url none | `get https://nothing.example` | 1 | `rbw get: couldn't find entry for 'https://nothing.example/':`… | identical |
| 160 | get Fields --field username | `get Fields --field username` | 0 | `fuser\n` | identical |
| 161 | get Fields --field user | `get Fields --field user` | 0 | `fuser\n` | identical |
| 162 | get Fields --field password | `get Fields --field password` | 0 | `fields-pw\n` | identical |
| 163 | get Fields --field totp | `get Fields --field totp` | 0 |  | identical |
| 164 | get Fields --field notes | `get Fields --field notes` | 0 | `fields notes\n` | identical |
| 165 | get Fields --field uris | `get Fields --field uris` | 0 | `\n` | identical |
| 166 | get Fields --field name | `get Fields --field name` | 0 |  | identical |
| 167 | get Fields --field text-field | `get Fields --field text-field` | 0 | `text value\n` | identical |
| 168 | get Fields --field hidden-field | `get Fields --field hidden-field` | 0 | `hidden value\n` | identical |
| 169 | get Fields --field bool-field | `get Fields --field bool-field` | 0 | `true\n` | identical |
| 170 | get Fields --field linked-field | `get Fields --field linked-field` | 0 | `\n` | identical |
| 171 | get Fields --field Notes | `get Fields --field Notes` | 0 | `fields notes\n` | identical |
| 172 | get Fields --field TEXT | `get Fields --field TEXT` | 0 | `text value\n` | identical |
| 173 | get Fields --field field | `get Fields --field field` | 0 | `text value\n` | identical |
| 174 | get Fields --field nosuch | `get Fields --field nosuch` | 0 |  | identical |
| 175 | get Secure Note --field notes | `get 'Secure Note' --field notes` | 0 | `first line\nsecond line\n` | identical |
| 176 | get Secure Note --field note-field | `get 'Secure Note' --field note-field` | 0 | `nv\n` | identical |
| 177 | get Secure Note --field password | `get 'Secure Note' --field password` | 0 |  | identical |
| 178 | get Secure Note --field nosuch | `get 'Secure Note' --field nosuch` | 0 |  | identical |
| 179 | get Card --field number | `get Card --field number` | 0 | `4111111111111111\n` | identical |
| 180 | get Card --field cardholder | `get Card --field cardholder` | 0 | `Card Holder\n` | identical |
| 181 | get Card --field cardholder_name | `get Card --field cardholder_name` | 0 | `Card Holder\n` | identical |
| 182 | get Card --field brand | `get Card --field brand` | 0 | `Visa\n` | identical |
| 183 | get Card --field exp_month | `get Card --field exp_month` | 0 | `12\n` | identical |
| 184 | get Card --field exp_year | `get Card --field exp_year` | 0 | `2030\n` | identical |
| 185 | get Card --field expiration | `get Card --field expiration` | 0 |  | identical |
| 186 | get Card --field code | `get Card --field code` | 0 |  | identical |
| 187 | get Card --field cvv | `get Card --field cvv` | 0 | `737\n` | identical |
| 188 | get Card --field notes | `get Card --field notes` | 0 | `card notes\n` | identical |
| 189 | get Card --field nosuch | `get Card --field nosuch` | 0 |  | identical |
| 190 | get Identity --field title | `get Identity --field title` | 0 |  | identical |
| 191 | get Identity --field first_name | `get Identity --field first_name` | 0 |  | identical |
| 192 | get Identity --field middle_name | `get Identity --field middle_name` | 0 |  | identical |
| 193 | get Identity --field last_name | `get Identity --field last_name` | 0 |  | identical |
| 194 | get Identity --field name | `get Identity --field name` | 0 | `Dr Ada B Lovelace\n` | identical |
| 195 | get Identity --field address | `get Identity --field address` | 0 | `1 Analytical St\nFloor 2\nRoom 3\n` | identical |
| 196 | get Identity --field address1 | `get Identity --field address1` | 0 |  | identical |
| 197 | get Identity --field city | `get Identity --field city` | 0 | `London\n` | identical |
| 198 | get Identity --field state | `get Identity --field state` | 0 | `LDN\n` | identical |
| 199 | get Identity --field postal_code | `get Identity --field postal_code` | 0 |  | identical |
| 200 | get Identity --field country | `get Identity --field country` | 0 | `UK\n` | identical |
| 201 | get Identity --field phone | `get Identity --field phone` | 0 | `+44 1\n` | identical |
| 202 | get Identity --field email | `get Identity --field email` | 0 | `ada@example.com\n` | identical |
| 203 | get Identity --field ssn | `get Identity --field ssn` | 0 | `123-45\n` | identical |
| 204 | get Identity --field license | `get Identity --field license` | 0 | `L456\n` | identical |
| 205 | get Identity --field license_number | `get Identity --field license_number` | 0 |  | identical |
| 206 | get Identity --field passport | `get Identity --field passport` | 0 | `P123\n` | identical |
| 207 | get Identity --field passport_number | `get Identity --field passport_number` | 0 |  | identical |
| 208 | get Identity --field username | `get Identity --field username` | 0 | `ada\n` | identical |
| 209 | get Identity --field company | `get Identity --field company` | 0 |  | identical |
| 210 | get Identity --field nosuch | `get Identity --field nosuch` | 0 |  | identical |
| 211 | get SSH Key --field public_key | `get 'SSH Key' --field public_key` | 0 | `ssh-ed25519 AAAAFAKEKEY e2e\n` | identical |
| 212 | get SSH Key --field private_key | `get 'SSH Key' --field private_key` | 0 | `-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-body\nsecond-lin`… | identical |
| 213 | get SSH Key --field fingerprint | `get 'SSH Key' --field fingerprint` | 0 | `SHA256:fake\n` | identical |
| 214 | get SSH Key --field key_fingerprint | `get 'SSH Key' --field key_fingerprint` | 0 |  | identical |
| 215 | get SSH Key --field nosuch | `get 'SSH Key' --field nosuch` | 0 |  | identical |
| 216 | get Keyed --field username | `get Keyed --field username` | 0 | `kuser\n` | identical |
| 217 | get Keyed --field kf | `get Keyed --field kf` | 0 | `kv\n` | identical |
| 218 | get Keyed --field notes | `get Keyed --field notes` | 0 | `keyed notes\n` | identical |
| 219 | get Org Item --field username | `get 'Org Item' --field username` | 0 | `ouser\n` | identical |
| 220 | get Org Item --field password | `get 'Org Item' --field password` | 0 | `org-pw\n` | identical |
| 221 | get totp-sha1 --field totp | `get totp-sha1 --field totp` | 0 | `132500\n` | identical |
| 222 | get -f short | `get Fields -f text-field` | 0 | `text value\n` | identical |
| 223 | get Fields --full | `get Fields --full` | 0 | `fields-pw\nUsername: fuser\ntext-field: text value\nhidden-fiel`… | identical |
| 224 | get Fields --raw | `get Fields --raw` | 0 | `{\n  "id": "3a1b3437-a0a9-4944-83e6-4701cef45f79",\n  "folder"`… | identical |
| 225 | get Fields -l | `get Fields -l` | 0 | `username\nuris\npassword\nnotes\ntext-field\nhidden-field\nbool-fi`… | identical |
| 226 | get GitHub --full | `get GitHub alice --full` | 0 | `gh-alice-pw\nUsername: alice\nURI: https://github.com\n\nGitHub `… | identical |
| 227 | get GitHub --raw | `get GitHub alice --raw` | 0 | `{\n  "id": "a8bdccd4-ed0b-4409-944a-ad91d6f7ec22",\n  "folder"`… | identical |
| 228 | get GitHub -l | `get GitHub alice -l` | 0 | `username\nuris\npassword\nnotes\n` | identical |
| 229 | get Multiline --full | `get Multiline --full` | 0 | `ml-pw\n\nline one\nline two\n\n  indented four zebra\n\n` | identical |
| 230 | get Multiline --raw | `get Multiline --raw` | 0 | `{\n  "id": "b4671b67-11c3-4e68-a61d-dc65aa40dadf",\n  "folder"`… | identical |
| 231 | get Multiline -l | `get Multiline -l` | 0 | `uris\npassword\nnotes\n` | identical |
| 232 | get Keyed --full | `get Keyed --full` | 0 | `keyed-pw\nUsername: kuser\nkf: kv\n\nkeyed notes\n` | identical |
| 233 | get Keyed --raw | `get Keyed --raw` | 0 | `{\n  "id": "ea10c6f4-182f-4357-bbd1-2b64d7ec2b0b",\n  "folder"`… | identical |
| 234 | get Keyed -l | `get Keyed -l` | 0 | `username\nuris\npassword\nnotes\nkf\n` | identical |
| 235 | get Org Item --full | `get 'Org Item' --full` | 0 | `org-pw\nUsername: ouser\n` | identical |
| 236 | get Org Item --raw | `get 'Org Item' --raw` | 0 | `{\n  "id": "d637d8ba-808d-47d6-9dd3-aa9d957e2b18",\n  "folder"`… | identical |
| 237 | get Org Item -l | `get 'Org Item' -l` | 0 | `username\nuris\npassword\n` | identical |
| 238 | get Secure Note --full | `get 'Secure Note' --full` | 0 | `first line\nsecond line\n` | identical |
| 239 | get Secure Note --raw | `get 'Secure Note' --raw` | 0 | `{\n  "id": "e6d3bfa2-583a-4444-9cac-5e51376d4e27",\n  "folder"`… | identical |
| 240 | get Secure Note -l | `get 'Secure Note' -l` | 0 | `notes\nnote-field\n` | identical |
| 241 | get Card --full | `get Card --full` | 0 | `4111111111111111\nExpiration: 12/2030\nCVV: 737\nName: Card Hol`… | identical |
| 242 | get Card --raw | `get Card --raw` | 0 | `{\n  "id": "4103e4b8-7b43-47b5-a389-096e61a62f4c",\n  "folder"`… | identical |
| 243 | get Card -l | `get Card -l` | 0 | `number\nexp_month\nexp_year\ncvv\ncardholder\nbrand\nnotes\n` | identical |
| 244 | get Identity --full | `get Identity --full` | 0 | `Dr Ada B Lovelace\nAddress: 1 Analytical St\nAddress: Floor 2\n`… | identical |
| 245 | get Identity --raw | `get Identity --raw` | 0 | `{\n  "id": "4d20d298-3915-45d4-8452-c7a29d86f6d2",\n  "folder"`… | identical |
| 246 | get Identity -l | `get Identity -l` | 0 | `name\nemail\naddress\ncity\nstate\npostcode\ncountry\nphone\nssn\nlic`… | identical |
| 247 | get SSH Key --full | `get 'SSH Key' --full` | 0 | `ssh-ed25519 AAAAFAKEKEY e2e\nFingerprint: SHA256:fake\n` | identical |
| 248 | get SSH Key --raw | `get 'SSH Key' --raw` | 0 | `{\n  "id": "e6238af4-8b49-4970-add9-67e54ed17701",\n  "folder"`… | identical |
| 249 | get SSH Key -l | `get 'SSH Key' -l` | 0 | `fingerprint\npublic_key\n` | identical |
| 250 | get Hist-5 --full | `get Hist-5 --full` | 0 | `h5-now\n` | identical |
| 251 | get Hist-5 --raw | `get Hist-5 --raw` | 0 | `{\n  "id": "feccf423-3a35-49a5-bd53-1091e232b663",\n  "folder"`… | identical |
| 252 | get Hist-5 -l | `get Hist-5 -l` | 0 | `uris\npassword\n` | identical |
| 253 | get totp-sha1 --full | `get totp-sha1 --full` | 0 | `totp_sha1-pw\nUsername: otp\nTOTP Secret: otpauth://totp/e2e:m`… | identical |
| 254 | get totp-sha1 --raw | `get totp-sha1 --raw` | 0 | `{\n  "id": "4b409fff-50c3-4ce1-bd32-2575e350e1d1",\n  "folder"`… | identical |
| 255 | get totp-sha1 -l | `get totp-sha1 -l` | 0 | `username\ntotp\nuris\npassword\n` | identical |
| 256 | get uri-multi --full | `get uri-multi --full` | 0 | `uri_multi-pw\nURI: https://one.example\nMatch type: domain\nURI`… | identical |
| 257 | get uri-multi --raw | `get uri-multi --raw` | 0 | `{\n  "id": "71d25652-3030-45d6-bbef-35973b6a2db6",\n  "folder"`… | identical |
| 258 | get uri-multi -l | `get uri-multi -l` | 0 | `uris\npassword\n` | identical |
| 259 | get Marked --full | `get Marked --full` | 0 | `marked-pw\nbwss:id: b-1\nobsidian:id: o-1\nplain: kept\n` | identical |
| 260 | get Marked --raw | `get Marked --raw` | 0 | `{\n  "id": "2c76910f-8512-4459-a703-8a0da594ea00",\n  "folder"`… | identical |
| 261 | get Marked -l | `get Marked -l` | 0 | `uris\npassword\nbwss:id\nobsidian:id\nplain\n` | identical |
| 262 | get Plain --full | `get Plain --full` | 0 | `plain-pw\n` | identical |
| 263 | get Plain --raw | `get Plain --raw` | 0 | `{\n  "id": "61e51eb4-dd2f-4850-863d-3ce443246b75",\n  "folder"`… | identical |
| 264 | get Plain -l | `get Plain -l` | 0 | `uris\npassword\n` | identical |
| 265 | get Guarded --full | `get Guarded --full` | 0 | `guarded-pw\nUsername: guser\n` | identical |
| 266 | get Guarded --raw | `get Guarded --raw` | 0 | `{\n  "id": "af08b1ef-a73b-4697-8069-54ea72f6a48b",\n  "folder"`… | identical |
| 267 | get Guarded -l | `get Guarded -l` | 0 | `username\nuris\npassword\n` | identical |
| 268 | code totp_sha1 | `code totp-sha1` | 0 | `132500\n` | identical |
| 269 | code totp_sha256 | `code totp-sha256` | 0 | `515555\n` | identical |
| 270 | code totp_sha512 | `code totp-sha512` | 0 | `003110\n` | identical |
| 271 | code totp_d8 | `code totp-d8` | 0 | `48132500\n` | identical |
| 272 | code totp_p60 | `code totp-p60` | 0 | `107432\n` | identical |
| 273 | code totp_steam | `code totp-steam` | 0 | `XR3XC\n` | identical |
| 274 | code totp_bare | `code totp-bare` | 0 | `132500\n` | identical |
| 275 | totp alias | `totp totp-sha1` | 0 | `132500\n` | identical |
| 276 | code no TOTP | `code Plain` | 1 | `rbw code: entry does not contain a totp secret\n` | identical |
| 277 | code note | `code 'Secure Note'` | 1 | `rbw code: not a login entry\n` | identical |
| 278 | code ambiguous | `code GitHub` | 1 | `rbw code: couldn't find entry for 'GitHub': multiple entries`… | identical |
| 279 | code not found | `code nonexistent` | 1 | `rbw code: couldn't find entry for 'nonexistent': no entry fo`… | identical |
| 280 | code -i | `code -i TOTP-SHA1` | 0 | `132500\n` | identical |
| 281 | code --folder | `code totp-sha1 --folder TOTP` | 0 | `132500\n` | identical |
| 282 | history Hist-1 | `history Hist-1` | 0 | `2024-01-02T03:04:05.000000Z: h1-old\n` | identical |
| 283 | history Hist-5 | `history Hist-5` | 0 | `2024-01-01T01:00:00.000000Z: h5-old-1\n2024-02-02T02:00:00.00`… | identical |
| 284 | history Plain (none) | `history Plain` | 0 |  | identical |
| 285 | history Secure Note | `history 'Secure Note'` | 0 |  | identical |
| 286 | history ambiguous | `history GitHub` | 1 | `rbw history: couldn't find entry for 'GitHub': multiple entr`… | identical |
| 287 | history not found | `history nonexistent` | 1 | `rbw history: couldn't find entry for 'nonexistent': no entry`… | identical |
| 288 | history -i | `history -i hist-1` | 0 | `2024-01-02T03:04:05.000000Z: h1-old\n` | identical |
| 289 | --version | `--version` | 0 | `rbw 1.15.0\n` | identical |
| 290 | after sync: list --fields id,name,user,folder,type | `list --fields id,name,user,folder,type` | 0 | `693af0e5-5b95-4edc-9a82-3e4b7261156d\t2f1a4f8e-6a3b-4c7d-9e0f`… | identical |
| 291 | after sync: get Synced Later | `get 'Synced Later'` | 0 | `synced-pw\n` | identical |
| 292 | unlocked (locked) | `unlocked` | 1 | `rbw unlocked: agent is locked\n` | identical |
| 293 | list while locked (unlocks first) | `list` | 0 | `2f1a4f8e-6a3b-4c7d-9e0f-123456789abc\nAge Dotfiles\nCard\nField`… | identical |
| 294 | unlocked (after unlock) | `unlocked` | 0 |  | identical |
| 295 | unlocked (agent stopped) | `unlocked` | 1 | `rbw unlocked: agent not running\n` | identical |
| 296 | after purge: list | `list --fields id,name,user,folder,type` | 0 | `693af0e5-5b95-4edc-9a82-3e4b7261156d\t2f1a4f8e-6a3b-4c7d-9e0f`… | identical |

### Tier B results (20 checks, 20 equivalent)

| # | Check | Result |
|---|---|---|
| 1 | add (stdin) | equivalent |
| 2 | add ($EDITOR, template and result) | equivalent |
| 3 | edit (stdin) | equivalent |
| 4 | edit ($EDITOR, login and note) | equivalent |
| 5 | edit of a card is refused | equivalent |
| 6 | generate (alphabets, diceware, NAME saved) | equivalent |
| 7 | remove (exit code and output; rbw: gone, shim: trashed) | equivalent |
| 8 | sync | equivalent |
| 9 | lock | equivalent |
| 10 | unlock | equivalent |
| 11 | config show (keys; email, base_url, pinentry) | equivalent |
| 12 | config set lock_timeout 7200 | equivalent |
| 13 | config set sync_interval 0 | equivalent |
| 14 | config set sync_interval 600 | equivalent |
| 15 | config unset lock_timeout (back to each default) | equivalent |
| 16 | config set lock_timeout 0 (refused, exit 0) | equivalent |
| 17 | config set unknown key | equivalent |
| 18 | stop-agent | equivalent |
| 19 | purge | equivalent |
| 20 | purge leaves nothing unlocked | equivalent |

### Tier C observations (15 runs)

| # | Case | rbw (exit, stdout or stderr) | shim (exit, stdout or stderr) | Same? |
|---|---|---|---|---|
| 1 | unlocked after purge (rbw: agent stopped; shim: profile locked) | 1, `rbw unlocked: agent not running\n` | 1, `rbw unlocked: agent is locked\n` | differs |
| 2 | search in notes (shim: names and users only) | 0, `Multiline\n` | 0,  | differs |
| 3 | search in a URI (shim: names and users only) | 0, `uri-domain\n` | 0,  | differs |
| 4 | search in a field value (shim: names and users only) | 0, `Proton\n` | 0,  | differs |
| 5 | add with an empty text (shim writes nothing) | 0,  | 1, `rbw add: the editor left nothing to save; nothing was changed\n` | differs |
| 6 | config set identity_url (shim refuses) | 0,  | 1, `rbw config set: 'identity_url' is not supported: dybw derives the iden`… | differs |
| 7 | config set base_url without a terminal (shim refuses) | 0,  | 1, `rbw config set: changing base_url/pinentry needs an interactive termin`… | differs |
| 8 | config set pinentry without a terminal (shim refuses) | 0,  | 1, `rbw config set: changing base_url/pinentry needs an interactive termin`… | differs |
| 9 | gen-completions bash | 0, `_rbw() {\n    local i cur prev opts cmd\n    COMPREPLY=()\n    if [[ "${B`… | 0, `_rbw() {\n    local i cur prev opts cmd\n    COMPREPLY=()\n    if [[ "${B`… | differs |
| 10 | gen-completions zsh | 0, `#compdef rbw\n\nautoload -U is-at-least\n\n_rbw() {\n    typeset -A opt_arg`… | 0, `#compdef rbw\n\nautoload -U is-at-least\n\n_rbw() {\n    typeset -A opt_arg`… | differs |
| 11 | gen-completions fish | 0, `# Print an optspec for argparse to handle cmd's options that are indep`… | 0, `# Print an optspec for argparse to handle cmd's options that are indep`… | differs |
| 12 | gen-completions powershell | 0, `\nusing namespace System.Management.Automation\nusing namespace System.M`… | 0, `\nusing namespace System.Management.Automation\nusing namespace System.M`… | same |
| 13 | gen-completions elvish | 0, `\nuse builtin;\nuse str;\n\nset edit:completion:arg-completer[rbw] = {\|@wo`… | 0, `\nuse builtin;\nuse str;\n\nset edit:completion:arg-completer[rbw] = {\|@wo`… | same |
| 14 | gen-completions nushell | 0, `module completions {\n\n  # Unofficial Bitwarden CLI\n  export extern rbw`… | 0, `module completions {\n\n  # Unofficial Bitwarden CLI\n  export extern rbw`… | same |
| 15 | gen-completions fig | 0, `const completion: Fig.Spec = {\n  name: "rbw",\n  description: "Unoffici`… | 0, `const completion: Fig.Spec = {\n  name: "rbw",\n  description: "Unoffici`… | same |
