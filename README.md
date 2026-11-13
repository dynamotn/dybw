# dybw-cli

The `dybw` command line client and the `dybw-agent` that holds the vault session, built on
[dybw-core](https://gitlab.com/dynamo-tools/dybw-core). MIT licensed.

**Status: P4.1, a read-only CLI and agent.** `dybw` logs in with an API key, unlocks, lists, searches and reads
items through the agent; writes, URI lookup and the SSH and git integrations come in later phases.

| Crate | What |
|-------|------|
| `dybw-proto` | Versioned IPC types (`{ version, op }`) and length-prefixed JSON framing (u32 big-endian, max 1 MiB) |
| `dybw-agent` | The agent: one worker per profile holds the unlocked vault, locks it on idle and after a suspend |
| `dybw` | The client binary |

## Commands

| Command | What |
|---------|------|
| `dybw login` | Store the profile's API key (client id and secret, asked through pinentry) |
| `dybw unlock` | Ask for the master password and unlock |
| `dybw unlocked` | Exit 0 when unlocked, 1 when not; never unlocks |
| `dybw lock [--all]` | Lock now |
| `dybw status` | `profile`, logged in, locked or unlocked, last sync (unix seconds); never unlocks |
| `dybw sync [--all]` | Fetch the vault now |
| `dybw list`, `dybw search <term>` | Names, or `--fields id,name,user,folder,type`, `--folder`, `--raw` (list only, JSON) |
| `dybw get <item> [user]` | The main value; `-f <field>`, `--full`, `--raw`, `-l` (`--list-fields`), `--folder`, `-i` |
| `dybw history <item>` | Previous passwords, newest first |
| `dybw policy show\|allow\|deny\|forget` | Show or change which programs may read values (changes are confirmed in pinentry) |
| `dybw audit [--ai] [-n N]` | The latest N audit lines (default 50) as tab-separated columns; `--ai` keeps AI-class callers. Read straight from the file, no agent needed |
| `dybw doctor` | Check the socket directory, the agent (reachable, same version), config, pinentry, `policy.json` and `audit.log`; exit 0 when all pass, 1 otherwise. Under an AI harness it also warns that the harness sandbox must not reach the agent |
| `dybw agent stop` | Stop the agent (locks every profile) |

`--profile <name>` (or `DYBW_PROFILE`) picks the profile; the default is the config's `default`.

## Usage

```sh
dybw login                 # once per profile: the API key, not the master password
dybw get example.org       # unlocks first if locked, then asks you to confirm the read
dybw get example.org -f user
dybw list --fields name,user,folder
```

A locked profile unlocks on first need: `list`, `search`, `get`, `history` and `sync` run the unlock flow first
(a master-password prompt; offline, the cached copy is used), then continue. A cancelled or failed unlock is its
own error and nothing else happens. A profile that is not logged in says so; there is no implicit login. The
agent starts on first use and logs to `agent.log` in its socket directory (`$XDG_RUNTIME_DIR/dybw/`); an error that
only says "see the agent log" is explained there.

## Limits

- API-key login only (`auth = "password"` profiles are refused).
- Reading a value (including `get --list-fields` and `history`) follows the caller policy: an AI-class caller is
  denied, an unknown caller (for example a `dybw` whose own parent exited) is asked every time, any other invoker is
  asked once or "always". `list` and `search` show only names and never ask. An AI-class caller also cannot stop
  the agent, unlock, log in or use `dybw policy` (even `show`), and never raises a master-password prompt: a locked
  profile answers "locked" to its `list` and `search`.
- Grants are a convenience for honest programs, not a boundary: code running as you can defeat them (a script's
  argv is its own memory, the environment can be injected, `policy.json` can be edited). The boundary is the harness
  sandbox, which must not reach the agent's socket or state directories, and the out-of-band pinentry confirmation.
  So:
  - "always" for a plain program is remembered in `policy.json` by its path (as the kernel reports it) and content
    hash; a changed program asks again. On Linux the running image is hashed (`/proc/<pid>/exe`); on macOS the file
    at the path must carry the running image's `LC_UUID` (a file without one is trusted by path and content).
  - "always" for a script run by an interpreter or shell ("which claims to run" it, in the question) lasts for that
    process only, in the agent's memory: until it exits or the profile locks or the agent stops. It is never written,
    and script entries an older build wrote to `policy.json` are ignored.
  - an interpreter, a shell, a launcher, multiplexer or terminal (`xargs`, `env`, `make`, `git`, `tmux`, `kitty`,
    `ssh`, `cron` and the like), a relative script and an unknown caller are never offered "always".
  - a detached caller (its parent exited, or it was started by launchd or a subreaper) is never offered "always" and
    is told apart in the question ("possibly an AI agent"); only `dybw policy allow --detached <program>` makes a
    grant for it, and that grant matches only its detached runs.
  - a grant never covers `get --full`, `get --raw` or `history`: they are asked every time.
- The policy file (`policy.json`, in the profile's state directory) is plain device state. `dybw policy show` is
  open to every class but AI; `allow`, `deny` and `forget` are confirmed in pinentry and refused for AI-class and
  unknown callers. `allow` takes a plain program only (`--detached` for its detached runs) and refuses interpreters,
  shells and launchers; `deny` accepts anything, and without `--script` covers every script of the program.
- The audit log (`~/.local/state/dybw/audit.log` under the agent's trusted home, never `XDG_STATE_HOME`, which the
  first caller of an on-demand agent could set; 0600, append-only, never through a symlink) records every decision
  on a value request from the AI class and every request, decision or not, from AI and unknown callers (`listed` for
  names, `failed` for a lookup that went nowhere; no needle, no candidates), and every decision of other callers on
  a value or a policy change. A line is JSON: time (UTC), profile, caller (program and script, or the harness),
  class, op, what `get` selected (`password`, `field`, `full`, `raw`, `list-fields`; never a field name), the item
  id (never its name or a value) and the verdict; for an unknown caller also why it could not be named and the
  program on the socket, and for any caller the program on the socket when it is a `dybw` or `rbw` other than the
  one next to the agent. `dybw audit --ai` shows AI-class and unknown callers. It rotates once to `audit.log.1` at 10 MiB (`dybw audit` reads
  only the current file); a rotation that fails is reported and the live file just keeps growing. A line that cannot
  be written is reported in the agent log and dropped: the request is still answered, and `dybw doctor` shows an
  unwritable log. The log is same-user device state: evidence, not a barrier; a program running as you can edit or
  delete it. `dybw audit` and `dybw doctor` find it under your home in the password database, like the agent.
- A `policy.json` that fails its checks (wrong mode, owner, not valid) is ignored for decisions, and `dybw policy
  allow|deny|forget` refuse to write over it, so a deny entry is never dropped by accident. Repair it by hand
  (`chmod 600`, or fix or remove the file; the grants are then asked again). `dybw doctor` names the problem.
- On macOS the agent calls `ptrace(PT_DENY_ATTACH)` first thing, so a debugger cannot attach to read the unlocked
  vault: running `dybw-agent` under lldb kills it. (Linux sets `PR_SET_DUMPABLE=0` instead.) A failure is reported
  on stderr and the agent keeps running.
- No lookup by URI yet.
- Items that ask for a master-password reprompt are denied until P4.3.
- Organization items are readable.
- Every file of the agent lives under its trusted home, your home in the password database: the config
  (`~/.config/dybw/config.toml`), the state (credentials, device id, `policy.json`, `harnesses.toml`, the audit log,
  in `~/.local/state/dybw`) and the vault cache (`~/.cache/dybw`). The agent refuses to start when `HOME` names
  another directory, and the `XDG_*` variables of whoever started it are ignored, so a starter cannot point it at
  another config, server or pinentry; `dybw doctor` reads the same places and flags a `HOME` that differs. Files an earlier build wrote under a custom
  `XDG_*` directory are not found: move them, or log in again.
- An agent started on demand inherits the environment of the first caller: `RUST_LOG`, and the session
  variables the agent forwards to pinentry (`SESSION_ENV` of `dybw-native`: `DISPLAY`, `WAYLAND_DISPLAY`,
  `DBUS_SESSION_BUS_ADDRESS`, `XAUTHORITY`, `LANG`, `HOME` and so on). Start the first `dybw` from the GUI
  session, or run `dybw agent stop` after an agent was started from an ssh session.

## Build and test

```sh
cargo build --locked
cargo test --workspace --locked
cargo llvm-cov --workspace --locked --fail-under-lines 100
```

MSRV is 1.89. CI also runs fmt, clippy (`-D warnings`) and `cargo audit`.

## End-to-end tests

The suite runs in Docker against a throwaway Vaultwarden:

```sh
scripts/e2e.sh
```

It builds `tests/e2e/Dockerfile`, starts Vaultwarden, and runs pytest in a container that shares its network.
The suite writes under the test user's real home (the agent only runs on the password database's home), so it runs
only in that container (`DYBW_E2E_CONTAINER`). The cargo tests run the agent binary on a home of their own through
`DYBW_TEST_PASSWD_HOME`, read only by the `dybw-agent-test-home` binary of the test-only `test-home` feature (never
in a release build, refused by CI in the normal graph); `dybw-agent` itself never reads it.
`DOCKER_HOST` and `DOCKER_CONFIG` come from your environment.
