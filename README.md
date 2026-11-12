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
  denied, an unknown or detached caller is asked every time, any other invoker is asked once or "always" (remembered
  by program, script and content hash; a changed script asks again). `list` and `search` show only names and never ask.
- The policy file (`policy.json`, in the profile's state directory) is plain device state: a program running as the
  same user can edit it directly. The boundary is the harness sandbox, which must not reach the agent's socket or
  state directories. `dybw policy show` is open to every class; `allow`, `deny` and `forget` are confirmed in
  pinentry and refused for AI-class and unknown callers. `allow` refuses a bare interpreter or shell and relative
  scripts (they cannot be remembered); `deny` accepts them.
- The audit log (`~/.local/state/dybw/audit.log` under the agent's trusted home, never `XDG_STATE_HOME`, which the
  first caller of an on-demand agent could set; 0600, append-only, never through a symlink) records every decision
  on a value request from the AI class and every request, decision or not, from AI and unknown callers (`listed` for
  names, `failed` for a lookup that went nowhere; no needle, no candidates), and every decision of other callers on
  a value or a policy change. A line is JSON: time (UTC), profile, caller (program and script, or the harness),
  class, op, what `get` selected (`password`, `field`, `full`, `raw`, `list-fields`; never a field name), the item
  id (never its name or a value) and the verdict. It rotates once to `audit.log.1` at 10 MiB (`dybw audit` reads
  only the current file); a rotation that fails is reported and the live file just keeps growing. A line that cannot
  be written is reported in the agent log and dropped: the request is still answered, and `dybw doctor` shows an
  unwritable log. The log is same-user device state: evidence, not a barrier; a program running as you can edit or
  delete it. `dybw audit` and `dybw doctor` find it from the raw `HOME` of the command (the CLI has no trusted
  home to check it against), so a `HOME` that differs from the agent's reads another file.
- A `policy.json` that fails its checks (wrong mode, owner, not valid) is ignored for decisions, and `dybw policy
  allow|deny|forget` refuse to write over it, so a deny entry is never dropped by accident. Repair it by hand
  (`chmod 600`, or fix or remove the file; the grants are then asked again). `dybw doctor` names the problem.
- On macOS the agent calls `ptrace(PT_DENY_ATTACH)` first thing, so a debugger cannot attach to read the unlocked
  vault: running `dybw-agent` under lldb kills it. (Linux sets `PR_SET_DUMPABLE=0` instead.) A failure is reported
  on stderr and the agent keeps running.
- No lookup by URI yet.
- Items that ask for a master-password reprompt are denied until P4.3.
- Organization items are readable.
- An agent started on demand inherits the environment of the first caller: `XDG_*`, `RUST_LOG`, and the session
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
`DOCKER_HOST` and `DOCKER_CONFIG` come from your environment.
