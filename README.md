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
- Every read of a value is confirmed through pinentry, including `get --list-fields`; `list` and `search` show only
  names and never ask.
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
