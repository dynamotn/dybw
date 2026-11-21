# Configuration

dybw reads one file, `~/.config/dybw/config.toml`. It holds no secret, so it can live in your dotfiles. Nothing in
it can grant access: the caller policy, the unlock protectors and the harness list are device state, set with
commands (see [Files and locations](#files-and-locations)).

## Example

```toml
default = "personal"

# Shared by every profile
lock_timeout_minutes = 60
sync_interval_seconds = 300
pinentry = "pinentry-mac"
clipboard_clear_seconds = 30

[agent]
touch_id_confirm = true

[ssh_agent]
profiles = ["personal", "work"]

[profiles.personal]
server_url = "https://vault.bitwarden.com"
email = "me@example.com"

[profiles.work]
server_url = "https://vault.example.corp"
email = "me@example.corp"
lock_timeout_minutes = 15        # this profile only
```

## Keys

A profile takes each setting from its own section first, then from the top level, then from the default.

| Key | Where | Default | Meaning |
|-----|-------|---------|---------|
| `default` | top level | none | The profile used when neither `-p` nor `DYBW_PROFILE` names one |
| `auth` | top level, profile | `"api-key"` | Only `"api-key"` works: the agent refuses `"password"` profiles |
| `lock_timeout_minutes` | top level, profile | `60` | Idle time before the profile locks; `0` never locks |
| `sync_interval_seconds` | top level, profile | `300` | Periodic sync; `0` turns it off |
| `pinentry` | top level, profile | `"pinentry"` | An absolute path, or a name looked up in `/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin` |
| `clipboard_clear_seconds` | top level | `30` | How long a `-c` copy stays on the clipboard |
| `server_url` | profile, required | none | The server, for example `https://vault.bitwarden.com` |
| `email` | profile, required | none | The account's email |
| `[agent] touch_id_confirm` | table | `true` | On a Mac with Touch ID, confirm reads with the Touch ID sheet; `false` uses the pinentry only |
| `[ssh_agent] profiles` | table | none | The profiles whose SSH keys the SSH agent offers, in order |

The file is checked strictly. A misspelt key is an error, even in a profile you are not using. A table the agent
does not own, such as `[bwss]`, is ignored. `[agent]` and `[ssh_agent]` accept only the keys above.

`pinentry` must be a program you cannot replace. Neither the program nor any directory above it may be writable by
you. The one exception is a program in the same Homebrew prefix as `dybw-agent`, when that prefix is outside your
home. Otherwise the agent refuses it, and `dybw doctor` says why.

`touch_id_confirm = false` grants nothing, so it is safe in a synced file.

## Choosing a profile

`--profile <name>` (`-p`) wins, then `DYBW_PROFILE`, then `default`. Profile names are 1 to 64 characters of
`A-Z`, `a-z`, `0-9`, `_` and `-`. Profiles are independent: unlocking, locking, syncing and errors in one never
touch another.

The rbw shim reads `RBW_PROFILE` instead, and ignores `-p` and `DYBW_PROFILE` (see [rbw-shim.md](rbw-shim.md)).

## Files and locations

Every file sits under the agent's trusted home, which is your home in the password database. The agent refuses to
start when `HOME` names another directory, and it ignores the `XDG_*` variables of whoever started it. So a caller
cannot point it at another config, server or pinentry. `dybw doctor` reads the same places and flags a `HOME` that
differs.

| Path | What |
|------|------|
| `~/.config/dybw/config.toml` | The configuration |
| `~/.local/state/dybw/profiles/<profile>/` | Credentials (the API key, bound to its server), device id, `policy.json`, unlock protectors |
| `~/.local/state/dybw/audit.log` | The audit log (0600, append-only) |
| `~/.local/state/dybw/harnesses.toml` | Extra AI harnesses (optional) |
| `~/.cache/dybw/profiles/<profile>/` | The encrypted copy of the vault |
| `$XDG_RUNTIME_DIR/dybw/` | Sockets (`agent.sock`, `ssh-agent.sock`) and `agent.log`. Without `XDG_RUNTIME_DIR`, as on macOS: `$TMPDIR/dybw-<uid>/` |

Socket paths are not configurable. Files that an earlier build wrote under a custom `XDG_*` directory are not
found: move them, or log in again.

## The agent's environment

An agent that `dybw` starts on demand inherits the environment of that first caller. This includes `RUST_LOG`, and
the session variables it passes to the pinentry (`DISPLAY`, `WAYLAND_DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`,
`XAUTHORITY`, `LANG` and so on). Start the first `dybw` from your GUI session. If an agent was started from an ssh
session, run `dybw agent stop`. Or run the agent as a service (see [install.md](install.md#run-the-agent-as-a-service)).
