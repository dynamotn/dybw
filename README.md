# dybw

A Bitwarden and Vaultwarden command line client and agent that knows who is asking for your secrets.

dybw is a drop-in replacement for [rbw](https://github.com/doy/rbw): same commands, same output, byte for byte.
On top of that, its agent identifies every caller and applies a per-caller policy. An AI coding agent or a script
cannot silently read a password: AI agents get item names only, and other programs must be confirmed in a pinentry
or a Touch ID sheet. It unlocks with Touch ID, a PIN or your Linux login password, and it doubles as an SSH agent for
the SSH keys in your vault.

## Features

- **rbw drop-in.** Symlink `rbw` to `dybw` and your scripts keep working: 296 of 296 rbw 1.15 cases give
  byte-identical output and exit codes, and 20 of 20 write cases leave the same vault state
  ([conformance report](docs/rbw-conformance.md)).
- **Caller policy.** Every value read is confirmed per program, out of band. "Always" is remembered only for an
  unchanged program binary, and scripts get it for one process only.
- **An AI-agent class.** Claude Code, Codex, Gemini, Copilot, Cursor, opencode, aider and others are recognized.
  They can list names but never read a value, unlock, log in or change the policy.
- **Audit log.** Every decision is logged as one JSON line: caller, item id and verdict, never a value.
  `dybw audit --ai` shows what your AI agents asked for.
- **Local unlock.** Touch ID through the Secure Enclave, a PIN held in memory, or on Linux your login password
  through `pam_bwss`. You type the master password far less often.
- **SSH agent.** SSH keys stored in the vault, each signature confirmed, `session-bind@openssh.com` host
  verification, refusal of SHA-1 RSA. Private keys never leave the agent.
- **The everyday parts.** TOTP codes, add, edit, generate and trash logins, and clipboard copies marked as secret
  and cleared after 30 seconds.

## Quick start

### Install

```sh
cargo install --git https://github.com/dynamotn/dybw.git --tag v1.0.0-rc.1 --locked dybw dybw-agent
```

Prebuilt binaries are on the [GitHub releases page](https://github.com/dynamotn/dybw/releases): static Linux builds
for x86_64 and aarch64, and an unsigned macOS arm64 build. See
[docs/install.md](docs/install.md#prebuilt-binaries) for the asset names and how to verify them. Building
needs Rust 1.89 or newer. On macOS it also needs the Xcode Command Line Tools (`xcode-select --install`), which build
the Secure Enclave code.

Keep `dybw` and `dybw-agent` in the same directory: `dybw` starts only the agent next to it, and the agent trusts
only the `dybw` next to it.

### Configure a profile

A profile is one account on one server. Write `~/.config/dybw/config.toml`:

```toml
default = "personal"
pinentry = "pinentry-mac"        # or pinentry-gnome3, pinentry-qt, ...

[profiles.personal]
server_url = "https://vault.bitwarden.com"
email = "me@example.com"
```

Every key is described in [docs/configuration.md](docs/configuration.md).

### First steps

```sh
dybw login                   # the API key (client id and secret), asked in the pinentry
dybw unlock                  # the master password, asked in the pinentry
dybw list                    # item names
dybw get example.org         # a password, after you confirm the read
dybw get example.org -f user
dybw code github             # a TOTP code
dybw doctor                  # check the setup
```

`dybw login` takes the API key from your web vault's account security settings, not the master password. A locked
profile unlocks on first need, so `dybw unlock` is optional.

## Use it as rbw

Make `rbw` a symlink to `dybw`, earlier on `PATH` than rbw's own binary (or uninstall rbw):

```sh
ln -s ~/.cargo/bin/dybw ~/.local/bin/rbw
rbw get example.org
RBW_PROFILE=work rbw list
```

Invoked as `rbw`, the binary takes rbw 1.15's command line and prints what rbw prints. You do not need an
`rbw-agent`: `rbw stop-agent` stops `dybw-agent`. Value reads still go through the caller policy. A few commands
behave differently on purpose. For example, `rbw remove` moves the item to the trash. See
[docs/rbw-shim.md](docs/rbw-shim.md).

## Unlock with Touch ID or a PIN

```sh
dybw unlock add biometric    # macOS: a Secure Enclave key that Touch ID opens
dybw unlock add pin          # any platform: a PIN of at least 6 characters, held in the agent's memory
dybw unlock add login        # Linux with pam_bwss: your login or screen unlock opens the vault
dybw unlock list
```

Each one asks for the master password once to enrol. `dybw unlock` then tries Touch ID, then the PIN, then the
master password. Cancel one to move on to the next. Five wrong PINs drop the PIN. Adding or removing a fingerprint
drops the Touch ID protector unless you enrolled it with `--any`. Details and trade-offs are in
[docs/local-unlock.md](docs/local-unlock.md).

## SSH agent

List the profiles whose SSH key items the agent should offer, then point `SSH_AUTH_SOCK` at its socket:

```toml
[ssh_agent]
profiles = ["personal"]
```

```sh
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/dybw/ssh-agent.sock"   # Linux
export SSH_AUTH_SOCK="${TMPDIR%/}/dybw-$(id -u)/ssh-agent.sock"   # macOS (no XDG_RUNTIME_DIR)
dybw ssh list
ssh-add -l
ssh git@example.org
```

Each signature asks for confirmation. The prompt names the client, the key and the destination host, and says
whether that host is verified. Git commit signing works the same way and is labelled "NOT an SSH login". See
[docs/ssh-agent.md](docs/ssh-agent.md).

## Let a script read one item

The first time a program reads a value, the agent asks you in the pinentry, or with Touch ID on a Mac:

```sh
#!/bin/sh
export PGPASSWORD="$(dybw get db.example.org)"   # you confirm this read
pg_dump mydb > backup.sql
```

For a script, "always" lasts only as long as that process. For a compiled program, you can remember the answer,
tied to that exact binary:

```sh
dybw policy allow /usr/local/bin/backup-tool
dybw policy show
dybw policy deny /usr/local/bin/untrusted
```

A grant never covers `get --full`, `get --raw` or `history`: those ask every time. See
[docs/policy.md](docs/policy.md).

## Keep AI agents in check

The agent walks each caller's process ancestry, and checks marker variables such as `CLAUDECODE`, to spot an AI
harness. An AI-class caller can:

- list and search item names;
- ask for a value, which is always denied and logged;
- ask for an SSH signature, which you confirm every time, outside its terminal.

It can never unlock, log in, change the policy or raise a master-password prompt. Review what it tried:

```sh
dybw audit --ai
```

This is a speed bump for honest tools, not a wall. The boundary that holds is the harness's sandbox, which must not
reach the agent's socket or state directories. `dybw doctor` warns when it runs under a harness. To teach the agent
another harness, add it to `~/.local/state/dybw/harnesses.toml` ([docs/policy.md](docs/policy.md#ai-agents)).

## Run the agent as a service

`dybw` starts the agent on first use, with that first caller's environment. Run it as a login service instead, so
pinentry and Touch ID also show for hotkeys and launchers:

```sh
# macOS (launchd)
sed -e "s|@HOME@|$HOME|g" -e "s|@TMPDIR@|$(getconf DARWIN_USER_TEMP_DIR)|g" \
  contrib/macos/org.dybw.agent.plist > ~/Library/LaunchAgents/org.dybw.agent.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.dybw.agent.plist

# Linux (systemd user unit, started with the graphical session)
cp contrib/systemd/dybw-agent.service ~/.config/systemd/user/
systemctl --user enable --now dybw-agent.service
```

See [docs/install.md](docs/install.md) for what each unit needs, how to check that your shells reach it, and how
to set up shell completions.

## Commands

| Command | What it does |
|---------|--------------|
| `dybw login` | Store the profile's API key |
| `dybw unlock` / `lock [--all]` / `unlocked` | Unlock, lock, or test (exit 0 when unlocked) |
| `dybw unlock add\|remove\|list` | Manage local unlock protectors: `pin`, `biometric`, `login` |
| `dybw status` | Logged in, locked, last sync, protectors |
| `dybw sync [--all]` | Fetch the vault now |
| `dybw list`, `dybw search <term>` | Item names (`--fields id,name,user,folder,type`, `--folder`, `--raw`) |
| `dybw get <item> [user]` | A value (`-f <field>`, `--full`, `--raw`, `-l`, `-c` to copy) |
| `dybw history <item> [user]` | Previous passwords, newest first |
| `dybw code <item> [user]` | The current TOTP code (`--next`, `-c`) |
| `dybw add`, `edit`, `remove` | Write logins; new values are typed in the agent's pinentry |
| `dybw generate <len> [name [user]]` | Print a password, or save a new login with one |
| `dybw policy show\|allow\|deny\|forget` | Which programs may read values |
| `dybw ssh list` | Keys the SSH agent offers |
| `dybw audit [--ai] [-n N]` | The latest audit lines |
| `dybw doctor` | Check the setup |
| `dybw agent stop` | Stop the agent and lock every profile |
| `dybw gen-completions <shell>` | Completion script for bash, zsh, fish, elvish or powershell |

Every command takes `-p, --profile <name>`, and falls back to `DYBW_PROFILE` and then the config's `default`.
`dybw <command> --help` has the details.

## How it works

```text
 dybw / rbw  ──┐
               ├─ agent.sock ──►  dybw-agent  ──►  worker "personal" ──► dybw-core ──► Bitwarden / Vaultwarden
 ssh, git    ──┘  ssh-agent.sock   (caller check,   worker "work"
                                    policy, audit)
```

`dybw` is a thin client. It sends versioned, length-prefixed JSON requests to `dybw-agent` over a Unix socket in
`$XDG_RUNTIME_DIR/dybw/` (or `$TMPDIR/dybw-<uid>/` when that is not set). For each request, the agent identifies
the calling process, its parents and its executable, then applies the policy and writes the audit line. It hands
the request to the worker of that profile. Each worker holds one unlocked vault through
[dybw-core](https://gitlab.com/dynamo-tools/dybw-core), which does the crypto and the API calls. Workers lock
after the idle timeout, after the machine sleeps and on `dybw lock`, and their keys are zeroized. The SSH agent
runs in the same process.

| Crate | Role |
|-------|------|
| `dybw` | The client binary, and the rbw shim when invoked as `rbw` |
| `dybw-agent` | The agent: caller identity, policy, audit, one worker per profile, the SSH agent |
| `dybw-proto` | Versioned IPC types and framing (u32 big-endian length, at most 1 MiB) |
| `dybw-peer` | Platform layer: who is on the other end of a socket, the secret clipboard (the only crate with `unsafe`) |

## Security model

- **The master password and new values never cross the socket.** The agent asks for them in its own pinentry, a
  program you cannot replace without write access to its directory.
- **Confirmation happens out of band:** a pinentry window or a Touch ID sheet, not the caller's terminal. Writes,
  policy changes and `rbw purge` are confirmed every time.
- **Grants are a convenience, not a boundary.** Code running as you can defeat them. The boundaries that hold are
  the AI harness's sandbox, which must not reach the agent, and the out-of-band confirmation.
- **Nothing that grants access comes from a synced file.** The policy, the protectors and the harness list are
  device state under `~/.local/state/dybw`. `config.toml` can be synced with your dotfiles and holds no secret.
- **The agent trusts only its own home.** It refuses to start when `HOME` is not your home in the password
  database, and it ignores the caller's `XDG_*` variables. It also denies debugger attach (`PT_DENY_ATTACH` on
  macOS, `PR_SET_DUMPABLE=0` on Linux).
- **An API key is bound to the server it was entered for** and is never sent to another one.

The details are in [docs/policy.md](docs/policy.md) (caller policy, AI agents, audit log, writes) and
[docs/local-unlock.md](docs/local-unlock.md) (protectors). The design records behind them are ADR 0006 (local unlock
protectors), ADR 0008 (one config file), ADR 0012 (AI agents as callers) and ADR 0025 (the agent as the vault
client). They live in the dybw specification repository.

## Status

Release candidate **v1.0.0-rc.1**. It runs on macOS (Touch ID needs a Mac with a Secure Enclave) and Linux (the
`login` protector needs `pam_bwss`). The minimum supported Rust version is 1.89. Login
uses an API key only, so there is no password login and no 2FA prompt. Organization items are readable, and new
items are personal.

## Development

```sh
cargo build --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo llvm-cov --workspace --locked --fail-under-lines 100 --ignore-filename-regex 'dybw-peer/src/keyring\.rs$'
cargo audit
scripts/e2e.sh               # end-to-end, in Docker, against a throwaway Vaultwarden
```

CI runs all of these, and checks the build on the MSRV. Line coverage must stay at 100%. The end-to-end suite
includes the rbw conformance run; `E2E_TESTS=<file or test id>` narrows it. See [docs/install.md](docs/install.md#tests)
for how the tests isolate their home directory.

## License

MIT, see [LICENSE](LICENSE). The rbw shim's command line and help text come from rbw (MIT, see
[`crates/dybw/src/rbw_completion/LICENSE-rbw`](crates/dybw/src/rbw_completion/LICENSE-rbw)). `--diceware` uses the
EFF large wordlist (Electronic Frontier Foundation, CC BY 3.0 US).
