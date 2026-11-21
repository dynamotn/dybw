# dybw-cli

The `dybw` command line client and the `dybw-agent` that holds the vault session, built on
[dybw-core](https://gitlab.com/dynamo-tools/dybw-core). MIT licensed.

**Status: P4.3.** `dybw` logs in with an API key, unlocks, lists, searches and reads items through the agent, gives
TOTP codes, copies to the clipboard, finds items by id, name or URI as rbw does, and adds, edits, generates and
trashes logins; the rbw shim and the SSH and git integrations come in later phases.

| Crate | What |
|-------|------|
| `dybw-proto` | Versioned IPC types (`{ version, op }`) and length-prefixed JSON framing (u32 big-endian, max 1 MiB) |
| `dybw-agent` | The agent: one worker per profile holds the unlocked vault, locks it on idle and after a suspend |
| `dybw` | The client binary |

## Commands

| Command | What |
|---------|------|
| `dybw login` | Store the profile's API key (client id and secret, asked through pinentry) |
| `dybw unlock` | Unlock: the PIN first when one is set (cancel it to type the master password), else the master password |
| `dybw unlock add pin` | Set a PIN for this profile on this device: the master password, then the PIN twice (at least 6 characters), in the agent's pinentry. The PIN lives in the agent's memory only: `dybw lock` and the idle lock keep it; `dybw agent stop`, `dybw login`, `rbw purge`, a user-key rotation and 5 wrong PINs drop it. Refused to AI-class and unnamed callers. A PIN unlocks only: an item that asks for the master password again (reprompt) still needs the master password |
| `dybw unlock add login` | Linux, with `pam_bwss` (bwss) in the PAM stack: the master password, then your login password twice (not checked against the system: type it exactly). The key is wrapped by Argon2id over it and kept in `~/.local/state/dybw/profiles/<p>/unlock/login` (0600), bound to this device. Logging in or unlocking the screen then unlocks the profile without a question: the agent takes the password `pam_bwss` puts in your kernel keyring (polled every second while a profile has this protector) and invalidates it at once. A password change re-wraps it; the old wrap stays until a login with the new password. A login password that opens neither the protector nor a pending re-wrap (a reset by root, say) deletes it, and so do another machine, a rotation, `dybw login` and `rbw purge`: the next unlock asks for the PIN or the master password, and enrolling again needs the master password. Without a TPM2, someone who takes the disk can guess the login password offline. When your last logind session closes, every profile locks |
| `dybw unlock remove pin\|login` | Drop the protector. Refused to AI-class and unnamed callers |
| `dybw unlock list` | `profile`, protector, wrong tries left (`-` for an AI-class caller, which gets names only, and for `login`, which has no limit); no agent running means the `login` protector only |
| `dybw unlocked` | Exit 0 when unlocked, 1 when not; never unlocks |
| `dybw lock [--all]` | Lock now |
| `dybw status` | `profile`, logged in, locked or unlocked, last sync (unix seconds), local unlock protectors (`pin`, `login`, comma-separated, or `-`); never unlocks |
| `dybw sync [--all]` | Fetch the vault now |
| `dybw list`, `dybw search <term>` | Names, or `--fields id,name,user,folder,type`, `--folder`, `--raw` (list only, JSON) |
| `dybw get <item> [user]` | The main value; `-f <field>`, `--full`, `--raw`, `-l` (`--list-fields`), `--folder`, `-i`, `-c` (copy instead of print) |
| `dybw history <item>` | Previous passwords, newest first |
| `dybw code <item> [user]` | The current TOTP code; `--next` waits for the next one when fewer than 5 s are left; `--folder`, `-i`, `-c` |
| `dybw add <name> [user]` | A new login: `--uri U` (repeatable), `--folder F` (created if missing); the password (unless `--no-password`), and with `--notes` the notes, are typed in the agent's pinentry |
| `dybw edit <item> [user]` | A new password (the old one goes to the history), and with `--notes` new notes (`--no-password`: notes only), typed in the agent's pinentry; `--folder` (to find the item) |
| `dybw remove <item> [user]` | Move the item to the trash (never purged); `--folder` |
| `dybw generate <len>` | Print a random password made here (OS random numbers, no agent): `--no-symbols`, `--only-numbers`, `--nonconfusables`, `--diceware` (`<len>` words of the EFF large list) |
| `dybw generate <len> <name> [user]` | The agent makes the password and saves it as a new login (`--uri`, `--folder`); nothing is printed |
| `dybw policy show\|allow\|deny\|forget` | Show or change which programs may read values (changes are confirmed in pinentry) |
| `dybw audit [--ai] [-n N]` | The latest N audit lines (default 50) as tab-separated columns; `--ai` keeps AI-class callers. Read straight from the file, no agent needed |
| `dybw doctor` | Check the socket directory, the agent (reachable, same version), config, pinentry, the machine fingerprint a PIN is bound to, on Linux the `login` protector (the user keyring readable, the last handover), `policy.json` and `audit.log`; exit 0 when all pass, 1 otherwise. Under an AI harness it also warns that the harness sandbox must not reach the agent |
| `dybw agent stop` | Stop the agent (locks every profile) |
| `dybw gen-completions <shell>` | Print the completion script for `bash`, `zsh`, `fish`, `elvish` or `powershell` (no agent needed). `rbw gen-completions <shell>` prints the shim's, as rbw |

`--profile <name>` (or `DYBW_PROFILE`) picks the profile; the default is the config's `default`.

## Install

Needs Rust 1.89 or newer (`cargo`), and on macOS the Xcode Command Line Tools (`xcode-select --install`), whose
`xcrun swiftc` builds the Secure Enclave code. Both binaries come from this repository, at a pinned revision:

```sh
cargo install --locked --git https://gitlab.com/dynamo-tools/dybw-cli.git --rev <rev> dybw dybw-agent
```

They land in `~/.cargo/bin` (`--root <dir>`: `<dir>/bin`) and must stay in one directory: `dybw` starts only the
`dybw-agent` next to it, and the agent trusts only the `dybw` next to it.

- **The agent.** `dybw` starts it on first use, with the environment of that first caller. To have it start at login
  with the GUI session's (so pinentry and Touch ID show for hotkeys and launchers without a terminal), install the
  service; on-demand start stays as the fallback, and a second agent finds the lock held and exits.
  - macOS: [`contrib/macos/org.dybw.agent.plist`](contrib/macos/org.dybw.agent.plist) (label `org.dybw.agent`).
    It is a template: `@HOME@` and `@TMPDIR@` must be substituted before launchd loads it (launchd expands no
    variables), `@HOME@` with your home and `@TMPDIR@` with `getconf DARWIN_USER_TEMP_DIR`. Copy it to
    `~/Library/LaunchAgents/`, then `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.dybw.agent.plist`.
    It logs to `~/Library/Logs/dybw-agent.log`.
  - Linux with systemd: [`contrib/systemd/dybw-agent.service`](contrib/systemd/dybw-agent.service), a user unit
    wanted by `graphical-session.target`: copy it to `~/.config/systemd/user/`, then
    `systemctl --user enable --now dybw-agent.service`. The compositor must import `WAYLAND_DISPLAY`, `DISPLAY`,
    `XAUTHORITY` and `DBUS_SESSION_BUS_ADDRESS` into the user manager first (`systemctl --user import-environment
    ...`; niri-session and uwsm do it). Until `WAYLAND_DISPLAY` or `DISPLAY` is there the unit is skipped
    (`ConditionEnvironment`, systemd 246+) rather than started without a display, and dybw starts the agent on
    demand. It logs to the journal (`journalctl --user -u dybw-agent`).
  - Check that your shells reach that agent: `dybw agent stop` in a terminal must stop the service's process
    (`launchctl print gui/$(id -u)/org.dybw.agent`, `systemctl --user status dybw-agent`); a shell with another
    `TMPDIR` or `XDG_RUNTIME_DIR` would start an agent of its own.
- **The `rbw` name.** A symlink named `rbw` to `dybw` makes it the rbw shim: `ln -s dybw ~/.cargo/bin/rbw`, or from
  any directory on `PATH` (`ln -s ~/.cargo/bin/dybw ~/.local/bin/rbw`). It must come before rbw's own `rbw` on
  `PATH`, so uninstall rbw. No `rbw-agent` is needed: the shim never starts one, and `rbw stop-agent` stops
  `dybw-agent`.
- **Completions.** fish loads `~/.config/fish/completions/<command>.fish` on first use, so these two files keep up
  with the installed version:

  ```fish
  # ~/.config/fish/completions/dybw.fish
  type -q dybw; and dybw gen-completions fish | source
  # ~/.config/fish/completions/rbw.fish
  type -q rbw; and rbw gen-completions fish | source
  ```

  bash: `dybw gen-completions bash > ~/.local/share/bash-completion/completions/dybw` (and `rbw` likewise); zsh:
  `dybw gen-completions zsh > ~/.zfunc/_dybw` with `~/.zfunc` on `fpath`.
- **First steps.** Write `~/.config/dybw/config.toml` (`default = "<profile>"`, then per profile `[profiles.<name>]`
  with `server_url`, `email`, and `pinentry` as an absolute path or a name found in
  `/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin`). Then, per profile, `dybw -p <name> login` (the API key's
  client id and secret, from the web vault's account security settings), `dybw -p <name> unlock`, and `dybw doctor`.

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
- Reading a value (including `history`) follows the caller policy: an AI-class caller is
  denied, an unknown caller (for example a `dybw` whose own parent exited) is asked every time, any other invoker is
  asked once or "always". `list`, `search` and `get --list-fields` show only names and never ask (only the names
  are decrypted; a reprompt item's field names still need the master password, so an AI-class caller gets none). An AI-class caller also cannot stop
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
- An item is found as rbw 1.15 finds it: by id (any UUID spelling), else a URL with a scheme such as `https://` is
  matched against the logins' URIs by their match types (domain by default, host, starts with, exact, regular
  expression, never), else by name; an exact name before a part of one, and an item with no folder or user before
  one with when `--folder` or the user is not given. Only names, users, folders and URIs are decrypted to find it.
- An item that asks for a master-password reprompt gives no value (a code included) and takes no change until the
  master password is typed again in the agent's pinentry, after the confirmation; a grant never skips it. The password
  is checked against the unlocked key and sent nowhere; a wrong one is refused and audited.
- Organization items are readable; one whose organization hides the password (`viewPassword: false`) gives no
  password, TOTP key or code, history, `--full`, `--raw`, nor any custom field of the hidden type.
- Writes (`add`, `edit`, `remove`, `generate <len> <name>`) are confirmed in the pinentry every time: no grant
  counts and "always" is never offered. AI-class and unknown callers are refused. `dybw`'s new values never travel
  over the socket: the agent asks for them in its own pinentry, one line each, so notes are a single line. An empty
  answer cancels. (The rbw shim's `add` and `edit` send theirs, see below.) `edit` changes the password and the notes
  only (no rename, user, URIs, folder or TOTP key). An item changed on the server since the last sync is refused
  ("sync and try again") and nothing is written. New logins are personal (no creating into an organization). A
  folder that `add` or `generate` created stays when the login create then fails, as with rbw.
- `generate <len> <name>` prints nothing: unlike rbw it does not show the new password, which the agent made and
  kept. Read it with `dybw get <name>`, which goes through the confirmation like any other value.
- Invoked as `rbw` (a symlink to `dybw`), the binary is the rbw 1.15 shim; its command line and help are rbw's (MIT,
  see `crates/dybw/src/rbw_completion/LICENSE-rbw`). `RBW_PROFILE=x` picks the profile; `DYBW_PROFILE` and `-p` are
  not read. `rbw config set|unset` edits the profile in `~/.config/dybw/config.toml` (comments and layout are kept, a
  symlinked file stays a link) and says what changed on stderr. Changing `base_url` or `pinentry` is refused when
  stdin is not a terminal, so a script or an AI harness cannot redirect the server or the prompt through the shim.
  This is a guard against accidents, not a barrier: any process of the same user can still edit `config.toml`; what
  protects the API key is that it stays bound to the identity origin it was stored for.
- The shim prints what rbw 1.15 prints, byte for byte, and its errors with exit code 1 (`couldn't find entry for
  'x': no entry found`, `multiple entries found: user@name, ...`, `entry does not contain a totp secret`, ...); an
  entry without the value `get` shows says so on stderr and exits 0, as rbw. Names and values are printed as they are
  (tabs and control characters included), as rbw does. `rbw search` matches names and users only (rbw also matches
  notes, URIs and field values, which would decrypt values without a confirmation).
- `rbw add` and `rbw edit` open `$VISUAL`, else `$EDITOR`, else `/usr/bin/vim`, as rbw: the first line is the
  password, the rest the notes (`edit` of a note: the notes). The file is in a new 0700 directory under
  `$XDG_RUNTIME_DIR`, else `$TMPDIR`, else `/tmp`; whatever happens it is overwritten with zeros, then it and the
  directory are removed (Ctrl-C, SIGHUP, SIGTERM or SIGQUIT while the editor runs are held until then, and end the
  command with 128 + the signal; a directory left by a killed run is wiped and removed by the next one). With stdin
  not a terminal the text is read from stdin (for `edit`, the agent splits it by the item's type: no value is read).
  The text goes to the agent with the write, which is still confirmed every time and refused to AI-class and unknown
  callers. An editor that fails, or a text with neither a password nor notes, writes nothing. `edit` in a terminal
  first reads the item's password and notes (one confirmation that says so) to fill the editor, then writes to that
  item by its id. `rbw generate <len> <name>` prints the password, as rbw, then saves that one as a
  new login (made by the shim and sent with the confirmed write).
- `rbw purge` locks the profile and deletes its copy of the vault (`~/.cache/dybw/profiles/<profile>`) once you
  confirm it in the pinentry; the API key, the device id, the policy and the KDF/security pins stay. `rbw unlock` logs
  in first when the profile has no API key.
- Migration from rbw: `rbw config set identity_url` is refused (dybw derives the identity URL from `base_url`; use
  `base_url`), as are `sso_id`, `ui_url`, `notifications_url` and `client_cert_path`. `lock_timeout` (seconds) is
  rounded up to whole minutes; `sync_interval` 0 means no periodic sync.
- `-c` copies in the `dybw` process and clears the clipboard after `clipboard_clear_seconds` (default 30) only if it
  still holds the copy. On macOS the copy is marked concealed and transient; on Wayland it is marked secret
  (`wl-copy --sensitive`, wl-clipboard 2.2+); on X11 (`xclip`, `xsel`) it cannot be marked, so a clipboard manager
  may keep it (`dybw` says so on stderr).
- `--diceware` uses the EFF large wordlist (Electronic Frontier Foundation, CC BY 3.0 US).
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
`DOCKER_HOST` and `DOCKER_CONFIG` come from your environment. `E2E_TESTS=<file or test id>` narrows the run.
The suite includes the rbw conformance run (`tests/e2e/test_rbw_conformance.py`, rbw 1.15.0 built in the image
under `/opt/rbw`, never on `PATH`); its cases and results are in `docs/rbw-conformance.md`.
