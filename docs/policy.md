# Caller policy, AI agents and the audit log

The agent identifies the process behind every request: its executable, the script it runs, and its parents. It
then decides what that caller may do. Names are cheap. Values are confirmed out of band, in the agent's pinentry or
with the Touch ID sheet ([local-unlock.md](local-unlock.md#touch-id-for-confirmations)).

## What each caller gets

| Caller | Names (`list`, `search`, `get -l`) | A value (`get`, `code`, `history`) | Writes, policy changes |
|--------|------------------------------------|------------------------------------|------------------------|
| A plain program | yes, never asked | asked once, or "always" for that binary | confirmed every time |
| A script run by an interpreter or shell | yes | asked; "always" lasts for that process only | confirmed every time |
| A detached caller (parent exited, started by launchd or a subreaper) | yes | asked every time, flagged "possibly an AI agent" | confirmed every time |
| An unknown caller | yes | asked every time | refused |
| An AI-class caller | yes | denied | refused |

`list`, `search` and `get --list-fields` decrypt names only and never ask. A reprompt item's field names still need
the master password, so an AI-class caller gets none.

A grant never covers `get --full`, `get --raw` or `history`: they are asked every time.

## Grants

Grants are a convenience for honest programs, not a boundary. Code running as you can defeat them: a script's argv
is its own memory, the environment can be injected, and `policy.json` can be edited. The boundary is the harness
sandbox, which must not reach the agent's socket or state directories, together with the out-of-band confirmation.

- **A plain program.** "Always" is remembered in `policy.json` by the program's path (as the kernel reports it) and
  content hash. A changed program asks again. On Linux the running image is hashed (`/proc/<pid>/exe`). On macOS the
  file at the path must carry the running image's `LC_UUID`. A file without one is trusted by path and content.
- **A script run by an interpreter or shell.** The question says which script the process "claims to run". "Always"
  lasts for that process only, in the agent's memory, until it exits or the profile locks or the agent stops. It is
  never written to disk, and script entries an older build wrote to `policy.json` are ignored.
- **Never offered "always":** an interpreter, a shell, a launcher, multiplexer or terminal (`xargs`, `env`, `make`,
  `git`, `tmux`, `kitty`, `ssh`, `cron` and the like), a relative script, an unknown caller and a detached caller.
- **A detached caller.** Only `dybw policy allow --detached <program>` makes a grant for it, and that grant matches
  only its detached runs.

### Managing the policy

```sh
dybw policy show                                 # rule, program, script, hash
dybw policy allow /usr/local/bin/backup-tool     # an absolute path to a plain program
dybw policy allow --detached /usr/local/bin/sync-job
dybw policy deny /usr/bin/python3 --script /home/me/bin/leaky.py
dybw policy deny /usr/local/bin/untrusted        # without --script: every script it runs
dybw policy forget /usr/local/bin/backup-tool
```

- `policy.json` lives in the profile's state directory and is plain device state.
- `show` is open to every class except AI.
- `allow`, `deny` and `forget` are confirmed in the pinentry, and refused to AI-class and unknown callers.
- `allow` takes a plain program only, and refuses interpreters, shells and launchers.
- `deny` takes anything. A deny entry also refuses that program's SSH signatures without a question.
- A `policy.json` that fails its checks (wrong mode, wrong owner, not valid) is ignored for decisions, and `allow`,
  `deny` and `forget` refuse to write over it, so a deny entry is never dropped by accident. Repair it by hand
  (`chmod 600`, or fix or remove the file; the grants are then asked again). `dybw doctor` names the problem.

## AI agents

A caller is AI-class when an AI harness runs among its ancestors, or when it carries a harness marker variable.
Markers can only make a caller stricter.

- **Built-in harnesses:** claude, codex, gemini, antigravity, copilot, cursor, goose, opencode, aider, hermes.
- **Marker variables:** `CLAUDECODE`, `CODEX_SANDBOX`, `GEMINI_CLI`, `CURSOR_AGENT`, `OPENCODE`, `HERMES_HOME`,
  `AI_AGENT`, `AGENT_SESSION_ID`.

An AI-class caller:

- gets names and ids;
- is denied every value, and every denial is audited;
- cannot unlock, log in, stop the agent, add a PIN or Touch ID protector, write items, or use `dybw policy` (not
  even `show`);
- never raises a master-password prompt, so a locked profile answers "locked" to its `list` and `search`;
- is asked every time for an SSH signature, in the pinentry and never with "always". Its request cannot unlock a
  profile.

This is a speed bump. The boundary that holds is the harness's sandbox, which must not reach the agent's socket
directory or `~/.local/state/dybw`. Under a harness, `dybw doctor` warns about it.

### Adding a harness

`~/.local/state/dybw/harnesses.toml` adds entries to the built-in table. It can never remove one. A process matches an
entry on any of its fields:

```toml
[[harness]]
name = "my-agent"
exe = ["my-agent"]                     # executable basename
exe_contains = ["/my-agent/versions/"] # a fragment of the executable's path
argv_contains = ["@acme/my-agent"]     # a fragment of any argv entry
argv_base = ["my-agent"]               # basename of argv[0] or argv[1] (an interpreter's script)
```

A missing file adds nothing. An unreadable, malformed or oversized one (over 64 KiB) adds nothing and is logged.

## Writes

`add`, `edit`, `remove` and `generate <len> <name>` are confirmed in the pinentry every time. No grant counts, and
"always" is never offered. AI-class and unknown callers are refused.

- `dybw`'s new values never travel over the socket. The agent asks for them in its own pinentry, one line each, so
  notes are a single line. An empty answer cancels. (The rbw shim's `add` and `edit` do send theirs, see
  [rbw-shim.md](rbw-shim.md).)
- `edit` changes the password and the notes only: no rename, user, URIs, folder or TOTP key. The old password goes to
  the history.
- An item changed on the server since the last sync is refused ("sync and try again"), and nothing is written.
- New logins are personal: there is no creating into an organization. A folder that `add` or `generate` created
  stays when the login create then fails, as with rbw.
- `remove` moves the item to the trash, and never purges it.
- `generate <len> <name>` prints nothing. Unlike rbw, it does not show the new password, which the agent made and
  kept. Read it with `dybw get <name>`, which goes through the confirmation like any other value.

## Items with extra protection

- **Reprompt items.** An item that asks for a master-password reprompt gives no value (a TOTP code included) and
  takes no change until the master password is typed again in the agent's pinentry, after the confirmation. A grant
  never skips it. The password is checked against the unlocked key and sent nowhere. A wrong one is refused and
  audited.
- **Hidden organization passwords.** An organization item whose organization hides the password
  (`viewPassword: false`) gives no password, TOTP key or code, history, `--full`, `--raw`, nor any custom field of
  the hidden type.

## The audit log

`~/.local/state/dybw/audit.log` is under the agent's trusted home, never `XDG_STATE_HOME`, which the first caller of
an on-demand agent could set. It is mode 0600, append-only, and never written through a symlink.

```sh
dybw audit              # the latest 50 lines, as tab-separated columns
dybw audit -n 200
dybw audit --ai         # AI-class and unknown callers only
```

`dybw audit` reads the file directly and needs no agent.

**What is recorded:**

- every decision on a value request;
- every request from AI-class and unknown callers, decision or not (`listed` for names, `failed` for a lookup that
  went nowhere);
- every policy change;
- every SSH signature decision (`op: ssh-sign`) and key removal (`op: ssh-remove`).

**A line** is JSON: the time (UTC), the profile, the caller (program and script, or the harness), its class, the op,
what `get` selected (`password`, `field`, `full`, `raw`, `list-fields`, never a field name), the item id (never its
name or a value) and the verdict. For an unknown caller it also says why the caller could not be named, and which
program is on the socket. For any caller, it names the program on the socket when that is a `dybw` or `rbw` other
than the one next to the agent. A confirmation also records its channel (`touch-id` or `pinentry`). The search term
and the candidates of a lookup are never logged.

**Limits:** the log rotates once, to `audit.log.1`, at 10 MiB, and `dybw audit` reads only the current file. A
rotation that fails is reported, and the live file keeps growing. A line that cannot be written is reported in the
agent log and dropped: the request is still answered, and `dybw doctor` shows an unwritable log. The log is
same-user device state, so it is evidence, not a barrier: a program running as you can edit or delete it.

## Hardening

- On macOS the agent calls `ptrace(PT_DENY_ATTACH)` first, so a debugger cannot attach to read the unlocked vault.
  Running `dybw-agent` under lldb kills it. Linux sets `PR_SET_DUMPABLE=0` instead. A failure is reported on stderr,
  and the agent keeps running.
- The agent refuses to start when `HOME` is not your home in the password database, and it ignores the caller's
  `XDG_*` variables ([configuration.md](configuration.md#files-and-locations)).
- `-c` copies in the `dybw` process, not in the agent, and clears the clipboard after `clipboard_clear_seconds`
  (default 30), but only if it still holds the copy. On macOS the copy is marked concealed and transient. On Wayland
  it is marked secret (`wl-copy --sensitive`, wl-clipboard 2.2+). On X11 (`xclip`, `xsel`) it cannot be marked, so a
  clipboard manager may keep it, and `dybw` says so on stderr.
