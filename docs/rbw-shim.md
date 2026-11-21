# The rbw shim

Invoked as `rbw`, through a symlink to `dybw`, the binary is an rbw 1.15 shim. Its command line and help are rbw's
(MIT, see [`LICENSE-rbw`](../crates/dybw/src/rbw_completion/LICENSE-rbw)). It talks to the same `dybw-agent`, so
every value read goes through the [caller policy](policy.md). Install it as described in
[install.md](install.md#the-rbw-name).

The [conformance report](rbw-conformance.md) runs the same commands through rbw 1.15.0 and the shim against one
Vaultwarden account. 296 of 296 cases print byte-identical stdout and stderr with the same exit code, and 20 of 20
write cases leave the vault in the same state. The known differences are listed there and below.

## Output

- The shim prints what rbw 1.15 prints, byte for byte. Its errors exit with code 1, for example
  `couldn't find entry for 'x': no entry found`, `multiple entries found: user@name, ...` and
  `entry does not contain a totp secret`.
- An entry without the value `get` shows says so on stderr and exits 0, as rbw does.
- Names and values are printed as they are, tabs and control characters included, as rbw does.
- `rbw search` matches names and users only. rbw also matches notes, URIs and field values, which would decrypt
  values without a confirmation.

## Finding an item

An item is found as rbw 1.15 finds it, and `dybw` uses the same rules:

1. by id, in any UUID spelling;
2. else, for a URL with a scheme such as `https://`, against the logins' URIs by their match types: domain by default,
   host, starts with, exact, regular expression, never;
3. else by name. An exact name wins over part of one.

When `--folder` or the user is not given, an item with no folder or user wins over one with. Only names, users,
folders and URIs are decrypted to find it.

## Profiles

`RBW_PROFILE=x` picks the profile. `DYBW_PROFILE` and `-p` are not read.

## `rbw config`

`rbw config set|unset` edits the profile in `~/.config/dybw/config.toml`. Comments and layout are kept, and a
symlinked file stays a link. It reports what changed on stderr.

- Changing `base_url` or `pinentry` is refused when stdin is not a terminal, so a script or an AI harness cannot
  redirect the server or the prompt through the shim. This guards against accidents, not attacks: any process of the
  same user can still edit `config.toml`. What protects the API key is that it stays bound to the server it was
  stored for.
- `identity_url` is refused, because dybw derives the identity URL from `base_url`: set `base_url` instead.
  `sso_id`, `ui_url`, `notifications_url` and `client_cert_path` are refused too.
- `lock_timeout` (seconds) is rounded up to whole minutes. `sync_interval` 0 means no periodic sync.

## `rbw add` and `rbw edit`

These open `$VISUAL`, else `$EDITOR`, else `/usr/bin/vim`, as rbw does. The first line is the password and the rest
is the notes (for `edit` of a note: the notes).

- The file is in a new 0700 directory under `$XDG_RUNTIME_DIR`, else `$TMPDIR`, else `/tmp`. Whatever happens, it is
  overwritten with zeros, then it and the directory are removed. Ctrl-C, SIGHUP, SIGTERM or SIGQUIT while the editor
  runs are held until then, and end the command with 128 + the signal. A directory left by a killed run is wiped and
  removed by the next one.
- When stdin is not a terminal, the text is read from stdin. For `edit`, the agent splits it by the item's type, and
  no value is read.
- Unlike `dybw add` and `dybw edit`, the text goes to the agent with the write. The write is still confirmed every
  time, and refused to AI-class and unknown callers.
- An editor that fails, or a text with neither a password nor notes, writes nothing.
- `edit` in a terminal first reads the item's password and notes to fill the editor, under one confirmation that says
  so. It then writes to that item by its id.

## Other commands

- `rbw generate <len> <name>` prints the password, as rbw does, then saves it as a new login. The shim makes the
  password and sends it with the confirmed write. (`dybw generate <len> <name>` prints nothing.)
- `rbw remove` moves the item to the trash. rbw deletes it for good.
- `rbw purge` locks the profile (the agent keeps running for the others) and deletes its copy of the vault
  (`~/.cache/dybw/profiles/<profile>`) once you confirm it in the pinentry. The API key, the device id, the policy
  and the KDF and security pins stay.
- `rbw unlock` logs in first when the profile has no API key.
- `rbw stop-agent` stops `dybw-agent`. No `rbw-agent` is ever started.
- `rbw gen-completions <shell>` prints the shim's completion script, as rbw does.
- `rbw register` and `rbw login` are the same step: they store the API key, as `dybw login` does. There is no
  password login and no two-factor prompt.
- `rbw lock` locks the profile, not the whole agent.
