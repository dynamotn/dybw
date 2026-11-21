# Installing and running dybw

## Install

```sh
cargo install --git https://github.com/dynamotn/dybw.git --tag v1.0.0-rc.1 --locked dybw dybw-agent
```

Building needs Rust 1.89 or newer. On macOS it also needs the Xcode Command Line Tools (`xcode-select --install`),
whose `xcrun swiftc` builds the Secure Enclave code.

The binaries land in `~/.cargo/bin`, or in `<dir>/bin` with `--root <dir>`. Keep them in one directory: `dybw`
starts only the `dybw-agent` next to it, and the agent trusts only the `dybw` next to it.

### Prebuilt binaries

Each `v*` tag has a [GitHub release](https://github.com/dynamotn/dybw/releases) with these assets, where
`<version>` is the tag without its `v` (`1.0.0-rc.1`):

| Platform | Asset |
| --- | --- |
| Linux x86_64 (static, musl) | `dybw-<version>-x86_64-linux-musl.tar.gz` |
| Linux aarch64 (static, musl) | `dybw-<version>-aarch64-linux-musl.tar.gz` |
| macOS arm64 | `dybw-<version>-aarch64-apple-darwin.tar.gz` |

Each has a `<asset>.sha256` next to it. A tarball holds `dybw`, `dybw-agent`, `contrib/`, `README.md` and `LICENSE`
at its top level, with no enclosing directory. The macOS build is not signed or notarized: a browser download gets
the quarantine attribute, so fetch it with `curl` (as below) or clear it with `xattr -d com.apple.quarantine`.

```sh
version=1.0.0-rc.1
asset=dybw-$version-x86_64-linux-musl.tar.gz      # or aarch64-linux-musl, aarch64-apple-darwin
base=https://github.com/dynamotn/dybw/releases/download/v$version
curl -fsSLO "$base/$asset" -O "$base/$asset.sha256"
shasum -a 256 -c "$asset.sha256"                   # or sha256sum -c
mkdir -p ~/.local/bin && tar -xzf "$asset" -C ~/.local/bin dybw dybw-agent
```

Then write `~/.config/dybw/config.toml` ([configuration.md](configuration.md)), and for each profile run:

```sh
dybw -p <profile> login      # the API key's client id and secret, from the web vault's account security settings
dybw -p <profile> unlock
dybw doctor
```

## The `rbw` name

A symlink named `rbw` to `dybw` turns it into the rbw shim:

```sh
ln -s dybw ~/.cargo/bin/rbw                    # next to dybw
ln -s ~/.cargo/bin/dybw ~/.local/bin/rbw       # or from any directory on PATH
```

It must come before rbw's own `rbw` on `PATH`, so uninstall rbw. No `rbw-agent` is needed: the shim never starts
one, and `rbw stop-agent` stops `dybw-agent`. See [rbw-shim.md](rbw-shim.md).

## Run the agent as a service

`dybw` starts the agent on first use, with the environment of that first caller. A login service starts it with the
GUI session's environment instead, so pinentry and Touch ID also show for hotkeys and launchers that have no
terminal. On-demand start stays as the fallback. A second agent finds the lock held and exits.

### macOS (launchd)

[`contrib/macos/org.dybw.agent.plist`](../contrib/macos/org.dybw.agent.plist), label `org.dybw.agent`. It is a
template, because launchd expands no variables. Replace `@HOME@` with your home and `@TMPDIR@` with
`getconf DARWIN_USER_TEMP_DIR`, the `TMPDIR` of your shells:

```sh
sed -e "s|@HOME@|$HOME|g" -e "s|@TMPDIR@|$(getconf DARWIN_USER_TEMP_DIR)|g" \
  contrib/macos/org.dybw.agent.plist > ~/Library/LaunchAgents/org.dybw.agent.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.dybw.agent.plist
```

It logs to `~/Library/Logs/dybw-agent.log` and restarts only after a crash.

### Linux (systemd)

[`contrib/systemd/dybw-agent.service`](../contrib/systemd/dybw-agent.service) is a user unit wanted by
`graphical-session.target`:

```sh
cp contrib/systemd/dybw-agent.service ~/.config/systemd/user/
systemctl --user enable --now dybw-agent.service
```

The compositor must import the display variables into the user manager first. niri-session and uwsm do this. Without
them, run this at the compositor's start:

```sh
systemctl --user import-environment WAYLAND_DISPLAY DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS
```

Until `WAYLAND_DISPLAY` or `DISPLAY` is there, the unit is skipped (`ConditionEnvironment`, systemd 246+) rather
than started without a display, and `dybw` starts the agent on demand. It logs to the journal
(`journalctl --user -u dybw-agent`).

### Check that your shells reach it

`dybw agent stop` in a terminal must stop the service's process. Check with
`launchctl print gui/$(id -u)/org.dybw.agent` or `systemctl --user status dybw-agent`. A shell with another `TMPDIR`
or `XDG_RUNTIME_DIR` would start an agent of its own.

## Shell completions

fish loads `~/.config/fish/completions/<command>.fish` on first use. With these two files, completions stay in step
with the installed version:

```fish
# ~/.config/fish/completions/dybw.fish
type -q dybw; and dybw gen-completions fish | source
# ~/.config/fish/completions/rbw.fish
type -q rbw; and rbw gen-completions fish | source
```

bash:

```sh
dybw gen-completions bash > ~/.local/share/bash-completion/completions/dybw
rbw gen-completions bash > ~/.local/share/bash-completion/completions/rbw
```

zsh, with `~/.zfunc` on `fpath`:

```sh
dybw gen-completions zsh > ~/.zfunc/_dybw
rbw gen-completions zsh > ~/.zfunc/_rbw
```

## Troubleshooting

- `dybw doctor` checks the socket directory, the agent (reachable, same version), the config, the pinentry, the
  machine fingerprint a PIN is bound to, the local unlock protectors, the SSH agent socket and `SSH_AUTH_SOCK`,
  `policy.json` and `audit.log`. It exits 0 when all checks pass.
- The agent logs to `agent.log` in its socket directory. An error that only says "see the agent log" is explained
  there.

## Tests

The cargo tests run the agent on a home of their own through `DYBW_TEST_PASSWD_HOME`. Only the
`dybw-agent-test-home` binary of the test-only `test-home` feature reads that variable. It is never in a release
build, and CI refuses it in the normal dependency graph. `dybw-agent` itself never reads it.

The end-to-end suite runs in Docker against a throwaway Vaultwarden:

```sh
scripts/e2e.sh
E2E_TESTS=tests/e2e/test_rbw_conformance.py scripts/e2e.sh   # one file or test id
```

It builds `tests/e2e/Dockerfile`, starts Vaultwarden, and runs pytest in a container that shares its network. The
agent only runs on the password database's home, so the suite writes under the test user's real home. That is why
it runs only in that container (`DYBW_E2E_CONTAINER`). `DOCKER_HOST` and `DOCKER_CONFIG` come from your environment.
The suite includes the rbw conformance run, with rbw 1.15.0 built in the image under `/opt/rbw` and never on `PATH`.
Its cases and results are in [rbw-conformance.md](rbw-conformance.md).
