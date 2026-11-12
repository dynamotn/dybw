# dybw-cli

The `dybw` command line client and the `dybw-agent` that holds the vault session, built on
[dybw-core](https://gitlab.com/dynamo-tools/dybw-core). MIT licensed.

**Status: P4.0 skeleton.** The workspace, CI and end-to-end harness exist; nothing user-facing ships yet.

| Crate | What |
|-------|------|
| `dybw-proto` | Versioned IPC types (`{ version, op }`) and length-prefixed JSON framing (u32 big-endian, max 1 MiB) |
| `dybw-agent` | The agent (lib + bin), prints its version for now |
| `dybw` | The client binary, `--version` for now |

An agent started by `dybw` on demand inherits the environment of the first caller (`XDG_*`, `RUST_LOG`) and logs to
`agent.log` in its socket directory.

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
