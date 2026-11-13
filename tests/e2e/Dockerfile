# Linux environment for the dybw end-to-end tests: a Rust toolchain and the
# python test clients. Build from the repository root:
#   docker build -t dybw-e2e -f tests/e2e/Dockerfile .
FROM rust:1-trixie

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pytest python3-cryptography \
 && rm -rf /var/lib/apt/lists/*

# The fake pinentry the agent tests (P4.1+) drive; installed like a real one, owned by root.
COPY --chmod=755 tests/e2e/fake_pinentry.py /usr/local/bin/fake-pinentry

# Both dybw-core and the crates.io dependencies are fetched here, so the test
# runs need no network. The sources are bind-mounted for this step only.
RUN --mount=type=bind,target=/fetch cargo fetch --locked --manifest-path /fetch/Cargo.toml

RUN useradd --create-home --uid 1000 tester

ENV DYBW_E2E_CONTAINER=1 CARGO_TARGET_DIR=/target DYBW_BIN=/target/release/dybw DYBW_AGENT_BIN=/target/release/dybw-agent PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
CMD ["sh", "-c", "cargo build --release --locked && setpriv --reuid=tester --regid=tester --init-groups env HOME=/home/tester python3 -m pytest -q -p no:cacheprovider tests/e2e"]
