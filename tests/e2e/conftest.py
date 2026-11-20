"""Fixtures for the dybw end-to-end tests: the built binaries and a Vaultwarden account."""

import os
from pathlib import Path

import pytest

from bwclient import Account

ROOT = Path(__file__).parents[2]
URL = os.environ.get("BW_E2E_URL")


@pytest.fixture(scope="session")
def dybw_bin():
    return os.environ.get("DYBW_BIN", str(ROOT / "target" / "release" / "dybw"))


@pytest.fixture(scope="session")
def dybw_agent_bin():
    return os.environ.get("DYBW_AGENT_BIN", str(ROOT / "target" / "release" / "dybw-agent"))


@pytest.fixture(scope="module")
def account():
    if not URL:
        pytest.skip("BW_E2E_URL not set")
    return Account(URL)


def pytest_terminal_summary(terminalreporter):
    """Print the conformance run's case lines (test_rbw_conformance.py), the source of docs/rbw-conformance.md."""
    results = Path("/tmp/rbw-conformance.jsonl")
    if os.environ.get("DYBW_E2E_CONTAINER") and results.exists():
        terminalreporter.section("rbw conformance")
        for line in results.read_text().splitlines():
            terminalreporter.write_line(line)
