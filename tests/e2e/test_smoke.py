"""The harness works: Vaultwarden is up, a test account can be registered and seeded, and the binaries run."""

import subprocess


def test_vaultwarden_account_and_seeded_login(account):
    account.add_login("e2e", "smoke", "hunter2", username="me")
    assert account.items("e2e")["smoke"]["password"] == "hunter2"


def test_binaries_run(dybw_bin, dybw_agent_bin):
    out = subprocess.run([dybw_bin, "--version"], capture_output=True, text=True, check=True).stdout
    assert out.startswith("dybw ")
    out = subprocess.run([dybw_agent_bin], capture_output=True, text=True, check=True).stdout
    assert out.startswith("dybw-agent ")
