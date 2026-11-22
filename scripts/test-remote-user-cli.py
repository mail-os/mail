#!/usr/bin/env python3
"""Exercise remote credential framing, shell quoting, and failure reporting."""

import json
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
import sys
import tempfile


check_terminal = runpy.run_path(str(Path(__file__).with_name("test-user-cli.py")))["check_terminal"]
SSH_FIXTURE = r"""
import json
import os
import subprocess
import sys

with open(os.environ["MAIL_TEST_SSH_ARGS"], "a", encoding="utf-8") as trace:
    trace.write(json.dumps(sys.argv[1:]) + "\n")
assert sys.argv[-3] == "--"
target, command = sys.argv[-2:]
if target == "unreachable":
    print("Simulated SSH connection failure", file=sys.stderr)
    sys.exit(255)
data = sys.stdin.buffer.read()
if target == "interrupted":
    data = data[:5]
sys.exit(subprocess.run(["/bin/sh", "-c", command], input=data).returncode)
"""


def verify(binary, root):
    fixture_bin = root / "bin"
    fixture_bin.mkdir()
    remote = root / "mail's working directory"
    remote.mkdir()
    (remote / "mail-server").symlink_to(binary)
    (remote / "mail").mkdir()  # Production Maildir has this name.
    ssh = fixture_bin / "ssh"
    ssh.write_text(f"#!{sys.executable}\n" + SSH_FIXTURE)
    ssh.chmod(0o700)
    aws = fixture_bin / "aws"
    aws.write_text('#!/bin/sh\nprintf "aws called\\n" >> "$MAIL_TEST_SSH_ARGS"\nexit 93\n')
    aws.chmod(0o700)
    sudo = fixture_bin / "sudo"
    sudo.write_text('#!/bin/sh\n[ "$1,$2,$3,$4" = "-n,-u,mail-server,--" ] || exit 1\nshift 4\nexec "$@"\n')
    sudo.chmod(0o700)

    trace = root / "ssh-argv.jsonl"
    config = root / "ssh config"
    config.touch()
    db_path = remote / "smtp.db"
    env = {"PATH": f"{fixture_bin}{os.pathsep}{os.environ['PATH']}", "MAIL_TEST_SSH_ARGS": str(trace)}
    common = ("--ssh-config", str(config), "--remote-dir", str(remote))
    target = ("--ssh-target", "fixture-mail")
    account = "o'connor+fixture@example.test"
    username = account.split("@")[0]
    initial = b"  initial '$;\\\"\x60 \x00\xff\t password  \r"
    replacement = b"  replacement special 'password'  "
    legacy = b"legacy 'argv' password"
    exact = b"x" * 4096
    secrets = (initial, initial.rstrip(b"\r"), replacement, legacy, exact)

    def run(*args, data=b"", failure=False, selected=target, environment=env):
        result = subprocess.run([binary, "user", *args, *selected, *common], cwd=root, env=environment,
                                input=data, capture_output=True, timeout=15)
        output = result.stdout + result.stderr
        assert (result.returncode != 0) == failure, output
        assert all(secret not in output for secret in secrets)
        return output

    assert b"specify --ssh-target" in run("create", account, selected=(), failure=True)
    assert b"ConflictingTargets" in run("create", account, selected=(*target, "--instance-id", "i-fixture"), failure=True)
    assert b"InvalidSshTarget" in run("create", account, selected=("--ssh-target", "mail alias"), failure=True)
    assert b"exceeds 4096 bytes" in run("create", account, data=exact + b"x\n", failure=True)
    assert b"did not contain a password" in run("create", account, data=b"\n", failure=True)
    assert b"ConflictingPasswordSources" in run("verify", username, legacy.decode(), "--password-stdin", failure=True)
    assert not trace.exists() and not db_path.exists()

    assert b"User created successfully" in run("create", account, "--password-stdin", data=initial + b"\r\nignored line\n")
    assert b"already exists" in run("create", account, data=replacement + b"\n", failure=True)
    assert b"Credentials invalid" in run("verify", username, data=b"wrong password\n", failure=True)
    assert b"Credentials valid" in run("verify", username, data=initial + b"\r\n",
                                       selected=("--instance-id", "i-fixture"))
    assert b"Credentials valid" in run("verify", username, data=initial + b"\r\n",
                                       selected=(), environment={**env, "MAIL_INSTANCE_ID": "i-fixture"})
    assert b"Credentials valid" in run("verify", username, "--run-as", "mail-server", data=initial + b"\r\n")
    run("change-password", username, "--run-as", "unauthorized", data=replacement + b"\n", failure=True)

    assert b"before its newline" in run("change-password", username, data=replacement + b"\n",
                                       selected=("--ssh-target", "interrupted"), failure=True)
    assert b"SSH connection to unreachable failed" in run("change-password", username, data=replacement + b"\n",
                                                         selected=("--ssh-target", "unreachable"), failure=True)
    terminal = [binary, "user", "change-password", username, *target, *common]
    check_terminal(terminal, b"unused secret", root, env, cancel=True, prompt=b"on fixture-mail: ")
    assert b"Credentials valid" in run("verify", username, data=initial + b"\r\n")
    assert b"Password changed successfully" in check_terminal(terminal, replacement, root, env, prompt=b"on fixture-mail: ")
    assert b"Credentials invalid" in run("verify", username, data=initial + b"\r\n", failure=True)
    assert b"Credentials valid" in run("verify", username, data=replacement + b"\n")
    assert b"not found" in run("change-password", "missing", data=replacement + b"\n", failure=True)
    assert b"Password changed successfully" in run("change-password", username, data=exact + b"\r\n")
    assert b"Credentials valid" in run("verify", username, data=exact + b"\n")
    assert b"Password changed successfully" in run("change-password", username, legacy.decode())
    assert b"Credentials valid" in run("verify", username, legacy.decode())
    (remote / "mail").rmdir()
    (remote / "mail-server").rename(remote / "mail")
    assert b"User created successfully" in run("create", "compat@example.test", "--password", legacy.decode(),
                                               "--env", "production", selected=("--instance-id", "i-fixture"))
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT username,email FROM users ORDER BY id").fetchall() == [
            (username, account), ("compat", "compat@example.test"),
        ]

    argv = [json.loads(line) for line in trace.read_text().splitlines()]
    for invocation in argv:
        assert "-T" in invocation and "StrictHostKeyChecking=yes" in invocation
        assert "--remote-stdin" in invocation[-1]
        assert all(secret not in os.fsencode(arg) for arg in invocation for secret in secrets)
    print("Verified remote credential input, quoting, target selection, exit status, interruption, and redaction.")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="mail-remote-user-cli-") as root:
        verify(Path(sys.argv[1]).resolve(strict=True), Path(root))
