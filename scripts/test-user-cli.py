#!/usr/bin/env python3
"""Exercise local mailbox credentials through the compiled CLI."""

import os
from pathlib import Path
import pty
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile
import termios


def check_terminal(command, secret, directory, env, *, cancel=False):
    master, terminal = pty.openpty()
    original = termios.tcgetattr(terminal)
    try:
        with subprocess.Popen(command, stdin=terminal, stderr=terminal, stdout=terminal, cwd=directory, env=env) as child:
            try:
                output = b""
                while b"password: " not in output.lower():
                    ready, _, _ = select.select([master], [], [], 5)
                    assert ready, output
                    output += os.read(master, 4096)
                assert not termios.tcgetattr(terminal)[3] & termios.ECHO
                if cancel:
                    child.send_signal(signal.SIGINT)
                else:
                    os.write(master, secret + b"\n")
                child.wait(timeout=10)
                while select.select([master], [], [], 0)[0]:
                    output += os.read(master, 4096)
                assert child.returncode == (130 if cancel else 0), output
                assert termios.tcgetattr(terminal) == original
                assert secret not in output, "The terminal echoed the password"
                return output
            finally:
                if child.poll() is None:
                    child.kill()
    finally:
        os.close(master)
        os.close(terminal)


def verify(binary, directory):
    db_path = directory / "smtp.db"
    env = {"PATH": os.environ["PATH"], "SMTP_DB_PATH": str(db_path)}
    mailbox = "cli@example.test"

    def run(*args, data=b"", failure=False):
        result = subprocess.run([binary, *args], cwd=directory, env=env, input=data,
                                capture_output=True, timeout=15)
        output = result.stdout + result.stderr
        assert (result.returncode != 0) == failure, output
        return output

    for group in ("user", "user:local"):
        assert b"change-password" in run(group, "--help")
        assert b"New password" in run(group, "change-password", "--help")
        assert b"unknown" in run(group, "missing-command", failure=True)
    assert not db_path.exists(), "Help opened the mailbox database"

    first = b"  initial 'mail' password  "
    second = b"terminal password"
    assert b"User created successfully" in run("user:local", "create", mailbox, data=first + b"\r\n")
    with sqlite3.connect(db_path) as db:
        row = db.execute("SELECT id, email, enabled FROM users WHERE username=?", (mailbox,)).fetchone()
        assert row[1] == mailbox
        db.execute("INSERT INTO imap_mailboxes (username, mailbox, uidvalidity) VALUES (?, 'INBOX', 72)", (mailbox,))
        db.execute("""INSERT INTO webmail_sessions
            (session_id, username, email, csrf_secret, created_at, last_activity, expires_at)
            VALUES ('fixture-session', ?, ?, 'fixture-csrf', 1, 1, 2000000000)""", (mailbox, mailbox))
        db.execute("""INSERT INTO mailbox_reset_tokens
            (token_hash, username, recovery_email, created_at, expires_at)
            VALUES ('fixture-reset-hash', ?, 'recovery@example.test', 1, 2000000000)""", (mailbox,))

    assert b"Credentials valid" in run("user:local", "verify", mailbox, "--password-stdin",
                                       data=first + b"\nignored second line\n")
    change = ("user:local", "change-password", mailbox)
    assert b"without --force" in run(*change, data=b"unrequested update\n", failure=True)
    assert b"did not contain a password" in run(*change, "--force", data=b"\n", failure=True)
    assert b"exceeds 4096 bytes" in run(*change, "--force", data=b"a" * 4097, failure=True)
    assert b"supply a password argument or --password-stdin" in run(
        *change, "--force", "--password-stdin", "conflicting-source", failure=True)
    assert b"not found" in run("user:local", "change-password", "missing@example.test", "--force",
                               data=b"unused\n", failure=True)
    assert b"Credentials valid" in run("user:local", "verify", mailbox, first.decode())

    command = [binary, *change, "--force"]
    assert b"Password changed successfully" in check_terminal(command, second, directory, env)
    check_terminal(command, b"unused password", directory, env, cancel=True)

    assert b"Credentials invalid" in run("user:local", "verify", mailbox, data=first)
    assert b"Credentials valid" in run("user:local", "verify", mailbox, data=second)
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT id, email, enabled FROM users WHERE username=?", (mailbox,)).fetchone() == row
        assert db.execute("SELECT uidvalidity FROM imap_mailboxes WHERE username=?", (mailbox,)).fetchone() == (72,)
        assert db.execute("SELECT count(*) FROM webmail_sessions").fetchone() == (0,)
        assert db.execute("SELECT count(*) FROM mailbox_reset_tokens").fetchone() == (0,)

    exact = b"x" * 4096
    assert b"Password changed successfully" in run(*change, "--force", "--password-stdin", data=exact + b"\r\n")
    assert b"Credentials valid" in run("user:local", "verify", mailbox, data=exact)
    assert b"Password changed successfully" in run(*change, "--force", "legacy-positional-password")
    assert b"Credentials valid" in run("user:local", "verify", mailbox, data=b"legacy-positional-password")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="mail-user-cli-") as sandbox:
        verify(Path(sys.argv[1]).resolve(strict=True), Path(sandbox))
    print("Verified user help, no-echo prompts and interruption, stdin and argv, and non-destructive password rotation.")
