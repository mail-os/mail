#!/usr/bin/env python3
"""Run the live webmail suites against a fresh local Mail instance."""

import argparse
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def reserve_ports(count):
    sockets = [socket.socket() for _ in range(count)]
    try:
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        return [str(listener.getsockname()[1]) for listener in sockets]
    finally:
        for listener in sockets:
            listener.close()


def ready(smtp, webmail, caldav, process):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("Mail exited before the test listeners were ready.")
        try:
            with socket.create_connection(("127.0.0.1", int(smtp)), timeout=0.2):
                pass
            with socket.create_connection(("127.0.0.1", int(caldav)), timeout=0.2):
                pass
            with urllib.request.urlopen(f"{webmail}/login", timeout=0.2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise RuntimeError("The local SMTP, webmail, and CalDAV listeners did not become ready.")


def verify(binary, directory):
    smtp, web_port, caldav, submission = reserve_ports(4)
    webmail = f"http://127.0.0.1:{web_port}"
    account = "webmail-check@example.test"
    password = secrets.token_hex(16)
    env = {
        "PATH": os.environ["PATH"],
        "SMTP_DB_PATH": str(directory / "smtp.db"),
        "SMTP_HOSTNAME": "mail.example.test",
        "SMTP_LOCAL_DOMAINS": "example.test",
        "SMTP_ENABLE_WEBMAIL": "true",
        "SMTP_WEBMAIL_PORT": web_port,
        "SMTP_WEBMAIL_TLS": "false",
        "SMTP_WEBMAIL_SECURE_COOKIES": "false",
        "SMTP_ANTISPAM_CHECK": "false",
        "SMTP_SPAM_FILTER": "false",
        "SMTP_ENABLE_DNSBL": "false",
        "SMTP_ENABLE_GREYLIST": "false",
        "IMAP_ENABLED": "false",
        "CALDAV_ENABLED": "true",
        "CALDAV_PORT": caldav,
        "CALDAV_DB_PATH": str(directory / "caldav.db"),
        "SUBMISSION_PORT": submission,
    }
    created = subprocess.run(
        [str(binary), "user:local", "create", account, password, account],
        cwd=directory, env=env, stdout=subprocess.DEVNULL, check=False,
    )
    if created.returncode:
        raise RuntimeError("Mail could not create the disposable test account.")

    log_file = directory / "server.log"
    with log_file.open("w", encoding="utf-8") as log:
        daemon = subprocess.Popen(
            [str(binary), "serve", "--host", "127.0.0.1", "--port", smtp,
             "--disable-tls", "--enable-auth"],
            cwd=directory, env=env, stdout=log, stderr=log,
        )
        try:
            ready(smtp, webmail, caldav, daemon)
            test_env = dict(os.environ, MAIL_WEBMAIL_E2E_URL=webmail,
                            MAIL_WEBMAIL_E2E_CALDAV_URL=f"http://127.0.0.1:{caldav}",
                            MAIL_WEBMAIL_E2E_USER=account, MAIL_WEBMAIL_E2E_PASSWORD=password)
            subprocess.run(
                ["bun", "test", "packages/webmail/e2e.test.ts",
                 "packages/webmail/ux-e2e.test.ts", "packages/webmail/calendar-e2e.test.ts"],
                cwd=ROOT, env=test_env, check=True,
            )
        except (RuntimeError, subprocess.CalledProcessError):
            print(log_file.read_text(encoding="utf-8", errors="replace")[-8000:])
            raise
        finally:
            if daemon.poll() is None:
                daemon.terminate()
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-webmail-e2e-") as directory:
        verify(args.binary.resolve(), Path(directory))


if __name__ == "__main__":
    main()
