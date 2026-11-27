#!/usr/bin/env python3
"""Test one-time mailbox setup using the native HTTPS, IMAP and SMTP listeners."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import imaplib
import json
from pathlib import Path
import runpy
import secrets
import smtplib
import sqlite3
import subprocess
import tempfile

hosted = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture = hosted["Fixture"]


def create_mailbox(mail, local_part):
    mailbox = f'{local_part}@{hosted["DOMAIN"]}'
    command = [str(mail.binary), "user:local", "create", mailbox, "--password-stdin", "--require-password-change"]
    subprocess.run(command, input=mail.password + "\n", text=True, cwd=mail.directory, env=mail.env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
    return mailbox


def verify(mail):
    mailbox = create_mailbox(mail, "first-sign-in")
    notice = "A message sent before the owner signs in"

    def login(password, new_password=None, origin=None):
        body = {"username": mailbox, "password": password}
        if new_password is not None:
            body["newPassword"] = new_password
        return mail.http(mail.webmail + "/webmail/auth/login", body,
                         {"Origin": origin or mail.webmail}, context=mail.tls_context)

    def check_protocols(password, expected):
        with smtplib.SMTP(mail.hostname, mail.submission_port, timeout=10) as smtp:
            smtp.starttls(context=mail.tls_context)
            smtp.ehlo()
            try:
                code, _ = smtp.auth("PLAIN", lambda challenge=None: f"\0{mailbox}\0{password}")
            except smtplib.SMTPAuthenticationError as failure:
                code = failure.smtp_code
            assert code == (235 if expected else 535), code
        with imaplib.IMAP4_SSL(mail.hostname, mail.imaps_port, ssl_context=mail.tls_context, timeout=10) as imap:
            try:
                status, _ = imap.login(mailbox, password)
            except imaplib.IMAP4.error:
                assert not expected, "IMAP rejected the new password"
            else:
                assert expected and status == "OK", "IMAP accepted a temporary password"
                assert imap.select("INBOX", readonly=True)[0] == "OK"
                assert imap.search(None, "SUBJECT", f'"{notice}"')[1][0], "Mail received before setup is readable"

    with mail.daemon():
        status, headers, raw = login(mail.password)
        assert status == 409 and json.loads(raw)["error"] == "password_change_required"
        assert "Set-Cookie" not in headers
        assert login("wrong-password")[0] == 401
        assert login(mail.password, mail.password)[0] == 400
        assert login(mail.password, secrets.token_urlsafe(), "https://untrusted.example.test")[0] == 403
        check_protocols(mail.password, False)
        assert mail.deliver(mailbox, subject=notice)[0] == 250
        replacements = [secrets.token_urlsafe(), secrets.token_urlsafe()]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda value: login(mail.password, value), replacements))
        assert sorted(result[0] for result in results) == [200, 401]
        winning_password, replacement = next((value, result) for value, result in zip(replacements, results) if result[0] == 200)
        assert "Set-Cookie" not in replacement[1] and json.loads(replacement[2]) == {"password_changed": True}
        with sqlite3.connect(mail.directory / "smtp.db") as database:
            assert database.execute("SELECT password_change_required FROM users WHERE username = ?", (mailbox,)).fetchone() == (0,)
            assert database.execute("SELECT COUNT(*) FROM webmail_sessions WHERE username = ?", (mailbox,)).fetchone() == (0,)
        status, headers, _ = login(winning_password)
        assert status == 200 and "Secure" in headers["Set-Cookie"]
        check_protocols(winning_password, True)
        assert login(mail.password)[0] == 401
        assert login(winning_password, secrets.token_urlsafe())[0] == 401
        check_protocols(mail.password, False)


def verify_browser(mail):
    mailbox = create_mailbox(mail, "first-browser-sign-in")
    script = Path(__file__).with_name("webmail-first-password-browser.mjs").resolve()
    with mail.daemon():
        subprocess.run(["bun", "--no-env-file", script], text=True, check=True, timeout=120,
                       input=json.dumps({"url": mail.webmail, "address": mailbox, "temporary": mail.password}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--browser", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-first-password-") as directory:
        mail = Fixture(args.binary.resolve(), Path(directory), staging=True, provisioning=False)
        if args.browser:
            verify_browser(mail)
        else:
            verify(mail)
            print("PASS first mailbox password rotation over Webmail, SMTP and IMAP")
