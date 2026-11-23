#!/usr/bin/env python3
"""Run the live webmail suites against a fresh local Mail instance."""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import smtplib
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
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


def verify_mime_variants(smtp, webmail, account, password):
    png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aGZQAAAAASUVORK5CYII="
    forwarded = (
        "From: author@example.test",
        "Subject: Forwarded letter",
        "Content-Type: text/plain",
        "",
        "Private forwarded body.",
    )
    received = []
    with smtplib.SMTP("127.0.0.1", int(smtp), timeout=8) as client:
        client.ehlo()
        assert client.has_extn("chunking")
        for label, sep in (("CRLF", "\r\n"), ("LF", "\n")):
            raw = sep.join((
                "From: sender@example.test",
                f"To: {account}",
                f"Subject: MIME parity {label} =?iso-8859-1?Q?caf=E9?=",
                f"Message-ID: <mime-parity-{label}@example.test>",
                "MIME-Version: 1.0",
                "Content-Type: multipart/mixed;",
                ' boundary = "outer"',
                "",
                "--outer",
                "Content-Type: text/plain",
                "Content-Transfer-Encoding: quoted-printable",
                "",
                "Visible=20text.",
                "--outer",
                "Content-Type: multipart/related; boundary=related",
                "",
                "--related",
                "Content-Type: text/html",
                "",
                '<p>Visible HTML <img src="cid:chart@example.test"></p>',
                "--related",
                "content-type: image/png",
                "content-id: <chart@example.test>",
                "Content-Disposition: inline;",
                " filename*0*=UTF-8''na%C3; filename*1*=%AFve.png",
                "Content-Transfer-Encoding: base64",
                "",
                png,
                "--related--",
                "--outer",
                "Content-Type: message/rfc822",
                'Content-Disposition: attachment; filename="forwarded.eml"',
                "",
                *forwarded,
                "--outer--",
                "",
            )).encode("ascii")
            assert client.mail("sender@example.test")[0] == 250
            assert client.rcpt(account)[0] == 250
            client.send(f"BDAT {len(raw)} LAST\r\n".encode("ascii") + raw)
            status, result = client.getreply()
            assert status == 250, result
            received.append((label, sep.join(forwarded).encode("ascii")))

    login = urllib.request.Request(webmail + "/webmail/auth/login",
                                   data=json.dumps({"username": account, "password": password}).encode(),
                                   headers={"Content-Type": "application/json", "Origin": webmail})
    with urllib.request.urlopen(login, timeout=8) as response:
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]

    def get(path):
        request = urllib.request.Request(webmail + "/webmail/api/" + path, headers={"Cookie": cookie})
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.read()

    for label, original in received:
        items = json.loads(get("messages?" + urllib.parse.urlencode({
            "folder": "INBOX", "q": f"MIME parity {label}", "conversations": "false",
        })))["items"]
        item, = items
        assert item["subject"] == f"MIME parity {label} café", item
        assert item["has_attachments"] and item["snippet"] == "Visible text.", item
        msg = json.loads(get("messages/ref/" + item["reference"]))
        assert msg["text"] == "Visible text."
        assert msg["html"] == '<p>Visible HTML <img src="cid:chart@example.test"></p>'
        assert msg["embedded_images"] == [{"id": "chart@example.test", "source": "data:image/png;base64," + png}]
        assert [part["filename"] for part in msg["attachments"]] == ["naïve.png", "forwarded.eml"], msg["attachments"]
        for index, expected in enumerate((base64.b64decode(png), original)):
            query = urllib.parse.urlencode({"reference": msg["reference"], "content_revision": msg["content_revision"],
                                           "index": index})
            assert msg["attachments"][index]["size"] == len(expected)
            assert get("attachment?" + query) == expected
    print("Verified identical webmail projections and exact attachment downloads for LF and CRLF MIME.")


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
            verify_mime_variants(smtp, webmail, account, password)
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
