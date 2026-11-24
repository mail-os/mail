#!/usr/bin/env python3
"""Test continuous reading against a disposable native HTTPS mailbox."""

import argparse
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
Fixture = runpy.run_path(str(HERE / "test-hosted-limits.py"))["Fixture"]
ENGINES = ("chromium", "firefox", "webkit")
SUBJECTS = ("Studio design notes", "Print proof updates", "Pickup details")
IMAGE_HOST = "https://reading-images.example.test"


def seed(test, account, count):
    date = datetime(2026, 11, 24, 14, tzinfo=timezone.utc)
    with test.imap(account) as client:
        for index in range(count):
            message = EmailMessage()
            subject = SUBJECTS[index] if index < len(SUBJECTS) else f"Studio correspondence {index:02}"
            message["From"] = "Kim Park <kim@studio.example.test>"
            message["To"] = account
            message["Date"] = format_datetime(date - timedelta(minutes=index))
            message["Subject"] = subject
            message["Message-ID"] = f"<reading-view-{index}@studio.example.test>"
            message.set_content(f"Notes for {subject}.\nThe print proofs are ready for review.")
            if index < 2:
                message.add_alternative(f'<p>Formatted notes for {subject}.</p><img src="{IMAGE_HOST}/{index}.png" alt="Print proof">', subtype="html")
                message.add_attachment(f"Attachment for {subject}\n".encode(), maintype="text", subtype="plain", filename="proof.txt")
            stamp = (date - timedelta(minutes=index)).timestamp()
            assert client.append("INBOX", None, stamp, message.as_bytes(policy=SMTP))[0] == "OK"


def verify(binary, output, engine):
    with tempfile.TemporaryDirectory(prefix="mail-reading-view-") as scratch:
        test = Fixture(binary, Path(scratch), staging=True)
        with test.daemon():
            desktop, phone = (test.provision(name) for name in ("desktop-reader", "phone-reader"))
            seed(test, desktop, 57)
            seed(test, phone, 15)
            expected = {}
            for account, count in ((desktop, 57), (phone, 15)):
                session = test.login(account)
                status, queue = test.api(session, "messages?folder=INBOX&queue=unread&per_page=200")
                assert status == 200 and len(queue["items"]) == 1 and queue["total"] == count, queue
                status, batch = test.api(session, "messages?folder=INBOX&queue=unread&batch=true&per_page=200")
                assert status == 200 and len(batch["items"]) == 12 and batch["total"] == count, batch
                assert [row["subject"] for row in batch["items"][:3]] == list(SUBJECTS)
                expected[account] = {row["subject"]: row["reference"] for row in batch["items"]}
            environment = dict(os.environ, MAIL_READING_URL=test.webmail, MAIL_READING_DESKTOP=desktop,
                               MAIL_READING_PHONE=phone, MAIL_READING_PASSWORD=test.password,
                               MAIL_READING_REFERENCES=json.dumps(expected))
            subprocess.run(["node", str(HERE / "webmail-reading-view.mjs"), engine, str(output / engine)],
                           env=environment, check=True, timeout=100)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("screenshots", type=Path)
    parser.add_argument("--engine", action="append", choices=ENGINES)
    args = parser.parse_args()
    for engine in args.engine or ENGINES:
        verify(args.binary.resolve(strict=True), args.screenshots.resolve(), engine)


if __name__ == "__main__":
    main()
