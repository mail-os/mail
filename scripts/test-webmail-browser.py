#!/usr/bin/env python3
"""Run browser journeys against a disposable native HTTPS Mail instance."""

import argparse
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
from urllib.parse import urlencode

SCRIPTS = Path(__file__).resolve().parent
hosted = runpy.run_path(str(SCRIPTS / "test-hosted-limits.py"))
Fixture, request = hosted["Fixture"], hosted["request"]
DavClient = runpy.run_path(str(SCRIPTS / "test-dav-https.py"))["DavClient"]
ENGINES = ("chromium", "firefox", "webkit")
RECEIPT = b"Receipt 1046 for Studio Hosting\n"


def seed_inbox(fixture, owner, sender):
    samples = [
        ("Morgan Lee", "Tuesday design handoff", "Please confirm the sidebar order before 4 PM."),
        ("Avery Patel", "Studio launch notes", "Here is the handoff for Thursday."),
        ("Jordan Kim", "Workshop agenda", "I set aside time for the accessibility review."),
        ("Studio Hosting", "Your receipt #1046", "Your November payment of $18.00 was received."),
    ]
    now = datetime.now(timezone.utc)
    for index, (name, subject, body) in enumerate(samples):
        message = EmailMessage()
        message["From"] = f"{name} <{sender}>"
        message["To"] = owner
        message["Date"] = format_datetime(now - timedelta(minutes=index * 30))
        message["Subject"] = subject
        message["Message-ID"] = f"<browser-fixture-{index}@hosted.example.test>"
        message.set_content(body)
        if index == 0:
            message.add_alternative(f"<p><strong>For Tuesday</strong></p><p>{body}</p>", subtype="html")
        if index == 3:
            message.add_attachment(RECEIPT, maintype="text", subtype="plain", filename="receipt-1046.txt")
        with fixture.smtp(sender) as connection:
            assert connection.send_message(message, from_addr=sender, to_addrs=[owner]) == {}


def seed_calendar(fixture, owner):
    now = datetime.now(timezone.utc)
    start = now.replace(hour=11, minute=0, second=0, microsecond=0)
    end = start + timedelta(hours=1)
    event = "\r\n".join([
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail browser fixture//EN", "BEGIN:VEVENT",
        "UID:studio-review", now.strftime("DTSTAMP:%Y%m%dT%H%M%SZ"), start.strftime("DTSTART:%Y%m%dT%H%M%SZ"),
        end.strftime("DTEND:%Y%m%dT%H%M%SZ"), "SUMMARY:Studio review", "END:VEVENT", "END:VCALENDAR", "",
    ])
    result = DavClient(fixture, owner).request(
        "PUT", f"/calendars/{owner}/Design/studio-review.ics", event, {"Content-Type": "text/calendar"},
    )
    assert result[0] == 201, result
    return start.date().isoformat()


def verify_delivery(fixture, sender):
    session = fixture.login(sender)
    status, listing = fixture.api(session, "messages?folder=INBOX&q=Browser+acceptance+handoff")
    assert status == 200 and listing["total"] == 1, (status, listing)
    uid = listing["items"][0]["uid"]
    status, detail = fixture.api(session, f"messages/{uid}?folder=INBOX")
    assert status == 200 and detail["attachments"][0]["filename"] == "handoff-checklist.txt", (status, detail)
    assert "Sent from the native browser fixture." in detail["text"]
    query = urlencode({"folder": "INBOX", "uid": uid, "index": 0, "account": sender})
    status, _, body = request(fixture.webmail + "/webmail/api/attachment?" + query,
                              headers=session, context=fixture.tls_context)
    assert status == 200 and body == b"Review the handoff", (status, body)


def verify(binary, output, engine):
    with tempfile.TemporaryDirectory(prefix="mail-browser-") as directory:
        fixture = Fixture(binary, Path(directory), staging=True)
        with fixture.daemon():
            owner = fixture.provision("alex.chen")
            sender = fixture.provision("morgan.lee")
            session = fixture.login(owner)
            assert fixture.api(session, "sender-review", {"setting": "disable"}, "PUT")[0] == 200
            assert fixture.api(session, "category-settings", {"automatic": True}, "PUT")[0] == 200
            seed_inbox(fixture, owner, sender)
            day = seed_calendar(fixture, owner)
            env = dict(os.environ, MAIL_BROWSER_URL=fixture.webmail, MAIL_BROWSER_OWNER=owner,
                       MAIL_BROWSER_SENDER=sender, MAIL_BROWSER_PASSWORD=fixture.password, MAIL_BROWSER_DAY=day)
            subprocess.run(["node", str(SCRIPTS / "webmail-browser.mjs"), engine, str(output / engine)],
                           env=env, check=True)
            verify_delivery(fixture, sender)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("screenshots", type=Path)
    parser.add_argument("--engine", choices=ENGINES, action="append")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    for engine in args.engine or ENGINES:
        verify(binary, args.screenshots.resolve(), engine)


if __name__ == "__main__":
    main()
