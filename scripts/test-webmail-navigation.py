#!/usr/bin/env python3
"""Record native HTTPS navigation timings and screenshots with disposable mailboxes."""

import argparse
from email.message import EmailMessage
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import time
from urllib.parse import urlencode

HERE = Path(__file__).resolve().parent
support = runpy.run_path(str(HERE / "test-webmail-browser.py"))
Fixture = support["Fixture"]
ENGINES = support["ENGINES"]
REVIEW_FOLDER = support["REVIEW_FOLDER"]


def seed(fixture, owner, sender):
    session = fixture.login(owner)
    assert fixture.api(session, "sender-review", {"setting": "disable"}, "PUT")[0] == 200
    assert fixture.api(session, "category-settings", {"automatic": True}, "PUT")[0] == 200
    support["seed_inbox"](fixture, owner, sender)
    newsletter = EmailMessage()
    newsletter["From"], newsletter["To"] = f"Studio Dispatch <{sender}>", owner
    newsletter["Subject"] = "November studio digest"
    newsletter["List-Id"] = "Studio Dispatch <dispatch.example.test>"
    newsletter.set_content("This month we opened the new print studio.")
    with fixture.smtp(sender) as smtp:
        assert smtp.send_message(newsletter, from_addr=sender, to_addrs=[owner]) == {}
    folder = EmailMessage()
    folder["From"], folder["To"], folder["Subject"] = sender, owner, "Archived color proofs"
    folder.set_content("The original signed proofs are filed here.")
    with fixture.imap(owner) as imap:
        assert imap.create(f'"{REVIEW_FOLDER}"')[0] == "OK"
        assert imap.append(f'"{REVIEW_FOLDER}"', r"(\Seen)", None, folder.as_bytes())[0] == "OK"
    studio_address = support["seed_shared_inbox"](fixture, owner, sender)
    support["team_command"](fixture, "team", "grant", "studio", studio_address, sender, "mailbox")
    assert fixture.api(session, "sender-review", {"setting": "enable"}, "PUT")[0] == 200
    for handle, subject in (("devon", "First note from Devon"), ("taylor", "First note from Taylor")):
        person = fixture.provision(handle)
        assert fixture.deliver(owner, identity=person, subject=subject,
                               body=f"Hello, this is {handle.title()}'s first message.")[0] == 250
    return support["seed_calendar"](fixture, owner)


def verify_rsvp(fixture, sender):
    session = fixture.login(sender)
    query = urlencode({"folder": "INBOX", "q": "Accepted: Studio reservation"})
    deadline = time.monotonic() + 10
    while True:
        status, listing = fixture.api(session, "messages?" + query)
        assert status == 200, listing
        rows = [row for row in listing["items"] if row["subject"] == "Accepted: Studio reservation"]
        if rows or time.monotonic() >= deadline:
            break
        time.sleep(0.2)
    row, = rows
    status, message = fixture.api(session, "messages/ref/" + row["reference"])
    assert status == 200 and message["attachments"][0]["filename"] == "reply.ics", message
    query = urlencode({"reference": row["reference"], "content_revision": message["content_revision"], "index": 0})
    status, _, attachment = fixture.http(fixture.webmail + "/webmail/api/attachment?" + query, headers=session,
                                         context=fixture.tls_context)
    assert status == 200 and b"UID:studio-reservation@example.test" in attachment and b"PARTSTAT=ACCEPTED" in attachment


def verify(binary, output, engine, device, revision):
    with tempfile.TemporaryDirectory(prefix="mail-navigation-") as directory:
        fixture = Fixture(binary, Path(directory), staging=True)
        with fixture.daemon():
            owner, sender = fixture.provision("alex.chen"), fixture.provision("morgan.lee")
            assert fixture.api(fixture.login(sender), "sender-review", {"setting": "disable"}, "PUT")[0] == 200
            day = seed(fixture, owner, sender)
            env = dict(os.environ, MAIL_NAVIGATION_URL=fixture.webmail, MAIL_NAVIGATION_OWNER=owner,
                       MAIL_NAVIGATION_PEER=sender, MAIL_NAVIGATION_PASSWORD=fixture.password,
                       MAIL_NAVIGATION_DAY=day, MAIL_NAVIGATION_REVISION=revision)
            subprocess.run(["node", str(HERE / "webmail-navigation.mjs"), engine, device, str(output / engine / device)],
                           env=env, check=True, timeout=90)
            verify_rsvp(fixture, sender)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("screenshots", type=Path)
    parser.add_argument("--revision", required=True, help="Revision of the supplied native binary")
    parser.add_argument("--engine", choices=ENGINES, action="append")
    parser.add_argument("--device", choices=("desktop", "phone"), action="append")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    for engine in args.engine or ENGINES:
        for device in args.device or ("desktop", "phone"):
            verify(binary, args.screenshots.resolve(), engine, device, args.revision)


if __name__ == "__main__":
    main()
