#!/usr/bin/env python3
"""Run browser journeys against a disposable native HTTPS Mail instance."""

import argparse
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from imaplib import Time2Internaldate
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
team_command = runpy.run_path(str(SCRIPTS / "test-webmail-teams.py"))["command"]
ENGINES = ("chromium", "firefox", "webkit")
RECEIPT = b"Receipt 1046 for Studio Hosting\n"
LONG_FOLDER = "Annual research and planning archive"
REVIEW_FOLDER = "Design reviews"


def seed_inbox(fixture, owner, sender):
    samples = [
        ("Morgan Lee", "Tuesday design handoff", "Please confirm the sidebar order before 4 PM."),
        ("Avery Patel", "Studio launch notes", "Here is the handoff for Thursday."),
        ("Jordan Kim", "Workshop agenda", "I set aside time for the accessibility review."),
        ("Studio Hosting", "Your receipt #1046", "Your November payment of $18.00 was received."),
        ("Casey Rivera", "Feedback on the print proofs", "The cover looks good. I left two notes on the inside spread."),
        ("Sam Taylor", "Thursday studio reservation", "We have the south room from 10 to noon."),
        ("Priya Raman", "November research interviews", "Two interviewees confirmed their availability."),
        ("Jamie Park", "Photos from the site visit", "I added the entrance and reception photos to the shared folder."),
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
        if subject == "Thursday studio reservation":
            invite = "\r\n".join((
                "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail//Browser Fixture//EN", "METHOD:REQUEST",
                "BEGIN:VEVENT", "UID:studio-reservation@example.test", "DTSTAMP:20261121T100000Z",
                "DTSTART;TZID=America/New_York:20261126T100000", "DTEND;TZID=America/New_York:20261126T120000",
                "RRULE:FREQ=DAILY;COUNT=3",
                f"ORGANIZER:mailto:{sender}", f"ATTENDEE:mailto:{owner}", "SUMMARY:Studio reservation",
                "LOCATION:South room <Studio>", "END:VEVENT", "END:VCALENDAR", "",
            ))
            message.add_alternative(invite, subtype="calendar", params={"method": "REQUEST"})
        with fixture.smtp(sender) as connection:
            assert connection.send_message(message, from_addr=sender, to_addrs=[owner]) == {}


def seed_calendar(fixture, owner):
    now = datetime.now(timezone.utc)
    client = DavClient(fixture, owner)
    for uid, title, hour, visibility in (
        ("studio-review", "Studio review", 11, "PUBLIC"),
        ("budget-check", "Private budget check", 14, "PRIVATE"),
    ):
        start = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        end = start + timedelta(hours=1)
        event = "\r\n".join([
            "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail browser fixture//EN", "BEGIN:VEVENT",
            f"UID:{uid}", now.strftime("DTSTAMP:%Y%m%dT%H%M%SZ"), start.strftime("DTSTART:%Y%m%dT%H%M%SZ"),
            end.strftime("DTEND:%Y%m%dT%H%M%SZ"), f"SUMMARY:{title}", f"CLASS:{visibility}", "END:VEVENT", "END:VCALENDAR", "",
        ])
        result = client.request("PUT", f"/calendars/{owner}/Design/{uid}.ics", event, {"Content-Type": "text/calendar"})
        assert result[0] == 201, result
    metadata = ('<D:propertyupdate xmlns:D="DAV:" xmlns:A="http://apple.com/ns/ical/">'
                '<D:set><D:prop><D:displayname>Design &amp; Research</D:displayname><A:calendar-color>#007AFF</A:calendar-color>'
                '</D:prop></D:set></D:propertyupdate>')
    status, _, payload = client.request("PROPPATCH", f"/calendars/{owner}/Design/", metadata, {"Content-Type": "application/xml"})
    assert status == 207 and payload.count(b"200 OK") == 2, (status, payload)
    return now.date().isoformat()


def archive_fixture(fixture, session, subject):
    status, listing = fixture.api(session, "messages?" + urlencode({"folder": "INBOX", "q": subject}))
    assert status == 200, listing
    row, = [row for row in listing["items"] if row["subject"] == subject]
    target = {field: row[field] for field in ("uid", "folder", "reference", "revision")}
    status, result = fixture.api(session, "bulk", {"action": "move", "folder": "Archive", "messages": [target]})
    assert status == 200 and result["ok"], result


def seed_invitation_updates(fixture, owner, sender):
    session = fixture.login(owner)
    for sequence, method, subject in ((0, "REQUEST", "Team breakfast invitation"), (1, "CANCEL", "Team breakfast cancelled")):
        source = "\r\n".join([
            "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail browser fixture//EN", f"METHOD:{method}",
            "BEGIN:VEVENT", "UID:breakfast@example.test", f"SEQUENCE:{sequence}", "DTSTAMP:20261121T100000Z",
            "DTSTART:20261126T090000Z", "SUMMARY:Team breakfast", f"ORGANIZER:mailto:{sender}",
            f"ATTENDEE:mailto:{owner}", "END:VEVENT", "END:VCALENDAR", "",
        ])
        message = EmailMessage()
        message["From"], message["To"], message["Subject"] = sender, owner, subject
        message.set_content("Join us for team breakfast." if method == "REQUEST" else "Team breakfast has been cancelled.")
        message.add_alternative(source, subtype="calendar", params={"method": method})
        with fixture.smtp(sender) as connection:
            assert connection.send_message(message) == {}
        archive_fixture(fixture, session, subject)

    for sequence, range_parameter, start, subject, title in (
        (1, ";RANGE=THISANDFUTURE", "130000", "Studio sessions moved from Friday", "Studio reservation series"),
        (2, "", "150000", "Friday studio session only moved again", "Friday studio reservation"),
    ):
        source = "\r\n".join([
            "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail browser fixture//EN", "METHOD:REQUEST",
            "BEGIN:VEVENT", "UID:studio-reservation@example.test", f"SEQUENCE:{sequence}", "DTSTAMP:20261121T100000Z",
            f"RECURRENCE-ID{range_parameter};TZID=America/New_York:20261127T100000",
            f"DTSTART;TZID=America/New_York:20261127T{start}", "DURATION:PT2H", f"SUMMARY:{title}",
            f"ORGANIZER:mailto:{sender}", f"ATTENDEE:mailto:{owner}", "END:VEVENT", "END:VCALENDAR", "",
        ])
        message = EmailMessage()
        message["From"], message["To"], message["Subject"] = sender, owner, subject
        message.set_content("Here is the updated studio booking.")
        message.add_alternative(source, subtype="calendar", params={"method": "REQUEST"})
        with fixture.smtp(sender) as connection:
            assert connection.send_message(message) == {}
        archive_fixture(fixture, session, subject)


def seed_shared_inbox(fixture, owner, sender):
    studio = fixture.provision("studio")
    session = fixture.login(studio)
    assert fixture.api(session, "sender-review", {"setting": "disable"}, "PUT")[0] == 200
    team_command(fixture, "team", "create", "studio", "Studio", studio)
    team_command(fixture, "team", "member", "studio", owner, "admin")
    team_command(fixture, "team", "member", "studio", sender, "member")
    team_command(fixture, "team", "grant", "studio", studio, owner, "mailbox")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = studio
    message["Subject"] = "Studio proof approval"
    message.set_content("The revised proof is ready for approval.")
    with fixture.smtp(sender) as connection:
        assert connection.send_message(message) == {}
    return studio


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
    reply_subject = "Re: Your receipt #1046"
    query = urlencode({"folder": "INBOX", "conversations": "false", "q": reply_subject})
    status, listing = fixture.api(session, "messages?" + query)
    assert status == 200, listing
    replies = []
    for row in listing["items"]:
        if row["subject"] != reply_subject:
            continue
        status, detail = fixture.api(session, "messages/ref/" + row["reference"])
        assert status == 200 and detail["in_reply_to"] == "<browser-fixture-3@hosted.example.test>", detail
        replies.append(detail["text"])
    assert len(replies) == 2, replies
    billing, = [text for text in replies if "Please use the updated billing contact" in text]
    reviewed, = [text for text in replies if "I checked the studio receipt before sending." in text]
    assert "> Your November payment of $18.00 was received." in billing
    assert billing != reviewed
    for label, response in (("Accepted", "ACCEPTED"), ("Tentative", "TENTATIVE")):
        subject = f"{label}: Studio reservation"
        status, listing = fixture.api(session, "messages?" + urlencode({"folder": "INBOX", "q": subject}))
        assert status == 200, listing
        row, = [row for row in listing["items"] if row["subject"] == subject]
        status, detail = fixture.api(session, "messages/ref/" + row["reference"])
        assert status == 200, detail
        reply, = detail["attachments"]
        assert reply["filename"] == "reply.ics"
        query = urlencode({"reference": row["reference"], "content_revision": detail["content_revision"], "index": 0})
        status, _, body = request(fixture.webmail + "/webmail/api/attachment?" + query, headers=session, context=fixture.tls_context)
        assert status == 200 and b"UID:studio-reservation@example.test" in body and f"PARTSTAT={response}".encode() in body, (status, body)


def verify(binary, output, engine, accessibility=False):
    with tempfile.TemporaryDirectory(prefix="mail-browser-") as directory:
        fixture = Fixture(binary, Path(directory), staging=True)
        with fixture.daemon():
            owner = fixture.provision("alex.chen")
            sender = fixture.provision("morgan.lee")
            newcomer = fixture.provision("jordan.kim")
            session = fixture.login(owner)
            assert fixture.api(session, "sender-review", {"setting": "disable"}, "PUT")[0] == 200
            assert fixture.api(session, "category-settings", {"automatic": True}, "PUT")[0] == 200
            seed_inbox(fixture, owner, sender)
            with fixture.imap(owner) as mailbox:
                for folder in (REVIEW_FOLDER, LONG_FOLDER):
                    assert mailbox.create(f'"{folder}"')[0] == "OK"
                    assert mailbox.select(f'"{folder}"')[0] == "OK"
            status, folders = fixture.api(session, "folders")
            assert status == 200 and {REVIEW_FOLDER, LONG_FOLDER} <= {folder["name"] for folder in folders}, folders
            seed_invitation_updates(fixture, owner, sender)
            newcomer_session = fixture.login(newcomer)
            assert fixture.api(newcomer_session, "sender-review", {"setting": "disable"}, "PUT")[0] == 200
            note = EmailMessage()
            note["From"], note["To"], note["Subject"] = sender, newcomer, "Studio launch notes"
            note.set_content("Here is the handoff for Thursday.")
            with fixture.smtp(sender) as connection:
                assert connection.send_message(note) == {}
            archived = EmailMessage()
            archived["From"], archived["To"], archived["Subject"] = sender, newcomer, "Archived planning notes"
            archived.set_content("Notes from last quarter.")
            with fixture.imap(newcomer) as mailbox:
                if mailbox.select("Archive")[0] != "OK":
                    assert mailbox.create("Archive")[0] == "OK"
                received = datetime.now(timezone.utc) - timedelta(days=45)
                assert mailbox.append("Archive", r"(\Seen)", Time2Internaldate(received), archived.as_bytes())[0] == "OK"
            assert fixture.deliver(sender, identity=owner, subject="Combined source briefing",
                                   body="Please send the design notes from this mailbox.")[0] == 250
            studio = seed_shared_inbox(fixture, owner, sender)
            team_command(fixture, "team", "grant", "studio", studio, sender, "mailbox")
            day = seed_calendar(fixture, owner)
            if accessibility:
                for letter in "abc":
                    contact = {"kind": "contact", "name": f"Harland {letter.upper()}", "emails": [f"harland-{letter}@example.test"]}
                    assert fixture.api(session, "address-book", contact, "POST")[0] == 201
            env = dict(os.environ, MAIL_BROWSER_URL=fixture.webmail, MAIL_BROWSER_OWNER=owner,
                       MAIL_BROWSER_SENDER=sender, MAIL_BROWSER_PASSWORD=fixture.password, MAIL_BROWSER_DAY=day,
                       MAIL_BROWSER_NEWCOMER=newcomer, MAIL_BROWSER_LONG_FOLDER=LONG_FOLDER,
                       MAIL_BROWSER_REVIEW_FOLDER=REVIEW_FOLDER,
                       MAIL_BROWSER_CERT=fixture.env["SMTP_TLS_CERT"])
            script = "webmail-accessibility.mjs" if accessibility else "webmail-browser.mjs"
            subprocess.run(["node", str(SCRIPTS / script), engine, str(output / engine)],
                           env=env, check=True)
            if not accessibility:
                verify_delivery(fixture, sender)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("screenshots", type=Path)
    parser.add_argument("--engine", choices=ENGINES, action="append")
    parser.add_argument("--accessibility", action="store_true", help="Audit native pages with axe-core and browser accessibility snapshots")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    for engine in args.engine or ENGINES:
        verify(binary, args.screenshots.resolve(), engine, args.accessibility)


if __name__ == "__main__":
    main()
