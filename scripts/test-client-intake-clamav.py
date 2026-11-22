#!/usr/bin/env python3
"""Exercise malware refusals before client uploads, mail sends, and DAV writes."""

import argparse
import base64
from email import policy
from email.message import EmailMessage
from pathlib import Path
import runpy
import secrets
import sqlite3
import tempfile
from types import SimpleNamespace
import urllib.parse


SCRIPTS = Path(__file__).resolve().parent
hosted = SimpleNamespace(**runpy.run_path(str(SCRIPTS / "test-hosted-limits.py")))
clamav = SimpleNamespace(**runpy.run_path(str(SCRIPTS / "test-smtp-clamav.py")))
CLEAN = b"Clean attachment data"
DEVICE = "IntakeScanDevice"


def mime(sender, recipient, data, subject="Intake scan"):
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content("Message body")
    message.add_attachment(data, maintype="application", subtype="octet-stream", filename="intake.txt")
    return message.as_bytes()


def send(test, sender, raw, client_id, *, command="SendMail", source=None, replace=False):
    body = hosted.eas_send(raw, client_id, save=True, command=command, source=source, replace=replace)
    return hosted.eas_result(test.eas(sender, body, device=DEVICE, command=command), command)


def dav(test, mailbox, path, body=None, *, content_type="text/calendar", tls=False):
    origin = (test.eas_url.rsplit("/", 1)[0] if tls else f"http://127.0.0.1:{test.env['CALDAV_PORT']}")
    credential = base64.b64encode(f"{mailbox}:{test.password}".encode()).decode()
    return hosted.request(origin + path, body, {"Authorization": f"Basic {credential}", "Content-Type": content_type},
                          method="PUT" if body is not None else "GET", context=test.tls_context)


def dav_payloads(mailbox):
    encoded = base64.b64encode(clamav.EICAR)
    folded = encoded[:32] + b"\r\n " + encoded[32:]
    event = (b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail Fixture//EN\r\nBEGIN:VEVENT\r\n"
             b"UID:intake\r\nDTSTAMP:20261121T100000Z\r\nDTSTART:20261121T120000Z\r\nSUMMARY:Intake scan\r\n")
    bad_event = event + b"ATTACH;FMTTYPE=application/octet-stream;ENCODING=BASE64;VALUE=BINARY:" + folded + b"\r\n"
    end_event = b"END:VEVENT\r\nEND:VCALENDAR\r\n"
    card = (b"BEGIN:VCARD\r\nVERSION:4.0\r\nUID:intake\r\nFN:Intake Scan\r\n"
            b"EMAIL:intake@example.test\r\nTEL;VALUE=uri:tel:+15550123\r\nNOTE:Retain this card\r\n")
    bad_card = card + b"PHOTO:data:image/png;base64," + folded + b"\r\n"
    host = urllib.parse.quote(mailbox, safe="@")
    yield f"/calendars/{host}/scan-events/intake.ics", "text/calendar", event + end_event, bad_event + end_event
    yield f"/addressbooks/{host}/scan-contacts/intake.vcf", "text/vcard", card + b"END:VCARD\r\n", bad_card + b"END:VCARD\r\n"


def uploads(test, session, upload_id, data):
    url = test.webmail + "/webmail/api/uploads?" + urllib.parse.urlencode({
        "filename": "intake.txt", "contentType": "application/octet-stream", "uploadId": upload_id,
    })
    return hosted.request(url, data, {**session, "Content-Type": "application/octet-stream"}, context=test.tls_context)


def assert_empty_table(path, query):
    with sqlite3.connect(path) as db:
        assert db.execute(query).fetchone()[0] == 0


def check_verdicts(test, owner, sink, polluted, clean, upload_id):
    source = hosted.synced_mail_item(test, owner, DEVICE)
    before = test.bytes(owner)
    assert send(test, owner, polluted, "scan-send") == 120
    assert hosted.eas_result(test.eas(owner, polluted, legacy=True, save=True)) == 500
    assert send(test, owner, polluted, "scan-reply", command="SmartReply", source=source, replace=True) == 120
    assert send(test, owner, clean, "scan-forward", command="SmartForward", source=source) == 120
    assert test.bytes(sink) == 0 and test.bytes(owner) == before and test.count(owner) == 0

    with test.imap(owner) as imap:
        status, data = imap.append("INBOX", None, None, polluted)
        assert status == "NO" and b"rejected by malware scanner" in data[0], (status, data)
        assert test.bytes(owner) == before
        assert imap.noop()[0] == "OK"
        assert imap.append("INBOX", None, None, clean)[0] == "OK"

    session = test.login(owner)
    assert uploads(test, session, upload_id, clamav.EICAR)[0] == 422
    assert_empty_table(test.directory / "smtp.db", "SELECT count(*) FROM webmail_uploads")
    attachment = {"filename": "intake.txt", "contentType": "application/octet-stream",
                  "data": base64.b64encode(clamav.EICAR).decode()}
    draft = {"attachments": [attachment], "text": "Suspect inline attachment"}
    compose = {**draft, "to": [sink]}
    before_draft = test.bytes(owner)
    for path, payload in (("drafts", draft), ("compose", compose), ("compose", {**compose, "sendId": upload_id})):
        status, result = test.api(session, path, payload)
        assert status == 422 and result["error"] == "malware_detected", (status, result)
    assert_empty_table(test.directory / "smtp.db", "SELECT count(*) FROM webmail_records WHERE kind IN ('draft','outbox')")
    assert test.bytes(owner) == before_draft and test.bytes(sink) == 0 and test.count(owner) == 0
    assert uploads(test, session, upload_id, CLEAN)[0] == 200

    status, listing = test.api(session, "messages?folder=INBOX")
    assert status == 200, listing
    uid, = [row["uid"] for row in listing["items"] if row["subject"] == "Clean intake scan"]
    url = f"{test.webmail}/webmail/api/attachment?folder=INBOX&uid={uid}&index=0"
    status, headers, raw = hosted.request(url, headers=session, context=test.tls_context)
    assert status == 200 and raw == CLEAN
    assert headers["Content-Security-Policy"] == "sandbox" and headers["X-Content-Type-Options"] == "nosniff"

    assert_empty_table(test.directory / "caldav.db", "SELECT count(*) FROM dav_events")
    assert_empty_table(test.directory / "caldav.db", "SELECT count(*) FROM dav_contacts")
    for path, kind, good, bad in dav_payloads(owner):
        assert dav(test, owner, path, bad, content_type=kind)[0] == 422
        assert dav(test, owner, path)[0] == 404
        assert dav(test, owner, path, good.replace(b"Intake", b"First"), content_type=kind)[0] == 201
        assert dav(test, owner, path, good, content_type=kind)[0] == 204
        assert dav(test, owner, path, bad, content_type=kind)[0] == 422
        status, _, saved = dav(test, owner, path)
        assert status == 200 and saved == good, (status, saved)

    assert send(test, owner, clean, "scan-send") == 0
    assert test.count(owner) == 1 and test.bytes(sink) > 0


def check_outage(test, owner, clean, upload_id):
    with test.imap(owner) as imap:
        status, data = imap.append("INBOX", None, None, clean)
        assert status == "NO" and b"[UNAVAILABLE]" in data[0], (status, data)
        assert imap.noop()[0] == "OK"
    assert send(test, owner, clean, "outage") == 111
    assert send(test, owner, clean, "scan-send") == 118
    assert test.count(owner) == 1
    assert hosted.eas_result(test.eas(owner, clean, legacy=True)) == 503
    session = test.login(owner)
    assert uploads(test, session, secrets.token_hex(16), CLEAN)[0] == 503
    assert uploads(test, session, upload_id, CLEAN)[0] == 200
    for path, kind, good, _ in dav_payloads(owner):
        assert dav(test, owner, path, good, content_type=kind)[0] == 503
        assert dav(test, owner, path)[2] == good


def check_fail_open(test, owner, clean):
    with test.imap(owner) as imap:
        assert imap.append("INBOX", None, None, clean)[0] == "OK"
    assert send(test, owner, clean, "fail-open") == 0
    assert test.count(owner) == 2
    session = test.login(owner)
    assert uploads(test, session, secrets.token_hex(16), CLEAN)[0] == 200
    for path, kind, good, _ in dav_payloads(owner):
        assert dav(test, owner, path, good, content_type=kind)[0] == 204


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--clamd", type=Path)
    parser.add_argument("--database", type=Path, default=Path("/var/lib/clamav"))
    args = parser.parse_args()
    clamd = args.clamd.resolve(strict=True) if args.clamd else None
    with tempfile.TemporaryDirectory(prefix="mail-intake-", dir="/tmp") as directory:
        root = Path(directory)
        test = hosted.Fixture(args.binary.resolve(strict=True), root, staging=True)
        with test.daemon():
            owner = test.provision("intake-owner")
            sink = test.provision("intake-sink")
            polluted = mime(owner, sink, clamav.EICAR)
            clean = mime(owner, sink, CLEAN, subject="Clean intake scan")
            # Model a mailbox that already held this source before scanning was enabled.
            with test.imap(owner) as imap:
                assert imap.append("INBOX", None, None, polluted)[0] == "OK"
        upload_id = secrets.token_hex(16)
        with clamav.scanner(root, clamd, args.database.resolve()) as endpoint:
            test.env.update(SMTP_CLAMAV_TRANSPORT=f"unix:{endpoint}", SMTP_CLAMAV_FAIL_MODE="closed")
            with test.daemon():
                check_verdicts(test, owner, sink, polluted, clean, upload_id)
        print("Verified malware refusals for IMAP APPEND, ActiveSync sends, DAV resource writes, and webmail attachments.")
        test.env["SMTP_CLAMAV_TRANSPORT"] = f"unix:{root / 'missing.sock'}"
        with test.daemon():
            check_outage(test, owner, clean, upload_id)
        print("Verified fail-closed responses, prior accepted replays, and preservation of stored resources.")
        test.env["SMTP_CLAMAV_FAIL_MODE"] = "open"
        with test.daemon():
            check_fail_open(test, owner, clean)
        print("Verified configured fail-open behavior across the client intake paths.")


if __name__ == "__main__":
    main()
