#!/usr/bin/env python3
"""Rehearse a published Mail release upgrade and rollback on disposable data."""

import argparse
from contextlib import closing, contextmanager
from email.message import EmailMessage
import json
from pathlib import Path
import runpy
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode


SCRIPTS = Path(__file__).resolve().parent
hosted = runpy.run_path(str(SCRIPTS / "test-hosted-limits.py"))
Fixture, DOMAIN = hosted["Fixture"], hosted["DOMAIN"]
ready = runpy.run_path(str(SCRIPTS / "test-webmail.py"))["ready"]
DavClient = runpy.run_path(str(SCRIPTS / "test-dav-https.py"))["DavClient"]
archive = runpy.run_path(str(SCRIPTS / "test-mail-backup-restore.py"))
mailbox_identity = archive["mailbox_identity"]
response = archive["response"]


@contextmanager
def released_daemon(server, dav=True):
    # The published release predates the private readiness endpoint. Use the
    # common loopback listeners and disable its fixed-port implicit IMAPS.
    log_path = server.directory / "released-mail.log"
    env = {**server.env, "CALDAV_ENABLED": str(dav).lower()}
    with log_path.open("w") as log, subprocess.Popen(
        [str(server.binary), "serve", "--host", "127.0.0.1", "--port", str(server.smtp_port),
         "--disable-tls", "--enable-auth"],
        cwd=server.directory, env=env, stdout=log, stderr=log,
    ) as process:
        try:
            ready(server.smtp_port, server.webmail, env["CALDAV_PORT"] if dav else None, process)
            yield
        except Exception:
            print(log_path.read_text(errors="replace")[-8000:])
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def read_mail(server, session, subject):
    query = urlencode({"folder": "INBOX", "q": subject, "conversations": "false"})
    found, = response(server.api(session, "messages?" + query))["items"]
    assert found["subject"] == subject, found
    return found


def send_mail(server, sender, recipient, subject):
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = sender, recipient, subject
    message["Message-ID"] = f"<{secrets.token_hex(16)}@{DOMAIN}>"
    message.set_content(f"Release rehearsal: {subject}")
    with server.smtp(sender) as client:
        assert client.send_message(message) == {}


def save_draft(server, session, draft_id, text, previous=None):
    fields = {} if previous is None else {"draftUid": previous["uid"], "draftRevision": previous["revision"]}
    return response(server.api(session, "drafts", {
        **fields, "draftId": draft_id, "saveToken": secrets.token_hex(16),
        "subject": "Draft across releases", "text": text,
    }))


def verify_draft(server, session, draft, text):
    result = response(server.api(session, f"drafts?uid={draft['uid']}"))
    assert result["message"]["text"] == text and result["revision"] == draft["revision"], result


def dav_value(server, owner, path):
    status, headers, body = DavClient(server, owner).request("GET", path, tls=False)
    assert status == 200, (path, status, body)
    return headers.get("ETag"), body


def create_dav_values(server, owner, uid):
    cal = "\r\n".join(("BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", f"UID:{uid}",
                       "DTSTAMP:20261121T090000Z", "DTSTART:20261127T090000Z", "DTEND:20261127T100000Z",
                       f"SUMMARY:Planning {uid}", "END:VEVENT", "END:VCALENDAR", ""))
    card = "\r\n".join(("BEGIN:VCARD", "VERSION:3.0", f"UID:{uid}", f"FN:Contact {uid}",
                        "EMAIL:contact@example.test", "END:VCARD", ""))
    resources = {f"/calendars/{owner}/Projects/{uid}.ics": ("text/calendar", cal),
                 f"/addressbooks/{owner}/People/{uid}.vcf": ("text/vcard", card)}
    client = DavClient(server, owner)
    for path, (content_type, data) in resources.items():
        status, _, raw = client.request("PUT", path, data, {"Content-Type": content_type}, tls=False)
        assert status == 201, (path, status, raw)
    return {path: data.encode() for path, (_, data) in resources.items()}


def stored_legacy_dav(directory, resources):
    # Use the bytes acknowledged by PUT and the persisted ETags as the baseline.
    etags_and_contents = {}
    with closing(sqlite3.connect(directory / "caldav.db")) as db:
        for path, contents in resources.items():
            resource = Path(path)
            query = ("SELECT etag,ics_data FROM dav_events WHERE uid=?" if resource.suffix == ".ics"
                     else "SELECT etag,vcf_data FROM dav_contacts WHERE uid=?")
            etag, stored = db.execute(query, (resource.stem,)).fetchone()
            assert stored.encode() == contents, path
            etags_and_contents[path] = (etag, contents)
    return etags_and_contents


def assign_dav(server, owner):
    # The fixture created both collections as this signed-in owner. Production
    # assignments require independently verified ownership for each collection.
    with closing(sqlite3.connect(server.directory / "caldav.db")) as db:
        calendar, = db.execute("SELECT id FROM dav_calendars WHERE name='Projects'").fetchone()
        book, = db.execute("SELECT id FROM dav_addressbooks WHERE name='People'").fetchone()
    assignments = server.directory / "assignments.json"
    assignments.write_text(json.dumps([
        {"kind": "calendar", "id": calendar, "mailbox": owner},
        {"kind": "address_book", "id": book, "mailbox": owner},
    ]))
    command = [sys.executable, str(SCRIPTS / "migrate-dav-ownership.py"),
               "--mail-db", str(server.directory / "smtp.db"), "--dav-db", str(server.directory / "caldav.db"),
               "--assignments", str(assignments)]
    subprocess.run(command, check=True)
    subprocess.run([*command, "--apply"], check=True)
    retry = subprocess.run([*command, "--apply"], check=True, text=True, capture_output=True)
    assert retry.stdout == "Assigned 0 legacy DAV collection(s).\n"


def check_databases(directory):
    for name in ("smtp.db", "caldav.db"):
        uri = (directory / name).as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as db:
            assert db.execute("PRAGMA integrity_check").fetchall() == [("ok",)], name


def verify(candidate, previous, root):
    live = root / "live"
    live.mkdir()
    server = Fixture(previous, live)
    server.env["CALDAV_SSL_PORT"] = "0"
    owner, other = (f"{name}@{DOMAIN}" for name in ("release-owner", "release-peer"))
    original_subject = "Accepted by the published release"
    draft_id = secrets.token_hex(16)
    for mailbox in (owner, other):
        subprocess.run([str(previous), "user:local", "create", mailbox, server.password, mailbox],
                       cwd=live, env=server.env, stdout=subprocess.DEVNULL, check=True)
    with released_daemon(server):
        send_mail(server, other, owner, original_subject)
        session = server.login(owner)
        original = read_mail(server, session, original_subject)
        identity = mailbox_identity(server, owner, original["uid"])
        draft = save_draft(server, session, draft_id, "Written by the published release")
        legacy_resources = create_dav_values(server, owner, "before-upgrade")
    original_dav = stored_legacy_dav(live, legacy_resources)
    checkpoint = root / "pre-upgrade"
    shutil.copytree(live, checkpoint)
    check_databases(checkpoint)

    server.binary = candidate
    with server.daemon():
        for path in original_dav:
            assert DavClient(server, owner).request("GET", path, tls=False)[0] == 404
    assign_dav(server, owner)

    next_subject = "Accepted by the upgrade candidate"
    dispatched = "Scheduled before the binary rollback"
    send_id = secrets.token_hex(16)
    with server.daemon():
        session = server.login(owner)
        upgraded = read_mail(server, session, original_subject)
        assert upgraded["uid"] == original["uid"] and upgraded["message_id"] == original["message_id"]
        assert mailbox_identity(server, owner, original["uid"]) == identity
        verify_draft(server, session, draft, "Written by the published release")
        updated_draft = save_draft(server, session, draft_id, "Edited by the upgrade candidate", draft)
        assert updated_draft["revision"] == draft["revision"] + 1
        for path, value in original_dav.items():
            actual = dav_value(server, owner, path)
            assert actual == value, (path, actual, value)
            assert DavClient(server, other).request("GET", path, tls=False)[0] == 404
        written = create_dav_values(server, owner, "after-upgrade")
        newer_dav = {path: dav_value(server, owner, path) for path in written}
        assert {path: body for path, (_, body) in newer_dav.items()} == written
        task = response(server.api(session, "calendar-tasks", {
            "title": "Candidate-only task", "day": None, "completed": False, "revision": 0,
        }), 201)
        send_mail(server, other, owner, next_subject)
        next_mail = read_mail(server, session, next_subject)
        response(server.api(session, "compose", {
            "sendId": send_id, "to": [other], "subject": dispatched, "text": "Common-format queued send.",
            "scheduleAt": int(time.time()) + 8,
        }))
        server.outbox(session, send_id, "pending")

    # The published binary cannot read the new DAV owner registry. Limit this
    # binary-only rollback to mail and a deliberately compatible queued send.
    rollback_subject = "Accepted while the published release was back"
    server.binary = previous
    with released_daemon(server, dav=False):
        try:
            with socket.create_connection(("127.0.0.1", int(server.env["CALDAV_PORT"])), timeout=1):
                raise AssertionError("The released DAV listener started during mail-only rollback.")
        except ConnectionRefusedError:
            pass
        session = server.login(owner)
        assert mailbox_identity(server, owner, original["uid"]) == identity
        verify_draft(server, session, updated_draft, "Edited by the upgrade candidate")
        rolled_draft = save_draft(server, session, draft_id, "Edited during rollback", updated_draft)
        assert rolled_draft["revision"] == updated_draft["revision"] + 1
        send_mail(server, other, owner, rollback_subject)
        server.outbox(session, send_id, "sent")
        assert read_mail(server, server.login(other), dispatched)
    print("The published Mail worker accepted SMTP and delivered a compatible queued send during rollback.")

    server.binary = candidate
    with server.daemon():
        session = server.login(owner)
        assert read_mail(server, session, original_subject)["reference"] == upgraded["reference"]
        assert read_mail(server, session, next_subject)["reference"] == next_mail["reference"]
        rollback_mail = read_mail(server, session, rollback_subject)
        assert server.outbox(session, send_id, "sent")["result"]["delivered"] == 1
        assert read_mail(server, server.login(other), dispatched)
        verify_draft(server, session, rolled_draft, "Edited during rollback")
        assert response(server.api(session, "calendar-tasks"))["tasks"] == [task]
        for path, value in (original_dav | newer_dav).items():
            assert dav_value(server, owner, path) == value
    check_databases(live)

    renamed_domain = "renamed.example.test"
    renamed = owner.replace(DOMAIN, renamed_domain)
    subprocess.run([str(candidate), "domain", "migrate", DOMAIN, renamed_domain, "--yes"],
                   cwd=live, env=server.env, check=True)
    server.env["SMTP_LOCAL_DOMAINS"] = renamed_domain
    with server.daemon():
        assert server.api(session, "messages?folder=INBOX")[0] == 401
        session = server.login(renamed)
        assert mailbox_identity(server, renamed, original["uid"]) == identity
        assert read_mail(server, session, rollback_subject)["reference"] == rollback_mail["reference"]
        verify_draft(server, session, rolled_draft, "Edited during rollback")
        assert response(server.api(session, "calendar-tasks"))["tasks"] == [task]
        for path, value in (original_dav | newer_dav).items():
            assert dav_value(server, renamed, path.replace(owner, renamed, 1)) == value
    check_databases(live)

    restored = Fixture(previous, checkpoint)
    restored.env["CALDAV_SSL_PORT"] = "0"
    restored.password = server.password
    with released_daemon(restored):
        session = restored.login(owner)
        assert mailbox_identity(restored, owner, original["uid"]) == identity
        verify_draft(restored, session, draft, "Written by the published release")
        query = urlencode({"folder": "INBOX", "q": rollback_subject})
        assert response(restored.api(session, "messages?" + query))["total"] == 0
    assert stored_legacy_dav(checkpoint, legacy_resources) == original_dav
    print("Verified the matching pre-upgrade checkpoint and a forward repair retaining mail, drafts, UIDs, and DAV data after rollback and domain rename.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--previous", required=True, type=Path, help="Published native Mail executable")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-release-upgrade-") as directory:
        verify(args.binary.resolve(strict=True), args.previous.resolve(strict=True), Path(directory))
