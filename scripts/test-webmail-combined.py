#!/usr/bin/env python3
"""Exercise browser-scoped mailbox aggregation against native HTTPS and IMAP."""

import argparse
import json
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
from pathlib import Path
import runpy
import secrets
import sqlite3
import tempfile
from urllib.parse import urlencode


support = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture, request = support["Fixture"], support["request"]
ACCOUNTS = "combined/accounts"
MESSAGES = "combined/messages"


def seed(imap, folder, from_address, to_address, subject, day, message_id, attachment=False):
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = from_address, to_address, subject
    message["Message-ID"] = f"<{message_id}@combined.example>"
    message["Date"] = format_datetime(datetime(2025, 1, day, 12, tzinfo=timezone.utc))
    message.set_content(f"Private text for {subject}.")
    if attachment:
        message.add_attachment(b"linked mailbox attachment", maintype="application", subtype="octet-stream", filename="notes.bin")
    assert imap.append(folder, None, None, message.as_bytes(policy=SMTP))[0] == "OK"


def verify(fixture):
    def call(session, path, payload=None, *, method=None, status=200):
        actual, data = fixture.api(session, path, payload, method)
        assert actual == status, (path, actual, data)
        return data

    def link_path(path, link, **params):
        return path + "?" + urlencode({"linked": link, **params})

    with fixture.daemon():
        owner = fixture.provision("combined-owner")
        second = fixture.provision("combined-second", daily=2)
        stranger = fixture.provision("combined-stranger")
        root = fixture.login(owner)
        other_browser = fixture.login(owner)
        peer, outsider = fixture.login(second), fixture.login(stranger)
        with fixture.imap(owner) as imap:
            seed(imap, "INBOX", second, owner, "Needle owner newest", 4, "same-message-id")
            seed(imap, "INBOX", second, owner, "Owner ordinary", 1, "owner-ordinary")
        with fixture.imap(second) as imap:
            imap.create("Archive")
            seed(imap, "INBOX", owner, second, "Needle linked source", 3, "same-message-id", attachment=True)
            seed(imap, "Archive", owner, second, "Needle linked archive", 2, "linked-archive")
        with fixture.imap(stranger) as imap:
            seed(imap, "INBOX", owner, stranger, "Needle unauthorized", 5, "same-message-id")

        assert call(root, ACCOUNTS) == {"owner": {"id": "", "username": owner, "address": owner}, "accounts": []}
        assert call(root, MESSAGES)["total"] == 2
        credentials = {"username": second, "password": fixture.password}
        call({}, ACCOUNTS, credentials, status=401)
        call({**root, "Origin": "https://foreign.example"}, ACCOUNTS, credentials, status=403)
        call(root, ACCOUNTS, {**credentials, "password": "incorrect"}, status=403)
        call(root, ACCOUNTS, {**credentials, "username": owner}, status=409)
        linked, = call(root, ACCOUNTS, credentials)["accounts"]
        link_id = linked["id"]
        assert len(link_id) == 32 and linked["username"] == linked["address"] == second
        assert set(linked) == {"id", "username", "address"}
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            private_session, = db.execute("SELECT source_session FROM webmail_account_links WHERE id=?", (link_id,)).fetchone()
            assert private_session not in str(linked)
        assert call(other_browser, ACCOUNTS)["accounts"] == []
        call(root, ACCOUNTS, credentials, status=409)
        call(peer, link_path("messages", link_id), status=403)
        call(outsider, link_path("messages", link_id), status=403)
        call(other_browser, link_path("messages", link_id), status=403)
        call({**root, "X-Webmail-Account": owner}, link_path("messages", link_id), status=409)
        assert call({**root, "X-Webmail-Account": second}, link_path("folders", link_id))
        status, headers, raw = request(fixture.webmail + "/webmail/auth/me?" + urlencode({"linked": link_id}), headers=root,
                                       context=fixture.tls_context)
        assert status == 200 and json.loads(raw) == {"user": {"username": second, "email": second}}
        assert "Set-Cookie" not in headers
        call(root, link_path("combined/accounts", link_id), status=403)

        first_page = call(root, MESSAGES + "?per_page=1&page=1")
        second_page = call(root, MESSAGES + "?per_page=1&page=2")
        assert first_page["total"] == second_page["total"] == 3
        first, = first_page["items"]
        second_row, = second_page["items"]
        assert first["source"]["username"] == owner and second_row["source"]["username"] == second
        assert first["message"]["message_id"] == second_row["message"]["message_id"]
        assert first["message"]["reference"] != second_row["message"]["reference"]
        assert [row["message"]["subject"] for row in call(root, MESSAGES + "?scope=mail&q=Needle")["items"]] == [
            "Needle owner newest", "Needle linked source", "Needle linked archive",
        ]
        assert call(root, MESSAGES + "?scope=mail&q=unauthorized")["total"] == 0
        first_ref, other_ref = first["message"]["reference"], second_row["message"]["reference"]
        assert call(root, link_path(f"messages/ref/{other_ref}", link_id))["subject"] == "Needle linked source"
        call(root, f"messages/ref/{other_ref}", status=404)
        call(root, link_path(f"messages/ref/{first_ref}", link_id), status=404)
        params = urlencode({"linked": link_id, "account": second, "reference": other_ref,
                            "content_revision": second_row["message"]["content_revision"], "index": 0})
        code, _, contents = request(fixture.webmail + "/webmail/api/attachment?" + params, headers=root, context=fixture.tls_context)
        assert code == 200 and contents == b"linked mailbox attachment"

        def selected(row):
            return {"account": row["source"]["id"], "reference": row["message"]["reference"], "revision": row["message"]["revision"]}

        action = {"action": "read", "messages": [selected(first), {**selected(second_row), "account": "0" * 32}]}
        call(root, "combined/actions", action, status=403)
        assert not call(root, f"messages/ref/{first_ref}")["flags"]["seen"]
        action["messages"][1] = selected(second_row)
        changed = call(root, "combined/actions", action)["items"]
        assert [(item["account"], item["affected"]) for item in changed] == [("", 1), (link_id, 1)]
        assert call(root, f"messages/ref/{first_ref}")["flags"]["seen"]
        assert call(root, link_path(f"messages/ref/{other_ref}", link_id))["flags"]["seen"]
        for row in call(root, MESSAGES)["items"]:
            if row["message"]["reference"] in {first_ref, other_ref}:
                changed = call(root, "combined/actions", {"action": "archive", "messages": [selected(row)]})["items"]
                assert changed == [{"account": row["source"]["id"], "affected": 1, "error_code": None}]
        assert call(root, MESSAGES)["total"] == 1
        assert call(root, link_path(f"messages/ref/{other_ref}", link_id))["folder"] == "Archive"

        draft_id = secrets.token_hex(16)
        reply = {"to": [owner], "subject": "Re: Needle linked source", "text": "Reply from the correct mailbox.",
                 "inReplyTo": "<same-message-id@combined.example>", "draftId": draft_id, "saveToken": secrets.token_hex(16)}
        draft = call(root, link_path("drafts", link_id), reply)
        draft_uid = draft["uid"]
        call(root, f"drafts?uid={draft_uid}", status=404)
        document = call(root, link_path("drafts", link_id, uid=draft_uid))
        assert document["draftId"] == draft_id and document["message"]["to"] == [owner]
        matches = call(root, MESSAGES + "?scope=mail&q=correct+mailbox")["items"]
        assert any(row["source"]["id"] == link_id and row["message"]["folder"] == "Drafts" for row in matches)
        call(root, link_path("compose", link_id), reply, status=400)
        message = {**reply, "draftUid": draft_uid, "draftRevision": draft["revision"], "sendId": secrets.token_hex(16), "delaySeconds": 0}
        call(root, link_path("compose", link_id), message)
        assert fixture.outbox(peer, message["sendId"], "sent")["result"]["delivered"] == 1
        assert fixture.count(second) == 1 and fixture.count(owner) == 0
        inbox = call(root, "messages?conversations=false&q=Re%3A+Needle+linked+source")["items"]
        assert any(item["from"] == second and item["subject"] == message["subject"] for item in inbox)

        pending = {**reply, "subject": "Revoked before dispatch", "draftId": None, "sendId": secrets.token_hex(16), "delaySeconds": 30}
        call(root, link_path("compose", link_id), pending)
        call(other_browser, f"{ACCOUNTS}/{link_id}", method="DELETE", status=403)
        assert call(root, f"{ACCOUNTS}/{link_id}", method="DELETE")["accounts"] == []
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            assert db.execute("SELECT 1 FROM webmail_sessions WHERE session_id=?", (private_session,)).fetchone() is None
        call(root, link_path(f"messages/ref/{other_ref}", link_id), status=403)
        call(root, link_path("drafts", link_id, uid=draft_uid), status=403)
        call(root, link_path("compose", link_id), pending, status=403)
        assert call(root, MESSAGES + "?scope=mail&q=linked+archive")["total"] == 0
        new_link, = call(root, ACCOUNTS, credentials)["accounts"]
        assert new_link["id"] != link_id
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            db.execute("UPDATE webmail_records SET due_at=unixepoch() WHERE kind='outbox' AND id=?", (pending["sendId"],))
        failed = fixture.outbox(peer, pending["sendId"], "failed")
        assert "removed or expired" in failed["error"] and fixture.count(second) == 1

        # A new primary login leaves the previous browser's links invisible.
        code, _, _ = request(fixture.webmail + "/webmail/auth/logout", {}, root, context=fixture.tls_context)
        assert code == 200
        call(root, ACCOUNTS, status=401)
        call(fixture.login(owner), link_path("messages", new_link["id"]), status=403)
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            assert db.execute("SELECT count(*) FROM webmail_account_links").fetchone() == (0,)
        assert call(peer, f"messages/ref/{other_ref}")["subject"] == "Needle linked source"
        disabled, = call(other_browser, ACCOUNTS, credentials)["accounts"]
        fixture.provision("combined-second", enabled=False)
        assert call(other_browser, ACCOUNTS)["accounts"] == []
        call(other_browser, link_path(f"messages/ref/{other_ref}", disabled["id"]), status=403)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-combined-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Combined inbox, search, scoped drafts and sending, privilege boundaries, and revocation passed.")
