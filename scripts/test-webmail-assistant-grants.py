#!/usr/bin/env python3
"""Exercise delegated reads and revisioned drafts over disposable HTTPS mailboxes."""

import argparse
from contextlib import closing
from email.message import EmailMessage
from hashlib import sha256
import json
from pathlib import Path
import runpy
from secrets import token_hex
import sqlite3
import tempfile
import time
from urllib.parse import urlencode


fixtures = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture, request = fixtures["Fixture"], fixtures["request"]
GRANTS = "assistant-grants"


def seed(fixture, owner, sender, title, body):
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = sender, owner, title
    message["Bcc"] = "hidden-recipient@example.test"
    message.set_content(body)
    message.add_attachment(b"private attachment content", maintype="application", subtype="octet-stream", filename="hidden-file.bin")
    with fixture.imap(owner) as inbox:
        assert inbox.append("INBOX", None, None, message.as_bytes())[0] == "OK"


def run(binary, root):
    fixture = Fixture(binary, root, staging=True)

    def call(headers, path, data=None, method=None, status=200):
        actual, result = fixture.api(headers, path, data, method)
        assert actual == status, (path, status, actual, result)
        return result

    def use(token, path, data, status=200):
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        actual, response, raw = request(fixture.webmail + "/webmail/assistant/" + path,
                                        data, headers, "POST", fixture.tls_context)
        assert actual == status, (path, status, actual, raw)
        assert "no-store" in response["Cache-Control"]
        return json.loads(raw)

    def make(session, payload):
        preview = call(session, f"{GRANTS}/preview", payload)
        issued = call(session, GRANTS, {**payload, "digest": preview["digest"]}, status=201)
        return preview, issued

    def reference(headers, subject, folder="INBOX"):
        listing = call(headers, "messages?" + urlencode({"folder": folder, "conversations": "false"}))
        return next(row["reference"] for row in listing["items"] if row["subject"] == subject)

    def sql(query, params=()):
        with closing(sqlite3.connect(root / "smtp.db")) as db, db:
            return db.execute(query, params).fetchall()

    with fixture.daemon():
        owner = fixture.provision("assistant-owner")
        peer = fixture.provision("assistant-peer")
        ours, theirs = fixture.login(owner), fixture.login(peer)
        call(theirs, "sender-review", {"setting": "disable"}, "PUT")
        seed(fixture, owner, peer, "Selected only", "Visible note. https://private.example.test/link#token=unique-secret")
        seed(fixture, owner, peer, "Outside selection", "Other inbox content")
        seed(fixture, peer, owner, "Separate mailbox", "Peer inbox content")
        selected = reference(ours, "Selected only")
        outside = reference(ours, "Outside selection")
        foreign = reference(theirs, "Separate mailbox")

        linked, = call(ours, "combined/accounts", {"username": peer, "password": fixture.password})["accounts"]
        target = urlencode({"linked": linked["id"]})
        options = {"integration": "Studio helper", "read": True, "draft": True, "lifetime": 3600, "references": [selected]}
        assert call(ours, GRANTS) == {"grants": [], "audit": []}
        call({}, GRANTS, status=401)
        call({**ours, "Origin": "https://other.example.test"}, f"{GRANTS}/preview", options, status=403)
        call(ours, f"{GRANTS}/preview?{target}", options, status=403)
        call(ours, f"{GRANTS}/preview", {**options, "references": [foreign]}, status=404)
        call(theirs, f"{GRANTS}/preview", options, status=404)
        call(ours, f"{GRANTS}/preview", {**options, "references": [selected, selected]}, status=400)
        call(ours, f"{GRANTS}/preview", {**options, "draft": False, "read": False}, status=400)
        call(ours, GRANTS, options, status=409)
        preview = call(ours, f"{GRANTS}/preview", options)
        item, = preview["messages"]
        assert {**item, "text": item["text"].strip()} == {
            "reference": selected, "subject": "Selected only", "text": "Visible note. [link removed]",
        }, item
        call(ours, GRANTS, {**options, "draft": False, "digest": preview["digest"]}, status=409)
        issued = call(ours, GRANTS, {**options, "digest": preview["digest"]}, status=201)
        token, grant = issued["token"], issued["grant"]
        assert grant["read"] and grant["draft"] and grant["message_count"] == 1
        assert len(token) == 64 and grant["expires_at"] > int(time.time())
        stored_hash, stored = sql("SELECT token_hash,payload FROM mail_assistant_grants WHERE id=?", (grant["id"],))[0]
        assert stored_hash == sha256(token.encode()).hexdigest()
        for secret in (token, "unique-secret", "hidden-recipient", "hidden-file.bin", "private attachment content"):
            assert secret not in stored
        assert use(token, "read", {"reference": selected}) == item
        use(token, "read", {"reference": outside}, 404)
        use(token, "read", {"reference": foreign}, 404)
        use(token, "read", {"reference": "bad"}, 404)
        use(token, "read", {"reference": selected, "attachments": True}, 400)
        use(None, "read", {"reference": selected}, 404)
        use(token, "read?" + target, {"reference": selected}, 403)
        call({"Authorization": f"Bearer {token}"}, "messages", status=401)
        call({"Authorization": f"Bearer {token}"}, "compose", {"to": [peer], "subject": "Rejected"}, status=401)

        original = call(ours, "messages/ref/" + selected)
        with fixture.imap(owner) as inbox:
            assert inbox.create("Archive")[0] == "OK"
            assert inbox.select("INBOX")[0] == "OK"
            assert inbox.xatom("UID", "MOVE", str(original["uid"]), "Archive")[0] == "OK"
        assert call(ours, "messages/ref/" + selected)["folder"] == "Archive"
        assert use(token, "read", {"reference": selected}) == item

        draft_body = {"request_id": token_hex(16), "to": [peer], "subject": "Owner reviews this draft", "text": "Suggested reply"}
        use(token, "drafts", {**draft_body, "sendId": token_hex(16)}, 400)
        ack = use(token, "drafts", draft_body)
        assert ack["revision"] > 0
        replay = use(token, "drafts", draft_body)
        assert replay == ack, (replay, ack)
        use(token, "drafts", {**draft_body, "text": "Changed retry body"}, 409)
        listing = call(ours, "messages?folder=Drafts&conversations=false")
        assert listing["total"] == 1 and listing["items"][0]["uid"] == ack["uid"]
        assert call(theirs, "messages?q=Owner+reviews+this+draft")["total"] == 0
        assert call(ours, "outbox") == []

        _, read_only = make(ours, {**options, "draft": False})
        _, draft_only = make(ours, {**options, "read": False, "references": []})
        use(read_only["token"], "drafts", draft_body, 404)
        assert use(read_only["token"], "read", {"reference": selected}) == item
        use(draft_only["token"], "read", {"reference": selected}, 404)
        sql("UPDATE mail_assistant_grants SET expires_at=unixepoch() WHERE id=?", (read_only["grant"]["id"],))
        use(read_only["token"], "read", {"reference": selected}, 404)

        fixture.provision("assistant-owner", enabled=False)
        use(token, "read", {"reference": selected}, 404)
        use(token, "drafts", draft_body, 404)
        fixture.provision("assistant-owner")
        ours = fixture.login(owner)
        assert use(token, "read", {"reference": selected}) == item
        grants = call(ours, GRANTS)
        assert len(grants["grants"]) == 2 and draft_only["grant"]["id"] in {row["id"] for row in grants["grants"]}
        assert next(row for row in grants["grants"] if row["id"] == grant["id"])["subjects"] == ["Selected only"]
        assert call(theirs, GRANTS) == {"grants": [], "audit": []}
        assert all(set(row) == {"integration", "actor", "action", "outcome", "occurred_at"} for row in grants["audit"])
        assert {("owner", "create", "ok"), ("integration", "read", "ok"), ("integration", "draft", "ok"),
                ("integration", "draft", "denied")} <= {(row["actor"], row["action"], row["outcome"]) for row in grants["audit"]}
        assert all(value not in json.dumps(grants) for value in (token, "Visible note", "Suggested reply", fixture.password))
        call(theirs, f"{GRANTS}/{grant['id']}", method="DELETE", status=404)
        call({**ours, "Origin": "https://other.example.test"}, f"{GRANTS}/{grant['id']}", method="DELETE", status=403)

    with fixture.daemon():
        ours, theirs = fixture.login(owner), fixture.login(peer)
        assert use(token, "drafts", draft_body) == ack
        assert call(ours, f"{GRANTS}/{grant['id']}", method="DELETE") == {"revoked": True}
        use(token, "read", {"reference": selected}, 404)
        use(token, "drafts", draft_body, 404)
        assert sql("SELECT payload FROM mail_assistant_grants WHERE id=?", (grant["id"],)) == [("{}",)]
        owner_send = {key: draft_body[key] for key in ("to", "subject", "text")}
        owner_send.update(draftId=ack["draftId"], draftUid=ack["uid"], draftRevision=ack["revision"],
                          sendId=token_hex(16), delaySeconds=0)
        call(ours, "compose", owner_send)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            result = call(theirs, "messages?folder=INBOX&q=Owner+reviews+this+draft")
            if result["total"] == 1:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("The recipient did not receive the owner's reviewed draft")
        assert call(ours, "messages?folder=Drafts")["total"] == 0
        events = call(ours, GRANTS)["audit"]
        assert any(row["actor"] == "owner" and row["action"] == "revoke" and row["outcome"] == "ok" for row in events)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-assistant-grants-") as tmp:
        run(args.binary.resolve(strict=True), Path(tmp))
    print("Verified native assistant consent, scoped reads, draft review, owner delivery, expiry, and revocation.")


if __name__ == "__main__":
    main()
