#!/usr/bin/env python3
"""Verify fixed share links over native HTTPS with disposable mailboxes."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from email.policy import SMTP
import hashlib
import json
from pathlib import Path
import runpy
import sqlite3
import tempfile
import time


fixture_tools = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture, request = fixture_tools["Fixture"], fixture_tools["request"]
LINKS = "snapshot-links"


def append(imap, address, subject, content, *, is_html=False, folder="INBOX", replies=False):
    message = EmailMessage()
    message["Subject"], message["From"], message["To"] = subject, "Sender <sender@example.test>", address
    message["Bcc"] = "private-recipient@example.test"
    if replies:
        message["In-Reply-To"] = "<snapshot-original@example.test>"
        message["References"] = "<snapshot-original@example.test>"
    elif subject == "Original message":
        message["Message-ID"] = "<snapshot-original@example.test>"
    message.set_content(content, subtype="html" if is_html else "plain")
    if subject == "Original message":
        message.add_attachment(b"private attachment", maintype="application", subtype="octet-stream", filename="private.bin")
    assert imap.append(folder, None, None, message.as_bytes(policy=SMTP))[0] == "OK"


def verify(fixture):
    def call(session, path, payload=None, *, method=None, status=200):
        actual, data = fixture.api(session, path, payload, method)
        assert actual == status, (path, actual, data)
        return data

    def view(token, expected_status=200):
        status, headers, raw = request(fixture.webmail + "/webmail/public/snapshot", {"token": token},
                                       {"Origin": fixture.webmail}, context=fixture.tls_context)
        assert status == expected_status, (status, raw)
        assert headers["Cache-Control"] == "no-store" and "Set-Cookie" not in headers
        return json.loads(raw)

    with fixture.daemon():
        owner, peer = fixture.provision("snapshot-owner"), fixture.provision("snapshot-peer")
        session, other = fixture.login(owner), fixture.login(peer)
        with fixture.imap(owner) as imap:
            assert imap.create("Drafts")[0] == "OK"
            append(imap, owner, "Original message", "The reader will see this text.\n<script>Plain text only</script>")
            append(imap, owner, "Formatted message", '<p>Formatted body</p><script>never shown</script><img src="https://external.example.test/track">', is_html=True)
            append(imap, owner, "Too much text", "x\n" * 70_000)
            append(imap, owner, "Open draft", "Unfinished work.", folder="Drafts")
        with fixture.imap(peer) as imap:
            append(imap, peer, "Peer message", "Private to the peer.")

        rows = {item["subject"]: item["reference"] for item in call(session, "messages?conversations=false")["items"]}
        draft = call(session, "messages?folder=Drafts")["items"][0]["reference"]
        peer_ref = call(other, "messages?conversations=false")["items"][0]["reference"]
        selection = {"references": [rows["Original message"], rows["Formatted message"]]}
        call({}, LINKS, status=401)
        call({}, LINKS + "/preview", selection, status=401)
        call({**session, "Origin": "https://cross.example.test"}, LINKS + "/preview", selection, status=403)
        call(session, LINKS + "/preview", {"references": [peer_ref]}, status=404)
        call(session, LINKS + "/preview", {"references": [draft]}, status=404)
        call(session, LINKS + "/preview", {"references": [rows["Too much text"]]}, status=413)
        for invalid in ([], ["not-a-reference"], [rows["Original message"]] * 2, [rows["Original message"]] * 11):
            call(session, LINKS + "/preview", {"references": invalid}, status=400)
        preview = call(session, LINKS + "/preview", selection)
        assert call(session, LINKS) == {"links": []}, "Preview must not create a share"
        assert [item["subject"] for item in preview["messages"]] == ["Original message", "Formatted message"]
        assert set(preview["messages"][0]) == {"subject", "from", "timestamp", "text"}
        assert "<script>Plain text only</script>" in preview["messages"][0]["text"]
        assert preview["messages"][1]["text"] == "Formatted body"
        assert "private-recipient" not in str(preview) and "private.bin" not in str(preview)
        creation = {**selection, "digest": preview["digest"], "lifetime": 3600}
        call(session, LINKS, {**creation, "lifetime": 3601}, status=400)
        call(session, LINKS, {**creation, "digest": "0" * 64}, status=409)
        call(session, LINKS, {**creation, "references": selection["references"][::-1]}, status=409)
        issued = call(session, LINKS, creation, status=201)
        link, token = issued["link"], issued["token"]
        assert len(token) == 64 and int(token, 16)
        assert abs(link["expires_at"] - time.time() - 3600) < 10
        frozen = view(token)
        assert frozen == {"messages": preview["messages"], "expires_at": link["expires_at"]}
        assert call(other, LINKS) == {"links": []}
        call(other, f"{LINKS}/{link['id']}", method="DELETE", status=404)
        call({**session, "Origin": "https://cross.example.test"}, f"{LINKS}/{link['id']}", method="DELETE", status=403)
        assert call(session, LINKS) == {"links": [link]}
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            assert db.execute("SELECT token_hash FROM mail_snapshot_links WHERE id=?", (link["id"],)).fetchone() == (hashlib.sha256(token.encode()).hexdigest(),)

        with fixture.imap(owner) as imap:
            append(imap, owner, "Later reply", "Snapshot readers must never see this.", replies=True)
            assert imap.select("INBOX")[0] == "OK"
            result, messages = imap.search(None, "HEADER", "Message-ID", "<snapshot-original@example.test>")
            assert result == "OK" and messages[0]
            assert imap.store(messages[0], "+FLAGS", r"(\Deleted)")[0] == "OK"
            assert imap.expunge()[0] == "OK"
        assert view(token) == frozen

    with fixture.daemon():
        session = fixture.login(owner)
        assert view(token) == frozen
        assert call(session, f"{LINKS}/{link['id']}", method="DELETE") == {"revoked": True}
        unavailable = view(token, 404)
        assert view("0" * 64, 404) == unavailable == view("malformed", 404)
        assert call(session, LINKS) == {"links": []}
        selection = {"references": [rows["Formatted message"]]}
        preview = call(session, LINKS + "/preview", selection)
        creation = {**selection, "digest": preview["digest"], "lifetime": 86400}
        expired = call(session, LINKS, creation, status=201)
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            db.execute("UPDATE mail_snapshot_links SET expires_at=? WHERE id=?", (int(time.time()), expired["link"]["id"]))
        assert view(expired["token"], 404) == unavailable
        assert call(session, LINKS) == {"links": []}

        # Populate the list to one below the limit, then race the two final writes.
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            db.execute("""
                WITH RECURSIVE copies(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM copies WHERE n<19)
                INSERT INTO mail_snapshot_links(user_id,token_hash,payload,subject,message_count,expires_at)
                SELECT users.id, printf('%064x',copies.n+10),'[]','Existing snapshot',1,? FROM copies,users WHERE users.username=?
            """, (int(time.time()) + 3600, owner))

        def issue(_):
            return fixture.api(session, LINKS, creation)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(issue, (0, 1)))
        assert sorted(status for status, _ in results) == [201, 409], results
        last = next(result for status, result in results if status == 201)
        assert last["link"]["id"] != link["id"]
        assert len(call(session, LINKS)["links"]) == 20
        fixture.provision("snapshot-owner", enabled=False)
        assert view(last["token"], 404) == unavailable
        call(session, LINKS, status=401)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-snapshot-links-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Snapshot link API verification passed.")


if __name__ == "__main__":
    main()
