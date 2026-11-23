#!/usr/bin/env python3
"""Verify reviewed batch replies through real HTTPS, IMAP, and local delivery."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
import runpy
import secrets
import sqlite3
import tempfile
import time


Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]
BATCHES = "reply-batches"


def append(imap, owner, sender, subject, message_id, *, reply_to=None, folder="INBOX"):
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = sender, owner, subject
    if message_id:
        message["Message-ID"] = f"<{message_id}@example.test>"
    if reply_to:
        message["Reply-To"] = reply_to
    message["Bcc"] = "hidden@example.test"
    message["References"] = "<parent@example.test>"
    message.set_content("Original private text.")
    assert imap.append(folder, None, None, message.as_bytes(policy=policy.SMTP))[0] == "OK"


def delivered(imap, subject):
    assert imap.select("INBOX")[0] == "OK"
    status, result = imap.search(None, "SUBJECT", f'"{subject}"')
    assert status == "OK" and len(result[0].split()) == 1, (subject, result)
    status, result = imap.fetch(result[0], "(BODY.PEEK[])")
    assert status == "OK"
    return BytesParser(policy=policy.default).parsebytes(result[0][1])


def verify(fixture):
    def call(session, path, payload=None, *, method=None, status=200):
        actual, data = fixture.api(session, path, payload, method)
        assert actual == status, (path, actual, data)
        return data

    with fixture.daemon():
        owner = fixture.provision("batch-owner", daily=2)
        first, second, outsider = (fixture.provision(name) for name in ("batch-first", "batch-second", "batch-outsider"))
        session, other = fixture.login(owner), fixture.login(outsider)
        with fixture.imap(owner) as imap:
            append(imap, owner, f'"First, Team" <{first}>', "First topic", "batch-first")
            append(imap, owner, first, "Second topic", "batch-second", reply_to=second)
            append(imap, owner, first, "Message without ID", None)
            append(imap, owner, first, "Copy of first", "batch-first")
            append(imap, owner, first, "Ambiguous reply address", "batch-ambiguous", reply_to=f"{first}, {second}")
            for index in range(21):
                append(imap, owner, first, f"Selection {index}", f"batch-selection-{index}")
        with fixture.imap(outsider) as imap:
            append(imap, outsider, first, "Other account", "batch-other")

        refs = {item["subject"]: item["reference"] for item in call(session, "messages?conversations=false")["items"]}
        other_ref = call(other, "messages?conversations=false")["items"][0]["reference"]
        selection = {"references": [refs["First topic"], refs["Second topic"]]}
        call({}, BATCHES + "/preview", selection, status=401)
        call({**session, "Origin": "https://foreign.example.test"}, BATCHES + "/preview", selection, status=403)
        call({**session, "X-Webmail-Account": outsider}, BATCHES + "/preview", selection, status=409)
        call(session, BATCHES + "/preview", {"references": [other_ref]}, status=404)
        boundary = [refs[f"Selection {index}"] for index in range(21)]
        assert len(call(session, BATCHES + "/preview", {"references": boundary[:20]})["replies"]) == 20
        for invalid in ([], [refs["First topic"]] * 2, boundary, [refs["First topic"], refs["Copy of first"]]):
            call(session, BATCHES + "/preview", {"references": invalid}, status=400)
        for subject in ("Message without ID", "Ambiguous reply address"):
            call(session, BATCHES + "/preview", {"references": [refs[subject]]}, status=422)

        preview = call(session, BATCHES + "/preview", selection)
        assert preview["account"] == preview["from"] == owner
        assert preview["replies"] == [
            {"reference": refs["First topic"], "to": first, "subject": "Re: First topic"},
            {"reference": refs["Second topic"], "to": second, "subject": "Re: Second topic"},
        ]
        assert "hidden@" not in str(preview)
        payload = {**selection, "batchId": secrets.token_hex(16), "digest": preview["digest"],
                   "text": "Thanks for the update.", "delaySeconds": 0}
        call(session, f"{BATCHES}/{payload['batchId']}", status=404)
        for change in ({"text": "   "}, {"text": "é" * (128 * 1024 + 1)}, {"delaySeconds": 31}):
            call(session, BATCHES, {**payload, **change}, status=400)
        call(session, BATCHES, {**payload, "digest": "0" * 64}, status=409)
        call(session, BATCHES, {**payload, "references": selection["references"][::-1]}, status=409)

        # Only one Outbox slot remains. Neither reply nor the receipt may be inserted.
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            db.execute("""
                WITH RECURSIVE entries(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM entries WHERE n<1023)
                INSERT INTO webmail_records(username,kind,id,payload,state,revision,expires_at)
                SELECT ?,'outbox',printf('capacity-%d',n),'{}','sent',1,? FROM entries
            """, (owner, int(time.time()) + 3600))
        failed = call(session, BATCHES, payload, status=413)
        assert failed["error"] == "outbox_storage_limit", failed
        call(session, f"{BATCHES}/{payload['batchId']}", status=404)
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            assert db.execute("SELECT count(*) FROM webmail_records WHERE kind='outbox'").fetchone() == (1023,)
            db.execute("DELETE FROM webmail_records WHERE id LIKE 'capacity-%'")

        with ThreadPoolExecutor(max_workers=2) as pool:
            receipt, replay = list(pool.map(lambda _: call(session, BATCHES, payload), range(2)))
        assert replay == receipt and len(set(receipt["sends"])) == 2
        call(other, f"{BATCHES}/{receipt['id']}", status=404)
        call(session, BATCHES, {**payload, "text": "A changed reply."}, status=409)
        for send_id in receipt["sends"]:
            assert fixture.outbox(session, send_id, "sent")["result"]["delivered"] == 1
        assert fixture.count(owner) == 2
        for address, subject, source in ((first, "Re: First topic", "batch-first"), (second, "Re: Second topic", "batch-second")):
            with fixture.imap(address) as imap:
                message = delivered(imap, subject)
                assert message["From"].addresses[0].addr_spec == owner
                assert [item.addr_spec for item in message["To"].addresses] == [address]
                assert message["Cc"] is None and message["Bcc"] is None
                assert message["In-Reply-To"] == f"<{source}@example.test>"
                assert message["References"] == f"<parent@example.test> <{source}@example.test>"
                assert message.get_body().get_content().strip() == payload["text"]

        rows = call(session, "messages?conversations=false")["items"]
        assert all(item["flags"]["answered"] for item in rows if item["subject"] in {"First topic", "Second topic"})
        sent = call(session, "messages?folder=Sent&conversations=false")["items"]
        assert {item["subject"] for item in sent} == {"Re: First topic", "Re: Second topic"}

        # Undo Send cancels one member without bypassing the shared allowance for the other.
        exhausted = call(session, BATCHES, {**payload, "batchId": secrets.token_hex(16), "delaySeconds": 4})
        cancelled, limited = exhausted["sends"]
        assert call(session, f"outbox/{cancelled}", method="DELETE")["state"] == "cancelled"
        assert "Daily recipient allowance" in fixture.outbox(session, limited, "failed")["error"]
        assert fixture.count(owner) == 2

        with fixture.imap(owner) as imap:
            assert imap.select("INBOX")[0] == "OK"
            status, messages = imap.search(None, "HEADER", "Message-ID", "<batch-second@example.test>")
            assert status == "OK" and messages[0]
            assert imap.store(messages[0], "+FLAGS", r"(\Deleted)")[0] == "OK"
            assert imap.expunge()[0] == "OK"

    with fixture.daemon():
        session = fixture.login(owner)
        assert call(session, f"{BATCHES}/{receipt['id']}") == receipt
        assert call(session, BATCHES, payload) == receipt
        assert fixture.count(owner) == 2
        call(session, BATCHES, {**payload, "batchId": secrets.token_hex(16)}, status=404)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-reply-batch-") as directory:
        verify(Fixture(args.binary.resolve(), Path(directory), staging=True))
    print("Batch reply preview, isolation, atomic admission, separate delivery, cancellation, and durable retry passed.")
