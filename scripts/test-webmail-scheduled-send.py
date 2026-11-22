#!/usr/bin/env python3
"""Verify scheduled mail against native HTTPS and the durable Outbox."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from email import policy
from email.parser import BytesParser
from pathlib import Path
import runpy
import secrets
import sqlite3
import tempfile
import time
from urllib.parse import urlencode


helpers = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture = helpers["Fixture"]
request = helpers["request"]
YEAR = 365 * 86400


def expect(response, status=200):
    assert response[0] == status, response
    return response[1]


def new_id():
    return secrets.token_hex(16)


def save(test, session, recipient, subject, **fields):
    payload = {"draftId": new_id(), "saveToken": new_id(), "subject": subject, "to": [recipient], **fields}
    saved = expect(test.api(session, "drafts", payload))
    return dict(payload, draftUid=saved["uid"], draftRevision=saved["revision"])


def route(payload):
    return f"outbox/{payload['sendId']}"


def draft(test, session, payload):
    return expect(test.api(session, f"drafts?uid={payload['draftUid']}"))


def verify_boundaries(test, sender, other):
    session = test.login(sender)
    message = {"subject": "Invalid schedules must never send", "to": [other], "text": "Rejected"}
    for when in (int(time.time()) - 1, int(time.time()) + YEAR + 60):
        request_body = {**message, "sendId": new_id(), "scheduleAt": when}
        rejected = expect(test.api(session, "compose", request_body), 400)
        assert rejected["error"] == "invalid_send_schedule", rejected
        expect(test.api(session, route(request_body)), 404)
    request_body = {**message, "scheduleAt": int(time.time()) + 600}
    expect(test.api(session, "compose", request_body), 400)  # Never use synchronous sending here.
    expect(test.api(session, "compose", {**request_body, "sendId": new_id(), "delaySeconds": 0}), 400)
    assert test.count(sender) == 0 and test.bytes(other) == 0


def verify_edit(test, db, sender, other):
    session = test.login(sender)
    other_session = test.login(other)
    attachment = b"scheduled attachment \x00\xff"
    upload_id = new_id()
    query = urlencode({"uploadId": upload_id, "filename": "handoff.bin", "contentType": "application/octet-stream"})
    status, _, response = request(test.webmail + "/webmail/api/uploads?" + query, attachment, session, context=test.tls_context)
    assert status == 200, response
    saved = save(test, session, other, "Original schedule", text="Before editing", attachments=[{"uploadId": upload_id}])
    queued = dict(saved, sendId=new_id(), scheduleAt=int(time.time()) + 3600)

    with db:
        # An interrupted freeze must roll back the new Outbox row, even if it
        # has already been inserted before the draft update runs.
        db.execute("""CREATE TRIGGER fixture_freeze BEFORE UPDATE ON webmail_records
                      WHEN NEW.kind='draft' AND NEW.state='queued'
                      BEGIN SELECT RAISE(ABORT, 'fixture freeze failure'); END""")
    expect(test.api(session, "compose", queued), 500)
    expect(test.api(session, route(queued)), 404)
    assert draft(test, session, saved)["state"] == "saved"
    with db:
        db.execute("DROP TRIGGER fixture_freeze")

    item = expect(test.api(session, "compose", queued))
    assert item["scheduled"] and item["state"] == "pending" and item["dueAt"] == queued["scheduleAt"]
    assert expect(test.api(session, "compose", queued))["id"] == item["id"]
    expect(test.api(session, "compose", dict(queued, scheduleAt=queued["scheduleAt"] + 120)), 409)
    expect(test.api(other_session, route(queued)), 404)
    expect(test.api(other_session, route(queued), method="DELETE"), 404)
    assert draft(test, session, saved)["revision"] == saved["draftRevision"] + 1
    assert draft(test, session, saved)["state"] == "queued"
    assert test.count(sender) == 0 and test.bytes(other) == 0

    with db:
        db.execute("""CREATE TRIGGER fixture_thaw BEFORE UPDATE ON webmail_records
                      WHEN OLD.kind='draft' AND OLD.state='queued' AND NEW.state='saved'
                      BEGIN SELECT RAISE(ABORT, 'fixture thaw failure'); END""")
    expect(test.api(session, route(queued), method="DELETE"), 500)
    assert expect(test.api(session, route(queued)))["state"] == "pending"
    assert draft(test, session, saved)["state"] == "queued"
    with db:
        db.execute("DROP TRIGGER fixture_thaw")

    for _ in range(2):
        paused = expect(test.api(session, route(queued), method="DELETE"))
        assert paused["state"] == "cancelled" and paused["scheduled"]
        assert draft(test, session, saved)["revision"] == saved["draftRevision"] + 2
    assert draft(test, session, saved)["state"] == "saved"
    assert test.count(sender) == 0 and test.bytes(other) == 0
    expect(test.api(session, "drafts", dict(saved, saveToken=new_id(), text="Stale edits")), 409)
    edited = dict(saved, subject="Edited schedule", text="After editing", saveToken=new_id(),
                  draftRevision=saved["draftRevision"] + 2)
    edited["draftRevision"] = expect(test.api(session, "drafts", edited))["revision"]
    edited.update(sendId=new_id(), scheduleAt=int(time.time()) + 5)
    assert expect(test.api(session, "compose", edited))["state"] == "pending"
    assert expect(test.api(session, "compose", queued))["state"] == "cancelled"
    with db:
        db.execute("UPDATE webmail_uploads SET expires_at=1 WHERE username=? AND id=?", (sender, upload_id))
    return edited, attachment


def verify_restart(test, sender, other, edited, attachment):
    # Let the deadline pass while the server is stopped.
    time.sleep(max(0, edited["scheduleAt"] - time.time() + 0.15))
    with test.daemon():
        session = test.login(sender)
        receipt = test.outbox(session, edited["sendId"], "sent")
        assert receipt["scheduled"] and receipt["dueAt"] == edited["scheduleAt"]
        assert expect(test.api(session, "compose", edited))["result"] == receipt["result"]
        expect(test.api(session, "compose", dict(edited, subject="Changed replay")), 409)
        expect(test.api(session, route(edited), method="DELETE"), 409)
        assert test.count(sender) == 1
        inbox, = (test.directory / "mail" / other / "new").glob("*.eml*")
        mail = BytesParser(policy=policy.default).parsebytes(inbox.read_bytes())
        assert mail["Subject"] == edited["subject"]
        assert mail.get_body().get_content().strip() == "After editing"
        file, = mail.iter_attachments()
        assert file.get_filename() == "handoff.bin" and file.get_payload(decode=True) == attachment


def verify_deadline_race(test, sender, other):
    session = test.login(sender)
    deadline = int(time.time()) + 4
    payload = {"sendId": new_id(), "subject": "Race at scheduled deadline", "to": [other], "scheduleAt": deadline}
    expect(test.api(session, "compose", payload))
    before = test.count(sender)

    def cancel(offset):
        time.sleep(max(0, deadline - time.time() + offset))
        return test.api(session, route(payload), method="DELETE")[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(cancel, (-0.025, 0.025)))
    assert set(results) <= {200, 409}, results
    if 200 in results:
        assert results == [200, 200], results
        assert expect(test.api(session, route(payload)))["state"] == "cancelled"
        assert test.count(sender) == before
    else:
        assert test.outbox(session, payload["sendId"], "sent")["scheduled"]
        assert test.count(sender) == before + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-scheduled-send-", dir="/tmp") as directory:
        root = Path(directory)
        test = Fixture(args.binary.resolve(strict=True), root, staging=True)
        with test.daemon(), closing(sqlite3.connect(root / "smtp.db")) as db:
            sender = test.provision("scheduler")
            other = test.provision("recipient")
            verify_boundaries(test, sender, other)
            edited, attachment = verify_edit(test, db, sender, other)
        verify_restart(test, sender, other, edited, attachment)
        with test.daemon():
            verify_deadline_race(test, sender, other)
    print("Verified scheduled-send boundaries, atomic edit and cancellation, account isolation, restart delivery, byte preservation, replay, and deadline races over HTTPS.")


if __name__ == "__main__":
    main()
