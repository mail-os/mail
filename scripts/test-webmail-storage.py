#!/usr/bin/env python3
"""Check hosted compose storage against the real Mail HTTPS listener."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import argparse
import json
from pathlib import Path
import runpy
import secrets
import sqlite3
import subprocess
import sys
import tempfile
from threading import Barrier
import time


suite = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture = suite["Fixture"]
request = suite["request"]
MIB = 1024 * 1024
ATTACHMENT_BYTES = MIB // 4
RESULT_RESERVE = 64 * 1024


def ok(response):
    status, result = response
    assert status == 200, response
    return result


def limited(response, error):
    status, result = response
    assert status == 413 and result["error"] == error, response


def upload(test, session, upload_id, data):
    status, _, raw = request(
        test.webmail + f"/webmail/api/uploads?filename=sample.bin&uploadId={upload_id}",
        data, session, context=test.tls_context,
    )
    return status, json.loads(raw)


def seed_record(db, user, kind, desired_bytes, state, expires=0):
    # Use the legacy shape without a quota column or request digest.
    empty = '{"message":{"text":""}}'
    assert desired_bytes >= len(empty)
    payload = empty.replace('""', '"' + 'x' * (desired_bytes - len(empty)) + '"')
    record_id = secrets.token_hex(16)
    with db:
        db.execute("INSERT INTO webmail_records VALUES (?,?,?,?,?,1,0,?)",
                   (user, kind, record_id, payload, state, expires))
    return record_id


def seed_small_records(db, user, kind, state, count, expires=0):
    with db:
        db.executemany("INSERT INTO webmail_records VALUES (?,?,?,'{\"message\":{}}',?,1,0,?)",
                       ((user, kind, secrets.token_hex(16), state, expires) for _ in range(count)))


def check_uploads(test, db):
    user = test.provision("staged", quota=8 * MIB)
    session = test.login(user)
    part = b"x" * ATTACHMENT_BYTES
    for _ in range(3):
        ok(upload(test, session, secrets.token_hex(16), part))
    barrier = Barrier(2)

    def compete(upload_id):
        barrier.wait(timeout=5)
        return upload(test, session, upload_id, part)

    ids = [secrets.token_hex(16) for _ in range(2)]
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(compete, ids))
    assert sorted(status for status, _ in results) == [200, 413], results
    accepted = ids[0] if results[0][0] == 200 else ids[1]
    ok(upload(test, session, accepted, part))
    limited(upload(test, session, secrets.token_hex(16), b"x"), "staging_limit")
    assert db.execute("SELECT SUM(size) FROM webmail_uploads WHERE username=?", (user,)).fetchone() == (MIB,)
    assert test.bytes(user) == 0
    with db:
        db.executemany("INSERT INTO webmail_uploads(username,id,filename,content_type,data,size,expires_at) VALUES (?,?, 'empty.bin','application/octet-stream',X'',0,?)",
                       ((user, secrets.token_hex(16), int(time.time()) + 1000) for _ in range(124)))
    limited(upload(test, session, secrets.token_hex(16), b""), "staging_limit")
    ok(test.api(session, f"uploads/{accepted}", method="DELETE"))
    replacement = secrets.token_hex(16)
    ok(upload(test, session, replacement, b"x"))

    # Only the structured attachment reference retains a blob. Plain text
    # containing an upload ID has no effect on ownership or retention.
    unreferenced = db.execute("SELECT id FROM webmail_uploads WHERE username=? AND size=? LIMIT 1",
                             (user, ATTACHMENT_BYTES)).fetchone()[0]
    draft = ok(test.api(session, "drafts", {"text": unreferenced, "attachments": [{"uploadId": replacement}]}))
    for upload_id in (unreferenced, replacement):
        ok(test.api(session, f"uploads/{upload_id}", method="DELETE"))
    assert db.execute("SELECT id FROM webmail_uploads WHERE username=? AND id IN (?,?)",
                      (user, unreferenced, replacement)).fetchall() == [(replacement,)]
    assert draft["uid"] > 0 and 0 < test.bytes(user) < ATTACHMENT_BYTES
    return user, replacement


def check_draft_budget(test, db):
    user = test.provision("draft-budget", quota=8 * MIB)
    session = test.login(user)
    initial = {"text": "café", "draftId": secrets.token_hex(16), "saveToken": "one"}
    ack = ok(test.api(session, "drafts", initial))
    ok(test.api(session, "drafts", initial))
    size, = db.execute("SELECT length(CAST(payload AS BLOB)) FROM webmail_records WHERE username=? AND kind='draft'",
                       (user,)).fetchone()
    legacy = seed_record(db, user, "draft", 2 * MIB - size, "saved")
    change = dict(initial, draftUid=ack["uid"], draftRevision=ack["revision"], saveToken="two", text="café!")
    original = list((test.directory / "mail" / user).rglob("*.eml*"))[0]
    before = original.read_bytes()
    limited(test.api(session, "drafts", change), "draft_storage_limit")
    assert original.read_bytes() == before
    assert db.execute("SELECT revision FROM webmail_records WHERE username=? AND id=?",
                      (user, ack["draftId"])).fetchone() == (1,)
    with db:
        db.execute("UPDATE webmail_records SET payload=replace(payload,'xxx\"','xx\"') WHERE id=?", (legacy,))
    saved = ok(test.api(session, "drafts", change))
    assert saved["uid"] == ack["uid"] and original.read_bytes() != before
    assert db.execute("SELECT SUM(length(CAST(payload AS BLOB))) FROM webmail_records WHERE username=? AND kind='draft'",
                      (user,)).fetchone() == (2 * MIB,)
    with db:
        db.execute("DELETE FROM webmail_records WHERE id=?", (legacy,))
    seed_small_records(db, user, "draft", "saved", 199)
    limited(test.api(session, "drafts", {"text": "One more draft"}), "draft_storage_limit")
    assert db.execute("SELECT COUNT(*) FROM imap_uids WHERE username=? AND mailbox='Drafts'", (user,)).fetchone() == (1,)
    assert len(list((test.directory / "mail" / user).rglob("*.eml*"))) == 1


def check_imap_draft_expunges(test, db, sink):
    user = test.provision("expunged-drafts", quota=8 * MIB)
    session = test.login(user)
    released_id, retained_id = (secrets.token_hex(16) for _ in range(2))
    for upload_id in (released_id, retained_id):
        ok(upload(test, session, upload_id, b"expunge attachment"))

    first = ok(test.api(session, "drafts", {
        "text": "Delete this draft", "attachments": [{"uploadId": released_id}],
    }))
    scheduled = {
        "text": "Keep this scheduled message", "to": [sink],
        "attachments": [{"uploadId": retained_id}],
    }
    second = ok(test.api(session, "drafts", scheduled))
    send_id = secrets.token_hex(16)
    queued = dict(scheduled, sendId=send_id, scheduleAt=int(time.time()) + 3600,
                  draftId=second["draftId"], draftUid=second["uid"], draftRevision=second["revision"])
    assert ok(test.api(session, "compose", queued))["state"] == "pending"

    with db:
        seed_small_records(db, user, "draft", "saved", 198)
    limited(test.api(session, "drafts", {"text": "Over capacity"}), "draft_storage_limit")

    with test.imap(user) as client:
        status, count = client.select("Drafts")
        assert status == "OK" and int(count[0]) == 2
        assert client.uid("STORE", str(first["uid"]), "+FLAGS.SILENT", r"(\Deleted)")[0] == "OK"
        assert client.expunge()[0] == "OK"
        assert client.uid("SEARCH", None, "ALL") == ("OK", [str(second["uid"]).encode()])
        assert db.execute("SELECT COUNT(*) FROM webmail_records WHERE username=? AND kind='draft'",
                          (user,)).fetchone() == (199,)
        freed = ok(test.api(session, "drafts", {"text": "Save into the released slot"}))
        assert client.select("Drafts")[0] == "OK"
        assert client.uid("STORE", str(second["uid"]), "+FLAGS.SILENT", r"(\Deleted)")[0] == "OK"
        assert client.close()[0] == "OK"
        assert client.select("Drafts")[0] == "OK"
        assert client.uid("SEARCH", None, "ALL") == ("OK", [str(freed["uid"]).encode()])

    assert db.execute("SELECT COUNT(*) FROM webmail_records WHERE username=? AND kind='draft'",
                      (user,)).fetchone() == (199,)
    for upload_id in (released_id, retained_id):
        ok(test.api(session, f"uploads/{upload_id}", method="DELETE"))
    with db:
        retained = db.execute("SELECT id FROM webmail_uploads WHERE username=?", (user,)).fetchall()
        assert retained == [(retained_id,)]
    assert ok(test.api(session, "compose", queued))["state"] == "pending"
    assert ok(test.api(session, f"outbox/{send_id}", method="DELETE"))["state"] == "cancelled"

    moved, = ok(test.api(session, "bulk", {
        "action": "move", "folder": "Trash", "messages": [{"uid": freed["uid"], "folder": "Drafts"}],
    }))["results"]
    assert moved["ok"] and moved["new_folder"] == "Trash"
    # Interruption after unlink: force the metadata checkpoint to fail.
    with db:
        db.execute(f"""
            CREATE TRIGGER fail_draft_expunge BEFORE DELETE ON webmail_records
            WHEN OLD.kind='draft' AND OLD.id='{freed['draftId']}'
            BEGIN SELECT RAISE(ABORT, 'fixture checkpoint failure'); END
        """)
    try:
        with test.imap(user) as client:
            assert client.select("Trash")[0] == "OK"
            assert client.uid("STORE", str(moved["new_uid"]), "+FLAGS.SILENT", r"(\Deleted)")[0] == "OK"
            assert client.expunge()[0] == "OK"
            assert client.uid("SEARCH", None, "ALL") == ("OK", [b""])
        retained = db.execute("SELECT kind FROM webmail_records WHERE username=? AND id=? ORDER BY kind",
                              (user, freed["draftId"])).fetchall()
        assert retained == [("draft",), ("draft-expunge",)], retained
    finally:
        with db:
            db.execute("DROP TRIGGER fail_draft_expunge")
    return user, freed["draftId"]


def check_outbox_budget(test, db, sink):
    user = test.provision("outbox-budget", quota=8 * MIB)
    session = test.login(user)
    sample = {"text": "Still queued", "to": [sink], "sendId": secrets.token_hex(16), "delaySeconds": 30}
    ok(test.api(session, "compose", sample))
    size, = db.execute("SELECT length(CAST(payload AS BLOB)) FROM webmail_records WHERE id=?",
                       (sample["sendId"],)).fetchone()
    cancelled = ok(test.api(session, f"outbox/{sample['sendId']}", method="DELETE"))
    assert cancelled["state"] == "cancelled" and cancelled["message"]["text"] == sample["text"]
    legacy = seed_record(db, user, "outbox", 2 * MIB - 2 * size - RESULT_RESERVE, "cancelled", int(time.time()) + 1000)
    next_send = dict(sample, sendId=secrets.token_hex(16))
    limited(test.api(session, "compose", dict(next_send, text=next_send["text"] + "!")), "outbox_storage_limit")
    competitors = [next_send, dict(next_send, sendId=secrets.token_hex(16))]
    barrier = Barrier(2)

    def compete(payload):
        barrier.wait(timeout=5)
        return test.api(session, "compose", payload)

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(compete, competitors))
    assert sorted(status for status, _ in results) == [200, 413], results
    accepted = competitors[0] if results[0][0] == 200 else competitors[1]
    ok(test.api(session, "compose", accepted))
    ok(test.api(session, f"outbox/{accepted['sendId']}", method="DELETE"))
    with db:
        db.execute("DELETE FROM webmail_records WHERE id=?", (legacy,))
    seed_small_records(db, user, "outbox", "cancelled", 1022, int(time.time()) + 1000)
    draft = ok(test.api(session, "drafts", {"text": "Still queued", "to": [sink]}))
    draft_route = f"drafts?uid={draft['uid']}"
    one_more = dict(sample, sendId=secrets.token_hex(16), draftId=draft["draftId"],
                    draftUid=draft["uid"], draftRevision=draft["revision"])
    limited(test.api(session, "compose", one_more), "outbox_storage_limit")
    assert ok(test.api(session, draft_route))["state"] == "saved"
    with db:
        db.execute("UPDATE webmail_records SET expires_at=1 WHERE id=?", (sample["sendId"],))
    ok(test.api(session, "compose", one_more))
    assert ok(test.api(session, draft_route))["state"] == "queued"
    ok(test.api(session, f"outbox/{one_more['sendId']}", method="DELETE"))
    assert ok(test.api(session, draft_route))["state"] == "saved"
    assert test.bytes(user) > 0 and test.count(user) == 0


def seed_legacy_drafts(test, db):
    user = test.provision("legacy-drafts", quota=8 * MIB)
    session = test.login(user)
    gone, moved, live = [
        ok(test.api(session, "drafts", {"text": text}))
        for text in ("Previously deleted", "Moved by a mail client", "Still in Drafts")
    ]
    with test.imap(user) as client:
        assert client.create("Recovered")[0] == "OK"
        assert client.select("Drafts")[0] == "OK"
        assert client.uid("MOVE", str(moved["uid"]), "Recovered")[0] == "OK"
    filename, = db.execute("SELECT filename FROM imap_uids WHERE username=? AND mailbox='Drafts' AND uid=?",
                           (user, gone["uid"])).fetchone()
    return user, filename, gone["draftId"], moved["draftId"], live["draftId"]


def seed_empty_legacy_mailbox(test):
    user = test.provision("legacy-empty", quota=8 * MIB)
    draft = ok(test.api(test.login(user), "drafts", {"text": "Previously deleted with no remaining UID"}))
    return user, draft["draftId"], draft["uid"]


def recover_drafts_command(test, user):
    return [
        sys.executable, str(Path(__file__).with_name("recover-orphaned-webmail-drafts.py")),
        "--database", str(test.directory / "smtp.db"),
        "--mail-root", str(test.directory / "mail"), "--mailbox", user,
    ]


def check_legacy_recovery(test, fixture):
    user, filename, gone, moved, live = fixture
    draft_path, = (test.directory / "mail" / user / "Drafts").glob(filename + "*")
    draft_path.unlink()
    database = test.directory / "smtp.db"
    command = recover_drafts_command(test, user)
    assert json.loads(subprocess.check_output(command)) == {"mode": "report", "draftIds": [gone]}
    with closing(sqlite3.connect(database)) as db:
        assert db.execute("SELECT COUNT(*) FROM webmail_records WHERE username=? AND kind='draft'",
                          (user,)).fetchone() == (3,)
    assert json.loads(subprocess.check_output([*command, "--apply"])) == {"mode": "applied", "draftIds": [gone]}
    assert json.loads(subprocess.check_output([*command, "--apply"])) == {"mode": "applied", "draftIds": []}
    with closing(sqlite3.connect(database)) as db:
        ids = db.execute("SELECT id FROM webmail_records WHERE username=? AND kind='draft'", (user,)).fetchall()
        assert set(ids) == {(moved,), (live,)}
    print("Verified recovery of a legacy orphan while preserving drafts in their original and moved folders.")


def check_legacy_without_uid(test, fixture):
    user, draft_id, uid = fixture
    draft_path, = (test.directory / "mail" / user / "Drafts").glob("*.eml*")
    draft_path.unlink()
    with closing(sqlite3.connect(test.directory / "smtp.db")) as db, db:
        deleted = db.execute("DELETE FROM imap_uids WHERE username=? AND mailbox='Drafts' AND uid=?", (user, uid))
        assert deleted.rowcount == 1
    command = recover_drafts_command(test, user)
    assert json.loads(subprocess.check_output(command)) == {"mode": "report", "draftIds": [draft_id]}
    assert json.loads(subprocess.check_output([*command, "--apply"])) == {"mode": "applied", "draftIds": [draft_id]}


def check_delivery_receipts(test, db, sink):
    user = test.provision("receipts", quota=8 * MIB)
    session = test.login(user)
    upload_id = secrets.token_hex(16)
    ok(upload(test, session, upload_id, b"example attachment"))
    message = {"to": [sink], "text": "Delivery result", "sendId": secrets.token_hex(16), "delaySeconds": 0,
               "attachments": [{"uploadId": upload_id}]}
    ok(test.api(session, "compose", message))
    sent = test.outbox(session, message["sendId"], "sent")
    assert sent["result"]["delivered"] == 1 and sent["message"]["attachments"] == []
    ok(test.api(session, f"uploads/{upload_id}", method="DELETE"))
    assert db.execute("SELECT COUNT(*) FROM webmail_uploads WHERE id=?", (upload_id,)).fetchone() == (0,)
    assert ok(test.api(session, "compose", message))["state"] == "sent"
    assert test.api(session, "compose", dict(message, text="Different"))[0] == 409
    assert test.count(user) == 1 and test.bytes(sink) > 0 and test.bytes(user) > 0

    pending_id, upload_id = secrets.token_hex(16), secrets.token_hex(16)
    ok(upload(test, session, upload_id, b"preserve this upload"))
    ok(test.api(session, "compose", dict(message, sendId=pending_id, delaySeconds=30,
                                          attachments=[{"uploadId": upload_id}])))
    with db:
        db.execute("UPDATE webmail_records SET state='sending',expires_at=1 WHERE id=?", (pending_id,))
        db.execute("UPDATE webmail_uploads SET expires_at=1 WHERE id=?", (upload_id,))
    return user, pending_id, upload_id, message


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-webmail-storage-") as root:
        test = Fixture(args.binary.resolve(), Path(root), staging=True)
        test.env.update(SMTP_MAX_MESSAGE_SIZE=str(MIB), SMTP_WEBMAIL_ATTACHMENT_MAX_TOTAL=str(ATTACHMENT_BYTES))
        with test.daemon(), closing(sqlite3.connect(Path(root) / "smtp.db")) as db:
            sink = test.provision("sink", quota=8 * MIB)
            staged_user, referenced_id = check_uploads(test, db)
            check_draft_budget(test, db)
            expunged_user, expunged_id = check_imap_draft_expunges(test, db, sink)
            legacy_drafts = seed_legacy_drafts(test, db)
            empty_legacy = seed_empty_legacy_mailbox(test)
            check_outbox_budget(test, db, sink)
            receipts_user, interrupted, upload_id, delivered = check_delivery_receipts(test, db, sink)
            print("Verified exact upload, draft and Outbox byte budgets, one byte over, record counts, and concurrent winners.")
            print("Verified draft replacement, cancellation, compact successful receipts, and send ID replay.")

        check_legacy_recovery(test, legacy_drafts)
        check_legacy_without_uid(test, empty_legacy)
        with test.daemon(), closing(sqlite3.connect(Path(root) / "smtp.db")) as db:
            assert db.execute("SELECT COUNT(*) FROM webmail_records WHERE username=? AND id=?",
                              (expunged_user, expunged_id)).fetchone() == (0,)
            print("Verified IMAP EXPUNGE, CLOSE, and interrupted draft expunge recovery across restart.")
            session = test.login(receipts_user)
            assert ok(test.api(session, "compose", delivered))["state"] == "sent"
            assert test.count(receipts_user) == 1
            unknown = test.outbox(session, interrupted, "unknown")
            assert unknown["message"]["attachments"][0]["uploadId"] == upload_id
            assert db.execute("SELECT COUNT(*) FROM webmail_uploads WHERE id=?", (upload_id,)).fetchone() == (1,)
            resolved = ok(test.api(session, f"outbox/{interrupted}", {"reviewed": True}, method="PATCH"))
            assert resolved["state"] == "resolved" and resolved["message"]["text"] == unknown["message"]["text"]
            assert ok(test.api(session, f"outbox/{interrupted}", {"reviewed": True}, method="PATCH"))["state"] == "resolved"
            with db:
                db.execute("UPDATE webmail_records SET expires_at=1 WHERE id=?", (interrupted,))

        subprocess.run([str(test.binary), "user:local", "delete", staged_user], env=test.env, cwd=root, check=True)
        with test.daemon(), closing(sqlite3.connect(Path(root) / "smtp.db")) as db:
            assert db.execute("SELECT COUNT(*) FROM webmail_records WHERE id=? OR username=?",
                              (interrupted, staged_user)).fetchone() == (0,)
            assert db.execute("SELECT COUNT(*) FROM webmail_uploads WHERE id IN (?,?)",
                              (upload_id, referenced_id)).fetchone() == (0,)
            print("Verified retained Unknown payloads, expiry after review, attachment reference release, and account removal across restart.")


if __name__ == "__main__":
    main()
