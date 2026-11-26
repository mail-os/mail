#!/usr/bin/env python3
"""Remove one reserved owner's DAV resources using the real TLS DAV service."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import runpy
import sqlite3
from tempfile import TemporaryDirectory
import time

scripts = Path(__file__).resolve().parent
operator = runpy.run_path(str(scripts / "test-hosted-operator.py"))
portable = runpy.run_path(str(scripts / "test-mailbox-export.py"))
Fixture, cli = (operator[key] for key in ("Fixture", "cli"))
DavClient, put_dav, EVENT, CARD = (portable[key] for key in ("DavClient", "put_dav", "EVENT", "CARD"))
CARD = CARD.replace(b"END:VCARD", b"TEL;TYPE=WORK:+15550102030\r\nEND:VCARD")
TABLES = (
    "dav_users", "dav_calendars", "dav_addressbooks", "dav_events", "dav_contacts",
    "dav_emails", "dav_phones", "dav_reminder_dismissals",
)


def success(result):
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def prepare(test, name, path, *, historical=False):
    mailbox = test.provision(name, enabled=False)
    actor = test.specs[mailbox]["actor"]
    case = f"{name}-review"
    inventory = success(cli(test, "hosted-erasure-inventory", mailbox, actor, case))
    if historical:
        with closing(sqlite3.connect(test.directory / "smtp.db")) as db, db:
            db.execute("""UPDATE audit_log SET details=json_remove(details,'$.inventory.dav.store_stamp','$.inventory.dav.owner_id')
                          WHERE id=?""", (inventory["audit_id"],))
    review = {
        "version": 1, "request_id": f"{name}-request", "mailbox": mailbox, "assignment_actor": actor,
        "case_reference": case, "inventory_audit_id": inventory["audit_id"],
        "retention_disposition": "cleared", "export_disposition": "not_requested",
        "evidence": dict.fromkeys(("authorization_reference", "retention_reference", "backup_reference",
                                   "billing_reference", "search_reference", "export_resolution_reference"), "fixture-case"),
    }
    path.write_text(json.dumps(review))
    path.chmod(0o600)
    approved = success(cli(test, "hosted-erasure-review", str(path)))
    started = success(cli(test, "hosted-erasure-begin", str(path), str(approved["audit_id"])))
    return mailbox, inventory["inventory"]["dav"], started["audit_id"]


def create_resources(test, mailbox):
    client = DavClient(test, mailbox)
    event = f"/calendars/{mailbox}/Calendar/item.ics"
    card = f"/addressbooks/{mailbox}/Contacts/item.vcf"
    put_dav(client, event, "text/calendar", EVENT)
    put_dav(client, card, "text/vcard", CARD)
    return client, event, card


def snapshot(db):
    return {table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall() for table in TABLES}


def verify(test):
    dav_path = test.directory / "caldav.db"
    database = test.directory / "smtp.db"
    path = test.directory / "review.json"
    with test.daemon():
        peer = test.provision("keep-dav")
        mailbox = test.provision("erase-dav")
        peer_dav, peer_event, peer_card = create_resources(test, peer)

        with closing(sqlite3.connect(dav_path)) as dav:
            peer_owner = dav.execute("SELECT id FROM dav_users WHERE username=?", (peer,)).fetchone()[0]
            with dav:
                dav.execute("INSERT INTO dav_reminder_dismissals VALUES (?, 'peer-marker', ?)",
                            (peer_owner, int(time.time()) + 3600))
            peer_rows = snapshot(dav)

        target_dav, target_event, _ = create_resources(test, mailbox)
        assert target_dav.request("GET", target_event)[0] == 200
        with closing(sqlite3.connect(dav_path)) as dav, dav:
            owner = dav.execute("SELECT id FROM dav_users WHERE username=?", (mailbox,)).fetchone()[0]
            dav.execute("INSERT INTO dav_reminder_dismissals VALUES (?, 'target-marker', ?)",
                        (owner, int(time.time()) + 3600))

        mailbox, reviewed_dav, start = prepare(test, "erase-dav", path)
        assert reviewed_dav["owner_id"] == owner and reviewed_dav["store_stamp"]
        assert set(row["matching_rows"] for row in reviewed_dav["tables"]) == {1}
        assert reviewed_dav["legacy_name_candidates"] == 0

        def erase(*, confirmed=dav_path, env=None):
            return cli(test, "hosted-erasure-dav", str(path), str(start), str(confirmed), env=env)

        def refuse(error=None, **kwargs):
            result = erase(**kwargs)
            assert result.returncode and not result.stdout and (error is None or error in result.stderr), result

        refuse("MaildirWriterActive")

    with closing(sqlite3.connect(database)) as db, closing(sqlite3.connect(dav_path)) as dav:
        def journal():
            return db.execute("""SELECT nonce,completion_audit_id FROM hosted_erasure_dav_steps
                                 WHERE start_audit_id=?""", (start,)).fetchone()

        before = snapshot(dav)
        assert all(len(before[table]) == len(peer_rows[table]) + 1 for table in TABLES)
        refuse("ErasureMaildirPending")
        success(cli(test, "hosted-erasure-maildir", str(path), str(start)))

        copy = test.directory / "different-dav.db"
        with closing(sqlite3.connect(copy)) as backup:
            dav.backup(backup)
        refuse("ErasureDavPathMismatch", confirmed=copy)
        refuse("ErasureDavFileChanged", confirmed=copy, env=dict(test.env, CALDAV_DB_PATH=str(copy)))
        link = test.directory / "linked-dav.db"
        link.symlink_to(dav_path)
        refuse(confirmed=link, env=dict(test.env, CALDAV_DB_PATH=str(link)))
        link.unlink()
        assert not journal() and snapshot(dav) == before

        with dav:
            dav.execute("CREATE TABLE dav_unresolved(user_id INTEGER)")
        refuse("ErasureDavSchemaUnresolved")
        with dav:
            dav.execute("DROP TABLE dav_unresolved")
            dav.execute("INSERT INTO dav_users(id,username) VALUES (9000,?)", (mailbox.split("@")[0],))
        refuse("ErasureDavOwnerUnresolved")
        with dav:
            dav.execute("DELETE FROM dav_users WHERE id=9000")
            dav.execute("DELETE FROM dav_reminder_dismissals WHERE user_id=?", (owner,))
        refuse("InventoryChanged")
        with dav:
            dav.execute("INSERT INTO dav_reminder_dismissals VALUES (?,?,?)", before["dav_reminder_dismissals"][-1])
            dav.execute("""CREATE TRIGGER skip_dav_child BEFORE DELETE ON dav_phones
                           BEGIN SELECT RAISE(IGNORE); END""")
        refuse("ErasureDavRecordsRemain")
        nonce, completion = journal()
        assert completion is None and snapshot(dav) == before
        assert not dav.execute("SELECT 1 FROM dav_erasure_receipts").fetchone()

        with dav:
            dav.execute("DROP TRIGGER skip_dav_child")
            dav.execute("""CREATE TRIGGER interrupt_dav_delete BEFORE DELETE ON dav_events
                           BEGIN SELECT RAISE(ABORT,'interrupted DAV delete'); END""")
        refuse("StepFailed")
        assert journal() == (nonce, None) and snapshot(dav) == before
        assert not dav.execute("SELECT 1 FROM dav_erasure_receipts").fetchone()
        with dav:
            dav.execute("DROP TRIGGER interrupt_dav_delete")

        with db:
            db.execute("""CREATE TRIGGER interrupt_dav_audit BEFORE INSERT ON audit_log
                          WHEN NEW.action='hosted.erasure.dav.removed'
                          BEGIN SELECT RAISE(ABORT,'interrupted after DAV commit'); END""")
        refuse("StepFailed")
        assert snapshot(dav) == peer_rows and journal() == (nonce, None)
        marks = dav.execute("""SELECT max_owner,max_calendar,max_event,max_book,max_contact
                               FROM dav_erasure_receipts WHERE nonce=?""", (nonce,)).fetchone()
        assert marks == tuple(max(row[0] for row in before[table]) for table in
                              ("dav_users", "dav_calendars", "dav_events", "dav_addressbooks", "dav_contacts"))
        with db:
            db.execute("DROP TRIGGER interrupt_dav_audit")

        receipt = success(erase())
        assert receipt == {
            "version": 1, "state": "dav_owned_data_removed_other_stores_pending", "mailbox": mailbox,
            "request_id": "erase-dav-request", "start_audit_id": start, "audit_id": receipt["audit_id"],
            "dav_owner_id": owner,
        }, receipt
        assert journal() == (nonce, receipt["audit_id"])
        assert success(erase()) == receipt
        assert db.execute("SELECT count(*) FROM audit_log WHERE action='hosted.erasure.dav.removed'").fetchone() == (1,)

        with dav:
            dav.execute("INSERT INTO dav_users VALUES (?,?,?)", before["dav_users"][-1])
        refuse("ErasureDavRecordsRemain")
        with dav:
            dav.execute("DELETE FROM dav_users WHERE id=?", (owner,))
        assert success(erase()) == receipt

    with test.daemon():
        assert peer_dav.request("GET", peer_event)[0] == 200
        assert peer_dav.request("GET", peer_card)[0] == 200
        assert target_dav.request("GET", target_event)[0] == 401
        newcomer = test.provision("new-dav")
        create_resources(test, newcomer)
        with closing(sqlite3.connect(dav_path)) as dav:
            for table, existing_mark in zip(
                ("dav_users", "dav_calendars", "dav_events", "dav_addressbooks", "dav_contacts"), marks
            ):
                assert dav.execute(f"SELECT max(id) FROM {table}").fetchone()[0] > existing_mark


def verify_historical(test):
    path = test.directory / "old-review.json"
    with test.daemon():
        mailbox, reviewed, start = prepare(test, "no-dav-owner", path, historical=True)
        assert reviewed["state"] == "no_owner"
    success(cli(test, "hosted-erasure-maildir", str(path), str(start)))
    result = success(cli(test, "hosted-erasure-dav", str(path), str(start), test.env["CALDAV_DB_PATH"]))
    assert result["mailbox"] == mailbox and result["dav_owner_id"] is None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    for check in (verify, verify_historical):
        with TemporaryDirectory(prefix="mail-erase-dav-") as directory:
            check(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Verified scoped DAV erasure, independent rollback, paired retry receipts, and ID watermarks after restart.")
