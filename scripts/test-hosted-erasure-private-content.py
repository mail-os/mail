#!/usr/bin/env python3
"""Verify offline private-content erasure using two hosted mailboxes over TLS."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import runpy
import sqlite3
from tempfile import TemporaryDirectory

scripts = Path(__file__).resolve().parent
fixture = runpy.run_path(str(scripts / "test-hosted-erasure-dav.py"))
Fixture, cli, prepare, success = (fixture[key] for key in ("Fixture", "cli", "prepare", "success"))
expect_smtp = runpy.run_path(str(scripts / "test-hosted-operator.py"))["expect_smtp"]
MARKER = "synthetic-private-content-7dfebbc5"


def verify(test):
    review = test.directory / "review.json"
    decision = test.directory / "decision.json"
    database = test.directory / "smtp.db"
    maildir = "hosted-erasure-maildir"
    search = "hosted-erasure-search"
    sqlite = "hosted-erasure-sqlite"
    shared = "hosted-erasure-shared-sqlite"
    links = "hosted-erasure-links"
    private = "hosted-erasure-private-content"

    def api(session, route, data=None, *, expected=200):
        status, body = test.api(session, route, data)
        assert status == expected, (route, status, body)
        return body

    def step(command=private, *args):
        return cli(test, command, str(review), str(start), *map(str, args))

    def refuse(error, command=private):
        result = step(command)
        assert result.returncode != 0 and not result.stdout and error in result.stderr, result

    def note(session, subject, marker):
        message, = [row for row in api(session, "messages?conversations=false")["items"]
                    if row["subject"] == subject]
        reference = message["reference"]
        message = api(session, "messages/ref/" + reference)
        api({**session, "If-Match": message["revision"]}, "private/message",
            {"reference": reference, "action": "note", "body": marker})
        return reference

    with test.daemon():
        owner, peer = [test.provision(name) for name in ("erase-private", "keep-private")]
        owner_session, peer_session = (test.login(mailbox) for mailbox in (owner, peer))
        for mailbox, subject in ((owner, "Private message"), (owner, "Pinned message"), (peer, "Peer message")):
            expect_smtp(test.deliver(mailbox, subject=subject), 250)
        removed_reference = note(owner_session, "Private message", MARKER)
        pinned_reference = note(owner_session, "Pinned message", MARKER)
        peer_reference = note(peer_session, "Peer message", "Peer note")
        draft = api(owner_session, "drafts", {"subject": "Private draft", "text": MARKER})
        peer_draft = api(peer_session, "drafts", {"subject": "Peer draft", "text": "Peer content"})
        with closing(sqlite3.connect(database)) as db, db:
            owner_id, peer_id = [db.execute("SELECT id FROM users WHERE username=?", (mailbox,)).fetchone()[0]
                                 for mailbox in (owner, peer)]
            payload = {"message": {"sharedReply": {"sourceId": str(peer_id)},
                                   "attachments": [{"uploadId": "protected-upload"}]}}
            db.executemany(
                """INSERT INTO webmail_records(username,kind,id,payload,state,revision) VALUES (?,?,?,?,?,1)""", [
                    (owner, "draft", "protected-draft", json.dumps(payload), "saved"),
                    (owner, "preferences", "ui", json.dumps({"fixture": MARKER}), "saved"),
                    (owner, "future-evidence", "unknown", json.dumps({"evidence": True}), "saved"),
                    (owner, "outbox", "completed-send", json.dumps({"message": {}}), "sent"),
                ])
            db.executemany(
                """INSERT INTO webmail_uploads(username,id,filename,content_type,data,size,expires_at)
                   VALUES (?,?,'fixture.bin','application/octet-stream',?,?,2000000000)""", [
                    (mailbox, upload, value.encode(), len(value))
                    for mailbox, upload, value in [(owner, "private-upload", MARKER),
                                                   (owner, "protected-upload", "Protected attachment"),
                                                   (peer, "private-upload", "Peer attachment")]
                ])
            db.execute("""INSERT INTO mail_ews_draft_sends(user_id,draft_reference,content_revision,save_copy,delivery_id)
                          VALUES (?,?,?,1,'fixture-ews-send')""", (owner_id, pinned_reference, "a" * 64))
            db.execute("""INSERT INTO sender_review_messages(user_id,basename,folder,envelope_from,author,verified_author)
                          VALUES (?,'synthetic-review','Screening',?,?,0)""", (owner_id, MARKER, MARKER))
            db.execute("""INSERT INTO mailbox_vacation(user_id,enabled,subject,body)
                          VALUES (?,1,'Private vacation',?)""", (owner_id, MARKER))
        _, _, start = prepare(test, "erase-private", review)
        refuse("MaildirWriterActive")

    refuse("ErasureLocalOperationsUnresolved", maildir)
    assert (test.directory / "mail" / owner).is_dir()
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("UPDATE mail_ews_draft_sends SET result='delivered' WHERE delivery_id='fixture-ews-send'")
    refuse("ErasureMaildirPending")
    proofs = {"maildir": success(step(maildir))["audit_id"]}
    refuse("ErasureLocalSearchPending")
    proofs["local_search"] = success(step(search))["audit_id"]
    refuse("ErasurePrivateSqlitePending")
    proofs["private_sqlite"] = success(step(sqlite))["audit_id"]
    refuse("ErasureSharedSqlitePending")
    plan = success(step(shared))["plan"]
    decision.write_text(json.dumps({"version": 1, "scope_sha256": plan["scope_sha256"],
                                    "approval_reference": "synthetic-private-content-case"}))
    decision.chmod(0o600)
    proofs["shared_sqlite"] = success(step(shared, decision))["audit_id"]
    refuse("ErasureLinkedSessionsPending")
    proofs["linked_sessions"] = success(step(links))["audit_id"]

    with closing(sqlite3.connect(database)) as db:
        def content():
            return tuple(db.execute(query).fetchall() for query in (
                "SELECT * FROM webmail_records ORDER BY username,kind,id",
                "SELECT * FROM webmail_uploads ORDER BY username,id",
                "SELECT * FROM mail_private_entries ORDER BY user_id,id",
                "SELECT * FROM mailbox_message_refs ORDER BY user_id,reference",
                "SELECT * FROM mail_ews_draft_sends ORDER BY delivery_id",
                "SELECT * FROM accepted_mail ORDER BY id",
                "SELECT * FROM accepted_mail_targets ORDER BY delivery_id,ordinal",
            ))

        with db:
            db.execute("UPDATE sender_review_messages SET operation='unsettled' WHERE user_id=?", (owner_id,))
        refuse("ErasureLocalOperationsUnresolved")
        with db:
            db.execute("UPDATE sender_review_messages SET operation=NULL WHERE user_id=?", (owner_id,))
            db.execute("""CREATE TRIGGER interrupt_content BEFORE INSERT ON audit_log
                          WHEN NEW.action='hosted.erasure.sqlite.content.removed'
                          BEGIN SELECT RAISE(ABORT,'synthetic interruption'); END""")
        before = content()
        refuse("StepFailed")
        assert content() == before
        with db:
            db.execute("DROP TRIGGER interrupt_content")

        result = success(step())
        assert result["state"] == "private_content_removed_retention_pending"
        assert (result["mailbox"], result["start_audit_id"]) == (owner, start)
        assert result["receipt"]["verified"] == proofs, result
        assert "backup_catalog_and_restore_verification" in result["outstanding_evidence"]
        assert "hosted_billing_and_support_disposition" in result["outstanding_evidence"]
        removed = {row["table"]: row["rows"] for row in result["receipt"]["removed"]}
        retained = {row["table"]: row["rows"] for row in result["receipt"]["retained_at_commit"]}
        assert {name: removed[name] for name in ("webmail_records", "webmail_uploads", "mail_private_entries",
                                                 "mailbox_vacation", "sender_review_messages")} == {
            "webmail_records": 2, "webmail_uploads": 1, "mail_private_entries": 2,
            "mailbox_vacation": 1, "sender_review_messages": 1,
        }, result
        assert retained["webmail_records"] == 3 and retained["webmail_uploads"] == 1
        assert retained["mail_ews_draft_sends"] == 1 and retained["mailbox_message_refs"] == 1
        assert retained["accepted_mail"] >= 2 and retained["accepted_mail_targets"] >= 2
        assert retained["users"] == retained["provisioned_mailboxes"] == 1
        after = content()
        assert after[0] == [row for row in before[0] if row[:3] not in
                            ((owner, "draft", draft["draftId"]), (owner, "preferences", "ui"))]
        assert after[1] == [row for row in before[1] if row[:2] != (owner, "private-upload")]
        assert after[2] == [row for row in before[2] if row[0] == peer_id]
        assert after[3] == [row for row in before[3] if row[0] == peer_id or row[1] == pinned_reference]
        assert removed_reference != pinned_reference
        assert after[4:] == before[4:]
        assert not db.execute("PRAGMA foreign_key_check").fetchall()
        audit, = db.execute("SELECT id,details FROM audit_log WHERE action='hosted.erasure.sqlite.content.removed'")
        assert audit[0] == result["audit_id"] and MARKER not in audit[1] and MARKER not in json.dumps(result)
        assert success(step()) == result

        # A partial restore must never produce a clean receipt over returned private data.
        with db:
            db.execute("""INSERT INTO webmail_records(username,kind,id,payload,state,revision)
                          VALUES (?,'undo','restored','{}','saved',1)""", (owner,))
        refuse("ErasurePrivateContentRemains")
        with db:
            db.execute("DELETE FROM webmail_records WHERE username=? AND id='restored'", (owner,))
        assert success(step()) == result

    with test.daemon():
        api(owner_session, "messages", expected=401)
        assert api(peer_session, "messages/ref/" + peer_reference)["subject"] == "Peer message"
        assert api(peer_session, f'drafts?uid={peer_draft["uid"]}')["message"]["text"] == "Peer content"
        expect_smtp(test.deliver(owner, subject="Address remains reserved"), 550)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="mail-erase-private-content-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Verified private-content erasure, blocked operations, retained delivery records, rollback, retry, and peer access over TLS.")
