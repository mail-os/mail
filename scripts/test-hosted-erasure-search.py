#!/usr/bin/env python3
"""Remove one reviewed mailbox's live local search records after Maildir removal."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
from pathlib import Path
import runpy
import sqlite3
from tempfile import TemporaryDirectory

fixtures = runpy.run_path(str(Path(__file__).with_name("test-hosted-operator.py")))
Fixture, cli, expect_smtp = (fixtures[key] for key in ("Fixture", "cli", "expect_smtp"))


def result_json(result):
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def search(test, session, term):
    status, response = test.api(session, f"messages?folder=INBOX&q={term}")
    assert status == 200, (status, response)
    return [message["subject"] for message in response["items"]]


def index_entries(db):
    # Read the FTS document metadata without depending on Python's SQLite build.
    # The native command checks the postings against their external content.
    return db.execute("SELECT id FROM webmail_search_text_docsize ORDER BY id").fetchall()


def verify(test):
    database = test.directory / "smtp.db"
    previous = test.directory / "before-start.db"
    path = test.directory / "review.json"
    keyword = "SharedIndexMarker"
    with test.daemon(), closing(sqlite3.connect(database)) as db:
        target = test.provision("remove-search")
        peer = test.provision("keep-search")
        target_subject, peer_subject = f"{keyword} target", f"{keyword} peer"
        expect_smtp(test.deliver(target, subject=target_subject), 250)
        expect_smtp(test.deliver(peer, subject=peer_subject), 250)
        target_session, peer_session = test.login(target), test.login(peer)
        assert search(test, target_session, keyword) == [target_subject]
        assert search(test, peer_session, keyword) == [peer_subject]

        ids = dict(db.execute("SELECT username,id FROM users WHERE username IN (?,?)", (target, peer)))
        target_doc = db.execute("SELECT id FROM webmail_search_docs WHERE user_id=?", (ids[target],)).fetchone()[0]
        peer_doc = db.execute("SELECT id FROM webmail_search_docs WHERE user_id=?", (ids[peer],)).fetchone()[0]
        both = sorted([(target_doc,), (peer_doc,)])
        assert index_entries(db) == both
        with db:
            db.executemany("INSERT INTO eas_search_keys(user_id,key) VALUES (?,?)",
                           [(ids[target], b"a" * 32), (ids[peer], b"b" * 32)])
            db.execute("INSERT INTO mail_search_pending(user_id,folder,basename,short_root) VALUES (?,'INBOX','remote.eml',0)",
                       (ids[target],))
        test.provision("remove-search", enabled=False)
        actor = test.specs[target]["actor"]
        case = "local-search-erasure"
        inventory = result_json(cli(test, "hosted-erasure-inventory", target, actor, case))
        review = {
            "version": 1, "request_id": "local-search-request", "mailbox": target, "assignment_actor": actor,
            "case_reference": case, "inventory_audit_id": inventory["audit_id"],
            "retention_disposition": "cleared", "export_disposition": "not_requested",
            "evidence": dict.fromkeys(("authorization_reference", "retention_reference", "backup_reference",
                                       "billing_reference", "search_reference", "export_resolution_reference"), "test-case"),
        }
        path.write_text(json.dumps(review))
        path.chmod(0o600)
        approved = result_json(cli(test, "hosted-erasure-review", str(path)))
        with closing(sqlite3.connect(previous)) as snapshot:
            db.backup(snapshot)
        start = result_json(cli(test, "hosted-erasure-begin", str(path), str(approved["audit_id"])))["audit_id"]

        def run(audit_id=start, *, env=None):
            return cli(test, "hosted-erasure-search", str(path), str(audit_id), env=env)

        def refuse(error, **kwargs):
            output = run(**kwargs)
            assert output.returncode and not output.stdout and error in output.stderr, output

        refuse("MaildirWriterActive")
        assert index_entries(db) == both

    with closing(sqlite3.connect(database)) as db:
        def journal():
            return db.execute("SELECT completion_audit_id FROM hosted_erasure_search_steps WHERE start_audit_id=?",
                              (start,)).fetchone()

        def key(owner):
            return db.execute("SELECT key FROM eas_search_keys WHERE user_id=?", (ids[owner],)).fetchone()

        def assert_retained():
            assert index_entries(db) == both
            assert key(target) == (b"a" * 32,) and key(peer) == (b"b" * 32,)
            assert not journal()

        refuse("ErasureMaildirPending")
        refuse("ErasureStartNotFound", audit_id=approved["audit_id"])
        refuse("ErasureStartNotFound", env=dict(test.env, SMTP_DB_PATH=str(previous)))
        path.write_text(json.dumps({**review, "retention_disposition": "held"}))
        refuse("RetentionHold")
        path.write_text(json.dumps(review))
        result_json(cli(test, "hosted-erasure-maildir", str(path), str(start)))
        assert_retained()

        restored = test.directory / "mail" / target
        restored.mkdir()
        refuse("ErasureDirectoryChanged")
        restored.rmdir()
        assert_retained()

        trigger = db.execute("SELECT sql FROM sqlite_schema WHERE name='webmail_search_delete'").fetchone()[0]
        with db:
            db.execute("DROP TRIGGER webmail_search_delete")
        refuse("StepFailed")
        assert_retained()
        with db:
            db.execute(trigger)
            db.execute("""CREATE TRIGGER interrupt_search_audit BEFORE INSERT ON audit_log
                          WHEN NEW.action='hosted.erasure.search.removed'
                          BEGIN SELECT RAISE(ABORT,'interrupted before receipt'); END""")
        refuse("StepFailed")
        assert_retained()
        with db:
            db.execute("DROP TRIGGER interrupt_search_audit")

        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(lambda _: run(), range(2)))
        successes = [json.loads(reply.stdout) for reply in replies if reply.returncode == 0]
        assert successes and all(reply.returncode == 0 or "MaildirWriterActive" in reply.stderr for reply in replies), replies
        receipt = result_json(run())
        assert all(result == receipt for result in successes)
        assert receipt == {
            "version": 1, "state": "local_search_removed_other_stores_pending", "mailbox": target,
            "request_id": review["request_id"], "start_audit_id": start, "audit_id": receipt["audit_id"],
            "search_documents": 1, "eas_search_keys": 1,
        }, receipt
        assert journal() == (receipt["audit_id"],)
        assert db.execute("SELECT id FROM audit_log WHERE action='hosted.erasure.search.removed'").fetchall() == [journal()]
        assert key(target) is None and key(peer) == (b"b" * 32,)
        assert index_entries(db) == [(peer_doc,)]
        assert db.execute("SELECT user_id FROM webmail_search_docs").fetchall() == [(ids[peer],)]
        assert db.execute("SELECT user_id,basename FROM mail_search_pending").fetchall() == [(ids[target], "remote.eml")]
        assert db.execute("SELECT user_id FROM mail_search_checkpoints").fetchall() == [(ids[target],)]

        # A receipt must not report success if local search state has returned.
        with db:
            db.execute("INSERT INTO eas_search_keys(user_id,key) VALUES (?,?)", (ids[target], b"c" * 32))
        refuse("ErasureSearchRecordsRemain")
        with db:
            db.execute("DELETE FROM eas_search_keys WHERE user_id=?", (ids[target],))
        assert result_json(run()) == receipt

    with test.daemon():
        assert search(test, test.login(peer), keyword) == [peer_subject]
        assert test.api(target_session, "messages?folder=INBOX")[0] == 401
        expect_smtp(test.deliver(target, subject="Reserved address"), 550)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="mail-erase-search-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Verified transaction rollback, live SQLite and FTS removal, unaffected peer search, and a stable receipt.")
