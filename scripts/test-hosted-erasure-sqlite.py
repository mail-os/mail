#!/usr/bin/env python3
"""Verify reviewed SQLite erasure against disposable native HTTPS mailboxes."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import runpy
import sqlite3
from tempfile import TemporaryDirectory
import time
from urllib.parse import urlencode

tools = runpy.run_path(str(Path(__file__).with_name("test-hosted-operator.py")))
Fixture, cli, expect_smtp, request = (tools[key] for key in ("Fixture", "cli", "expect_smtp", "request"))


def success(result):
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def publish_links(test, session, address, label):
    expect_smtp(test.deliver(address, subject=f"{label} private snapshot"), 250)
    status, messages = test.api(session, "messages?conversations=false")
    assert status == 200, (status, messages)
    selection = {"references": [messages["items"][0]["reference"]]}
    status, preview = test.api(session, "snapshot-links/preview", selection)
    assert status == 200, (status, preview)
    status, snapshot = test.api(session, "snapshot-links", {**selection, "digest": preview["digest"], "lifetime": 3600})
    assert status == 201, (status, snapshot)

    # Reuse the same logical upload ID in the other mailbox.
    content = f"{label} private file".encode()
    query = urlencode({"filename": "Review.bin", "uploadId": "a" * 32, "lifetime": 3600})
    status, _, body = request(test.webmail + "/webmail/api/file-links?" + query, content,
                              {**session, "Content-Type": "application/octet-stream"}, context=test.tls_context)
    assert status == 201, (status, body)
    return snapshot["token"], json.loads(body)["token"], content


def public_links(test, links, expected):
    snapshot, file_token, content = links
    for path, payload, headers in [
        ("snapshot", {"token": snapshot}, {"Origin": test.webmail}),
        ("file-link/download", ("token=" + file_token).encode(),
         {"Origin": "null", "Content-Type": "application/x-www-form-urlencoded"}),
    ]:
        status, _, body = request(test.webmail + "/webmail/public/" + path, payload, headers, context=test.tls_context)
        assert status == expected, (path, status, body)
        if status == 200 and path == "file-link/download":
            assert body == content


def seed_private_rows(db, names, ids):
    now = int(time.time())
    by_owner = {
        "mail_client_passwords": ("user_id,digest,label,scope,created_at", lambda i: (ids[i], bytes([i + 1]), "fixture", "mail", now)),
        "hosted_sign_in_proofs": ("digest,user_id,actor,expires_at", lambda i: (bytes([i + 1]), ids[i], "fixture", now + 600)),
        "hosted_sign_in_factors": ("digest,previous_session", lambda i: (bytes([i + 1]), None)),
        "mail_attention_replies": ("user_id,parent_id,last_ms", lambda i: (ids[i], "same-message", now * 1000)),
        "mail_notification_settings": ("user_id,enabled", lambda i: (ids[i], 1)),
        "mail_notification_senders": ("user_id,author,rule", lambda i: (ids[i], "sender@example.test", "notify")),
        "mail_notification_events": ("user_id,event_key,folder,author,parents_json,created_at", lambda i: (ids[i], "same-id", "INBOX", "sender@example.test", "[]", now)),
        "mail_category_settings": ("user_id,automatic", lambda i: (ids[i], 1)),
        "mail_category_rules": ("user_id,author,destination", lambda i: (ids[i], "sender@example.test", "receipts")),
        "mail_calendar_day_labels": ("user_id,day,label,revision", lambda i: (ids[i], "2030-01-01", "fixture", 1)),
        "mail_calendar_tasks": ("user_id,title,completed,revision", lambda i: (ids[i], "fixture", 0, 1)),
        "mail_calendar_tools": ("user_id,payload,revision", lambda i: (ids[i], "{}", 1)),
        "eas_mailbox_state": ("user_id,device_id,collection_id,sync_key,items", lambda i: (ids[i], "same-device", "inbox", "fixture", "[]")),
        "eas_mailbox_ping": ("user_id,device_id,heartbeat,folders", lambda i: (ids[i], "same-device", 60, "[]")),
        "eas_folder_stamp_aliases": ("user_id,stamp,previous_stamp", lambda i: (ids[i], "same-stamp", "previous")),
        "ews_item_sync": ("user_id,folder,sync_key,items,touched_at", lambda i: (ids[i], "INBOX", f"fixture-{i}", "[]", now)),
        "webmail_mfa_factors": ("user_id,secret,last_step", lambda i: (ids[i], bytes([i + 1]), 0)),
        "webmail_mfa_recovery_codes": ("user_id,digest", lambda i: (ids[i], bytes([i + 1]))),
        "webmail_mfa_session_tickets": ("user_id,session_id", lambda i: (ids[i], f"ticket-{i}")),
    }
    by_name = {
        "mailbox_reset_tokens": ("username,token_hash,recovery_email,created_at,expires_at", lambda i: (names[i], f"token-{i}", "recover@example.test", now, now + 600)),
        "imap_mailboxes": ("username,mailbox,uidvalidity", lambda i: (names[i], "ErasureFixture", 10)),
        "imap_uids": ("username,mailbox,filename,uid", lambda i: (names[i], "ErasureFixture", "same.eml", 1)),
    }
    for table, (columns, values) in {**by_owner, **by_name}.items():
        rows = [values(i) for i in range(2)]
        placeholders = ",".join("?" for _ in rows[0])
        db.executemany(f"INSERT INTO {table}({columns}) VALUES ({placeholders})", rows)
    return (*by_owner, *by_name, "webmail_mfa_enrollment", "webmail_sessions", "mail_file_links", "mail_snapshot_links",
            "imap_mailbox_generations", "mail_attention", "mail_notification_threads")


def rows(db, tables):
    return {table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall() for table in tables}


def verify(test):
    database = test.directory / "smtp.db"
    path = test.directory / "review.json"
    case = "private-sqlite-erasure"

    with test.daemon(), closing(sqlite3.connect(database)) as db:
        db.execute("PRAGMA foreign_keys=ON")
        target, peer = names = [test.provision(label) for label in ("remove-private", "keep-private")]
        target_session, peer_session = [test.login(name) for name in names]
        target_root, peer_source = [test.login(name)["Cookie"].split("=", 1)[1] for name in names]
        unlinked = target_session["Cookie"].split("=", 1)[1]
        target_links, peer_links = [publish_links(test, session, address, label) for session, address, label in
                                    [(target_session, target, "Target"), (peer_session, peer, "Peer")]]
        public_links(test, target_links, 200)
        public_links(test, peer_links, 200)

        # Keep a real disabled mailbox assignment and deliberately insert data that
        # existed on older installations before automatic credential invalidation.
        saved_sessions = db.execute("SELECT * FROM webmail_sessions WHERE username=?", (target,)).fetchall()
        test.provision("remove-private", enabled=False)
        public_links(test, target_links, 404)
        ids = [db.execute("SELECT id FROM users WHERE username=?", (name,)).fetchone()[0] for name in names]
        with db:
            columns = ",".join("?" for _ in saved_sessions[0])
            db.executemany(f"INSERT INTO webmail_sessions VALUES ({columns})", saved_sessions)
            tables = seed_private_rows(db, names, ids)
            db.execute("INSERT INTO webmail_account_links VALUES ('shared-link',?,?,?)", (target_root, peer_source, ids[1]))
            for index, session in enumerate((unlinked, peer_source)):
                owner = ids[index]
                db.execute("INSERT INTO webmail_mfa_enrollment VALUES (?,?,?,?)", (owner, session, b"fixture", int(time.time()) + 600))
                reference = db.execute("SELECT reference FROM mailbox_message_refs WHERE user_id=? LIMIT 1", (owner,)).fetchone()[0]
                db.execute("INSERT INTO mail_attention(user_id,reference,kind,deadline,changed_ms,wire_ids) VALUES (?,?,'saved',0,0,'[]')", (owner, reference))
                db.execute("INSERT INTO mail_notification_threads VALUES (?,?,'[]','quiet')", (owner, reference))
                db.execute("INSERT INTO mail_private_collections(user_id,id,name) VALUES (?,'same-collection','Shared scope')", (owner,))
            db.execute("INSERT INTO imap_mailbox_generations VALUES (?,?,?)", (peer, "Existing", 99))
        actor = test.specs[target]["actor"]
        inventory = success(cli(test, "hosted-erasure-inventory", target, actor, case))
        review = {
            "version": 1, "request_id": "private-sqlite-request", "mailbox": target, "assignment_actor": actor,
            "case_reference": case, "inventory_audit_id": inventory["audit_id"],
            "retention_disposition": "cleared", "export_disposition": "not_requested",
            "evidence": dict.fromkeys(("authorization_reference", "retention_reference", "backup_reference",
                                       "billing_reference", "search_reference", "export_resolution_reference"), "test-case"),
        }
        path.write_text(json.dumps(review))
        path.chmod(0o600)
        approved = success(cli(test, "hosted-erasure-review", str(path)))
        start = success(cli(test, "hosted-erasure-begin", str(path), str(approved["audit_id"])))["audit_id"]

        def run(audit=start):
            return cli(test, "hosted-erasure-sqlite", str(path), str(audit))

        def refuse(error, audit=start):
            result = run(audit)
            assert result.returncode and not result.stdout and error in result.stderr, result

        refuse("MaildirWriterActive")

    with closing(sqlite3.connect(database)) as db:
        before = rows(db, tables)
        protected_tables = ("users", "provisioned_mailboxes", "webmail_account_links", "mail_private_collections",
                            "mailbox_message_refs", "accepted_mail", "accepted_mail_targets")
        protected = rows(db, protected_tables)
        assert {unlinked, target_root, peer_source} <= {row[1] for row in before["webmail_sessions"]}
        assert db.execute("SELECT name FROM sqlite_schema WHERE name='password_reset_tokens'").fetchone() is None

        refuse("ErasureStartNotFound", approved["audit_id"])
        refuse("ErasureMaildirPending")
        assert rows(db, tables) == before
        success(cli(test, "hosted-erasure-maildir", str(path), str(start)))

        with db:
            db.execute("""CREATE TRIGGER block_private_receipt BEFORE INSERT ON audit_log
                          WHEN NEW.action='hosted.erasure.sqlite.private.removed'
                          BEGIN SELECT RAISE(ABORT,'interrupted before receipt'); END""")
        refuse("StepFailed")
        assert rows(db, tables) == before
        assert db.execute("SELECT count(*) FROM hosted_erasure_sqlite_steps").fetchone() == (0,)
        with db:
            db.execute("DROP TRIGGER block_private_receipt")
            db.execute("CREATE TABLE password_reset_tokens (unexpected TEXT)")
        refuse("PrepareFailed")
        assert rows(db, tables) == before
        with db:
            db.execute("DROP TABLE password_reset_tokens")
            db.execute("CREATE TABLE password_reset_tokens (username TEXT, token_hash TEXT UNIQUE)")
            db.executemany("INSERT INTO password_reset_tokens VALUES (?,?)", [(target, "target"), (peer, "peer")])

        receipt = success(run())
        assert receipt["state"] == "private_sqlite_removed_other_data_pending"
        assert receipt["records_deleted"] >= len(tables) - 1
        assert receipt["mailbox"] == target and receipt["start_audit_id"] == start
        assert success(run()) == receipt
        assert db.execute("SELECT id FROM audit_log WHERE action='hosted.erasure.sqlite.private.removed'").fetchall() == [(receipt["audit_id"],)]
        assert rows(db, protected_tables) == protected
        assert db.execute("SELECT * FROM password_reset_tokens").fetchall() == [(peer, "peer")]

        expected = {}
        for table, records in before.items():
            if table == "webmail_sessions":
                expected[table] = [row for row in records if row[2] == peer or row[1] == target_root]
            elif table in ("hosted_sign_in_factors", "hosted_sign_in_proofs"):
                expected[table] = [row for row in records if row[0] == b"\x02"]
            elif table in ("imap_uids", "imap_mailboxes"):
                expected[table] = [row for row in records if row[1] == peer]
            elif table in ("imap_mailbox_generations", "mailbox_reset_tokens"):
                column = 0 if table == "imap_mailbox_generations" else 1
                expected[table] = [row for row in records if row[column] == peer]
            else:
                column = 1 if table in ("mail_client_passwords", "mail_snapshot_links", "mail_calendar_tasks",
                                         "mail_notification_events", "ews_item_sync", "webmail_mfa_session_tickets") else 0
                expected[table] = [row for row in records if row[column] == ids[1]]
        actual = rows(db, tables)
        for table in tables:
            assert actual[table] == expected[table], (table, actual[table], expected[table])
        with db:
            db.execute("INSERT INTO mail_notification_settings VALUES (?,1)", (ids[0],))
        refuse("ErasurePrivateSqliteRecordsRemain")
        with db:
            db.execute("DELETE FROM mail_notification_settings WHERE user_id=?", (ids[0],))
        assert success(run()) == receipt

        # Restore the peer's ordinary authentication for the post-restart TLS
        # check. Every seeded peer MFA row was already checked above.
        with db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("DELETE FROM webmail_mfa_factors WHERE user_id=?", (ids[1],))

    with test.daemon():
        public_links(test, target_links, 404)
        public_links(test, peer_links, 200)
        assert test.api(target_session, "messages")[0] == 401
        status, body = test.api(test.login(peer), "messages")
        assert status == 200 and body["items"][0]["subject"] == "Peer private snapshot", (status, body)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="mail-erase-private-sqlite-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Verified private SQLite erasure, rollback, durable receipt, and peer access over TLS.")
