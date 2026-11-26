#!/usr/bin/env python3
"""Revoke a reviewed mailbox's incoming and outgoing links over native TLS."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import runpy
import secrets
import sqlite3
from tempfile import TemporaryDirectory
import time

helpers = runpy.run_path(str(Path(__file__).with_name("test-hosted-operator.py")))
Fixture, cli, expect_smtp = (helpers[key] for key in ("Fixture", "cli", "expect_smtp"))
ACCOUNTS = "combined/accounts"


def success(result):
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def verify(test):
    database = test.directory / "smtp.db"
    path = test.directory / "review.json"

    def call(session, route, payload=None, *, method=None, expected=200):
        status, body = test.api(session, route, payload, method=method)
        assert status == expected, (route, status, body)
        return body

    def link(session, address):
        return next(account["id"] for account in
                    call(session, ACCOUNTS, {"username": address, "password": test.password})["accounts"]
                    if account["username"] == address)

    def queue(session, route):
        send_id = secrets.token_hex(16)
        item = call(session, route, {"sendId": send_id, "to": [other], "subject": "Scheduled fixture",
                                     "text": "Fixture", "scheduleAt": int(time.time()) + 3600})
        assert item["state"] == "pending"
        return send_id

    with test.daemon(), closing(sqlite3.connect(database)) as db:
        target, peer, other = [test.provision(label) for label in ("remove-linked", "keep-linked", "unrelated")]
        target_session, peer_session = test.login(target), test.login(peer)
        expect_smtp(test.deliver(peer, subject="Peer independent inbox"), 250)
        expect_smtp(test.deliver(other, subject="Unrelated linked inbox"), 250)
        outgoing = link(target_session, peer)
        incoming = link(peer_session, target)
        unrelated = link(peer_session, other)
        assert call(target_session, "messages?linked=" + outgoing)["items"][0]["subject"] == "Peer independent inbox"
        assert call(peer_session, "messages?linked=" + incoming)["items"] == []
        assert call(peer_session, "messages?linked=" + unrelated)["items"][0]["subject"] == "Unrelated linked inbox"
        peer_root = peer_session["Cookie"].split("=", 1)[1]
        peer_delegate = db.execute("SELECT source_session FROM webmail_account_links WHERE id=?", (outgoing,)).fetchone()[0]
        assert peer_root != peer_delegate
        delegated_send = queue(target_session, "compose?linked=" + outgoing)
        direct_send = queue(peer_session, "compose")
        target_id = db.execute("SELECT id FROM users WHERE username=?", (target,)).fetchone()[0]

        # Expiry followed by the reviewed reservation preserves the real API
        # link rows until the operator can reconcile them offline.
        spec = test.specs[target]
        change = {key: value for key, value in spec.items() if not key.startswith("initial_")}
        now = int(time.time())
        change.update(operation_id=secrets.token_hex(16), revision=2,
                      access_window={"service_until": now - 120, "read_until": now - 60})
        status, _, raw = test.http(test.private + "/provisioning/v1/mailbox", change, test.auth)
        assert status == 200, (status, raw)
        case = "linked-session-erasure"
        inventory = success(cli(test, "hosted-erasure-inventory", target, spec["actor"], case))
        review = {
            "version": 1, "request_id": "linked-session-request", "mailbox": target,
            "assignment_actor": spec["actor"], "case_reference": case,
            "inventory_audit_id": inventory["audit_id"], "retention_disposition": "cleared",
            "export_disposition": "not_requested",
            "evidence": dict.fromkeys(("authorization_reference", "retention_reference", "backup_reference",
                                       "billing_reference", "search_reference", "export_resolution_reference"), "test-case"),
        }
        path.write_text(json.dumps(review))
        path.chmod(0o600)
        approved = success(cli(test, "hosted-erasure-review", str(path)))
        start = success(cli(test, "hosted-erasure-begin", str(path), str(approved["audit_id"])))["audit_id"]

        def run(audit=start):
            return cli(test, "hosted-erasure-links", str(path), str(audit))

        def refuse(error, audit=start):
            result = run(audit)
            assert result.returncode and not result.stdout and error in result.stderr, result

        refuse("MaildirWriterActive")

    with closing(sqlite3.connect(database)) as db:
        def sessions():
            return db.execute("SELECT * FROM webmail_sessions ORDER BY id").fetchall()

        def links():
            return db.execute("SELECT * FROM webmail_account_links ORDER BY id").fetchall()

        refuse("ErasureStartNotFound", approved["audit_id"])
        refuse("ErasureMaildirPending")
        success(cli(test, "hosted-erasure-maildir", str(path), str(start)))
        refuse("ErasurePrivateSqlitePending")
        success(cli(test, "hosted-erasure-sqlite", str(path), str(start)))
        before = (sessions(), links())
        assert {row[0] for row in before[1]} == {incoming, outgoing, unrelated}
        refuse("ErasureLinkedDeliveryUnresolved")
        assert (sessions(), links()) == before
        assert db.execute("SELECT count(*) FROM hosted_erasure_link_steps").fetchone() == (0,)

    with test.daemon():
        assert call(peer_session, "outbox/" + delegated_send, method="DELETE")["state"] == "cancelled"
        assert call(peer_session, "outbox/" + direct_send)["state"] == "pending"

    with closing(sqlite3.connect(database)) as db:
        with db:
            db.execute("UPDATE webmail_account_links SET source_session=? WHERE id=?", (peer_root, outgoing))
        refuse("ErasureLinkedSessionOwnershipUnresolved")
        with db:
            db.execute("UPDATE webmail_account_links SET source_session=? WHERE id=?", (peer_delegate, outgoing))
            trigger = db.execute("SELECT sql FROM sqlite_schema WHERE name='webmail_account_link_cleanup'").fetchone()[0]
            db.execute("DROP TRIGGER webmail_account_link_cleanup")
        before = (sessions(), links())
        refuse("ErasureLinkedSessionsRemain")
        assert (sessions(), links()) == before
        with db:
            db.execute(trigger)
            db.execute("""CREATE TRIGGER deny_link_receipt BEFORE INSERT ON audit_log
                          WHEN NEW.action='hosted.erasure.links.revoked'
                          BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END""")
        refuse("StepFailed")
        assert (sessions(), links()) == before
        assert db.execute("SELECT count(*) FROM hosted_erasure_link_steps").fetchone() == (0,)
        with db:
            db.execute("DROP TRIGGER deny_link_receipt")

        receipt = success(run())
        assert receipt == {
            "version": 1, "state": "linked_sessions_revoked_other_data_pending", "mailbox": target,
            "request_id": review["request_id"], "start_audit_id": start, "audit_id": receipt["audit_id"],
            "links_revoked": 2, "remaining_mailbox_sessions_removed": 1,
        }, receipt
        assert links() == [row for row in before[1] if row[0] == unrelated]
        assert sessions() == [row for row in before[0] if row[2] != target and row[1] != peer_delegate]
        assert db.execute("SELECT id FROM audit_log WHERE action='hosted.erasure.links.revoked'").fetchall() == [(receipt["audit_id"],)]
        assert success(run()) == receipt

        # An older partial restore must not let the receipt certify a returned link.
        with db:
            db.execute("INSERT INTO webmail_account_links VALUES ('reintroduced',?,?,?)",
                       (peer_root, "missing-source-session", target_id))
        refuse("ErasureLinkedSessionsRemain")
        with db:
            db.execute("DELETE FROM webmail_account_links WHERE id='reintroduced'")
        assert success(run()) == receipt

    with test.daemon():
        call(target_session, "messages", expected=401)
        call(peer_session, "messages?linked=" + incoming, expected=403)
        assert call(peer_session, "messages")["items"][0]["subject"] == "Peer independent inbox"
        assert call(peer_session, "messages?linked=" + unrelated)["items"][0]["subject"] == "Unrelated linked inbox"
        assert [item["id"] for item in call(peer_session, ACCOUNTS)["accounts"]] == [unrelated]
        assert call(peer_session, "outbox/" + direct_send)["state"] == "pending"
        expect_smtp(test.deliver(target, subject="Reserved address"), 550)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="mail-erase-linked-sessions-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Verified linked-session revocation in both directions, delivery refusal, audit rollback, and peer access over TLS.")
