#!/usr/bin/env python3
"""Exercise hosted mailbox retirement with the operator CLI and a live daemon."""

import argparse
from contextlib import closing
import hashlib
import imaplib
import json
from pathlib import Path
import runpy
import secrets
import sqlite3
import tarfile
import tempfile
import time
from urllib.parse import urlencode


HERE = Path(__file__).resolve().parent
support = runpy.run_path(str(HERE / "test-webmail-team-invitations.py"))
Fixture, command, paid_mailbox = (support[name] for name in ("Fixture", "command", "paid_mailbox"))
DOMAIN, OTHER = "studio.example.test", "sub.studio.example.test"


def verify(test):
    owner = paid_mailbox(test, "desk", DOMAIN)
    retired_later = paid_mailbox(test, "old", DOMAIN)
    unrelated = paid_mailbox(test, "desk", OTHER)
    # Exercise an existing hosted IMAP client created before deadline support.
    with closing(sqlite3.connect(test.env["SMTP_DB_PATH"])) as db, db:
        db.execute("UPDATE provisioned_mailboxes SET service_until=NULL,read_until=NULL WHERE mailbox=?", (retired_later,))
    assert test.deliver(owner, subject="Retained mail")[0] == 250
    messages = test.directory / "mail" / owner / "new"
    before = {file.name: file.read_bytes() for file in messages.iterdir()}
    assert len(before) == 1 and b"Retained mail" in next(iter(before.values()))
    session = test.login(owner)
    original = test.directory / "reviewed.json"
    original.write_text(command(test, "domain", "inventory", DOMAIN))
    operation = "retirement-staging-00001"
    retire = ("domain", "retire", operation, str(original))
    receipt_url = test.private + "/provisioning/v1/retirement?" + urlencode({"id": operation})
    command(test, *retire, error="ExplicitApprovalRequired")
    assert test.http(receipt_url, headers=test.auth)[0] == 404
    assert test.http(receipt_url)[0] == 401

    tampered = json.loads(original.read_bytes())
    tampered["mailboxes"][1]["revision"] += 1
    different = test.directory / "stale.json"
    different.write_text(json.dumps(tampered))
    command(test, "domain", "retire", operation, str(different), "--yes", error="InventoryChanged")

    with closing(sqlite3.connect(test.env["SMTP_DB_PATH"])) as db:
        now = int(time.time())
        with db:
            uid = db.execute("SELECT id FROM users WHERE username=?", (owner,)).fetchone()[0]
            db.execute("INSERT INTO accepted_mail(id,accepted_at,accepted_ms,envelope_from,author,verified_author,remote_addr,mime,complete) VALUES (?,?,?,?,?,?,?,?,?)",
                       ("pending-retirement", now, now * 1000, "origin@example.test", "origin@example.test", 0, "127.0.0.1", b"fixture", 0))
            db.execute("INSERT INTO accepted_mail_targets(delivery_id,ordinal,recipient,mailbox,mailbox_id,folder,outcome,queued_bytes,retry_at,is_primary) VALUES (?,?,?,?,?,?,?,?,?,?)",
                       ("pending-retirement", 0, owner, owner, uid, "new", "pending", 7, now + 3600, 1))
        command(test, *retire, "--yes", error="PendingDelivery")
        with db:
            db.execute("DELETE FROM accepted_mail_targets WHERE delivery_id='pending-retirement'")
            db.execute("DELETE FROM accepted_mail WHERE id='pending-retirement'")
            db.execute("INSERT INTO message_queue(id,from_addr,to_addr,message_data,status,next_retry,created_at,updated_at,hosted_user_id) VALUES (?,?,?,?,?,?,?,?,?)",
                       ("queued-retirement", owner, unrelated, "fixture", "retry", now + 3600, now, now, uid))
        command(test, *retire, "--yes", error="PendingDelivery")
        with db:
            db.execute("DELETE FROM message_queue WHERE id='queued-retirement'")
            db.execute("INSERT INTO webmail_records(username,kind,id,payload,state,revision,due_at) VALUES (?,?,?,?,?,?,?)",
                       (owner, "outbox", "scheduled-retirement", "{}", "pending", 1, now + 3600))
        command(test, *retire, "--yes", error="PendingDelivery")
        with db:
            db.execute("DELETE FROM webmail_records WHERE id='scheduled-retirement'")
            db.execute("""CREATE TRIGGER reject_retirement_audit BEFORE INSERT ON audit_log
                       WHEN NEW.action='hosted.domain.retire' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END""")
        command(test, *retire, "--yes", error="StepFailed")
        assert db.execute("SELECT count(*) FROM hosted_retired_mailboxes").fetchone()[0] == 0
        assert test.api(session, "messages?folder=INBOX")[0] == 200
        assert test.http(receipt_url, headers=test.auth)[0] == 404
        with db:
            db.execute("DROP TRIGGER reject_retirement_audit")

        with test.imap(retired_later) as imap:
            assert imap.select("INBOX")[0] == "OK"
            result = json.loads(command(test, *retire, "--yes"))
            try:
                imap.fetch("1", "(BODY.PEEK[])")
            except imaplib.IMAP4.abort:
                pass
            else:
                raise AssertionError("A retired mailbox's IMAP session stayed open")

        assert result["domain"] == DOMAIN and result["id"] == operation and result["mailbox_count"] == 2
        assert result["inventory_sha256"] == hashlib.sha256(original.read_bytes()).hexdigest()
        assert json.loads(command(test, *retire, "--yes")) == result
        command(test, "domain", "retire", operation, str(different), "--yes", error="RetirementConflict")
        assert db.execute("SELECT count(*) FROM audit_log WHERE action='hosted.domain.retire'").fetchone()[0] == 1
        status, _, raw = test.http(receipt_url, headers=test.auth)
        assert status == 200 and json.loads(raw) == result
        assert db.execute("SELECT count(*) FROM hosted_retired_mailboxes WHERE retirement_id=?", (operation,)).fetchone()[0] == 2

    assert test.api(session, "messages?folder=INBOX")[0] == 401
    for mailbox in (owner, retired_later):
        response = test.http(test.webmail + "/webmail/auth/login", {"username": mailbox, "password": test.password},
                             {"Origin": test.webmail}, context=test.tls_context)
        assert response[0] == 401, response[0]
        assert test.deliver(mailbox, subject="Refused mail")[0] == 550, mailbox
    assert test.ews(owner, "<m:GetFolder/>", full_login=True)[0] == 401
    assert test.eas(owner, b"", command="FolderSync", full_login=True)[0] == 401
    assert test.deliver(unrelated, subject="Independent domain")[0] == 250
    assert test.api(test.login(unrelated), "messages?folder=INBOX")[0] == 200
    assert {file.name: file.read_bytes() for file in messages.iterdir()} == before
    export = test.directory / "retained-mailbox.tar"
    command(test, "user:local", "export", owner, str(export))
    with tarfile.open(export) as archive:
        assert any(b"Retained mail" in archive.extractfile(entry).read() for entry in archive if entry.isfile() and entry.name.endswith(".eml"))
    assert {row["retirement_id"] for row in json.loads(command(test, "domain", "inventory", DOMAIN))["mailboxes"]} == {operation}

    spec = test.specs[owner]
    preflight = json.loads(command(test, "user:local", "hosted-erasure-preflight", owner, spec["actor"], "retired-exit-case"))
    assert preflight["observation"]["access"]["state"] == "disabled"
    assert preflight["observation"]["access"]["retirement_id"] == operation
    assert preflight["observation"]["identity"]["initial_provisioning_operation"] == spec["operation_id"]
    endpoint = test.private + "/provisioning/v1/mailbox"
    status, _, raw = test.http(endpoint + "?" + urlencode({"mailbox": owner, "actor": spec["actor"]}), headers=test.auth)
    assert status == 200 and json.loads(raw)["retired"] is True
    for actor, revision in ((spec["actor"], 2), (secrets.token_hex(16), 1)):
        request = dict(spec, actor=actor, revision=revision, operation_id=secrets.token_hex(16))
        if revision > 1:
            del request["initial_recovery"], request["initial_password"]
        response = test.http(endpoint, request, test.auth)
        assert response[0] == 409 and json.loads(response[2])["error"] == "mailbox_unavailable", (response[0], response[2])
    response = test.http(endpoint + "/access", {"mailbox": owner, "actor": spec["actor"], "revision": 2,
        "operation_id": secrets.token_hex(16), "access_window": spec["access_window"]}, test.auth)
    assert response[0] == 409 and json.loads(response[2])["error"] == "mailbox_unavailable"
    command(test, "user:local", "enable", owner, error="StepFailed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="mail-domain-retirement-") as directory:
        test = Fixture(binary, Path(directory), staging=True)
        test.env["SMTP_LOCAL_DOMAINS"] += f",{DOMAIN},{OTHER}"
        test.env.update(SMTP_EXACT_MAILBOX_DOMAINS=f"{DOMAIN},{OTHER}", SMTP_PROVISIONING_ADDITIONAL_DOMAINS=f"{DOMAIN},{OTHER}")
        with test.daemon():
            verify(test)
    print("Verified retirement rollback and replay, access revocation, address reservation, data retention, and domain isolation.")


if __name__ == "__main__":
    main()
