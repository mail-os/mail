#!/usr/bin/env python3
"""Verify hosted erasure closeout against disposable Mail and backup stores."""

import argparse
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import runpy
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import time
from urllib.error import HTTPError

scripts = Path(__file__).resolve().parent
fixtures = runpy.run_path(str(scripts / "test-hosted-erasure-dav.py"))
restore = runpy.run_path(str(scripts / "test-hosted-erasure-restore.py"))
Typesense = runpy.run_path(str(scripts / "test-hosted-erasure-typesense.py"))["Typesense"]
Fixture, cli, prepare, success, create_resources = (
    fixtures[k] for k in ("Fixture", "cli", "prepare", "success", "create_resources")
)
snapshot, expect_smtp = (restore[k] for k in ("snapshot", "expect_smtp"))
PRIVATE_MARKER = "Closeout fixture private message and draft marker"
ACTION = "hosted.erasure.closeout.recorded"


def verify(binary, work, engine=None):
    live = work / "live"
    live.mkdir()
    test = Fixture(binary, live, staging=True)
    if engine is not None:
        test.env.update(TYPESENSE_HOST="127.0.0.1", TYPESENSE_PORT=str(engine.port), TYPESENSE_API_KEY=engine.key)
    smtp_db = live / "smtp.db"
    review = live / "review.json"
    decision_path = live / "decision.json"

    def step(name, *args, env=None):
        result = cli(test, name, str(review), str(start), *map(str, args), env=env)
        return result

    def record(value=None, *, mode=0o600, env=None):
        if value is None:
            return step("hosted-erasure-closeout", env=env)
        decision_path.write_text(json.dumps(value))
        decision_path.chmod(mode)
        return step("hosted-erasure-closeout", decision_path, env=env)

    def refuse(result, error):
        assert result.returncode != 0 and not result.stdout and error in result.stderr, result

    def disposition(state, reference, *, expiry=None):
        value = {"state": state, "reference": reference}
        if expiry is not None:
            value["retain_until"] = expiry
        return value

    with test.daemon():
        target, peer = [test.provision(name) for name in ("closeout-target", "closeout-peer")]
        owner_session, peer_session = [test.login(mailbox) for mailbox in (target, peer)]
        expect_smtp(test.deliver(target, subject="Closeout private", body=PRIVATE_MARKER), 250)
        expect_smtp(test.deliver(peer, subject="Peer remains"), 250)
        status, _ = test.api(owner_session, "drafts", {"subject": "Closeout draft", "text": PRIVATE_MARKER})
        assert status == 200
        create_resources(test, target)
        peer_dav, peer_event, _ = create_resources(test, peer)
        if engine is not None:
            engine.create_collection("messages")
            engine.put("messages", target, "target-legacy.eml")
            indexed_peer = engine.put("messages", peer, "peer-legacy.eml")
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    indexed = {row["username"] for row in engine.documents("messages_v3").values()}
                except HTTPError:
                    indexed = set()
                with closing(sqlite3.connect(smtp_db)) as db:
                    pending, = db.execute("SELECT count(*) FROM mail_search_pending").fetchone()
                if {target, peer} <= indexed and pending == 0:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("The real Typesense index did not settle before the erasure inventory")
        _, _, start = prepare(test, "closeout-target", review)
        refuse(record(), "MaildirWriterActive")

    refuse(record(), "ErasureMaildirPending")
    success(step("hosted-erasure-maildir"))
    success(step("hosted-erasure-search"))
    success(step("hosted-erasure-sqlite"))
    shared = success(step("hosted-erasure-shared-sqlite"))
    decision_path.write_text(json.dumps({"version": 1, "scope_sha256": shared["plan"]["scope_sha256"],
                                         "approval_reference": "approved-shared-fixture"}))
    decision_path.chmod(0o600)
    success(step("hosted-erasure-shared-sqlite", decision_path))
    success(step("hosted-erasure-links"))
    refuse(record(), "ErasurePrivateContentPending")
    content = success(step("hosted-erasure-private-content"))
    refuse(record(), "ErasureDavPending")
    dav = success(step("hosted-erasure-dav", live / "caldav.db"))
    refuse(record(env=dict(test.env, TYPESENSE_HOST="127.0.0.1", TYPESENSE_API_KEY="fixture-key")),
           "ErasureTypesensePending")
    search_audit = None
    if engine is not None:
        search = success(step("hosted-erasure-typesense", "127.0.0.1", str(engine.port)))
        search_audit = search["audit_id"]
        refuse(record(env={k: v for k, v in test.env.items() if not k.startswith("TYPESENSE_")}),
               "ErasureTypesenseUnavailable")
        restored_doc = engine.put("messages", target, "unexpected-restore.eml")
        refuse(record(), "ErasureTypesenseDocumentsRemain")
        assert engine.documents("messages")[restored_doc["id"]] == restored_doc
        engine.request(f"/collections/messages/documents/{restored_doc['id']}", "DELETE")
        assert engine.documents("messages") == {indexed_peer["id"]: indexed_peer}

    plan = success(record())
    assert plan["state"] == "hosted_erasure_closeout_review_pending" and plan["audit_id"] is None
    scope = plan["scope"]
    assert scope["verified"]["private_content_audit_id"] == content["audit_id"]
    assert scope["verified"]["dav_audit_id"] == dav["audit_id"]
    assert scope["verified"]["typesense_audit_id"] == search_audit
    assert PRIVATE_MARKER not in json.dumps(plan)
    counts = {row["table"]: row["rows"] for row in scope["retained_records"]}
    assert counts["accepted_mail"] == 1 and counts["accepted_mail_targets"] == 1, counts
    assert counts["users"] == counts["provisioned_mailboxes"] == 1
    assert counts["audit_log"] > 0 and scope["sqlite_tables_requiring_scope_review"]
    assert success(record()) == plan

    # This case verifies a disposable backup and removes it before closeout.
    with TemporaryDirectory(prefix="discarded-backup-", dir=work) as backup_dir:
        recovered = snapshot(test, Path(backup_dir))
        verified = subprocess.run([str(binary), "backup", "verify-erasure-restore", str(smtp_db),
                                   str(recovered / "smtp.db"), str(recovered / "mail"),
                                   str(recovered / "caldav.db")], capture_output=True, text=True)
        assert success(verified)["reservations_checked"] == 1
        restore_reference = "restore-" + sha256(verified.stdout.encode()).hexdigest()

    expiry = int(time.time()) + 86400
    required = disposition("retention_required", "approved-audit-scope")
    decision = {
        "version": 1, "scope_sha256": plan["scope_sha256"], "approval_reference": "case-closeout-v1",
        "external_search_reference": "search-inventory-reviewed", "sqlite_scope_reference": "schema-scope-reviewed",
        "sqlite_history": disposition("retained_until", "storage-history-review", expiry=expiry),
        "backups": {
            "disposition": disposition("removed", restore_reference), "retained_snapshots": 0,
        },
        "hosted_billing": disposition("retention_required", "billing-ledger-review"),
        "support_records": disposition("removed", "support-case-review"),
        "retained_records": [{"table": table, "disposition": required} for table in counts],
    }
    refuse(record(decision, mode=0o644), "ErasureCloseoutDecisionNotPrivate")
    refuse(record({**decision, "retained_records": decision["retained_records"][:-1]}), "ErasureCloseoutRetentionScopeMismatch")
    refuse(record({**decision, "retained_records": [
        {**item, "disposition": disposition("removed", "contradicts-live-scope")} for item in decision["retained_records"]
    ]}), "InvalidErasureCloseoutDisposition")
    refuse(record({**decision, "sqlite_history": disposition("retained_until", "expired-approval", expiry=1)}),
           "ErasureCloseoutRetentionExpired")

    with closing(sqlite3.connect(smtp_db)) as db:
        target_delivery, raw = db.execute("""SELECT a.id,a.mime FROM accepted_mail a JOIN accepted_mail_targets t
                                             ON t.delivery_id=a.id WHERE t.mailbox=?""", (target,)).fetchone()
        with db:
            db.execute("UPDATE accepted_mail SET mime=? WHERE id=?", (b"replacement bytes", target_delivery))
        stale = success(record())
        assert stale["scope_sha256"] != plan["scope_sha256"]
        assert {row["table"]: row["rows"] for row in stale["scope"]["retained_records"]} == counts
        refuse(record(decision), "ErasureCloseoutScopeChanged")
        with db:
            db.execute("UPDATE accepted_mail SET mime=? WHERE id=?", (raw, target_delivery))
            db.execute("""CREATE TRIGGER reject_closeout BEFORE INSERT ON audit_log
                          WHEN NEW.action='hosted.erasure.closeout.recorded'
                          BEGIN SELECT RAISE(ABORT,'fixture rollback'); END""")
        refuse(record(decision), "StepFailed")
        assert db.execute("SELECT 1 FROM audit_log WHERE action=?", (ACTION,)).fetchone() is None
        assert success(record()) == plan
        with db:
            db.execute("DROP TRIGGER reject_closeout")

        receipt = success(record(decision))
        assert receipt["state"] == "hosted_erasure_disposition_recorded"
        assert receipt["scope"] == scope and receipt["recorded_at"] > 0
        assert receipt["decision"]["backups"]["disposition"]["reference"] == restore_reference
        assert receipt["verified_replay"] is None
        assert success(record(decision)) == receipt
        assert db.execute("SELECT id FROM audit_log WHERE action=?", (ACTION,)).fetchall() == [(receipt["audit_id"],)]
        refuse(record({**decision, "external_search_reference": "changed-evidence"}), "ErasureCloseoutApprovalConflict")

    with test.daemon():
        assert test.api(owner_session, "messages")[0] == 401
        expect_smtp(test.deliver(target, subject="Reserved after closeout"), 550)
        status, found = test.api(peer_session, "messages?conversations=false")
        assert status == 200 and any(row["subject"] == "Peer remains" for row in found["items"])
        assert peer_dav.request("GET", peer_event)[0] == 200


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--typesense-server", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="mail-erasure-closeout-") as directory:
        root = Path(directory)
        binary = args.binary.resolve(strict=True)
        if args.typesense_server is None:
            verify(binary, root)
        else:
            with Typesense(args.typesense_server, root / "typesense").running() as engine:
                verify(binary, root, engine)
            print("Verified a real Typesense closeout and refusal of reintroduced target documents.")
    print("Verified scoped hosted erasure closeout, retained bytes, backup restoration, stable retry, and peer data over TLS.")
