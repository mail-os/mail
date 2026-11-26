#!/usr/bin/env python3
"""Verify that the native restore gate rejects older Mail backups after erasure."""

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
import tarfile
from tempfile import TemporaryDirectory

scripts = Path(__file__).resolve().parent
fixtures = runpy.run_path(str(scripts / "test-hosted-erasure-dav.py"))
Fixture, cli, prepare, success, create_resources = (
    fixtures[key] for key in ("Fixture", "cli", "prepare", "success", "create_resources")
)
expect_smtp = runpy.run_path(str(scripts / "test-hosted-operator.py"))["expect_smtp"]
MARKER = "private restore fixture body"


def snapshot(source, location):
    archive_dir = location / "archive"
    restored = location / "restored"
    restored.mkdir(parents=True)
    env = dict(os.environ, MAIL_DIR=str(source.directory), BACKUP_DIR=str(archive_dir),
               MAIL_BACKUP_BIN=str(source.binary), MAIL_BACKUP_ENV_FILE="")
    result = subprocess.run(["bash", str(scripts / "mail-backup.sh")], env=env, capture_output=True, text=True)
    assert result.returncode == 0, (result.stdout, result.stderr)
    archive, = archive_dir.glob("mail-backup-*.tgz")
    with tarfile.open(archive, "r:gz") as package:
        package.extractall(restored, filter="data")
    return restored


def verify(binary, work):
    live = work / "source"
    live.mkdir()
    source = Fixture(binary, live, staging=True)
    authority = source.directory / "smtp.db"
    review = source.directory / "review.json"
    approval = source.directory / "shared-sqlite-approval.json"

    authority_store = work / "independent-authority"
    authority_store.mkdir()
    seed = work / "publisher-key"
    seed.touch(mode=0o600)
    seed.write_text(os.urandom(32).hex() + "\n")
    scope = "fixture-hosted-mail"

    def api(server, session, path, payload=None, *, expected=200):
        status, body = server.api(session, path, payload)
        assert status == expected, (path, status, body)
        return body

    def check(candidate, *, evidence=authority, with_dav=True, legacy=False):
        args = [str(binary), "backup", "verify-erasure-restore", str(evidence),
                str(candidate / "smtp.db"), str(candidate / "mail")]
        if with_dav:
            args.append(str(candidate / "caldav.db"))
        if legacy:
            args.append("--legacy")
        return subprocess.run(args, capture_output=True, text=True)

    def refuse(candidate, error, **kwargs):
        result = check(candidate, **kwargs)
        assert result.returncode != 0 and not result.stdout and error in result.stderr, result

    def seal(name):
        result = subprocess.run([str(binary), "backup", "seal-erasure-authority", str(authority), scope, str(seed)],
                                capture_output=True, text=True)
        document = success(result)
        path = authority_store / name
        path.write_text(result.stdout)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return path, digest, document["public_key"], document["payload"]["state"]["observed_at"]

    def check_checkpoint(candidate, pin, *, checkpoint=None, expected=0, error=None, **overrides):
        path, digest, public, observed_at = pin
        controls = {"scope": scope, "public-key": public, "expected-sha256": digest, "not-before": str(observed_at)}
        controls.update(overrides)
        args = [str(binary), "backup", "verify-erasure-checkpoint", str(checkpoint or path),
                str(candidate / "smtp.db"), str(candidate / "mail"), str(candidate / "caldav.db")]
        for name, value in controls.items():
            args += ["--" + name, value]
        result = subprocess.run(args, capture_output=True, text=True)
        if expected != 0:
            assert result.returncode != 0 and not result.stdout and error in result.stderr, result
            return None
        return success(result)

    def step(name, *args):
        return cli(source, name, str(review), str(start), *map(str, args))

    with source.daemon():
        target, peer = [source.provision(name) for name in ("restore-erased", "restore-peer")]
        target_session, peer_session = [source.login(mailbox) for mailbox in (target, peer)]
        expect_smtp(source.deliver(target, subject="Erased mailbox", body=MARKER), 250)
        expect_smtp(source.deliver(peer, subject="Recovered peer mail"), 250)
        api(source, target_session, "drafts", {"subject": "Erased draft", "text": MARKER})
        peer_draft = api(source, peer_session, "drafts", {"subject": "Peer draft", "text": "Peer recovery"})
        _, event, _ = create_resources(source, target)
        peer_dav, peer_event, _ = create_resources(source, peer)
        older = snapshot(source, work / "older")
        baseline = seal("before-erasure.json")
        assert check_checkpoint(older, baseline)["reservations_checked"] == 0
        seed.chmod(0o644)
        bad_key = subprocess.run([str(binary), "backup", "seal-erasure-authority", str(authority), scope, str(seed)],
                                 capture_output=True, text=True)
        assert bad_key.returncode and not bad_key.stdout and "ErasureCheckpointKeyNotPrivate" in bad_key.stderr
        seed.chmod(0o600)
        assert (older / "mail" / target).is_dir()
        before = success(check(older))
        assert before["state"] == "erasure_restore_verified"
        assert before["reservations_checked"] == 0 and before["newest_reservation_audit_id"] is None
        assert success(check(older, legacy=True))["authority_sha256"] == before["authority_sha256"]
        refuse(older, "RestoreErasureAuthorityMustBeSeparate", evidence=older / "smtp.db")
        refuse(older, "FileNotFound", evidence=work / "absent.db")
        empty = work / "empty-authority.db"
        with closing(sqlite3.connect(empty)) as db, db:
            db.execute("CREATE TABLE hosted_erasure_operations(id INTEGER PRIMARY KEY)")
            db.execute("CREATE TABLE provisioned_mailboxes(mailbox TEXT,user_id INTEGER,actor TEXT)")
            db.execute("CREATE TABLE provisioning_operations(mailbox TEXT,revision INTEGER,operation_id TEXT)")
        refuse(older, "RestoreErasureAuthorityLineageMismatch", evidence=empty)
        with closing(sqlite3.connect(older / "smtp.db")) as db:
            assert db.execute("SELECT enabled FROM users WHERE username=?", (target,)).fetchone() == (1,)
        _, _, start = prepare(source, "restore-erased", review)
        refuse(older, "RestoreErasureReconciliationRequired")
        refuse(older, "RestoreErasureRequiresIsolatedPromotion", legacy=True)
        interrupted = snapshot(source, work / "interrupted")
        in_flight = seal("interrupted-erasure.json")
        check_checkpoint(interrupted, in_flight, expected=1, error="RestoreErasureAuthorityIncomplete")
        refuse(interrupted, "RestoreErasureAuthorityIncomplete")

    success(step("hosted-erasure-maildir"))
    refuse(interrupted, "RestoreErasureReconciliationRequired")
    success(step("hosted-erasure-search"))
    success(step("hosted-erasure-sqlite"))
    shared = "hosted-erasure-shared-sqlite"
    plan = success(step(shared))["plan"]
    approval.write_text(json.dumps({"version": 1, "scope_sha256": plan["scope_sha256"],
                                    "approval_reference": "fixture-restore-source"}))
    approval.chmod(0o600)
    success(step(shared, approval))
    success(step("hosted-erasure-links"))
    success(step("hosted-erasure-private-content"))
    success(step("hosted-erasure-dav", source.directory / "caldav.db"))
    refuse(older, "RestoreErasureReconciliationRequired")
    refuse(interrupted, "RestoreErasureReconciliationRequired")

    restored = snapshot(source, work / "reconciled")
    candidate = restored / "smtp.db"
    result = subprocess.run([str(binary), "backup", "rebind-local", str(candidate), str(restored / "mail")],
                            capture_output=True, text=True)
    assert result.returncode == 0, result
    receipt = success(check(restored))
    assert receipt["state"] == "erasure_restore_verified" and receipt["reservations_checked"] == 1
    assert receipt["source"] == "separate_current_smtp_database"
    assert receipt["newest_reservation_audit_id"] == start and receipt["checked_at"] > 0
    assert receipt["authority_sha256"] != before["authority_sha256"]
    assert MARKER not in json.dumps(receipt) and target not in json.dumps(receipt)
    refuse(restored, "RestoreErasureDavRequired", with_dav=False)
    refuse(restored, "RestoreErasureReconciliationRequired", evidence=older / "smtp.db")
    refuse(restored, "RestoreErasureRequiresIsolatedPromotion", legacy=True)
    assert success(check(restored))["authority_sha256"] == receipt["authority_sha256"]

    # An apparently finished receipt cannot cover files or data restored from
    # another snapshot. Failing a check must leave the candidate unchanged.
    target_dir = restored / "mail" / target
    target_dir.mkdir()
    refuse(restored, "ErasureDirectoryChanged")
    target_dir.rmdir()
    with closing(sqlite3.connect(candidate)) as db, db:
        db.execute("""INSERT INTO webmail_records(username,kind,id,payload,state,revision)
                      VALUES (?,'preferences','partial-restore','{}','saved',1)""", (target,))
    before_check = candidate.read_bytes()
    refuse(restored, "ErasurePrivateContentRemains")
    assert candidate.read_bytes() == before_check
    with closing(sqlite3.connect(candidate)) as db, db:
        db.execute("DELETE FROM webmail_records WHERE id='partial-restore'")
    assert success(check(restored))["authority_sha256"] == receipt["authority_sha256"]

    with closing(sqlite3.connect(candidate)) as db, db:
        before_operation, = db.execute(
            "SELECT operation_id FROM provisioning_operations WHERE mailbox=? AND revision=1", (target,)
        ).fetchone()
        db.execute("UPDATE provisioning_operations SET operation_id='different-original-operation' WHERE operation_id=?",
                   (before_operation,))
    refuse(restored, "ErasureReviewConflict")
    with closing(sqlite3.connect(candidate)) as db, db:
        db.execute("UPDATE provisioning_operations SET operation_id=? WHERE operation_id='different-original-operation'",
                   (before_operation,))
    assert success(check(restored))["authority_sha256"] == receipt["authority_sha256"]

    complete = seal("after-erasure.json")
    for artifact in (baseline[0], in_flight[0], complete[0]):
        data = artifact.read_text()
        assert MARKER not in data and target not in data and peer not in data and seed.read_text().strip() not in data
    seed.unlink()
    authority.rename(source.directory / "smtp.db.unavailable")
    check_checkpoint(older, complete, expected=1, error="RestoreErasureReconciliationRequired")
    check_checkpoint(interrupted, complete, expected=1, error="RestoreErasureReconciliationRequired")
    checked = check_checkpoint(restored, complete)
    assert checked["source"] == "signed_erasure_checkpoint" and checked["checkpoint_sha256"] == complete[1]
    assert checked["authority_observed_at"] == complete[3]
    assert checked["authority_sha256"] == receipt["authority_sha256"]
    check_checkpoint(restored, complete, checkpoint=baseline[0], expected=1, error="ErasureCheckpointPinMismatch")
    check_checkpoint(restored, complete, scope="other-deployment", expected=1, error="InvalidErasureCheckpointScope")
    check_checkpoint(restored, complete, expected=1, error="ErasureCheckpointKeyMismatch", **{"public-key": "00" * 32})
    check_checkpoint(restored, complete, expected=1, error="ErasureCheckpointStale",
                     **{"not-before": str(complete[3] + 1)})

    altered = authority_store / "tampered.json"
    payload = json.loads(complete[0].read_text())
    signature = payload["signature"]
    payload["signature"] = ("0" if signature[0] != "0" else "1") + signature[1:]
    altered.write_text(json.dumps(payload))
    check_checkpoint(restored, complete, checkpoint=altered, expected=1, error="InvalidErasureCheckpointSignature",
                     **{"expected-sha256": hashlib.sha256(altered.read_bytes()).hexdigest()})

    recovery = Fixture(binary, restored, staging=True)
    recovery.password = source.password
    with recovery.daemon():
        api(recovery, target_session, "messages", expected=401)
        status, _, _ = recovery.http(recovery.webmail + "/webmail/auth/login",
                                     {"username": target, "password": recovery.password},
                                     {"Origin": recovery.webmail}, context=recovery.tls_context)
        assert status == 401
        expect_smtp(recovery.deliver(target, subject="Still reserved"), 550)
        peer_session = recovery.login(peer)
        items = api(recovery, peer_session, "messages?conversations=false")["items"]
        assert any(row["subject"] == "Recovered peer mail" for row in items)
        assert api(recovery, peer_session, f'drafts?uid={peer_draft["uid"]}')["message"]["text"] == "Peer recovery"
        dav_client = fixtures["DavClient"](recovery, peer)
        assert dav_client.request("GET", peer_event)[0] == 200
        assert dav_client.request("GET", event)[0] in (403, 404)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="mail-erasure-restore-") as directory:
        verify(args.binary.resolve(strict=True), Path(directory))
    print("Verified old and reconciled Mail archives, signed off-host erasure authority, tamper and replay refusal, and peer access over TLS.")
