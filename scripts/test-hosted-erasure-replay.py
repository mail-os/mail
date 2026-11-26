#!/usr/bin/env python3
"""Reconcile an actual pre-erasure backup and verify the signed promotion decision."""

import argparse
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
from tempfile import TemporaryDirectory

scripts = Path(__file__).resolve().parent
fixtures = runpy.run_path(str(scripts / "test-hosted-erasure-dav.py"))
calendar = runpy.run_path(str(scripts / "test-hosted-erasure-calendar-copy.py"))
restore = runpy.run_path(str(scripts / "test-hosted-erasure-restore.py"))
Fixture, cli, prepare, success = (fixtures[k] for k in ("Fixture", "cli", "prepare", "success"))
DavClient, put_dav, EVENT = (fixtures[k] for k in ("DavClient", "put_dav", "EVENT"))
command, shared_calendar = (calendar[k] for k in ("command", "shared_calendar"))
snapshot, expect_smtp = (restore[k] for k in ("snapshot", "expect_smtp"))
SCOPE = "replay-fixture-mail"
APPROVAL = "independent-fixture-recovery-approval"


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def refuse(result, error):
    assert result.returncode != 0 and not result.stdout and error in result.stderr, result


def verified_document(path, result):
    document = success(result)
    path.write_text(result.stdout)
    return path, ["--scope", SCOPE, "--expected-sha256", sha256(path.read_bytes()).hexdigest(),
                  "--public-key", document["public_key"],
                  "--not-before", str(document["payload"]["state"]["observed_at"])]


def verify(binary, work):
    original = work / "live"
    original.mkdir()
    source = Fixture(binary, original, staging=True)
    review_path = original / "review.json"
    key = work / "publisher-key"
    key.touch(mode=0o600)
    key.write_text(os.urandom(32).hex() + "\n")

    def api(server, session, route, data=None, *, method=None, expected=200):
        status, body = server.api(session, route, data, method=method)
        assert status == expected, (route, status, body)
        return body

    def backup(name, *args, cwd=None):
        return subprocess.run([str(binary), "backup", name, *map(str, args)], cwd=cwd, capture_output=True, text=True)

    def check(candidate, credential):
        checkpoint, pin = credential
        return backup("verify-erasure-checkpoint", checkpoint, candidate / "smtp.db", candidate / "mail",
                      candidate / "caldav.db", *pin)

    def finish(server, review, start):
        decision = server.directory / "approval.json"

        def step(name, *args):
            return success(cli(server, name, str(review), str(start), *map(str, args)))

        for store, name, key_name, selection in (
            ("maildir", "thread_archives", "retained_thread_archives",
             lambda _: {"peer_user_id": peer_id, "source_share_id": thread_id}),
            ("dav", "calendar_copies", "retained_calendar_copies",
             lambda plan: {"peer_user_id": peer_id, "source_share_id": plan["scope"]["current"][0]["share_id"],
                           "destination_calendar_id": destination}),
        ):
            plan = step("hosted-erasure-shared-release", store)
            private_json(decision, {"version": 1, "scope_sha256": plan["scope_sha256"],
                                    "approval_reference": "fixture-share-scope",
                                    "disposition": "release_source_with_" + name, key_name: [selection(plan)]})
            step("hosted-erasure-shared-release", store, decision)
        step("hosted-erasure-retain-threads")
        step("hosted-erasure-maildir")
        step("hosted-erasure-search")
        step("hosted-erasure-sqlite")
        step("hosted-erasure-dav", server.directory / "caldav.db")
        plan = step("hosted-erasure-shared-sqlite")["plan"]
        private_json(decision, {"version": 1, "scope_sha256": plan["scope_sha256"], "approval_reference": "fixture-sqlite"})
        step("hosted-erasure-shared-sqlite", decision)
        step("hosted-erasure-links")
        step("hosted-erasure-private-content")

    team = "restore-replay"
    with source.daemon():
        target, peer = [source.provision(name) for name in ("replay-erased", "replay-peer")]
        command(source, "team", "create", team, "Replay preservation", target)
        command(source, "team", "member", team, peer, "member")
        with closing(sqlite3.connect(original / "smtp.db")) as db:
            peer_id, = db.execute("SELECT id FROM users WHERE username=?", (peer,)).fetchone()
        target_session, peer_session = [source.login(mailbox) for mailbox in (target, peer)]
        expect_smtp(source.deliver(target, subject="Retained conversation", body="Original shared body"), 250)
        expect_smtp(source.deliver(peer, subject="Peer inbox message"), 250)
        api(source, target_session, "drafts", {"subject": "Owner draft", "text": "Erase this private draft"})
        peer_draft = api(source, peer_session, "drafts", {"subject": "Peer draft", "text": "Peer survives"})
        messages = api(source, target_session, "messages?conversations=false")["items"]
        shared, = [row["reference"] for row in messages if row["subject"] == "Retained conversation"]
        selected = {"references": [shared], "downloads": False}
        preview = api(source, target_session, "thread-shares/preview", selected)
        thread_id = api(source, target_session, "thread-shares",
                        {**selected, "team": team, "grantee": peer, "digest": preview["digest"]}, expected=201)["id"]
        thread_path = f"thread-shares/{thread_id}"
        api(source, peer_session, thread_path + "/comments", {"text": "Peer discussion"}, expected=201)
        thread = api(source, peer_session, thread_path)
        calendar_id = api(source, target_session, "calendars", {"name": "Replay calendar"}, expected=201)["id"]
        destination = api(source, peer_session, "calendars", {"name": "Replay retained"}, expected=201)["id"]
        original_event = f"/calendars/{target}/Replay%20calendar/portable-event.ics"
        retained_event = f"/calendars/{peer}/Replay%20retained/portable-event.ics"
        put_dav(DavClient(source, target), original_event, "text/calendar", EVENT)
        api(source, target_session, f"teams/{team}/calendar-shares",
            {"calendarId": calendar_id, "grantee": peer, "access": "viewer"}, method="PUT")
        peer_dav = DavClient(source, peer)
        status, _, retained_ics = peer_dav.request("GET", shared_calendar(peer_dav) + "portable-event.ics")
        assert status == 200
        put_dav(peer_dav, retained_event, "text/calendar", retained_ics)
        older = snapshot(source, work / "older")
        _, _, source_start = prepare(source, "replay-erased", review_path)

    finish(source, review_path, source_start)
    source_checkpoint = verified_document(work / "original-checkpoint.json",
                                          backup("seal-erasure-authority", original / "smtp.db", SCOPE, key))
    (original / "smtp.db").rename(original / "smtp.db.unavailable")
    refuse(check(older, source_checkpoint), "RestoreErasureReconciliationRequired")
    rebind = backup("rebind-local", older / "smtp.db", older / "mail")
    assert rebind.returncode == 0, rebind.stderr
    replay = Fixture(binary, older, staging=True)
    replay.password = source.password
    replay_db = older / "smtp.db"
    replay_review = older / "review.json"
    review = json.loads(review_path.read_text())
    checkpoint, pin = source_checkpoint

    def inspect():
        return backup("check-erasure-replay-target", checkpoint, replay_db, replay_review, *pin)

    def sign(seed=key):
        return backup("seal-erasure-replay", checkpoint, replay_db, older / "mail", seed, older / "caldav.db",
                      *pin, "--approval-reference", APPROVAL)

    private_json(replay_review, {**review, "case_reference": "wrong-case"})
    refuse(inspect(), "RestoreErasureReplayCaseMismatch")
    private_json(replay_review, review)
    assert success(inspect())["source_start_audit_id"] == source_start
    with closing(sqlite3.connect(replay_db)) as db, db:
        operation, = db.execute("SELECT operation_id FROM provisioning_operations WHERE mailbox=? AND revision=1",
                                (target,)).fetchone()
        db.execute("UPDATE provisioning_operations SET operation_id='reused-address' WHERE operation_id=?", (operation,))
    refuse(inspect(), "RestoreErasureReplayCaseMismatch")
    with closing(sqlite3.connect(replay_db)) as db, db:
        db.execute("UPDATE provisioning_operations SET operation_id=? WHERE operation_id='reused-address'", (operation,))

    def isolate():
        return success(backup("check-erasure-replay-target", checkpoint, replay_db, replay_review, *pin,
                              "--isolate-maildir", older / "mail", cwd=older))

    unrelated_db = work / "other-smtp.db"
    with closing(sqlite3.connect(replay_db)) as source_db, closing(sqlite3.connect(unrelated_db)) as copy_db:
        source_db.backup(copy_db)
    refuse(backup("check-erasure-replay-target", checkpoint, unrelated_db, replay_review, *pin,
                  "--isolate-maildir", older / "mail", cwd=older), "RestoreErasureIsolationRootMismatch")
    isolated = isolate()
    assert isolated["state"] == "erasure_replay_target_isolated" and isolate() == isolated
    with closing(sqlite3.connect(replay_db)) as db:
        assert db.execute("SELECT enabled FROM users WHERE username=?", (target,)).fetchone() == (0,)
        assert db.execute("SELECT count(*) FROM audit_log WHERE action='hosted.erasure.restore.isolated'").fetchone() == (1,)
    # Allocate a separate inventory audit to make the source and restored
    # sequences differ even if their first few operator actions coincide.
    for _ in range(2):
        inventory = success(cli(replay, "hosted-erasure-inventory", target, review["assignment_actor"], review["case_reference"]))
    private_json(replay_review, {**review, "inventory_audit_id": inventory["audit_id"],
                                "evidence": dict.fromkeys(review["evidence"], "restored-scope-approved")})
    approved = success(cli(replay, "hosted-erasure-review", str(replay_review)))
    begin = success(cli(replay, "hosted-erasure-begin", str(replay_review), str(approved["audit_id"])))["audit_id"]

    refuse(sign(), "RestoreErasureReconciliationRequired")
    finish(replay, replay_review, begin)
    assert source_start != begin
    refuse(check(older, source_checkpoint), "RestoreErasureReconciliationRequired")
    with closing(sqlite3.connect(replay_db)) as db, db:
        original_approval, = db.execute(
            "SELECT approval_id FROM hosted_erasure_thread_archive_steps WHERE start_audit_id=?", (begin,)
        ).fetchone()
        db.execute("DELETE FROM hosted_erasure_thread_archive_steps WHERE start_audit_id=?", (begin,))
    refuse(sign(), "RestoreErasurePeerCopyChanged")
    with closing(sqlite3.connect(replay_db)) as db, db:
        db.execute("INSERT INTO hosted_erasure_thread_archive_steps VALUES (?,?)", (begin, original_approval))
    bad_seed = work / "untrusted-key"
    bad_seed.touch(mode=0o600)
    bad_seed.write_text(os.urandom(32).hex() + "\n")
    refuse(sign(bad_seed), "ErasureCheckpointKeyMismatch")
    certified = verified_document(work / "replay-checkpoint.json", sign())
    key.unlink()
    receipt = success(check(older, certified))
    assert receipt["source"] == "signed_erasure_replay"
    assert receipt["replayed_from_sha256"] == sha256(checkpoint.read_bytes()).hexdigest()
    assert receipt["newest_reservation_audit_id"] == begin and receipt["recovery_approval_reference"] == APPROVAL
    assert target not in certified[0].read_text() and "Original shared body" not in certified[0].read_text()

    with closing(sqlite3.connect(replay_db)) as db, db:
        copy_hash, = db.execute("SELECT sha256 FROM mail_retained_thread_archives WHERE share_id=?", (thread_id,)).fetchone()
        db.execute("UPDATE mail_retained_thread_archives SET sha256=? WHERE share_id=?", ("0" * 64, thread_id))
    refuse(check(older, certified), "ErasureThreadArchiveInvalid")
    with closing(sqlite3.connect(replay_db)) as db, db:
        db.execute("UPDATE mail_retained_thread_archives SET sha256=? WHERE share_id=?", (copy_hash, thread_id))
    with closing(sqlite3.connect(older / "caldav.db")) as db, db:
        prior, = db.execute("SELECT ics_data FROM dav_events WHERE calendar_id=?", (destination,)).fetchone()
        db.execute("UPDATE dav_events SET ics_data='changed after signing' WHERE calendar_id=?", (destination,))
    refuse(check(older, certified), "RestoreErasurePeerCopyChanged")
    with closing(sqlite3.connect(older / "caldav.db")) as db, db:
        db.execute("UPDATE dav_events SET ics_data=? WHERE calendar_id=?", (prior, destination))
    assert success(check(older, certified))["authority_sha256"] == receipt["authority_sha256"]

    with replay.daemon():
        api(replay, target_session, "messages", expected=401)
        status, _, _ = replay.http(replay.webmail + "/webmail/auth/login", {"username": target, "password": replay.password},
                                   {"Origin": replay.webmail}, context=replay.tls_context)
        assert status == 401
        expect_smtp(replay.deliver(target, subject="Address stays reserved"), 550)
        peer_session = {**peer_session, "Origin": replay.webmail}
        retained = api(replay, peer_session, thread_path)
        assert retained["grant"]["retained"] and retained["comments"] == thread["comments"]
        assert retained["messages"] == thread["messages"]
        assert api(replay, peer_session, f'drafts?uid={peer_draft["uid"]}')["message"]["text"] == "Peer survives"
        assert DavClient(replay, peer).request("GET", retained_event)[2] == retained_ics
        assert any(row["subject"] == "Peer inbox message" for row in
                   api(replay, peer_session, "messages?conversations=false")["items"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="mail-erasure-replay-") as directory:
        verify(args.binary.resolve(strict=True), Path(directory))
    print("Verified authorized erasure replay of a pre-erasure archive, signed recovery, tamper refusal, and retained peer Mail and Calendar over TLS.")
