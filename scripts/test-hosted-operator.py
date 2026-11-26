#!/usr/bin/env python3
"""Exercise audited hosted-mailbox diagnostics and sending holds on a disposable daemon."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import runpy
import secrets
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import time

suite = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture, expect_smtp = suite["Fixture"], suite["expect_smtp"]
request = suite["request"]


def cli(test, *args, env=None, input=None):
    return subprocess.run([str(test.binary), "user:local", *args], env=env or test.env,
                          cwd=test.directory, input=input, text=True, capture_output=True, timeout=12)


def report(test, mailbox):
    result = cli(test, "hosted-status", mailbox)
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["version"] == 1 and output["mailbox"] == mailbox, output
    assert abs(output["observed_at"] - int(time.time())) < 10, output
    return output


def stage_accounting(db, mailbox, peer):
    now = int(time.time())
    user_id = db.execute("SELECT id FROM users WHERE username=?", (mailbox,)).fetchone()[0]
    peer_id = db.execute("SELECT id FROM users WHERE username=?", (peer,)).fetchone()[0]
    with db:
        db.executemany(
            """INSERT INTO mail_file_links(user_id,id,token_hash,filename,data,size,expires_at)
            VALUES(?,?,?,'diagnostic-only.txt',?,?,?)""",
            [(user_id, "active", "fixture-active", b"x" * 39, 39, now + 1000),
             (user_id, "expired", "fixture-expired", b"x" * 80, 80, now - 1)],
        )
        db.execute(
            """INSERT INTO accepted_mail(id,accepted_at,accepted_ms,envelope_from,author,verified_author,remote_addr,mime)
            VALUES('fixture-inbound',?,?,?,?,1,'127.0.0.1',?)""",
            (now, now * 1000, peer, peer, b"queued-contents"),
        )
        db.executemany(
            """INSERT INTO accepted_mail_targets
            (delivery_id,ordinal,recipient,mailbox,mailbox_id,folder,outcome,queued_bytes,retry_at,is_primary)
            VALUES('fixture-inbound',?,?,?,?, 'INBOX',?,?,?,1)""",
            [(0, mailbox, mailbox, user_id, "pending", 53, now + 3600),
             (1, mailbox, mailbox, user_id, "filed", 79, now + 3600),
             (2, peer, peer, peer_id, "pending", 99, now + 3600)],
        )
        db.executemany(
            """INSERT INTO message_queue
            (id,from_addr,to_addr,message_data,status,next_retry,created_at,updated_at,hosted_user_id)
            VALUES(?,?,'private-queue-recipient@example.test','private-queue-body',?,?,?,?,?)""",
            [(f"queue-{index}", peer, status, now + 3600, now, now, owner)
             for index, (status, owner) in enumerate((
                 ("pending", user_id), ("retry", user_id), ("processing", user_id),
                 ("failed", user_id), ("pending", peer_id),
             ))],
        )
    return user_id


def verify(test, db):
    mailbox = test.provision("operator-check", quota=16_384, daily=3)
    peer = test.provision("relay")
    other = test.provision("other", daily=0)
    unmanaged = cli(test, "create", "unmanaged@example.test", input=test.password + "\n")
    assert unmanaged.returncode == 0, unmanaged.stderr
    for name in ("unmanaged@example.test", "missing@example.test"):
        absent = cli(test, "hosted-status", name)
        assert absent.returncode and not absent.stdout, absent

    initial = report(test, mailbox)
    assert initial["account"]["recipients_remaining"] == 3
    assert initial["account"]["counter_utc_day"] is None
    unlimited = report(test, other)
    assert unlimited["account"]["recipients_remaining"] is None

    expect_smtp(test.deliver(mailbox, identity=peer, subject="private-inbound-subject"), 250)
    expect_smtp(test.deliver([peer, other], identity=mailbox, subject="private-outbound-subject"), 250)
    stored = test.bytes(mailbox)
    assert stored > 0, stored
    user_id = stage_accounting(db, mailbox, peer)
    observed = report(test, mailbox)
    account, storage = observed["account"], observed["storage"]
    assert account["enabled"] and account["requested_enabled"] and account["revision"] == 1, account
    assert account["quota_bytes"] == account["requested_quota_bytes"] == 16_384, account
    assert account["recipients_used_today"] == 2 and account["recipients_remaining"] == 1, account
    assert account["utc_day"] == account["counter_utc_day"], account
    assert account["outbound_queue"] == {"pending": 1, "retry": 1, "processing": 1}, account
    assert storage == {
        "maildir_bytes": stored, "pending_delivery_bytes": 53, "linked_file_bytes": 39,
        "remaining_bytes": 16_384 - stored - 53 - 39,
    }, storage
    filtered = json.dumps(observed)
    for private in (test.password, "private-queue-recipient", "private-queue-body",
                    "private-inbound-subject", "private-outbound-subject", "diagnostic-only.txt"):
        assert private not in filtered

    deletion = cli(test, "delete", mailbox)
    assert deletion.returncode != 0 and "managed retirement workflow" in deletion.stderr
    legacy = subprocess.run([str(test.binary), "gdpr", "delete", mailbox], env=test.env,
                            cwd=test.directory, text=True, capture_output=True, timeout=15)
    assert legacy.returncode != 0 and "managed retirement workflow" in legacy.stderr, legacy.stderr
    after_refusal = report(test, mailbox)
    assert after_refusal["account"] == account and after_refusal["storage"] == storage

    disabled = cli(test, "disable", mailbox)
    assert disabled.returncode == 0, disabled.stderr
    suspended = report(test, mailbox)
    assert not suspended["account"]["enabled"] and suspended["account"]["requested_enabled"], suspended
    assert suspended["account"]["outbound_queue"] == account["outbound_queue"]
    deletion = cli(test, "delete", mailbox)
    assert deletion.returncode != 0 and "managed retirement workflow" in deletion.stderr
    legacy = subprocess.run([str(test.binary), "gdpr", "delete", mailbox], env=test.env,
                            cwd=test.directory, text=True, capture_output=True, timeout=15)
    assert legacy.returncode != 0 and "managed retirement workflow" in legacy.stderr, legacy.stderr
    assert report(test, mailbox)["storage"] == storage

    deleted = cli(test, "delete", "unmanaged@example.test")
    assert deleted.returncode == 0, deleted.stderr
    assert db.execute("SELECT 1 FROM users WHERE username=?", ("unmanaged@example.test",)).fetchone() is None

    test.provision("operator-check", quota=1, daily=1)
    capped = report(test, mailbox)
    assert capped["account"]["revision"] == 2 and capped["account"]["enabled"]
    assert capped["account"]["recipients_used_today"] == 2 and capped["account"]["recipients_remaining"] == 0
    assert capped["storage"]["remaining_bytes"] == 0

    for counter_day, remaining in ((account["utc_day"] - 1, 1), (account["utc_day"] + 1, 0)):
        with db:
            db.execute("UPDATE hosted_sending_usage SET utc_day=? WHERE user_id=?", (counter_day, user_id))
        changed = report(test, mailbox)["account"]
        assert changed["recipients_used_today"] == 0 and changed["recipients_remaining"] == remaining, changed
        assert changed["counter_utc_day"] == counter_day

    audit = db.execute(
        "SELECT action,actor,target,target_type,details FROM audit_log WHERE id=?", (observed["audit_id"],),
    ).fetchone()
    assert audit == ("hosted.status", f"local-operator:{os.geteuid()}", mailbox, "hosted_mailbox", None), audit
    with db:
        db.execute("""CREATE TRIGGER deny_status_audit BEFORE INSERT ON audit_log
                      WHEN NEW.action='hosted.status' BEGIN SELECT RAISE(ABORT,'audit failure'); END""")
    blocked = cli(test, "hosted-status", mailbox)
    assert blocked.returncode and not blocked.stdout, blocked
    with db:
        db.execute("DROP TRIGGER deny_status_audit")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="mail-hosted-operator-") as directory:
        root = Path(directory)
        test = Fixture(args.binary.resolve(strict=True), root, staging=True)
        missing_path = root / "wrong.db"
        missing = cli(test, "hosted-status", "nobody@example.test", env=dict(test.env, SMTP_DB_PATH=str(missing_path)))
        assert missing.returncode and not missing_path.exists(), missing
        with test.daemon(), closing(sqlite3.connect(root / "smtp.db")) as db:
            verify(test, db)
            mailbox, peer, held_since = verify_sending_hold(test, db)
        with closing(sqlite3.connect(root / "smtp.db")) as db, db:
            now = int(time.time())
            db.execute(
                """INSERT INTO message_queue
                (id,from_addr,to_addr,message_data,status,attempts,next_retry,created_at,updated_at,hosted_user_id)
                SELECT 'hosted-retry-fixture', ?, 'nobody@external.invalid', 'fixture', 'retry', 2, ?, ?, ?, id
                FROM users WHERE username=?""", (mailbox, now, now, now, mailbox),
            )
        with test.daemon(), closing(sqlite3.connect(root / "smtp.db")) as db:
            suite["check_suspended_retry"](test, now)
            with db:
                db.execute("DELETE FROM message_queue WHERE id='hosted-retry-fixture'")
            verify_sending_release(test, db, mailbox, peer, held_since)
            verify_hold_access_windows(test, peer)
    print("Verified audited hosted quota, provisioning drift, UTC usage, queue counts and redaction.")
    print("Verified audited sending holds across SMTP, webmail, EWS, ActiveSync, provisioning and restart.")


def verify_sending_hold(test, db):
    mailbox = test.provision("held-sender", daily=3)
    peer = test.provision("hold-recipient")
    session = test.login(mailbox)
    send_id = secrets.token_hex(16)
    payload = {
        "sendId": send_id, "subject": "Scheduled before hold",
        "to": [peer], "text": "Keep the scheduled message for review.", "delaySeconds": 30,
    }
    assert test.api(session, "compose", payload)[0] == 200
    with test.smtp(mailbox) as client:
        expect_smtp(client.mail(mailbox), 250)
        expect_smtp(client.rcpt(peer), 250)
        result = cli(test, "hosted-sending-hold", mailbox, "place", "case-17")
        assert result.returncode == 0, result.stderr
        raw = f"From: {mailbox}\r\nTo: {peer}\r\nSubject: Held SMTP\r\n\r\nHeld body.\r\n"
        expect_smtp(client.data(raw), 550, "5.7.1 Sending is on hold")

    duplicate = cli(test, "hosted-sending-hold", mailbox, "place", "case-17")
    assert duplicate.returncode == 0 and "already in place" in duplicate.stderr
    status = report(test, mailbox)["account"]
    held_since = status["sending_held_since"]
    assert status["access"] == "full" and held_since is not None

    # A newer enabled entitlement still applies its quota while leaving the hold.
    test.provision("held-sender", quota=65_536, daily=4)
    status = report(test, mailbox)["account"]
    assert status["revision"] == 2 and status["quota_bytes"] == 65_536
    assert status["sending_held_since"] == held_since
    expect_smtp(test.deliver(peer, identity=mailbox), 550, "5.7.1 Sending is on hold")
    expect_smtp(test.deliver(mailbox, identity=peer, subject="Inbound while held"), 250)
    with test.imap(mailbox) as client:
        assert client.select("INBOX") == ("OK", [b"1"])
    assert test.api(session, "folders")[0] == 200

    code, rejected = test.api(session, "compose", {**payload, "sendId": secrets.token_hex(16)})
    assert code == 403 and rejected["error"] == "sending_on_hold", rejected
    with db:
        db.execute("UPDATE webmail_records SET due_at=unixepoch() WHERE kind='outbox' AND id=?", (send_id,))
    failed = test.outbox(session, send_id, "failed")
    assert "Sending is on hold" in failed["error"], failed
    ews = suite["create_ews_item"]("SendOnly", to=[peer], subject="Held EWS")
    assert suite["ews_codes"](test.ews(mailbox, ews)) == ["ErrorMessageSubmissionBlocked"]
    eas = suite["eas_send"](suite["eas_mime"](mailbox, peer, subject="Held ActiveSync"), "hold-retry")
    assert suite["eas_result"](test.eas(mailbox, eas)) == 130
    with test.imap(peer) as client:
        assert client.select("INBOX") == ("OK", [b"0"])
    assert test.count(mailbox) == 0
    return mailbox, peer, held_since


def verify_sending_release(test, db, mailbox, peer, held_since):
    assert report(test, mailbox)["account"]["sending_held_since"] == held_since
    expect_smtp(test.deliver(peer, identity=mailbox), 550, "5.7.1 Sending is on hold")
    with db:
        db.execute("""CREATE TRIGGER deny_hold_release BEFORE INSERT ON audit_log
                    WHEN NEW.action='hosted.sending_release' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END""")
    refused = cli(test, "hosted-sending-hold", mailbox, "release", "case-17-reviewed")
    assert refused.returncode != 0
    assert report(test, mailbox)["account"]["sending_held_since"] == held_since
    with db:
        db.execute("DROP TRIGGER deny_hold_release")
    test.provision("held-sender", quota=65_536, daily=4, enabled=False)
    result = cli(test, "hosted-sending-hold", mailbox, "release", "case-17-reviewed")
    assert result.returncode == 0, result.stderr
    status = report(test, mailbox)["account"]
    assert status["access"] == "disabled" and status["sending_held_since"] is None
    test.provision("held-sender", quota=65_536, daily=4)
    eas = suite["eas_send"](suite["eas_mime"](mailbox, peer, subject="Held ActiveSync"), "hold-retry")
    assert suite["eas_result"](test.eas(mailbox, eas)) == 0
    assert test.count(mailbox) == 1
    records = db.execute(
        "SELECT action,actor,details FROM audit_log WHERE target=? AND action IN ('hosted.sending_hold','hosted.sending_release') ORDER BY id",
        (mailbox,),
    ).fetchall()
    actor = f"local-operator:{os.geteuid()}"
    assert [(action, who, json.loads(details)) for action, who, details in records] == [
        ("hosted.sending_hold", actor, {"reason": "case-17"}),
        ("hosted.sending_release", actor, {"reason": "case-17-reviewed"}),
    ], records


def verify_hold_access_windows(test, peer):
    mailbox = test.provision("held-paid")
    revision = 1
    now = int(time.time())
    url = test.private + "/provisioning/v1/mailbox/access"

    def change_window(service_until, read_until, expected_access):
        nonlocal revision
        revision += 1
        window = {"service_until": service_until, "read_until": read_until}
        change = {
            "mailbox": mailbox, "actor": test.specs[mailbox]["actor"],
            "operation_id": secrets.token_hex(16), "revision": revision, "access_window": window,
        }
        status, _, raw = request(url, change, test.auth)
        assert status == 200, (status, raw)
        state = json.loads(raw)
        assert state["access"] == expected_access and state["access_window"] == window, state
        replay_status, _, replay = request(url, change, test.auth)
        assert replay_status == 200 and json.loads(replay) == state, (replay_status, replay)

    def hold(action, case):
        result = cli(test, "hosted-sending-hold", mailbox, action, case)
        assert result.returncode == 0, result.stderr
        return report(test, mailbox)["account"]

    change_window(now + 3600, now + 7200, "full")
    expect_smtp(test.deliver(mailbox, identity=peer, subject="Kept for export"), 250)
    held = hold("place", "paid-read-only")
    change_window(now + 7200, now + 10_800, "full")
    renewed = report(test, mailbox)["account"]
    assert renewed["sending_held_since"] == held["sending_held_since"] is not None
    expect_smtp(test.deliver(peer, identity=mailbox), 550, "5.7.1 Sending is on hold")

    session = test.login(mailbox)
    change_window(now - 30, now + 3600, "read_only")
    released = hold("release", "paid-read-only-reviewed")
    assert released["access"] == "read_only" and released["sending_held_since"] is None
    expect_smtp(test.deliver(peer, identity=mailbox), 550, "5.7.1 Sender mailbox is read-only")
    status, page = test.api(session, "messages?folder=INBOX")
    assert status == 200 and [item["subject"] for item in page["items"]] == ["Kept for export"]

    change_window(now + 3600, now + 7200, "full")
    hold("place", "paid-expired")
    change_window(now - 60, now - 30, "expired")
    released = hold("release", "paid-expired-reviewed")
    assert released["access"] == "expired" and released["sending_held_since"] is None
    assert test.api(session, "folders")[0] == 401
    change_window(now + 7200, now + 10_800, "full")
    expect_smtp(test.deliver(peer, identity=mailbox), 250)


if __name__ == "__main__":
    main()
