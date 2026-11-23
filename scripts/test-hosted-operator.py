#!/usr/bin/env python3
"""Exercise the audited hosted-mailbox status command against a disposable daemon."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import time

suite = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture, expect_smtp = suite["Fixture"], suite["expect_smtp"]


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

    disabled = cli(test, "disable", mailbox)
    assert disabled.returncode == 0, disabled.stderr
    suspended = report(test, mailbox)
    assert not suspended["account"]["enabled"] and suspended["account"]["requested_enabled"], suspended
    assert suspended["account"]["outbound_queue"] == account["outbound_queue"]
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
    print("Verified audited hosted quota, provisioning drift, UTC usage, queue counts and redaction.")


if __name__ == "__main__":
    main()
