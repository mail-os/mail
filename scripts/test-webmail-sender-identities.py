#!/usr/bin/env python3
"""Exercise delegated From addresses at compose, admission, and Outbox recovery."""

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import runpy
import sqlite3
import tempfile
import time


scheduled = runpy.run_path(str(Path(__file__).with_name("test-webmail-scheduled-send.py")))
operator = runpy.run_path(str(Path(__file__).with_name("test-webmail-teams.py")))
recovery = runpy.run_path(str(Path(__file__).with_name("test-webmail-outbox-recovery.py")))
Fixture, new_id, save, draft = (scheduled[name] for name in ("Fixture", "new_id", "save", "draft"))
command, expect = (operator[name] for name in ("command", "expect"))
messages, wait_for = (recovery[name] for name in ("messages", "wait_for"))


def grant(test, action, team, studio, writer):
    command(test, "team", action, team, studio, writer, "sender")


def item_route(payload):
    return "outbox/" + payload["sendId"]


def stored_id(db, mailbox):
    return str(db.execute("SELECT id FROM users WHERE username=?", (mailbox,)).fetchone()[0])


def deliver_now(db, payload):
    with db:
        db.execute("UPDATE webmail_records SET due_at=unixepoch() WHERE kind='outbox' AND id=?", (payload["sendId"],))


def message_detail(test, session, folder, subject):
    only, = messages(test, session, folder, subject)
    return expect(test.api(session, f'messages/{only["uid"]}?folder={folder}'))


def verify_grant(test, db, studio, writer, target):
    identities = "sender-identities"
    user = test.login(writer)
    foreign = test.login(target)
    identity = stored_id(db, studio)
    expect(test.api({}, identities), 401)
    assert expect(test.api(foreign, identities)) == []
    assert expect(test.api(user, identities)) == [{"id": identity, "address": studio}]
    grant(test, "revoke", "second", studio, writer)
    assert expect(test.api(user, identities)) == [{"id": identity, "address": studio}]
    for selection in (identity, stored_id(db, writer)):
        rejected = expect(test.api(foreign, "compose", {"to": [studio], "senderId": selection, "text": "Denied"}), 403)
        assert rejected["error"] == "sender_identity_unavailable"
    for selection in ("0", "0002", "1@bad", "9223372036854775808"):
        expect(test.api(user, "compose", {"to": [target], "senderId": selection, "text": "Rejected"}), 400)

    saved = save(test, user, target, "Delegated message", text="From a shared address", senderId=identity)
    assert draft(test, user, saved)["message"]["senderId"] == identity
    queued = dict(saved, sendId=new_id(), scheduleAt=int(time.time()) + 3600, bcc=[studio])
    expect(test.api(user, "compose", queued))
    deliver_now(db, queued)
    sent = test.outbox(user, queued["sendId"], "sent")
    assert sent["message"]["senderId"] == identity and sent["result"]["delivered"] == 2
    for mailbox in (target, studio):
        copy = message_detail(test, test.login(mailbox), "INBOX", queued["subject"])
        assert copy["from"] == studio and not copy["bcc"]
    filed = message_detail(test, user, "Sent", queued["subject"])
    assert filed["from"] == studio and filed["bcc"] == studio
    assert messages(test, test.login(studio), "Sent", queued["subject"]) == []
    assert test.count(writer) == 2 and test.count(studio) == 0
    return queued


def verify_revocation(test, db, studio, writer, target, sent):
    user = test.login(writer)
    identity = sent["senderId"]
    saved = save(test, user, target, "Revoked scheduled message", text="Keep this draft", senderId=identity)
    scheduled_send = dict(saved, sendId=new_id(), scheduleAt=int(time.time()) + 3600)
    expect(test.api(user, "compose", scheduled_send))
    grant(test, "revoke", "studio", studio, writer)
    assert expect(test.api(user, "sender-identities")) == []
    assert expect(test.api(user, "compose", sent))["state"] == "sent"
    expect(test.api(user, "compose", dict(sent, senderId=None)), 409)
    expect(test.api(user, "compose", dict(scheduled_send, sendId=new_id())), 403, "sender_identity_unavailable")
    deliver_now(db, scheduled_send)
    failed = test.outbox(user, scheduled_send["sendId"], "failed")
    assert "From address is no longer available" in failed["error"] and failed["result"] is None
    thawed = draft(test, user, saved)
    assert thawed["state"] == "saved" and thawed["message"]["senderId"] == identity
    assert thawed["message"]["text"] == saved["text"]
    assert test.count(writer) == 2 and test.count(studio) == 0
    assert not messages(test, test.login(target), "INBOX", scheduled_send["subject"])

    # Force the grant to disappear after service-level resolution, as the
    # Outbox persists its journal key just before the admission transaction.
    grant(test, "grant", "studio", studio, writer)
    racing = {"subject": "Revocation at admission", "to": [target], "senderId": identity,
              "sendId": new_id(), "delaySeconds": 0}
    with db:
        db.execute("""CREATE TRIGGER fixture_revoke_at_admission AFTER UPDATE OF payload ON webmail_records
                      WHEN NEW.kind='outbox' AND NEW.state='sending'
                      AND json_extract(NEW.payload,'$.dispatch.from_address') IS NOT NULL
                      BEGIN DELETE FROM mail_team_grants WHERE scope='sender'; END""")
    expect(test.api(user, "compose", racing))
    raced = test.outbox(user, racing["sendId"], "failed")
    assert "From address is no longer available" in raced["error"]
    assert not messages(test, test.login(target), "INBOX", racing["subject"])
    assert test.count(writer) == 2
    with db:
        db.execute("DROP TRIGGER fixture_revoke_at_admission")

    # The actor can change the retained draft to their own address. Untrusted
    # free-form From fields from older clients have no effect on the envelope.
    changed = dict(thawed["message"], senderId=None, saveToken=new_id(), draftRevision=thawed["revision"])
    revision = expect(test.api(user, "drafts", changed))["revision"]
    retry = dict(changed, draftRevision=revision, sendId=new_id(), delaySeconds=0, **{"from": studio})
    expect(test.api(user, "compose", retry))
    assert test.outbox(user, retry["sendId"], "sent")["result"]["delivered"] == 1
    assert message_detail(test, test.login(target), "INBOX", retry["subject"])["from"] == writer
    assert test.count(writer) == 3


def interrupt(test, db, studio, writer, target):
    user = test.login(writer)
    grant(test, "grant", "studio", studio, writer)
    queued = {"subject": "Recover delegated Sent", "to": [target], "senderId": stored_id(db, studio),
              "sendId": new_id(), "delaySeconds": 0}
    with db:
        db.executescript("""
            CREATE TRIGGER fixture_interrupt_outbox BEFORE UPDATE OF state ON webmail_records
            WHEN OLD.kind='outbox' AND OLD.state='sending' AND NEW.state<>'sending'
            BEGIN SELECT RAISE(ABORT,'fixture interrupted terminal update'); END;
            CREATE TRIGGER fixture_interrupt_sent BEFORE INSERT ON accepted_mail
            WHEN NEW.id IN (SELECT json_extract(payload,'$.dispatch.sent_delivery_id')
                            FROM webmail_records WHERE kind='outbox' AND state='sending')
            BEGIN SELECT RAISE(ABORT,'fixture interrupted Sent copy'); END;
        """)
    expect(test.api(user, "compose", queued))
    wait_for(lambda: messages(test, test.login(target), "INBOX", queued["subject"]))
    assert expect(test.api(user, item_route(queued)))["state"] == "sending"
    assert not messages(test, user, "Sent", queued["subject"])
    return queued


def verify_legacy_replay(test, db, writer, target):
    user = test.login(writer)
    payload = {"to": [target], "text": "Replay a receipt from the previous server", "subject": "Legacy receipt",
               "sendId": new_id(), "scheduleAt": int(time.time()) + 3600, "clearFollowUp": True}
    pending = expect(test.api(user, "compose", payload))
    legacy = pending["message"]
    del legacy["senderId"]
    del legacy["sharedReply"]
    legacy.pop("externalReview", None)
    checksum = hashlib.sha256(json.dumps(legacy, separators=(",", ":")).encode()).hexdigest()
    deliver_now(db, payload)
    test.outbox(user, payload["sendId"], "sent")
    with db:
        db.execute("""UPDATE webmail_records SET payload=json_set(payload,'$.request_hash',?)
                      WHERE kind='outbox' AND id=?""", (checksum, payload["sendId"]))
    assert expect(test.api(user, "compose", payload))["state"] == "sent"


def verify_direct_send(test, db, studio, writer, target):
    user = test.login(writer)
    grant(test, "grant", "studio", studio, writer)
    payload = {"subject": "Direct delegated send", "to": [target], "senderId": stored_id(db, studio)}
    charged = test.count(writer)
    local_part = studio.split("@", 1)[0]
    test.provision(local_part, enabled=False)
    assert expect(test.api(user, "sender-identities")) == []
    expect(test.api(user, "compose", payload), 403, "sender_identity_unavailable")
    assert test.count(writer) == charged
    test.provision(local_part, enabled=True)
    assert expect(test.api(user, "compose", payload))["delivered"] == 1
    assert message_detail(test, test.login(target), "INBOX", payload["subject"])["from"] == studio
    assert test.count(writer) == charged + 1 and test.count(studio) == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-delegated-sender-", dir="/tmp") as directory:
        root = Path(directory)
        test = Fixture(args.binary.resolve(strict=True), root, staging=True)
        with test.daemon(), closing(sqlite3.connect(root / "smtp.db")) as db:
            studio, writer, target = (test.provision(name) for name in ("studio", "writer", "target"))
            for team in ("studio", "second"):
                command(test, "team", "create", team, "Studio", studio)
                command(test, "team", "member", team, writer, "member")
                grant(test, "grant", team, studio, writer)
            sent = verify_grant(test, db, studio, writer, target)
            verify_revocation(test, db, studio, writer, target, sent)
            queued = interrupt(test, db, studio, writer, target)
        with closing(sqlite3.connect(root / "smtp.db")) as db:
            db.executescript("DROP TRIGGER fixture_interrupt_outbox; DROP TRIGGER fixture_interrupt_sent;")
        grant(test, "revoke", "studio", studio, writer)
        with test.daemon(), closing(sqlite3.connect(root / "smtp.db")) as db:
            user = test.login(writer)
            item = test.outbox(user, queued["sendId"], "sent")
            assert item["result"]["delivered"] == 1 and item["result"]["sent_saved"]
            assert message_detail(test, user, "Sent", queued["subject"])["from"] == studio
            assert expect(test.api(user, "compose", queued))["state"] == "sent"
            assert test.count(writer) == 4 and test.count(studio) == 0
            verify_legacy_replay(test, db, writer, target)
            verify_direct_send(test, db, studio, writer, target)
    print("Verified delegated addresses, actor quotas, Bcc privacy, revoked schedules, atomic admission, Sent recovery, and legacy replay over native HTTPS.")


if __name__ == "__main__":
    main()
