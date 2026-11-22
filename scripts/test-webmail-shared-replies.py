#!/usr/bin/env python3
"""Exercise shared reply reservations, delivery admission, and Outbox recovery."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from email.message import EmailMessage
from email.parser import BytesParser
from email import policy
import os
from pathlib import Path
import runpy
import secrets
import sqlite3
import tempfile
from threading import Barrier
import time

teams = runpy.run_path(str(Path(__file__).with_name("test-webmail-teams.py")))
sender_ids = runpy.run_path(str(Path(__file__).with_name("test-webmail-sender-identities.py")))
recovery = runpy.run_path(str(Path(__file__).with_name("test-webmail-outbox-recovery.py")))
Fixture, command, expect = (teams[key] for key in ("Fixture", "command", "expect"))
deliver_now = sender_ids["deliver_now"]
wait_for = recovery["wait_for"]


def new_id():
    return secrets.token_hex(16)


def configure(test, db):
    studio, one, two, observer, sender, target = [test.provision(name) for name in ("studio", "alex", "taylor", "observer", "client", "client-replies")]
    for team, members in (("studio", (one, observer)), ("second", (two,))):
        command(test, "team", "create", team, team, studio)
        for member in members:
            command(test, "team", "member", team, member, "member")
            command(test, "team", "grant", team, studio, member, "mailbox")
            if member != observer:
                command(test, "team", "grant", team, studio, member, "sender")
    sid = db.execute("SELECT id FROM users WHERE username=?", (studio,)).fetchone()[0]
    return studio, one, two, observer, sender, target, sid


def seed(test, studio, sender, target, sid, label):
    message = EmailMessage()
    message["From"] = sender
    message["To"] = studio
    message["Reply-To"] = target
    message["Message-ID"] = f"<{label}@client.example.test>"
    message["Subject"] = f"Studio request {label}"
    message.set_content("Please review the proof.")
    with test.smtp(sender) as client:
        assert client.send_message(message) == {}
    owner = test.login(studio)
    page = expect(test.api(owner, f"shared-inboxes/studio/{sid}"))
    ref, = [row["message"]["reference"] for row in page["items"] if row["message"]["subject"] == message["Subject"]]
    return tuple(f"shared-inboxes/{team}/{sid}/messages/{ref}" for team in ("studio", "second"))


def stage(test, session, path):
    info = expect(test.api(session, path))
    assert info["canReply"] and info["reply"] is None
    request = {"draftId": new_id(), "messageRevision": info["revision"]}
    ack = expect(test.api(session, path + "/reply", request))
    assert expect(test.api(session, path + "/reply", request)) == ack
    draft = expect(test.api(session, f'drafts?uid={ack["uid"]}'))
    return dict(draft["message"], draftUid=ack["uid"], draftRevision=ack["revision"],
                sendId=new_id(), scheduleAt=int(time.time()) + 3600)


def saved(test, session, payload):
    return expect(test.api(session, f'drafts?uid={payload["draftUid"]}'))


def status(test, session, path, expected, actor):
    detail = expect(test.api(session, path))
    assert detail["reply"]["state"] == expected and detail["reply"]["actor"] == actor and not detail["canReply"], detail
    return detail


def verify_race(test, db, fixture):
    studio, one, two, observer, sender, target, sid = fixture
    p1, p2 = seed(test, studio, sender, target, sid, "competition")
    actor1, actor2, reader = (test.login(mailbox) for mailbox in (one, two, observer))
    before = expect(test.api(reader, p1))
    assert not before["canReply"]
    request = {"draftId": new_id(), "messageRevision": before["revision"]}
    expect(test.api(reader, p1 + "/reply", request), 409, "shared_reply_unavailable")
    expect(test.api(test.login(sender), p1 + "/reply", request), 404)
    expect(test.api(dict(actor1, Origin="https://other.example.test"), p1 + "/reply", request), 403)
    payload1, payload2 = stage(test, actor1, p1), stage(test, actor2, p2)
    for payload in (payload1, payload2):
        assert payload["to"] == [target] and payload["senderId"] == str(sid)
        assert payload["inReplyTo"] == "<competition@client.example.test>"
        assert "Please review the proof." in payload["text"]
    expect(test.api(actor1, "compose", dict(payload1, sendId=None, scheduleAt=None)), 400, "shared_reply_queue_required")
    expect(test.api(actor1, "compose", dict(payload1, sharedReply=None)), 409, "shared_reply_unavailable")
    expect(test.api(actor1, "compose", dict(payload1, inReplyTo="")), 409, "shared_reply_unavailable")

    start = Barrier(2)

    def queue(pair):
        session, body = pair
        start.wait(timeout=5)
        return test.api(session, "compose", body)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(queue, [(actor1, payload1), (actor2, payload2)]))
    assert sorted(result[0] for result in results) == [200, 409], results
    if results[0][0] == 200:
        winner, winner_path, winning, who = actor1, p1, payload1, one
        other, other_path, losing, teammate = actor2, p2, payload2, two
    else:
        winner, winner_path, winning, who = actor2, p2, payload2, two
        other, other_path, losing, teammate = actor1, p1, payload1, one
    status(test, winner, winner_path, "queued", who)
    status(test, other, other_path, "queued", None)
    assert saved(test, other, losing)["state"] == "saved"
    assert expect(test.api(winner, "compose", winning))["state"] == "pending"
    cancelled = expect(test.api(winner, "outbox/" + winning["sendId"], method="DELETE"))
    assert cancelled["state"] == "cancelled" and saved(test, winner, winning)["state"] == "saved"
    assert expect(test.api(other, other_path))["canReply"]
    expect(test.api(other, "compose", losing))
    assert test.count(who) == test.count(teammate) == 0
    deliver_now(db, losing)
    result = test.outbox(other, losing["sendId"], "sent")
    assert result["result"]["delivered"] == 1
    assert expect(test.api(other, "compose", losing))["result"] == result["result"]
    status(test, other, other_path, "replied", teammate)
    status(test, winner, winner_path, "replied", None)
    assert test.count(teammate) == 1 and test.count(studio) == 0
    path, = (test.directory / "mail" / target / "new").glob("*.eml*")
    raw = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    assert raw["From"].addresses[0].addr_spec == studio and raw["In-Reply-To"] == "<competition@client.example.test>"
    with db:
        db.execute("DELETE FROM webmail_records WHERE kind='outbox' AND id=?", (losing["sendId"],))
    status(test, other, other_path, "replied", teammate)


def verify_queued_revocation(test, db, fixture):
    studio, one, two, _, sender, target, sid = fixture
    p1, p2 = seed(test, studio, sender, target, sid, "scheduled-revocation")
    actor1, actor2 = test.login(one), test.login(two)
    queued = stage(test, actor1, p1)
    expect(test.api(actor1, "compose", queued))
    command(test, "team", "revoke", "studio", studio, one, "sender")
    item = test.outbox(actor1, queued["sendId"], "cancelled")
    assert "Team access changed" in item["error"]
    assert saved(test, actor1, queued)["state"] == "saved"
    assert expect(test.api(actor1, p1))["reply"] is None and expect(test.api(actor2, p2))["canReply"]
    assert not db.execute("SELECT 1 FROM mail_shared_reply_claims WHERE send_id=?", (queued["sendId"],)).fetchone()
    command(test, "team", "grant", "studio", studio, one, "sender")


def verify_admission_revocation(test, db, fixture):
    studio, one, two, _, sender, target, sid = fixture
    p1, p2 = seed(test, studio, sender, target, sid, "revoked")
    actor1, actor2 = test.login(one), test.login(two)
    first = stage(test, actor1, p1)
    before = test.count(one)
    expect(test.api(actor1, "compose", first))
    with db:
        db.execute("""CREATE TRIGGER fixture_revoke_shared_reply AFTER UPDATE OF payload ON webmail_records
                      WHEN NEW.kind='outbox' AND NEW.state='sending'
                      AND json_extract(NEW.payload,'$.dispatch.from_address') IS NOT NULL
                      BEGIN DELETE FROM mail_team_grants WHERE team_id='studio' AND scope='mailbox'; END""")
    deliver_now(db, first)
    failure = test.outbox(actor1, first["sendId"], "failed")
    assert failure["result"] is None and "shared reply" in failure["error"]
    assert test.count(one) == before and saved(test, actor1, first)["state"] == "saved"
    expect(test.api(actor1, p1), 404)
    assert expect(test.api(actor2, p2))["canReply"]
    with db:
        db.execute("DROP TRIGGER fixture_revoke_shared_reply")
    command(test, "team", "grant", "studio", studio, one, "mailbox")


def verify_recovery(test, fixture):
    studio, one, two, _, sender, target, sid = fixture
    with test.daemon(), closing(sqlite3.connect(test.directory / "smtp.db")) as db:
        p1, p2 = seed(test, studio, sender, target, sid, "restart")
        actor1, actor2 = test.login(one), test.login(two)
        queued = stage(test, actor1, p1)
        expect(test.api(actor1, "compose", queued))
        with db:
            db.execute("UPDATE webmail_records SET state='sending',revision=revision+1 WHERE kind='outbox' AND id=?", (queued["sendId"],))
        status(test, actor2, p2, "sending", None)
    with test.daemon() as daemon:
        actor1, actor2 = test.login(one), test.login(two)
        failed = test.outbox(actor1, queued["sendId"], "failed")
        assert "restarted before admitting" in failed["error"] and saved(test, actor1, queued)["state"] == "saved"
        assert expect(test.api(actor2, p2))["canReply"]

        # Interrupt after SMTP admission has started but before the remote
        # exchange returns. The established SES stub performs no network I/O.
        payload = dict(stage(test, actor2, p2), to=["uncertain@remote.example.test"], scheduleAt=None, delaySeconds=0)
        expect(test.api(actor2, "compose", payload))
        attempts = test.directory / "fixture-ses-attempts"
        wait_for(lambda: attempts.exists() and "uncertain@remote.example.test" in attempts.read_text())
        status(test, actor1, p1, "sending", None)
        daemon.kill()
        daemon.wait()
    return p1, p2, payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-shared-replies-", dir="/tmp") as directory:
        root = Path(directory)
        test = Fixture(args.binary.resolve(strict=True), root, staging=True)
        recovery["install_stub"](root)
        test.env.update(PATH=str(root) + os.pathsep + test.env["PATH"], SMTP_DELIVERY_METHOD="ses")
        with test.daemon(), closing(sqlite3.connect(root / "smtp.db")) as db:
            fixture = configure(test, db)
            verify_race(test, db, fixture)
            verify_queued_revocation(test, db, fixture)
            verify_admission_revocation(test, db, fixture)
        p1, p2, payload = verify_recovery(test, fixture)
        with test.daemon():
            actor1, actor2 = test.login(fixture[1]), test.login(fixture[2])
            outbox = test.outbox(actor2, payload["sendId"], "unknown")
            assert outbox["result"]["unknown"] == ["uncertain@remote.example.test"]
            status(test, actor1, p1, "review", None)
            assert expect(test.api(actor2, "outbox/" + payload["sendId"], {"reviewed": True}, method="PATCH"))["state"] == "resolved"
            status(test, actor2, p2, "review", fixture[2])
            assert (root / "fixture-ses-attempts").read_text().splitlines() == ["uncertain@remote.example.test"]
    print("Verified shared reply privileges, draft identity, scheduling races, cancellation, revocation at admission, receipt retention, and restart recovery.")


if __name__ == "__main__":
    main()
