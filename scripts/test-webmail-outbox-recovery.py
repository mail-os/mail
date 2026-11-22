#!/usr/bin/env python3
"""Recover interrupted Outbox sends through native HTTPS with no external delivery."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import runpy
import secrets
import sqlite3
import sys
import tempfile
import time
from urllib.parse import urlencode


Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]


def ok(response):
    status, body = response
    assert status == 200, response
    return body


def wait_for(read):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        result = read()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for the interrupted dispatch")


def saved_message(fixture, session, subject, to, bcc=()):
    message = {
        "subject": subject, "text": "Durable Outbox recovery fixture",
        "to": to, "bcc": list(bcc), "draftId": secrets.token_hex(16), "saveToken": secrets.token_hex(16),
    }
    draft = ok(fixture.api(session, "drafts", message))
    return dict(message, draftUid=draft["uid"], draftRevision=draft["revision"],
                sendId=secrets.token_hex(16), delaySeconds=0)


def messages(fixture, session, folder, subject):
    query = urlencode({"folder": folder, "q": subject})
    return ok(fixture.api(session, f"messages?{query}"))["items"]


def replay(fixture, session, message, expected, mailbox, charged):
    replayed = ok(fixture.api(session, "compose", message))
    assert replayed["state"] == expected, replayed
    assert fixture.api(session, "compose", dict(message, text="Different request"))[0] == 409
    assert fixture.count(mailbox) == charged


def all_local(binary, root):
    fixture = Fixture(binary, root, staging=True)
    with fixture.daemon() as daemon, closing(sqlite3.connect(root / "smtp.db")) as db:
        sender = fixture.provision("all-local", daily=1)
        target = fixture.provision("local-target")
        session = fixture.login(sender)
        subject = "Local interruption fixture"
        message = saved_message(fixture, session, subject, [target])
        with db:
            # Leave the durable routing write intact. Prevent the worker from
            # filing Sent or acknowledging completion at this crash boundary.
            db.executescript("""
                CREATE TRIGGER fixture_stop_outbox BEFORE UPDATE OF state ON webmail_records
                WHEN OLD.kind='outbox' AND OLD.state='sending' AND NEW.state<>'sending'
                BEGIN SELECT RAISE(ABORT, 'fixture interrupted Outbox checkpoint'); END;
                CREATE TRIGGER fixture_stop_sent BEFORE INSERT ON accepted_mail
                WHEN NEW.id IN (SELECT json_extract(payload,'$.dispatch.sent_delivery_id')
                                FROM webmail_records WHERE kind='outbox' AND state='sending')
                BEGIN SELECT RAISE(ABORT, 'fixture interrupted Sent admission'); END;
                CREATE TRIGGER fixture_stop_draft BEFORE DELETE ON webmail_records
                WHEN OLD.kind='draft' AND OLD.state='queued'
                BEGIN SELECT RAISE(ABORT, 'fixture interrupted draft cleanup'); END;
            """)
        ok(fixture.api(session, "compose", message))
        wait_for(lambda: messages(fixture, session, "Trash", subject))
        assert len(messages(fixture, fixture.login(target), "INBOX", subject)) == 1
        assert not messages(fixture, session, "Sent", subject)
        assert ok(fixture.api(session, "outbox/" + message["sendId"]))["state"] == "sending"
        daemon.kill()
        daemon.wait()
        with db:
            # An old receipt still belongs to its unresolved Outbox dispatch.
            db.execute("""UPDATE accepted_mail SET accepted_at=1
                          WHERE id=(SELECT json_extract(payload,'$.dispatch.delivery_id')
                                    FROM webmail_records WHERE id=?)""", (message["sendId"],))
            db.executescript("DROP TRIGGER fixture_stop_outbox; DROP TRIGGER fixture_stop_sent; DROP TRIGGER fixture_stop_draft;")

    for _ in range(2):
        with fixture.daemon():
            session = fixture.login(sender)
            recovered = fixture.outbox(session, message["sendId"], "sent")
            result = recovered["result"]
            assert result["delivered"] == 1 and result["sent_saved"] and not result["failed"] and not result["unknown"], recovered
            sent = messages(fixture, session, "Sent", subject)
            inbox = messages(fixture, fixture.login(target), "INBOX", subject)
            assert len(sent) == len(inbox) == 1
            assert sent[0]["message_id"] == inbox[0]["message_id"] == result["message_id"], (sent, inbox)
            assert sent[0]["date"] == inbox[0]["date"], (sent, inbox)
            assert len(messages(fixture, session, "Trash", subject)) == 1
            assert fixture.api(session, f'drafts?uid={message["draftUid"]}')[0] == 404
            replay(fixture, session, message, "sent", sender, 1)
    print("Verified all-local recovery, one Sent copy, one draft cleanup, and unchanged allowance over two restarts.")


def install_stub(root):
    aws = root / "aws"
    aws.write_text(f"""#!{sys.executable}
import json
import os
from pathlib import Path
import sys
import time

assert sys.argv[1:3] == ["ses", "send-raw-email"]
payload = Path(sys.argv[-1].removeprefix("file://"))
recipient, = json.loads(payload.read_text())["Destinations"]
with Path("fixture-ses-attempts").open("a") as log:
    print(recipient, file=log)
if recipient == "uncertain@remote.example.test":
    parent = os.getppid()
    # This subprocess must terminate even if the fixture parent is interrupted.
    for _ in range(160):
        if os.getppid() != parent:
            break
        time.sleep(0.05)
    payload.unlink(missing_ok=True)
    sys.exit(3)
if recipient == "refused@remote.example.test":
    sys.exit(1)
assert recipient == "confirmed@remote.example.test", recipient
""")
    aws.chmod(0o700)


def mixed_delivery(binary, root):
    fixture = Fixture(binary, root, staging=True)
    install_stub(root)
    fixture.env.update(PATH=str(root) + os.pathsep + fixture.env["PATH"], SMTP_DELIVERY_METHOD="ses")
    confirmed = "confirmed@remote.example.test"
    refused = "refused@remote.example.test"
    uncertain = "uncertain@remote.example.test"
    untouched = "untouched@remote.example.test"
    attempts = root / "fixture-ses-attempts"
    with fixture.daemon() as daemon:
        sender = fixture.provision("mixed-sender", daily=5)
        target = fixture.provision("mixed-local")
        session = fixture.login(sender)
        subject = "Mixed interruption fixture"
        message = saved_message(fixture, session, subject, [confirmed, refused, uncertain, untouched], bcc=[target])
        ok(fixture.api(session, "compose", message))
        wait_for(lambda: attempts.exists() and uncertain in attempts.read_text())
        assert len(messages(fixture, fixture.login(target), "INBOX", subject)) == 1
        assert not messages(fixture, session, "Sent", subject)
        daemon.kill()
        daemon.wait()

    with fixture.daemon():
        session = fixture.login(sender)
        recovered = fixture.outbox(session, message["sendId"], "unknown")
        result = recovered["result"]
        assert result["delivered"] == 2 and result["sent_saved"], recovered
        assert result["failed"] == [refused, untouched] and result["unknown"] == [uncertain], recovered
        assert attempts.read_text().splitlines() == [confirmed, refused, uncertain]
        sent, = messages(fixture, session, "Sent", subject)
        detail = ok(fixture.api(session, f'messages/{sent["uid"]}?folder=Sent'))
        assert detail["message_id"] == result["message_id"] and detail["bcc"] == target, detail
        replay(fixture, session, message, "unknown", sender, 5)
        path = f'outbox/{message["sendId"]}'
        resolved = ok(fixture.api(session, path, {"reviewed": True}, method="PATCH"))
        assert resolved["state"] == "resolved", resolved
        draft = ok(fixture.api(session, f'drafts?uid={message["draftUid"]}'))
        # The saved retry draft contains neither the confirmed remote recipient nor the local Bcc.
        assert draft["message"]["to"] == [refused, uncertain, untouched] and not draft["message"]["bcc"], draft
        repeated = ok(fixture.api(session, path, {"reviewed": True}, method="PATCH"))
        assert repeated["state"] == "resolved" and repeated["result"] == resolved["result"]

    with fixture.daemon():
        session = fixture.login(sender)
        replay(fixture, session, message, "resolved", sender, 5)
        assert len(messages(fixture, session, "Sent", subject)) == 1
        assert len(messages(fixture, fixture.login(target), "INBOX", subject)) == 1
        assert attempts.read_text().splitlines() == [confirmed, refused, uncertain]
    print("Verified an interrupted mixed send preserves confirmed, refused, unattempted, and uncertain recipient outcomes without redispatch.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve()
    with tempfile.TemporaryDirectory(prefix="mail-outbox-recovery-") as directory:
        for scenario in (all_local, mixed_delivery):
            root = Path(directory) / scenario.__name__
            root.mkdir()
            scenario(binary, root)


if __name__ == "__main__":
    main()
