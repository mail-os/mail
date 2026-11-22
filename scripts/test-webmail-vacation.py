#!/usr/bin/env python3
"""Native HTTPS settings and SMTP/webmail automatic reply regression."""

import argparse
import base64
from contextlib import closing
from email import policy
from email.parser import BytesParser
import json
from pathlib import Path
import runpy
import sqlite3
import subprocess
import tempfile
import time


forwarding = runpy.run_path(str(Path(__file__).with_name("test-webmail-forwarding.py")))
Fixture = forwarding["Fixture"]
eventually = forwarding["eventually"]
fake_ses = forwarding["fake_ses"]
parser = BytesParser(policy=policy.default)
SUBJECT = "Away from the studio — 戻ります"
BODY = "Thanks for your message.\nI'll reply when I'm back on Tuesday."
AUTO = "Auto: " + SUBJECT


def run(binary, verify_inbound_auth):
    with tempfile.TemporaryDirectory(prefix="mail-vacation-") as directory:
        root = Path(directory)
        fixture = Fixture(binary, root, staging=True)
        fake_ses(root)
        fixture.env.update(SMTP_DELIVERY_METHOD="ses", PATH=f"{root}:{fixture.env['PATH']}")
        if verify_inbound_auth:
            fixture.env["SMTP_ANTISPAM_CHECK"] = "true"

        def web(session, path, data=None, method=None, status=200):
            code, result = fixture.api(session, path, data, method)
            assert code == status, (path, method, code, result)
            return result

        def sql(query, values=()):
            with closing(sqlite3.connect(root / "smtp.db")) as db, db:
                return db.execute(query, values).fetchall()

        def save(session, revision, *, expected=200, **overrides):
            data = dict(enabled=True, subject=SUBJECT, body=BODY, startsAt=None, endsAt=None, revision=revision)
            return web(session, "vacation", {**data, **overrides}, "PUT", status=expected)

        def set_review(session, enabled):
            return web(session, "sender-review", {"setting": "enable" if enabled else "disable"}, "PUT")

        def mail(client, sender, recipient, name, *, displayed=None, extra="", body="Private original text.", bdat=False, author=None):
            message_id = f"<{name}@vacation.example.test>"
            raw = (f"From: {author or sender or 'mailer-daemon@vacation.example.test'}\r\n"
                   f"To: {displayed or recipient}\r\nSubject: {name}\r\nMessage-ID: {message_id}\r\n"
                   f"{extra}\r\n{body}\r\n").encode()
            assert client.mail(sender)[0] == 250
            assert client.rcpt(recipient)[0] == 250
            if bdat:
                client.send(f"BDAT {len(raw)} LAST\r\n".encode() + raw)
                code, reply = client.getreply()
            else:
                code, reply = client.data(raw)
            assert code == 250, (code, reply)
            return message_id

        def messages(user, subject, folders=("new", "cur")):
            return [msg for folder in folders for path in (root / "mail" / user / folder).glob("*")
                    if path.is_file() and (msg := parser.parsebytes(path.read_bytes()))["Subject"] == subject]

        def verify_reply(message, owner, sender, parent):
            assert message["From"] == owner and message["To"] == sender, (message["From"], message["To"])
            assert message["Auto-Submitted"] == "auto-replied" and message["X-Auto-Response-Suppress"] == "All"
            if parent:
                assert message["In-Reply-To"] == parent and message["References"] == parent
            assert message["Reply-To"] is None
            assert message.get_content().replace("\r\n", "\n").rstrip() == BODY
            assert message.get_content_type() == "text/plain" and not list(message.iter_attachments())

        def remote_messages(recipient):
            path = root / "ses.jsonl"
            if not path.exists():
                return []
            captures = [json.loads(line) for line in path.read_bytes().splitlines(keepends=True) if line.endswith(b"\n")]
            return [(record["Source"], parser.parsebytes(base64.b64decode(record["RawMessage"]["Data"])))
                    for record in captures if record["Destinations"] == [recipient]]

        with fixture.daemon():
            owner = fixture.provision("away", daily=4)
            sender = fixture.provision("sender", quota=2 * 1024 * 1024, daily=60)
            other = fixture.provision("other", daily=40)
            blocked = fixture.provision("blocked-publication")
            robot = fixture.provision("no-reply")
            remote = "external@vacation.example.test"
            if not verify_inbound_auth:
                subprocess.run([str(binary), "user:local", "create", remote, "--password-stdin"], input=(fixture.password + "\n").encode(),
                               cwd=root, env=fixture.env, check=True, capture_output=True)
            account, sender_session, other_session, blocked_session = map(fixture.login, (owner, sender, other, blocked))
            for session in (account, sender_session, other_session, blocked_session):
                set_review(session, False)
            assert web(account, "vacation") == {"enabled": False, "subject": "Out of office", "body": "", "startsAt": None, "endsAt": None, "revision": 0}
            web({}, "vacation", status=401)
            save({**account, "Origin": "https://elsewhere.example.test"}, 0, expected=403)
            save({**other_session, "X-Webmail-Account": owner}, 0, expected=409)
            save(account, 0, expected=400, startsAt=100, endsAt=100)
            save(account, 0, expected=400, subject="Subject\r\nBcc: sink@example.test")
            save(account, 0, expected=400, body="")
            save(account, 0, expected=400, body="x" * 8193)
            now = int(time.time())
            pending = save(account, 0, startsAt=now+3600, endsAt=now+7200)
            assert pending["revision"] == 1 and pending["startsAt"] == now+3600
            assert not web(other_session, "vacation")["enabled"]
            with fixture.smtp(sender) as client:
                mail(client, sender, owner, "before-window")
            assert messages(owner, "before-window") and not messages(sender, AUTO)
            active = save(account, 1, startsAt=now - 10, endsAt=now+3600)
            assert active["revision"] == 2
            save(account, 1, expected=412, enabled=False)
            with fixture.smtp() as client:
                mail(client, sender, owner, "forged-author", extra="Authentication-Results: forged; dmarc=pass\r\n")
                mail(client, "", owner, "null-return-path")
            with fixture.smtp(robot) as client:
                mail(client, robot, owner, "daemon-mail")
            with fixture.smtp(sender) as client:
                mail(client, sender, owner, "blind-copy", displayed=other)
                for name, header in {
                    "auto-submitted": "Auto-Submitted:\r\n auto-replied\r\n",
                    "mailing-list": "List-Id: <news.example.test>\r\n",
                    "bulk-precedence": "Precedence: BuLk\r\n",
                    "suppressed-oof": "X-Auto-Response-Suppress: DR, OOF\r\n",
                    "delivery-report": "Content-Type: multipart/report; report-type=delivery-status\r\n",
                    "forwarded-copy": "X-Mail-Forwarded: yes\r\n",
                }.items():
                    mail(client, sender, owner, name, extra=header)
            assert not messages(sender, AUTO) and not messages(robot, AUTO) and fixture.count(owner) == 0
            set_review(account, True)
            with fixture.smtp(sender) as client:
                mail(client, sender, owner, "screened-sender")
            held, = web(account, "sender-review")["items"]
            assert held["subject"] == "screened-sender" and not messages(sender, AUTO)
            web({**account, "If-Match": held["revision"]}, "sender-review/decision",
                {"reference": held["reference"], "action": "allow", "rule_revision": held["rule_revision"]}, "POST")
            assert not messages(sender, AUTO)
            set_review(account, False)

            with fixture.smtp(sender) as client:
                parent = mail(client, sender, owner, "first-direct", displayed=other, bdat=True,
                              extra=f'Cc: "Studio, Alex"\r\n <{owner}>\r\nAuto-Submitted: no\r\nReply-To: {other}\r\n',
                              body="List-Id: only body text\r\nNever include this in the reply.")
                mail(client, sender, owner, "repeat-direct")
            first, = messages(sender, AUTO)
            verify_reply(first, owner, sender, parent)
            assert messages(owner, "first-direct") and not messages(other, AUTO)
            assert fixture.count(owner) == 1
            # The pending reply waits for primary publication, and survives a restart.
            blocker = root / "mail" / blocked / "new"
            blocker.parent.mkdir(parents=True, exist_ok=True)
            blocker.write_bytes(b"fixture blocks the Inbox directory")
            save(blocked_session, 0)
            with fixture.smtp(other) as client:
                waiting_parent = mail(client, other, blocked, "awaiting-publication")
            assert not messages(other, AUTO)
            assert sql("SELECT COUNT(*) FROM accepted_mail_targets WHERE recipient=? AND reply_author=? AND outcome='pending' AND forward_after IS NOT NULL", (other, blocked)) == [(1,)]

        blocker.unlink()
        with fixture.daemon():
            account, other_session = map(fixture.login, (owner, other))
            recovered, = eventually(lambda: messages(other, AUTO))
            verify_reply(recovered, blocked, other, waiting_parent)
            assert web(account, "vacation")["enabled"]
            with fixture.smtp(sender) as client:
                mail(client, sender, owner, "after-restart")
            assert len(messages(sender, AUTO)) == 1 and fixture.count(owner) == 1

            web(other_session, "compose", {"to": [owner], "subject": "Webmail signal", "text": "Message from webmail."}, "POST")
            office, = [item for item in messages(other, AUTO) if item["From"] == owner]
            verify_reply(office, owner, other, None)
            assert fixture.count(owner) == 2

            # Set the first cooldown to the exact end of its seven-day window.
            sql("UPDATE mailbox_vacation_sends SET accepted_at=unixepoch()-604800 WHERE correspondent=? AND user_id=(SELECT id FROM users WHERE username=?)", (sender, owner))
            with fixture.smtp(sender) as client:
                mail(client, sender, owner, "cooldown-complete")
            assert len(messages(sender, AUTO)) == 2 and fixture.count(owner) == 3
            if verify_inbound_auth:
                with fixture.smtp() as client:
                    mail(client, "different@vacation.example.test", owner, "unaligned-reverse-path", author=remote)
                assert fixture.count(owner) == 3 and not remote_messages("different@vacation.example.test")
            with fixture.smtp(None if verify_inbound_auth else remote) as client:
                external_parent = mail(client, remote, owner, "external-reverse-path")
            (envelope, reply), = eventually(lambda: remote_messages(remote))
            assert envelope == "no-reply@" + owner.split("@")[1]
            verify_reply(reply, owner, remote, external_parent)
            assert fixture.count(owner) == 4
            with fixture.smtp(robot) as client:
                mail(client, robot, owner, "still-ignore-robot")
            sql("DELETE FROM mailbox_vacation_sends WHERE correspondent=? AND user_id=(SELECT id FROM users WHERE username=?)", (sender, owner))
            with fixture.smtp(sender) as client:
                mail(client, sender, owner, "allowance-exhausted")
            assert messages(owner, "allowance-exhausted") and len(messages(sender, AUTO)) == 2
            assert sql("SELECT COUNT(*) FROM accepted_mail_targets WHERE outcome='vacation_allowance' AND reply_author=?", (owner,)) == [(1,)]

            # Distinguish the end boundary and manual disable from quota refusal.
            sql("DELETE FROM hosted_sending_usage WHERE user_id=(SELECT id FROM users WHERE username=?)", (owner,))
            expired = save(account, 2, endsAt=int(time.time()))
            with fixture.smtp(sender) as client:
                mail(client, sender, owner, "after-end")
            assert expired["enabled"] and messages(owner, "after-end") and fixture.count(owner) == 0
            assert save(account, 3, enabled=False)["enabled"] is False
            with fixture.smtp(sender) as client:
                mail(client, sender, owner, "after-disable")
            assert messages(owner, "after-disable") and len(messages(sender, AUTO)) == 2

        if verify_inbound_auth:
            fixture.env.update(SMTP_SPAM_FILTER="true", SMTP_SPAM_JUNK_SCORE="0.1", SMTP_SPAM_REJECT_SCORE="99")
            with fixture.daemon():
                account = fixture.login(owner)
                save(account, 4)
                junk_sender = "parcel@vacation.example.test"
                with fixture.smtp() as client:
                    mail(client, junk_sender, owner, "parcel-fee", body=
                         "DHL Express Shipment Release Information. A fee must be paid before final delivery. "
                         "Total amount due $3.35. Status: Awaiting payment at the local facility.")
                junk, = messages(owner, "parcel-fee", folders=("Junk",))
                assert "dmarc=pass" in str(junk["Authentication-Results"])
                assert fixture.count(owner) == 0 and not remote_messages(junk_sender)
    print("Verified vacation settings, scheduled windows, loop suppression, hosted charges, and journaled local and remote replies.")


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("binary", type=Path)
    cli.add_argument("--verify-inbound-auth", action="store_true",
                     help="Exercise unauthenticated SMTP from vacation.example.test using a disposable SPF/DMARC DNS resolver.")
    args = cli.parse_args()
    run(args.binary.resolve(), args.verify_inbound_auth)
