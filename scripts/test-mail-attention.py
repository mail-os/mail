#!/usr/bin/env python3
"""Verify the reply queue and reminder workflow against native TLS listeners."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, ExitStack
from pathlib import Path
import json
import runpy
import sqlite3
import subprocess
import tempfile
from time import time
from urllib.parse import urlencode
import uuid


scripts = Path(__file__).resolve().parent
fixture = runpy.run_path(str(scripts / "test-hosted-limits.py"))
Fixture = fixture["Fixture"]
request = fixture["request"]
expect_smtp = fixture["expect_smtp"]
routing = runpy.run_path(str(scripts / "test-local-routing.py"))
eventually = routing["eventually"]


def verify(candidate, previous, browser, webhook_ip):
    with tempfile.TemporaryDirectory(prefix="mail-attention-") as directory, ExitStack() as stack:
        test = Fixture(previous or candidate, Path(directory), staging=True)
        webhook = stack.enter_context(routing["listener"](webhook_ip)) if webhook_ip else None
        if webhook:
            test.env.update(SMTP_WEBHOOK_ENABLED="true",
                            SMTP_WEBHOOK_URL=f"http://{webhook_ip}:{webhook.server_port}/hook")

        def api(session, path, payload=None, method=None, expected=200, extra=None):
            status, _, raw = request(test.webmail + "/webmail/api/" + path, payload,
                                     dict(session, **(extra or {})), method, test.tls_context)
            parsed = json.loads(raw)
            assert status == expected, (path, status, parsed)
            return parsed

        def delivery(recipient, author, subject, *, parent=None, automatic=False):
            msgid = f"<{uuid.uuid4()}@hosted.example.test>"
            headers = [f"From: {author}", f"To: {recipient}", f"Subject: {subject}", f"Message-ID: {msgid}"]
            if parent:
                headers.extend(["In-Reply-To:\r\n " + parent, "References: " + parent])
            if automatic:
                headers.append("Auto-Submitted: auto-replied")
            mime = ("\r\n".join(headers) + "\r\n\r\nMail workflow fixture.\r\n").encode()
            with test.smtp(author) as smtp:
                assert smtp.mail(author)[0] == smtp.rcpt(recipient)[0] == 250
                expect_smtp(smtp.data(mime), 250)
            return msgid

        def rows(session, folder="INBOX", view=None, **params):
            query = dict(folder=folder, **params)
            if view:
                query["attention"] = view
            return api(session, "messages?" + urlencode(query))

        def subjects(session, folder="INBOX", view=None, **params):
            return {row["subject"]: row for row in rows(session, folder, view, **params)["items"]}

        def detail(session, item):
            return api(session, "messages/ref/" + item["reference"])

        def mark(session, item, kind, enabled=True, deadline=0, expected=200, extra=None):
            return api(session, "attention", dict(reference=item["reference"], kind=kind,
                       enabled=enabled, deadline=deadline), "PUT", expected,
                       dict({"If-Match": item["revision"]}, **(extra or {})))

        def move(session, item, folder):
            return api(session, "messages/ref/" + item["reference"], {"folder": folder}, "PUT",
                       extra={"If-Match": item["revision"]})

        def sent(session, to, subject):
            api(session, "compose", {"to": [to], "subject": subject, "text": "Can you reply?"}, "POST")
            return detail(session, subjects(session, "Sent")[subject])

        def queue(session, item, to, subject, delay):
            send_id = str(uuid.uuid4())
            payload = {"to": [to] if isinstance(to, str) else to,
                       "subject": subject, "text": "Here is my reply.", "sendId": send_id,
                       "delaySeconds": delay, "inReplyTo": detail(session, item)["message_id"],
                       "replyContext": {key: item[key] for key in ("uid", "folder", "reference", "revision")},
                       "clearFollowUp": True}
            return api(session, "compose", payload, "POST")

        def notifications(mailbox):
            with webhook.events_lock:
                return sum(mailbox in payload["recipients"] for _, payload in webhook.events)

        def effects_pending(mailbox):
            with closing(sqlite3.connect(Path(directory) / "smtp.db")) as db:
                return db.execute("""SELECT count(*) FROM accepted_mail_effects e
                    JOIN accepted_mail_targets t USING(delivery_id,ordinal)
                    WHERE t.mailbox=? AND (e.notified=0 OR e.indexed=0)""", (mailbox,)).fetchone()[0]

        if previous:
            with test.daemon():
                legacy = test.provision("legacy", daily=100)
                author = test.provision("author", daily=100)
                delivery(legacy, author, "Existing message")
                legacy_session = test.login(legacy)
                legacy_ref = subjects(legacy_session)["Existing message"]["reference"]
                legacy_payload = {"to": [author], "subject": "Legacy completed send", "text": "Retain the request identity.",
                                  "sendId": str(uuid.uuid4()), "delaySeconds": 0}
                queued = api(legacy_session, "compose", legacy_payload, "POST")
                assert eventually(lambda: api(legacy_session, "outbox/" + queued["id"]), lambda item: item["state"] == "sent")
            test.binary = candidate

        with test.daemon():
            if previous:
                legacy_session = test.login(legacy)
                old = subjects(legacy_session)["Existing message"]
                assert old["reference"] == legacy_ref
                assert mark(legacy_session, old, "saved")["saved"]
                replay = api(legacy_session, "compose", legacy_payload, "POST")
                assert replay["id"] == legacy_payload["sendId"] and replay["state"] == "sent"
            else:
                author = test.provision("author", daily=100)
            owner = test.provision("owner", daily=100)
            other = test.provision("other", daily=100)
            session = test.login(owner)
            other_session = test.login(other)
            root = delivery(owner, author, "Reply to me")
            delivery(owner, author, "Reply to me too")
            original = subjects(session)["Reply to me"]
            second = subjects(session)["Reply to me too"]
            assert mark(session, original, "follow_up")["follow_up"]
            assert mark(session, second, "follow_up")["follow_up"]
            assert mark(session, original, "saved")["saved"]
            mark(other_session, original, "saved", expected=404)
            mark(session, original, "saved", expected=403, extra={"Origin": "https://other.example"})
            assert rows(session, view="follow_up", per_page=1)["total"] == 2
            assert set(subjects(session, view="follow_up", q="Reply to me too")) == {"Reply to me too"}
            assert not subjects(other_session, view="saved")
            assert mark(session, original, "snoozed", deadline=int(time()) - 1, expected=400)["error"] == "invalid_deadline"
            assert mark(session, original, "reminders", deadline=int(time()) + 3600, expected=400)["error"] == "invalid_sent_message"
            until = int(time()) + 900
            assert mark(session, original, "snoozed", deadline=until)["snooze_until"] == until
            assert subjects(session, view="snoozed")["Reply to me"]["attention_deadline"] == until
            assert set(subjects(session)) == {"Reply to me too"}
            assert set(subjects(session, "*")) == {"Reply to me", "Reply to me too"}
            inbox = next(row for row in api(session, "folders") if row["name"] == "INBOX")
            assert (inbox["total"], inbox["unread"]) == (1, 1)
            with test.imap(owner) as imap:
                assert imap.select("INBOX") == ("OK", [b"2"])
            delivery(owner, author, "Automatic response", parent=root, automatic=True)
            assert set(subjects(session)) == {"Reply to me too"}

            pending = sent(session, author, "Waiting for a reply")
            persist = sent(session, author, "Reminder survives restart")
            cancel = sent(session, author, "Cancel this reminder")
            race = sent(session, author, "Concurrent replies target")
            for item in [pending, persist, cancel, race]:
                assert mark(session, item, "reminders", deadline=until)["remind_at"] == until
            assert mark(session, cancel, "reminders", False)["remind_at"] is None
            assert set(subjects(session, view="reminders")) == {item["subject"] for item in (pending, persist, race)}
            delivery(owner, author, "Automatic receipt", parent=pending["message_id"], automatic=True)
            assert detail(session, pending)["attention"]["remind_at"] == until
            delivery(owner, author, "Human reply", parent=pending["message_id"])
            assert detail(session, pending)["attention"]["remind_at"] is None
            mark(session, pending, "reminders", deadline=until, expected=409)
            with ThreadPoolExecutor(max_workers=4) as pool:
                jobs = [pool.submit(delivery, owner, client, name, parent=parent)
                        for client, name, parent in ((author, "Reply race A", root), (other, "Reply race B", root),
                                                     (author, "Reminder race A", race["message_id"]),
                                                     (other, "Reminder race B", race["message_id"]))]
                assert all(job.result() for job in jobs)
            assert not subjects(session, view="snoozed")
            assert detail(session, original)["attention"]["follow_up"]
            assert detail(session, race)["attention"]["remind_at"] is None
            assert {"Reply to me", "Reply race A", "Reply race B"}.issubset(subjects(session))
            assert set(subjects(session, view="reminders")) == {persist["subject"]}

            assert mark(session, original, "muted")["muted"]
            child = delivery(owner, author, "Muted reply", parent=root)
            delivery(owner, author, "Muted grandchild", parent=child)
            assert not subjects(session, q="Muted")
            muted = subjects(session, "*", q="Muted grandchild")["Muted grandchild"]
            assert detail(session, muted)["attention"]["muted"]
            assert not mark(session, muted, "muted", False)["muted"]
            assert "Muted grandchild" in subjects(session)
            assert mark(session, original, "muted")["muted"]
            assert mark(session, second, "snoozed", deadline=until)["snooze_until"] == until
            if webhook:
                watcher = test.provision("mute-webhook", daily=100)
                watched = test.login(watcher)
                thread = delivery(watcher, author, "Webhook baseline")
                eventually(lambda: notifications(watcher), lambda count: count == 1)
                anchor = subjects(watched)["Webhook baseline"]
                mark(watched, anchor, "muted")
                delivery(watcher, author, "Muted webhook", parent=thread)
                eventually(lambda: effects_pending(watcher), lambda count: count == 0)
                assert notifications(watcher) == 1
                mark(watched, anchor, "muted", False)
                delivery(watcher, author, "Unmuted webhook", parent=thread)
                eventually(lambda: notifications(watcher), lambda count: count == 2)
            print("Verified mailbox isolation, flags and counts, wake-on-reply, auto-reply exclusions, mute ancestry, and concurrent replies.")

        with test.daemon():
            session = test.login(owner)
            assert detail(session, persist)["attention"]["remind_at"] == until
            assert detail(session, original)["attention"]["muted"]
            assert detail(session, second)["attention"]["snooze_until"] == until
            assert mark(session, original, "muted", False)["muted"] is False
            assert mark(session, second, "snoozed", False)["snooze_until"] is None
            moved = move(session, original, "Archive")
            assert moved["reference"] == original["reference"]
            mark(session, original, "saved", False, expected=412)
            assert subjects(session, view="saved")["Reply to me"]["folder"] == "Archive"

            archived = detail(session, moved)
            queued = queue(session, archived, author, "Cancelled queued reply", 20)
            api(session, "outbox/" + queued["id"], method="DELETE")
            assert detail(session, archived)["attention"]["follow_up"]
            failed_user = test.provision("disabled", enabled=False)
            queued = queue(session, archived, failed_user, "Failed queued reply", 0)
            status = eventually(lambda: api(session, "outbox/" + queued["id"]),
                                lambda result: result["state"] not in ("pending", "sending"))
            assert status["state"] == "failed", status
            assert detail(session, archived)["attention"]["follow_up"]
            queued = queue(session, archived, [author, failed_user], "Partially delivered reply", 0)
            status = eventually(lambda: api(session, "outbox/" + queued["id"]),
                                lambda result: result["state"] not in ("pending", "sending"))
            assert status["state"] == "partial" and detail(session, archived)["attention"]["follow_up"]
            queued = queue(session, archived, author, "Successful queued reply", 0)
            status = eventually(lambda: api(session, "outbox/" + queued["id"]),
                                lambda result: result["state"] not in ("pending", "sending"))
            assert status["state"] == "sent", status
            assert detail(session, archived)["flags"]["answered"]
            assert not detail(session, archived)["attention"]["follow_up"]
            assert detail(session, archived)["attention"]["saved"]
            assert set(subjects(session, view="follow_up")) == {"Reply to me too"}

            queued = queue(session, second, author, "Late reply with a renewed follow-up", 4)
            mark(session, second, "follow_up", False)
            mark(session, second, "follow_up")
            status = eventually(lambda: api(session, "outbox/" + queued["id"]),
                                lambda result: result["state"] not in ("pending", "sending"))
            assert status["state"] == "sent" and detail(session, second)["attention"]["follow_up"]
            second = detail(session, second)

            expiry = int(time()) + 4
            mark(session, persist, "reminders", deadline=expiry)
            mark(session, second, "snoozed", deadline=expiry)
            assert "Reply to me too" not in subjects(session)
            eventually(lambda: api(session, "attention"), lambda status: status["due_reminders"] == 1)
            assert api(session, "attention?" + urlencode({"reference": persist["reference"]}))["attention"]["remind_at"] == expiry
            assert "Reply to me too" in subjects(session)
            assert not subjects(session, view="snoozed")
            mark(session, persist, "reminders", False)
            assert api(session, "attention")["due_reminders"] == 0
            print("Verified upgrade, persisted deadlines, expiry, cancellation, moves, and clearing Follow-up only after successful delivery.")
            if browser:
                outcome = subprocess.run([str(browser), test.webmail, owner, test.password], check=False)
                assert outcome.returncode == 0, f"Browser driver exited with status {outcome.returncode}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--browser", type=Path)
    parser.add_argument("--webhook-ip", help="documentation IP assigned to loopback in a network namespace")
    args = parser.parse_args()
    verify(args.binary.resolve(), args.previous.resolve() if args.previous else None,
           args.browser.resolve() if args.browser else None, args.webhook_ip)
