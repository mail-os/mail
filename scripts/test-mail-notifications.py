#!/usr/bin/env python3
"""Exercise notification privacy, rules, and delivery deduplication over native TLS."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from email.policy import SMTP
import json
from pathlib import Path
import runpy
import sqlite3
import tempfile
from time import sleep
from urllib.parse import urlencode


fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture = fixture["Fixture"]
request = fixture["request"]
expect_smtp = fixture["expect_smtp"]
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/en0AAAAASUVORK5CYII=")


def run(candidate, previous):
    with tempfile.TemporaryDirectory(prefix="mail-notifications-") as tmp:
        test = Fixture(previous or candidate, Path(tmp), staging=True)

        def api(session, path, payload=None, method=None, status=200, extra=None):
            code, _, raw = request(test.webmail + "/webmail/api/" + path, payload,
                                   dict(session, **(extra or {})), method, test.tls_context)
            data = json.loads(raw)
            assert code == status, (path, code, data)
            return data

        def send(owner, sender, subject, marker, *, reply=None, newsletter=False, verified=True, body="Delivery fixture."):
            msg = EmailMessage()
            msg["From"] = sender
            msg["To"] = owner
            msg["Subject"] = subject
            msg["Message-ID"] = f"<{marker}@example.test>"
            if reply:
                msg["In-Reply-To"] = f"<{reply}@example.test>"
                msg["References"] = f"<{reply}@example.test>"
            if newsletter:
                msg["List-Id"] = "Weekly newsletter <weekly.example.test>"
            msg.set_content(body)
            deliver(owner, sender, msg, verified)

        def deliver(owner, sender, msg, verified=True):
            with test.smtp(sender if verified else None) as smtp:
                assert smtp.mail(sender)[0] == smtp.rcpt(owner)[0] == 250
                expect_smtp(smtp.data(msg.as_bytes(policy=SMTP)), 250)

        def get(session, subject, folder="INBOX"):
            listing = api(session, "messages?" + urlencode({"folder": folder, "q": subject}))
            row = next(item for item in listing["items"] if item["subject"] == subject)
            return api(session, "messages/ref/" + row["reference"])

        def rule(session, msg, scope, value, expect=200):
            return api(session, "notifications/rule", dict(reference=msg["reference"], scope=scope, rule=value),
                       "PUT", expect, {"If-Match": msg["revision"]})

        def claim(session, count=None):
            result = api(session, "notifications/claim", method="POST")
            assert set(result) == {"ids"} and all(isinstance(event, int) for event in result["ids"])
            if count is not None:
                assert len(result["ids"]) == count, result
            return result["ids"]

        def enabled(session, value):
            assert api(session, "notifications", {"enabled": value}, "PUT") == {"enabled": value}

        if previous:
            with test.daemon():
                old = test.provision("old-owner")
                author = test.provision("author", daily=100)
                send(old, author, "Mail before upgrade", "upgrade")
                old_ref = get(test.login(old), "Mail before upgrade")["reference"]
            test.binary = candidate

        with test.daemon():
            if previous:
                old_session = test.login(old)
                assert api(old_session, "notifications") == {"enabled": False}
                assert get(old_session, "Mail before upgrade")["reference"] == old_ref
            else:
                author = test.provision("author", daily=100)
            owner = test.provision("owner", daily=100)
            other = test.provision("other", daily=100)
            session = test.login(owner)
            second_tab = test.login(owner)
            other_session = test.login(other)
            assert api(session, "notifications") == {"enabled": False}
            api({}, "notifications/claim", method="POST", status=401)
            api(session, "notifications/claim", method="POST", status=403, extra={"Origin": "https://elsewhere.example"})
            api(session, "notifications", {"enabled": True}, "PUT", 403, {"Origin": "https://elsewhere.example"})
            send(owner, author, "Quiet before opt-in", "root")
            seed = get(session, "Quiet before opt-in")
            assert seed["notifications"] == {"verified_author": author, "sender": "default", "thread": "default"}
            enabled(session, True)
            claim(session, 0)
            send(owner, author, "One notification", "dedupe")
            sleep(1.1)  # Submission synthesizes a different Date for the retry.
            send(owner, author, "One notification", "dedupe")
            with ThreadPoolExecutor(2) as pool:
                ids = [item for bucket in pool.map(claim, [session, second_tab]) for item in bucket]
            assert len(ids) == 1, ids
            claim(session, 0)
            claim(other_session, 0)
            rule(other_session, seed, "thread", "quiet", 404)
            rule(session, seed, "sender", "quiet")
            send(owner, author, "Quiet sender", "quiet-sender")
            claim(session, 0)
            rule(session, seed, "thread", "notify")
            send(owner, author, "Thread overrides sender", "thread-arrival", reply="root")
            claim(session, 1)

            muted = {"reference": seed["reference"], "kind": "muted", "enabled": True}
            api(session, "attention", muted, "PUT", extra={"If-Match": seed["revision"]})
            send(owner, author, "Muted reply", "quiet-mute", reply="root")
            claim(session, 0)
            send(owner, author, "Muted reply to a reply", "quiet-mute-child", reply="quiet-mute")
            claim(session, 0)
            api(session, "attention", dict(muted, enabled=False), "PUT", extra={"If-Match": seed["revision"]})
            rule(session, seed, "sender", "notify")
            send(owner, author, "Quiet after arrival", "late-quiet", reply="thread-arrival")
            rule(session, seed, "thread", "quiet")
            claim(session, 0)
            send(owner, author, "Thread quiet beats sender", "quiet-thread", reply="thread-arrival")
            claim(session, 0)
            descendant = get(session, "Thread overrides sender")
            assert descendant["notifications"]["thread"] == "quiet"
            rule(session, descendant, "thread", "default")
            send(owner, author, "Thread now follows sender", "inherited", reply="root")
            claim(session, 1)
            api(session, "category-settings", {"automatic": True}, "PUT")
            send(owner, author, "Opted-in newsletter alert", "newsletter-1", newsletter=True)
            assert get(session, "Opted-in newsletter alert", "Newsletters")["notifications"]["sender"] == "notify"
            claim(session, 1)
            send(owner, other, "Quiet categorized by default", "newsletter-2", newsletter=True)
            claim(session, 0)
            send(owner, author, "Unverified sender", "unverified", verified=False)
            unknown = get(session, "Unverified sender")
            assert unknown["notifications"]["verified_author"] == ""
            rule(session, unknown, "sender", "quiet", 409)
            claim(session, 1)
            send(owner, author, "Queued before disabling", "disabled")
            enabled(session, False)
            enabled(session, True)
            claim(session, 0)
            send(owner, author, "One notification", "dedupe", body="Different content sharing an identifier.")
            claim(session, 1)
            send(owner, author, "Expired browser notification", "expired")
            with sqlite3.connect(Path(tmp) / "smtp.db") as db:
                db.execute("UPDATE mail_notification_events SET created_at=unixepoch()-181 WHERE claimed_at IS NULL")
            claim(session, 0)

            msg = EmailMessage()
            msg["From"], msg["To"], msg["Subject"] = author, owner, "Embedded image support"
            msg.set_content("Plain version.")
            msg.add_alternative('<p>Formatted</p><img src="cid:card@example.test">', subtype="html")
            msg.get_payload()[-1].add_related(PNG, maintype="image", subtype="png", cid="<card@example.test>")
            msg.get_payload()[-1].add_related(b"not a raster image", maintype="image", subtype="png", cid="<bad@example.test>")
            deliver(owner, author, msg)
            inline = get(session, "Embedded image support")
            assert inline["text"].strip() == "Plain version."
            assert inline["embedded_images"] == [{"id": "card@example.test", "source": "data:image/png;base64," + base64.b64encode(PNG).decode()}]
            claim(session, 1)
            print("Verified opt-in, private claims, concurrent tabs, verified sender and thread precedence, mute, categorized mail, and inline MIME.")

        with test.daemon():
            session = test.login(owner)
            assert api(session, "notifications") == {"enabled": True}
            assert get(session, "Quiet before opt-in")["notifications"]["sender"] == "notify"
            send(owner, author, "One notification", "dedupe")
            claim(session, 0)
            send(owner, author, "Fresh after restart", "new-after-restart")
            claim(session, 1)
            print("Verified settings and notification deduplication survive restart.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--previous", type=Path)
    args = parser.parse_args()
    run(args.binary.resolve(), args.previous.resolve() if args.previous else None)
