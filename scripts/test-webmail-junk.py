#!/usr/bin/env python3
"""Native HTTPS, SMTP, and IMAP regression for Junk feedback and recovery."""

import argparse
from base64 import b64encode
from contextlib import closing
import json
from pathlib import Path
import runpy
import sqlite3
import tempfile
from urllib.parse import urlencode


fixtures = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture, expect_smtp = fixtures["Fixture"], fixtures["expect_smtp"]
JUNK = "Spam Review"
PARCEL = "DHL Express Shipment Release Information. A fee must be paid before final delivery. Total amount due $3.35. Status: Awaiting payment at the local facility."


def verify_mime_scoring(test, recipient):
    sender = "campaign@example.org"
    encoded = b64encode(b"Are you interested in seo services?").decode("ascii")
    cases = (
        ("Folded MIME scoring", "Content-Transfer-Encoding:\n\tbase64", "text/html", True, True),
        ("Mixed-case MIME scoring", "cOnTeNt-TrAnSfEr-EnCoDiNg\t: bAsE64", "text/html", False, True),
        ("Binary MIME scoring", "Content-Transfer-Encoding: base64", "application/octet-stream", True, False),
    )
    for subject, transfer_header, content_type, bdat, _ in cases:
        message = "\n".join((
            f"From: {sender}", f"To: {recipient}", f"Subject: {subject}",
            "Date: Sun, 22 Nov 2026 12:00:00 +0000", "MIME-Version: 1.0",
            "Content-Type: multipart/mixed; boundary=outer", "", "--outer",
            f"Content-Type: {content_type}", transfer_header, "", encoded, "--outer--", "",
        ))
        with test.smtp() as client:
            expect_smtp(client.mail(sender), 250)
            expect_smtp(client.rcpt(recipient), 250)
            if bdat:
                raw = message.encode("ascii")
                client.send(f"BDAT {len(raw)} LAST\r\n".encode("ascii") + raw)
                expect_smtp(client.getreply(), 250)
            else:
                expect_smtp(client.data(message), 250)

    with test.imap(recipient) as client:
        assert client.select("INBOX", readonly=True)[0] == "OK"
        for subject, _, _, _, expected_rule in cases:
            status, matches = client.uid("SEARCH", "SUBJECT", f'"{subject}"')
            assert status == "OK", matches
            uid, = matches[0].split()
            status, data = client.uid("FETCH", uid, "(BODY.PEEK[HEADER.FIELDS (X-Spam-Status)])")
            assert status == "OK", data
            header = b"".join(chunk[1] for chunk in data if isinstance(chunk, tuple))
            assert b"X-Spam-Status:" in header and (b"SEO_SOLICITATION" in header) == expected_rule, (subject, header)


def run(candidate, previous=None, verify_inbound_auth=False):
    with tempfile.TemporaryDirectory(prefix="mail-junk-feedback-") as directory:
        root = Path(directory)
        test = Fixture(previous or candidate, root, staging=True)
        test.env["SMTP_JUNK_FOLDER"] = JUNK

        def sql(query, args=()):
            with closing(sqlite3.connect(root / "smtp.db")) as db, db:
                return db.execute(query, args).fetchall()

        def api(session, path, payload=None, method=None, status=200):
            received, value = test.api(session, path, payload, method)
            assert received == status, (path, received, status, value)
            return value

        def rows(session, folder="INBOX"):
            return api(session, "messages?" + urlencode({"folder": folder, "per_page": 100}))["items"]

        def row(session, folder, subject):
            found, = [item for item in rows(session, folder) if item["subject"] == subject]
            return found

        def exists(session, folder, subject):
            return any(item["subject"] == subject for item in rows(session, folder))

        def action(session, op, *items, folder="Archive", status=200):
            refs = [{key: item[key] for key in ("folder", "uid", "reference", "revision") if key in item} for item in items]
            return api(session, "bulk", {"action": op, "messages": refs, "folder": folder}, "POST", status)

        def undo(session, receipt, status=200):
            return api(session, "undo/" + receipt["undoId"], {}, "POST", status)

        def smtp(sender, recipient, subject, *, body="Original text.", older_auth=False):
            with test.smtp() as client:
                assert client.mail(sender)[0] == client.rcpt(recipient)[0] == 250
                claimed = "Authentication-Results: forged.example.test; dmarc=pass\r\n" if older_auth else ""
                mime = (f"From: {sender}\r\nTo: {recipient}\r\nSubject: {subject}\r\n{claimed}\r\n{body}\r\n").encode()
                return client.data(mime)

        def disable_review(*sessions):
            for session in sessions:
                api(session, "sender-review", {"setting": "disable"}, "PUT")

        if previous:
            with test.daemon():
                legacy = test.provision("legacy-owner")
                legacy_sender = test.provision("legacy-sender")
                old = test.login(legacy)
                disable_review(old)
                expect_smtp(test.deliver(legacy, identity=legacy_sender, subject="Existing mail"), 250)
                existing = row(old, "INBOX", "Existing mail")
            assert not sql("SELECT 1 FROM sqlite_master WHERE name='mailbox_junk_feedback'")
            test.binary = candidate
            with test.daemon():
                old = test.login(legacy)
                same = row(old, "INBOX", "Existing mail")
                assert same["reference"] == existing["reference"]
                action(old, "junk", same)
                assert row(old, JUNK, "Existing mail")["reference"] == same["reference"]

        with test.daemon():
            owner = test.provision("owner")
            neighbor = test.provision("neighbor")
            sender = test.provision("sender", daily=40)
            redirected = test.provision("redirected")
            a, b, c = map(test.login, (owner, neighbor, redirected))
            disable_review(a, b, c)
            assert api(a, "config")["junkFolder"] == JUNK
            assert any(folder["name"] == JUNK for folder in api(a, "folders"))
            with test.imap(owner) as imap:
                listings = imap.list()[1]
                assert [entry for entry in listings if b"\\Junk" in entry] == [b'(\\HasNoChildren \\Junk) "/" "Spam Review"']
                assert imap.create("Cases")[0] == "OK"
                assert imap.create("Temporary")[0] == "OK"
            expect_smtp(test.deliver([owner, neighbor], identity=sender, subject="An archived sender"), 250)
            original = row(a, "INBOX", "An archived sender")
            action(a, "move", original, folder="Cases")
            archived = row(a, "Cases", "An archived sender")
            assert archived["reference"] == original["reference"]
            action(b, "junk", archived, status=404)
            action(a, "junk", original, status=412)
            action(a, "junk", {"folder": "Cases", "uid": archived["uid"]}, status=400)
            action({**a, "Origin": "https://invalid.example.test"}, "junk", archived, status=403)
            action(a, "not_junk", archived, status=400)
            assert not sql("SELECT 1 FROM mailbox_junk_feedback WHERE user_id=(SELECT id FROM users WHERE username=?)", (owner,))

            flagged = action(a, "flag", archived)
            assert flagged["ok"]
            archived = row(a, "Cases", "An archived sender")
            marked = action(a, "junk", archived, folder="Trash")
            assert marked["ok"] and marked["results"][0]["new_folder"] == JUNK
            marked_row = row(a, JUNK, "An archived sender")
            assert marked_row["reference"] == archived["reference"] and marked_row["flags"]["flagged"]
            with test.imap(owner) as imap:
                assert imap.select('"Spam Review"', readonly=True)[1] == [b"1"]
                assert imap.select("Cases", readonly=True)[1] == [b"0"]
            assert sql("SELECT author,action,source_folder FROM mailbox_junk_feedback WHERE user_id=(SELECT id FROM users WHERE username=?)", (owner,)) == [(sender, "junk", "Cases")]
            undo(b, marked, status=404)
            undo(a, marked)
            undo(a, marked)  # Replaying Undo is idempotent.
            assert row(a, "Cases", "An archived sender")["flags"]["flagged"]
            assert not sql("SELECT 1 FROM mailbox_junk_feedback WHERE user_id=(SELECT id FROM users WHERE username=?)", (owner,))

            marked = action(a, "junk", row(a, "Cases", "An archived sender"))
            (root / "forwards.json").write_text(json.dumps({owner: [redirected]}))
            api(a, "vacation", {"enabled": True, "subject": "Away", "body": "Out of office", "revision": 0}, "PUT")
            expect_smtp(test.deliver([owner, neighbor], identity=sender, subject="Later from the same sender", chunked=True), 250)
            assert exists(a, JUNK, "Later from the same sender") and exists(b, "INBOX", "Later from the same sender")
            assert not exists(c, "INBOX", "Later from the same sender") and test.count(owner) == 0
            item = row(a, JUNK, "Later from the same sender")
            detail = api(a, "messages/ref/" + item["reference"])
            assert detail["placement"]["reason"] == "junk_feedback" and detail["placement"]["verified_author"] == sender
            # A forged From is not used to apply another sender's Junk preference.
            expect_smtp(smtp(sender, owner, "Unverified correspondent", older_auth=True), 250)
            assert exists(a, "INBOX", "Unverified correspondent")
            forged = row(a, "INBOX", "Unverified correspondent")
            action(a, "junk", forged)
            assert sql("SELECT author FROM mailbox_junk_feedback WHERE reference=?", (forged["reference"],)) == [("",)]
            newer = row(a, JUNK, "Later from the same sender")
            action(a, "not_junk", newer)
            undo(a, marked)
            assert sql("SELECT action FROM mailbox_junk_feedback WHERE reference=?", (newer["reference"],)) == [("not_junk",)]
            expect_smtp(test.deliver(owner, identity=sender, subject="Genuine after undo"), 250)
            assert exists(a, "INBOX", "Genuine after undo")
            api(a, "vacation", {"enabled": False, "subject": "Away", "body": "Out of office", "revision": 1}, "PUT")

            action(a, "junk", row(a, "Cases", "An archived sender"))
            with test.imap(owner) as imap:
                assert imap.rename("Cases", '"Current Cases"')[0] == "OK"
            recovered = action(a, "not_junk", row(a, JUNK, "An archived sender"))
            assert recovered["ok"] and recovered["results"][0]["new_folder"] == "Current Cases"
            assert row(a, "Current Cases", "An archived sender")["flags"]["flagged"]
            undo(a, recovered)
            expect_smtp(test.deliver(owner, identity=sender, subject="Rule restored by undo"), 250)
            assert exists(a, JUNK, "Rule restored by undo")
            action(a, "not_junk", row(a, JUNK, "An archived sender"))
            expect_smtp(test.deliver(owner, identity=sender, subject="Rule corrected"), 250)
            assert exists(a, "INBOX", "Rule corrected")

            action(a, "move", row(a, "INBOX", "Rule corrected"), folder="Temporary")
            action(a, "junk", row(a, "Temporary", "Rule corrected"))
            with test.imap(owner) as imap:
                assert imap.delete("Temporary")[0] == "OK"
            result = action(a, "not_junk", row(a, JUNK, "Rule corrected"))
            assert result["results"][0]["new_folder"] == "INBOX"
            untouched = row(a, "INBOX", "Rule corrected")
            action(a, "junk", untouched, row(b, "INBOX", "Later from the same sender"), status=404)
            assert row(a, "INBOX", "Rule corrected")["revision"] == untouched["revision"]

            # Simulate loss of the SQLite checkpoint after the Maildir rename.
            sql("CREATE TRIGGER block_feedback_checkpoint BEFORE INSERT ON mailbox_junk_feedback BEGIN SELECT RAISE(ABORT,'injected failure'); END")
            failed_status, _ = test.api(a, "bulk", {"action": "junk", "messages": [
                {key: untouched[key] for key in ("folder", "uid", "reference", "revision")}
            ]}, "POST")
            assert failed_status >= 500, failed_status
            assert sql("SELECT next_folder FROM mailbox_message_refs WHERE reference=?", (untouched["reference"],)) == [(JUNK,)]
            sql("DROP TRIGGER block_feedback_checkpoint")

        with test.daemon():
            a, b = map(test.login, (owner, neighbor))
            recovered = row(a, JUNK, "Rule corrected")
            assert recovered["reference"] == untouched["reference"]
            saved = sql("SELECT COUNT(*) FROM mailbox_junk_feedback WHERE reference=? AND action='junk'", (untouched["reference"],))
            row(a, JUNK, "Rule corrected")
            assert sql("SELECT COUNT(*) FROM mailbox_junk_feedback WHERE reference=? AND action='junk'", (untouched["reference"],)) == saved == [(2,)]
            expect_smtp(test.deliver([owner, neighbor], identity=sender, subject="Rule after restart"), 250)
            assert exists(a, JUNK, "Rule after restart") and exists(b, "INBOX", "Rule after restart")

        test.env.update(SMTP_SPAM_FILTER="true", SMTP_SPAM_JUNK_SCORE="99", SMTP_SPAM_REJECT_SCORE="100")
        with test.daemon():
            verify_mime_scoring(test, owner)
        print("Verified MIME scoring through native SMTP DATA, BDAT and IMAP.")

        if verify_inbound_auth:
            test.env.update(SMTP_ANTISPAM_CHECK="true", SMTP_SPAM_FILTER="true", SMTP_SPAM_JUNK_SCORE="0.1", SMTP_SPAM_REJECT_SCORE="99")
            external = "parcel@vacation.example.test"
            with test.daemon():
                a, b, c = map(test.login, (owner, neighbor, redirected))
                expect_smtp(smtp(external, owner, "Initial verified false positive", body=PARCEL), 250)
                false_positive = row(a, JUNK, "Initial verified false positive")
                detail = api(a, "messages/ref/" + false_positive["reference"])
                assert detail["placement"]["verified_author"] == external and detail["placement"]["reason"] == "spam_filter"
                action(a, "not_junk", false_positive)
                expect_smtp(smtp(external, owner, "Reclassified soft spam", body=PARCEL), 250)
                expect_smtp(smtp(external, neighbor, "Unchanged neighbor policy", body=PARCEL), 250)
                assert exists(a, "INBOX", "Reclassified soft spam") and not exists(c, "INBOX", "Reclassified soft spam")
                assert exists(b, JUNK, "Unchanged neighbor policy")
                api(a, "sender-review", {"setting": "enable"}, "PUT")
                expect_smtp(smtp(external, owner, "Still held for review", body=PARCEL), 250)
                assert any(item["subject"] == "Still held for review" for item in api(a, "sender-review")["items"])
            test.env["SMTP_SPAM_REJECT_SCORE"] = "0.2"
            with test.daemon():
                expect_smtp(smtp(external, owner, "Still hard rejected", body=PARCEL), 550)
    print("Verified Junk feedback, isolation, folder recovery, Undo, journal replay, and delivery placement.")


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("binary", type=Path)
    cli.add_argument("--previous", type=Path)
    cli.add_argument("--verify-inbound-auth", action="store_true", help="Use the disposable SPF/DMARC resolver for vacation.example.test.")
    args = cli.parse_args()
    run(args.binary.resolve(), args.previous.resolve() if args.previous else None, args.verify_inbound_auth)
