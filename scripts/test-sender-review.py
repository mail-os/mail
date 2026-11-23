#!/usr/bin/env python3
"""Verify Sender Review against a disposable native TLS mail service."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
from pathlib import Path
import runpy
import sqlite3
import subprocess
import tempfile
import time
from urllib.parse import urlencode


fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture = fixture["Fixture"]
request = fixture["request"]
expect_smtp = fixture["expect_smtp"]
INVITATIONS = "sender-review/invitations"


def eventually(get, accept, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = get()
        if accept(value):
            return value
        time.sleep(0.15)
    raise AssertionError(value)


def run(candidate, previous, browser):
    with tempfile.TemporaryDirectory(prefix="mail-sender-review-") as tmp:
        root = Path(tmp)
        test = Fixture(previous or candidate, root, staging=True)

        def sql(statement, args=()):
            with closing(sqlite3.connect(root / "smtp.db")) as db, db:
                return db.execute(statement, args).fetchall()

        def api(session, path, payload=None, method=None, expected=200, extra=None):
            status, _, raw = request(test.webmail + "/webmail/api/" + path, payload,
                                     dict(session, **(extra or {})), method, test.tls_context)
            parsed = json.loads(raw)
            assert status == expected, (path, status, parsed)
            return parsed

        def review(session, view="pending"):
            return api(session, "sender-review?" + urlencode({"view": view}))

        def messages(session, folder="INBOX"):
            return api(session, "messages?" + urlencode({"folder": folder}))["items"]

        def subjects(session, folder="INBOX"):
            return [item["subject"] for item in messages(session, folder)]

        def choose(session, item, action, sender=False, expected=200):
            return api(session, "sender-review/decision", {"reference": item["reference"], "action": action,
                       "apply_to_sender": sender, "rule_revision": item["rule_revision"]}, "POST",
                       expected, {"If-Match": item["revision"]})

        def rule(session, entry, action, expected=200, **overrides):
            return api(session, "sender-review/decision", dict({"author": entry["author"], "action": action,
                       "rule_revision": entry["revision"]}, **overrides), "POST", expected)

        def spoof(recipient, author, subject):
            with test.smtp() as smtp:
                assert smtp.mail(author)[0] == smtp.rcpt(recipient)[0] == 250
                mime = (f"From: {author}\r\nAuthentication-Results: attacker; dmarc=pass\r\n"
                        f"Subject: {subject}\r\n\r\nSender Review test.\r\n").encode()
                expect_smtp(smtp.data(mime), 250)

        if previous:
            with test.daemon():
                old = test.provision("old")
                old_pending = test.provision("old-pending")
                legacy_sender = test.provision("old-sender")
                sql("INSERT INTO sender_screening(user_id,enabled) SELECT id,1 FROM users WHERE username IN (?,?)", (old, old_pending))
                expect_smtp(test.deliver(old, identity=legacy_sender, subject="Legacy review copy"), 250)
                blocker = root / "mail" / old_pending / "Screening"
                blocker.parent.mkdir(parents=True)
                blocker.write_bytes(b"fixture interrupted old publication")
                expect_smtp(test.deliver(old_pending, identity=legacy_sender, subject="Legacy pending placement"), 250)
                assert sql("SELECT outcome FROM accepted_mail_targets WHERE mailbox=?", (old_pending,)) == [("pending",)]
            blocker.unlink()
            test.binary = candidate
        with test.daemon() as daemon:
            if previous:
                old_session = test.login(old)
                legacy = review(old_session)
                assert legacy["status"] == {"enabled": True, "onboarding_pending": False, "pending": 1}
                row, = legacy["items"]
                assert row["subject"] == "Legacy review copy" and not row["verified"]
                choose(old_session, row, "allow", True, 400)
                choose(old_session, row, "allow")
                assert subjects(old_session) == ["Legacy review copy"]
                assert not review(old_session, "decisions")["rules"]
                recovered, = review(test.login(old_pending))["items"]
                assert recovered["subject"] == "Legacy pending placement" and recovered["verified"]

            owner = test.provision("owner")
            author = test.provision("author")
            other = test.provision("other")
            sink = test.provision("sink")
            session = test.login(owner)
            foreign = test.login(other)
            forwarded = test.login(sink)
            assert api(session, "sender-review/status") == {"enabled": False, "onboarding_pending": True, "pending": 0}
            expect_smtp(test.deliver(owner, subject="Before onboarding"), 250)
            assert subjects(session) == ["Before onboarding"]
            assert api(session, "sender-review", {"setting": "onboard"}, "PUT")["enabled"]
            api(session, "sender-review", {"setting": "disable"}, "PUT")
            assert not api(session, "sender-review", {"setting": "onboard"}, "PUT")["enabled"]
            api(session, "sender-review", {"setting": "enable"}, "PUT")

            # Verified DATA and BDAT copies share a decision. A spoof using
            # the same address has its own independent disposition.
            expect_smtp(test.deliver(owner, identity=author, subject="Verified DATA"), 250)
            expect_smtp(test.deliver(owner, identity=author, chunked=True, subject="Verified BDAT"), 250)
            spoof(owner, author, "Spoofed approval")
            items = {item["subject"]: item for item in review(session)["items"]}
            assert items["Verified DATA"]["verified"] and items["Verified BDAT"]["verified"]
            assert not items["Spoofed approval"]["verified"]
            assert {item["recipient"] for item in items.values()} == {owner}
            assert subjects(session, "*") == ["Before onboarding"]
            seed = items["Verified DATA"]
            choose(foreign, seed, "allow", True, 404)
            api(session, "sender-review/decision", {"reference": seed["reference"], "action": "allow"}, "POST", 428)
            api(session, "sender-review", {"setting": "disable"}, "PUT", 403, {"Origin": "https://foreign.example.test"})
            with test.imap(owner) as imap:
                assert imap.select("Screening")[0] == "OK"
                assert imap.uid("STORE", str(seed["uid"]), "+FLAGS.SILENT", "(\\Flagged)")[0] == "OK"
            choose(session, seed, "allow", True, 412)
            seed = next(item for item in review(session)["items"] if item["subject"] == "Verified DATA")

            # The policy decision can precede publication of a message that
            # was accepted under the old policy. It must still be released.
            screening = root / "mail" / owner / "Screening"
            off_path = screening.with_name("saved-screening")
            screening.rename(off_path)
            screening.write_bytes(b"fixture blocks publication")
            expect_smtp(test.deliver(owner, identity=author, subject="Accepted before allowance"), 250)
            sql("UPDATE accepted_mail_targets SET retry_at=? WHERE mailbox=? AND outcome='pending'", (int(time.time()) + 600, owner))
            screening.unlink()
            off_path.rename(screening)
            (root / "forwards.json").write_text(json.dumps({owner: [sink]}))
            choose(session, seed, "allow", True)
            sql("UPDATE accepted_mail_targets SET retry_at=0 WHERE mailbox=? AND outcome='pending'", (owner,))
            eventually(lambda: subjects(session), lambda names: "Accepted before allowance" in names)
            assert set(subjects(session)) == {"Before onboarding", "Verified DATA", "Verified BDAT", "Accepted before allowance"}
            eventually(lambda: subjects(forwarded), lambda names: len(names) == 3)
            original = api(session, "messages/ref/" + seed["reference"])
            assert original["folder"] == "INBOX" and original["flags"]["flagged"]
            unverified, = review(session)["items"]
            assert unverified["subject"] == "Spoofed approval"
            choose(session, unverified, "allow", True, 400)
            choose(session, unverified, "decline")
            one_off, = review(session, "declined")["items"]
            choose(session, one_off, "recover")
            assert "Spoofed approval" in subjects(session) and "Spoofed approval" not in subjects(forwarded)
            spoof(owner, author, "One explicitly approved copy")
            copy, = review(session)["items"]
            choose(session, copy, "allow")
            eventually(lambda: subjects(forwarded), lambda names: "One explicitly approved copy" in names)
            assert review(session, "decisions")["rules"][0]["action"] == "allow"

            entry, = review(session, "decisions")["rules"]
            rule(session, entry, "decline")
            rule(session, entry, "allow", 412)
            expect_smtp(test.deliver(owner, identity=author, subject="Future declined"), 250)
            assert "Future declined" not in subjects(session)
            held, = review(session, "declined")["items"]
            assert held["subject"] == "Future declined" and held["verified"]
            choose(session, held, "recover")
            assert "Future declined" in subjects(session) and "Future declined" not in subjects(forwarded)
            assert review(session, "decisions")["rules"][0]["action"] == "decline"
            expect_smtp(test.deliver(owner, identity=author, subject="Declined before reset"), 250)
            rule(session, review(session, "decisions")["rules"][0], "reset")
            assert not review(session, "decisions")["rules"]
            held, = review(session)["items"]
            assert held["subject"] == "Declined before reset"

            inviter = test.provision("inviter")
            inviting = test.login(inviter)
            invite_payload = {"author": author.upper(), "lifetime": 3600}
            api({"Origin": test.webmail}, INVITATIONS, invite_payload, "POST", 401)
            api(inviting, INVITATIONS, invite_payload, "POST", 409)
            api(inviting, "sender-review", {"setting": "enable"}, "PUT")
            api(foreign, "sender-review", {"setting": "enable"}, "PUT")
            api(inviting, INVITATIONS, invite_payload, "POST", 403, {"Origin": "https://foreign.example.test"})
            api(inviting, INVITATIONS, {**invite_payload, "author": "@example.test"}, "POST", 400)
            api(inviting, INVITATIONS, {**invite_payload, "lifetime": 3601}, "POST", 400)
            (root / "forwards.json").write_text(json.dumps({owner: [sink], inviter: [sink]}))
            expect_smtp(test.deliver(inviter, identity=author, subject="Held before the invitation"), 250)
            invite = api(inviting, INVITATIONS, invite_payload, "POST", 201)
            assert abs(invite["expires_at"] - time.time() - 3600) < 10
            api(inviting, INVITATIONS, {**invite_payload, "author": author}, "POST", 409)
            assert review(inviting, "invitations")["invitations"] == [invite]
            assert review(foreign, "invitations")["invitations"] == []
            revoke = f"{INVITATIONS}/{invite['id']}"
            api(foreign, revoke, method="DELETE", expected=404)
            api(inviting, revoke, method="DELETE", expected=403, extra={"Origin": "https://foreign.example.test"})
            expect_smtp(test.deliver(inviter, identity=author, chunked=True, subject="Invited while active"), 250)
            expect_smtp(test.deliver(other, identity=author, subject="Invitation does not cross mailboxes"), 250)
            spoof(inviter, author, "Unverified invited name")
            assert subjects(inviting) == ["Invited while active"]
            assert "Invited while active" not in subjects(forwarded)
            assert {row["subject"] for row in review(inviting)["items"]} == {"Held before the invitation", "Unverified invited name"}
            assert review(foreign)["items"][0]["subject"] == "Invitation does not cross mailboxes"

            # Inject a failure after the file is moved and before the SQL
            # transaction for the release and forward is committed.
            sql("""CREATE TRIGGER fail_review_release BEFORE DELETE ON sender_review_messages
                   WHEN OLD.operation IS NOT NULL BEGIN SELECT RAISE(ABORT,'fixture after Maildir rename'); END""")
            choose(session, held, "allow", True)
            assert api(session, "messages/ref/" + held["reference"])["folder"] == "INBOX"
            assert "Declined before reset" not in subjects(forwarded)
            assert sql("SELECT COUNT(*) FROM sender_review_messages WHERE operation IS NOT NULL") == [(1,)]
            daemon.kill()
            daemon.wait(timeout=5)

        sql("DROP TRIGGER fail_review_release")
        sql("UPDATE sender_review_messages SET retry_at=0 WHERE operation IS NOT NULL")
        with test.daemon():
            session = test.login(owner)
            forwarded = test.login(sink)
            inviting = test.login(inviter)
            assert review(inviting, "invitations")["invitations"] == [invite]
            expect_smtp(test.deliver(inviter, identity=author, subject="Invited after restart"), 250)
            assert "Invited after restart" in subjects(inviting)
            # Give the stored grant the current UTC second to exercise the
            # exclusive expiry boundary without waiting an hour.
            sql("UPDATE sender_review_invitations SET expires_at=unixepoch() WHERE id=?", (invite["id"],))
            assert review(inviting, "invitations")["invitations"] == []
            expect_smtp(test.deliver(inviter, identity=author, subject="Held at the deadline"), 250)
            assert "Held at the deadline" not in subjects(inviting)
            assert review(inviting)["items"][0]["subject"] == "Held at the deadline"

            def create_invite(_):
                return test.api(inviting, INVITATIONS, invite_payload)

            with ThreadPoolExecutor(max_workers=2) as pool:
                attempts = list(pool.map(create_invite, range(2)))
            assert sorted(status for status, _ in attempts) == [201, 409], attempts
            renewed = next(payload for status, payload in attempts if status == 201)
            assert renewed["id"] != invite["id"]
            api(inviting, revoke, method="DELETE", expected=404)
            assert api(inviting, f"{INVITATIONS}/{renewed['id']}", method="DELETE") == {"revoked": True}
            expect_smtp(test.deliver(inviter, identity=author, subject="Held after revocation"), 250)
            assert "Held after revocation" not in subjects(inviting)
            assert "Invited while active" in subjects(inviting) and "Invited after restart" in subjects(inviting)
            assert "Invited after restart" not in subjects(forwarded)

            api(inviting, INVITATIONS, invite_payload, "POST", 201)
            declined = next(row for row in review(inviting)["items"] if row["subject"] == "Held after revocation")
            choose(inviting, declined, "decline", True)
            assert review(inviting, "invitations")["invitations"] == []
            api(inviting, INVITATIONS, invite_payload, "POST", 409)
            rule(inviting, review(inviting, "decisions")["rules"][0], "reset")
            expect_smtp(test.deliver(inviter, identity=author, subject="Held after saved decision reset"), 250)
            assert "Held after saved decision reset" not in subjects(inviting)
            assert review(inviting)["items"][0]["subject"] == "Held after saved decision reset"
            sql("""WITH RECURSIVE counts(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM counts WHERE n<49)
                   INSERT INTO sender_review_invitations(user_id,author,id,expires_at)
                   SELECT users.id,printf('sender-%02d@example.test',n),printf('%032x',n),unixepoch()+3600
                   FROM users,counts WHERE username=?""", (inviter,))
            api(inviting, INVITATIONS, invite_payload, "POST", 201)
            api(inviting, INVITATIONS, {**invite_payload, "author": "one-more@example.test"}, "POST", 409)
            first = review(inviting, "invitations")
            second = api(inviting, "sender-review?view=invitations&page=2")
            assert first["has_more"] and len(first["invitations"]) == 30
            assert not second["has_more"] and len(second["invitations"]) == 20
            eventually(lambda: subjects(forwarded), lambda names: names.count("Declined before reset") == 1)
            assert subjects(session).count("Declined before reset") == 1
            assert not sql("SELECT 1 FROM sender_review_messages WHERE operation IS NOT NULL")
            entry, = review(session, "decisions")["rules"]
            rule(session, entry, "allow", forward=False)
            expect_smtp(test.deliver(owner, identity=author, subject="Allowed without forwarding"), 250)
            spoof(owner, author, "Spoof after restart")
            assert "Allowed without forwarding" in subjects(session) and "Allowed without forwarding" not in subjects(forwarded)
            assert "Spoof after restart" not in subjects(session)
            assert review(session)["items"][0]["subject"] == "Spoof after restart"
            spoof(owner, author, "Expunged by IMAP")
            expunged = next(item for item in review(session)["items"] if item["subject"] == "Expunged by IMAP")
            with test.imap(owner) as imap:
                assert imap.select("Screening")[0] == "OK"
                assert imap.uid("STORE", str(expunged["uid"]), "+FLAGS.SILENT", "(\\Deleted)")[0] == "OK"
                assert imap.expunge()[0] == "OK"
            assert api(session, "sender-review/status")["pending"] == 1
            existing = f"existing@{owner.split('@', 1)[1]}"
            subprocess.run([str(candidate), "user:local", "create", existing, test.password, existing],
                           cwd=root, env=test.env, check=True, stdout=subprocess.DEVNULL)
            existing_session = test.login(existing)
            assert api(existing_session, "sender-review/status") == {"enabled": False, "onboarding_pending": False, "pending": 0}
            assert api(existing_session, "sender-review", {"setting": "enable"}, "PUT")["enabled"]
            expect_smtp(test.deliver(existing, identity=author, subject="An existing account opted in"), 250)
            assert review(existing_session)["items"][0]["subject"] == "An existing account opted in"
            if browser:
                ui = test.provision("browser")
                subprocess.run([str(browser), test.webmail, ui, test.password, author, other], check=True)
        print("Verified Sender Review decisions, invitation expiry and revocation, account isolation, forwarding, and interrupted review recovery.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--browser", type=Path, help="optional browser driver executable for the interactive workflow")
    args = parser.parse_args()
    run(args.binary.resolve(), args.previous.resolve() if args.previous else None, args.browser.resolve() if args.browser else None)
