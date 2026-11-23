#!/usr/bin/env python3
"""Verify opt-in Maildir cleanup over native HTTPS and TLS IMAP."""

import argparse
from contextlib import closing
from datetime import datetime, timedelta, timezone
from imaplib import Time2Internaldate
from pathlib import Path
import runpy
import sqlite3
import tempfile
import time


Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]
DAY = 86400
SEEN = r"(\Seen)"


def append(imap, folder, subject, received, flags=SEEN):
    raw = (f"From: notices@sender.example.test\r\nSubject: {subject}\r\n"
           f"Message-ID: <{subject.replace(' ', '-')}@sender.example.test>\r\n"
           "Date: Sun, 15 Mar 2020 10:00:00 +0000\r\n\r\nOriginal message.\r\n").encode()
    status, reply = imap.append(folder, flags, Time2Internaldate(received), raw)
    assert status == "OK", (folder, subject, status, reply)
    return int(imap.response("APPENDUID")[1][0].split()[1])


def eventually(read, ready):
    deadline = time.monotonic() + 18
    while time.monotonic() < deadline:
        result = read()
        if ready(result):
            return result
        time.sleep(0.2)
    raise AssertionError(f"Cleanup did not reach the expected state: {result!r}")


def run(binary, root):
    fixture = Fixture(binary, root, staging=True)
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=45)

    def sql(query, values=()):
        with closing(sqlite3.connect(root / "smtp.db")) as db, db:
            return db.execute(query, values).fetchall()

    def api(session, path="retention", body=None, method=None, expected=200):
        status, data = fixture.api(session, path, body, method)
        assert status == expected, (path, expected, status, data)
        return data

    def preview(session, revision=0, folder="INBOX", days=30, expected=200):
        return api(session, "retention/preview", {"folder": folder, "days": days, "revision": revision}, "POST", expected)

    def enable(session, token, revision=0, password=None, expected=200):
        return api(session, body={"action": "enable", "revision": revision, "preview": token,
                                  "currentPassword": fixture.password if password is None else password},
                   method="PUT", expected=expected)

    def disable(session, revision, expected=200):
        return api(session, body={"action": "disable", "revision": revision}, method="PUT", expected=expected)

    def restore(session, reference, expected=200):
        return api(session, "retention/restore", {"reference": reference}, "POST", expected)

    def status():
        return api(owner)

    def next_run(user):
        sql("UPDATE mail_retention_rules SET next_run=unixepoch() WHERE user_id=(SELECT id FROM users WHERE username=?)", (user,))

    def stored_bytes(user):
        return sum(path.stat().st_size for path in (root / "mail" / user).rglob("*")
                   if path.is_file() and ".eml" in path.name)

    with fixture.daemon():
        source = fixture.provision("cleanup")
        observer = fixture.provision("observer")
        interrupted = fixture.provision("interrupted")
        batched = fixture.provision("batched")
        owner, other, recovery = map(fixture.login, (source, observer, interrupted))
        assert status()["rule"]["policy"] is None and not status()["recoverable"]
        api({}, expected=401)
        api(owner, "retention?page=0", expected=400)
        preview(owner, folder="Sent", expected=400)
        preview(owner, days=31, expected=400)
        preview({**owner, "Origin": "https://other.example.test"}, expected=403)
        preview(owner, revision=10, expected=412)
        assert enable(owner, None, expected=409)["error"] == "preview_required"

        with fixture.imap(source) as mailbox:
            assert mailbox.create("Archive")[0] == "OK"
            first = append(mailbox, "INBOX", "Older read message", old)
            append(mailbox, "INBOX", "Older unread message", old, None)
            append(mailbox, "INBOX", "Older flagged message", old, r"(\Seen \Flagged)")
            append(mailbox, "INBOX", "Older draft", old, r"(\Seen \Draft)")
            append(mailbox, "INBOX", "Pending expunge", old, r"(\Seen \Deleted)")
            append(mailbox, "INBOX", "Recent delivery with an older date header", now)
            append(mailbox, "INBOX", "Saved older message", old)
            append(mailbox, "INBOX", "Follow-up older message", old)
            append(mailbox, "Archive", "Older message outside the folder", old)
            inbox = api(owner, "messages?folder=INBOX")["items"]
            for label, kind in (("Saved older message", "saved"), ("Follow-up older message", "follow_up")):
                item = next(row for row in inbox if row["subject"] == label)
                api({**owner, "If-Match": item["revision"]}, "attention",
                    {"reference": item["reference"], "kind": kind, "enabled": True}, "PUT")
            first_reference = next(row["reference"] for row in inbox if row["uid"] == first)
            trial = preview(owner)
            assert trial["total"] == 1 and trial["examples"] == [
                {"subject": "Older read message", "received_at": int(old.timestamp())}
            ], trial
            assert not status()["recoverable"] and status()["rule"]["policy"] is None
            enable(other, trial["token"], expected=409)
            enable({**owner, "Origin": "https://other.example.test"}, trial["token"], expected=403)
            enable(owner, trial["token"], password="bad-password", expected=400)

            assert mailbox.select("INBOX")[0] == "OK"
            assert mailbox.uid("STORE", str(first), "+FLAGS", r"(\Flagged)")[0] == "OK"
            enable(owner, trial["token"], expected=409)
            assert preview(owner)["total"] == 0
            assert mailbox.uid("STORE", str(first), "-FLAGS", r"(\Flagged)")[0] == "OK"

        expired = preview(owner)
        sql("UPDATE mail_retention_previews SET expires_at=unixepoch() WHERE token=?", (expired["token"],))
        enable(owner, expired["token"], expected=409)
        current = preview(owner)
        initial_bytes = stored_bytes(source)
        rule = enable(owner, current["token"])
        assert rule["revision"] == 1 and rule["policy"] == {"folder": "INBOX", "days": 30}
        disable(owner, 0, expected=412)
        moved = eventually(status, lambda result: len(result["recoverable"]) == 1)
        assert moved["rule"]["last_moved"] == 1
        entry, = moved["recoverable"]
        assert (entry["reference"], entry["subject"], entry["source_folder"]) == (first_reference, "Older read message", "INBOX")
        assert stored_bytes(source) == initial_bytes
        assert api(other)["recoverable"] == []
        restore(other, first_reference, expected=404)
        restore({**owner, "Origin": "https://other.example.test"}, first_reference, expected=403)
        with fixture.imap(source) as mailbox:
            assert mailbox.select("Trash") == ("OK", [b"1"])
            assert mailbox.select("Archive") == ("OK", [b"1"])
        assert restore(owner, first_reference) == {"restored": True}
        assert restore(owner, first_reference) == {"restored": False}
        assert api(owner, "messages/ref/" + first_reference)["folder"] == "INBOX"
        assert stored_bytes(source) == initial_bytes
        assert preview(owner, 1)["total"] == 0
        next_run(source)
        eventually(status, lambda result: result["rule"]["next_run"] > int(time.time()) + 3000)
        assert not status()["recoverable"]
        assert disable(owner, 1)["revision"] == 2

        # APPEND a message at the preview's exact cutoff. It is outside that
        # snapshot, so the unchanged authorization still succeeds.
        boundary = preview(other)
        cutoff, = sql("SELECT cutoff FROM mail_retention_previews WHERE token=?", (boundary["token"],))[0]
        with fixture.imap(observer) as mailbox:
            append(mailbox, "INBOX", "At the preview cutoff", datetime.fromtimestamp(cutoff, timezone.utc))
        assert enable(other, boundary["token"])["revision"] == 1
        assert disable(other, 1)["policy"] is None

        batch = fixture.login(batched)
        with fixture.imap(batched) as mailbox:
            assert mailbox.create("Archive")[0] == "OK"
            for index in range(21):
                append(mailbox, "Archive", f"Cleanup batch {index + 1}", old)
        sample = preview(batch, folder="Archive")
        assert sample["total"] == 21 and len(sample["examples"]) == 8
        assert enable(batch, sample["token"])["revision"] == 1
        count = lambda: sql("SELECT COUNT(*) FROM mail_retention_moves WHERE user_id=(SELECT id FROM users WHERE username=?)", (batched,))[0][0]
        eventually(count, lambda value: value == 10)
        assert api(batch)["rule"]["last_moved"] == 10
        next_run(batched)
        eventually(count, lambda value: value == 20)
        assert api(batch)["rule"]["last_moved"] == 10
        next_run(batched)
        eventually(count, lambda value: value == 21)
        first_page = api(batch)
        second_page = api(batch, "retention?page=2")
        assert len(first_page["recoverable"]) == 20 and first_page["has_more"]
        moved_out, = second_page["recoverable"]
        assert not second_page["has_more"] and second_page["page"] == 2

        # An ordinary IMAP move out of Trash also dismisses that recovery
        # entry and prevents the saved message from being cleaned up again.
        ref = moved_out["reference"]
        uid = api(batch, "messages/ref/" + ref)["uid"]
        with fixture.imap(batched) as mailbox:
            assert mailbox.select("Trash") == ("OK", [b"21"])
            assert mailbox.xatom("UID", "MOVE", str(uid), "Archive")[0] == "OK"
        assert restore(batch, ref) == {"restored": False}
        assert api(batch, "messages/ref/" + ref)["folder"] == "Archive"
        assert not api(batch)["has_more"]
        assert preview(batch, 1, folder="Archive")["total"] == 0
        assert disable(batch, 1)["policy"] is None

        # Fail only the final write after a real Maildir rename. The pending
        # reference needs to survive shutdown and recover on the next start.
        with fixture.imap(interrupted) as mailbox:
            append(mailbox, "INBOX", "Interrupted cleanup", old)
        sql("""CREATE TRIGGER retention_fixture_stop BEFORE UPDATE OF folder ON mailbox_message_refs
               WHEN OLD.next_retention_at IS NOT NULL AND NEW.folder='Trash'
               BEGIN SELECT RAISE(ABORT, 'simulated interrupted handoff'); END""")
        assert enable(recovery, preview(recovery)["token"])["policy"] is not None
        trash = root / "mail" / interrupted / "Trash"
        eventually(lambda: list(trash.glob("*.eml*")), bool)
        assert sql("SELECT COUNT(*) FROM mailbox_message_refs WHERE next_retention_at IS NOT NULL") == [(1,)]

    sql("DROP TRIGGER retention_fixture_stop")
    with fixture.daemon():
        owner = fixture.login(source)
        assert status()["rule"]["policy"] is None and status()["rule"]["revision"] == 2
        assert api(owner, "messages/ref/" + first_reference)["folder"] == "INBOX"
        recovery = fixture.login(interrupted)
        entry, = api(recovery)["recoverable"]
        assert entry["subject"] == "Interrupted cleanup"
        assert restore(recovery, entry["reference"]) == {"restored": True}
        assert api(recovery, "messages/ref/" + entry["reference"])["folder"] == "INBOX"
        assert not api(recovery)["recoverable"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--previous-binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="mail-retention-") as root:
        run(binary, Path(root))
    print("Verified retention opt-in, preview boundaries, authorization, restore, and interrupted Maildir recovery.")
    if args.previous_binary:
        with tempfile.TemporaryDirectory(prefix="mail-retention-upgrade-") as root:
            verify_upgrade(args.previous_binary.resolve(strict=True), binary, Path(root))


def verify_upgrade(previous, binary, root):
    fixture = Fixture(previous, root, staging=True)
    with fixture.daemon():
        mailbox = fixture.provision("before-cleanup")
        with fixture.imap(mailbox) as client:
            append(client, "INBOX", "Mail from before the upgrade", datetime.now(timezone.utc) - timedelta(days=45))
        code, inbox = fixture.api(fixture.login(mailbox), "messages?folder=INBOX")
        assert code == 200
        reference = inbox["items"][0]["reference"]
    with closing(sqlite3.connect(root / "smtp.db")) as db:
        assert "next_retention_at" not in {row[1] for row in db.execute("PRAGMA table_info(mailbox_message_refs)")}

    fixture.binary = binary
    with fixture.daemon():
        session = fixture.login(mailbox)
        status, settings = fixture.api(session, "retention")
        assert status == 200 and settings["rule"]["policy"] is None
        status, preview = fixture.api(session, "retention/preview", {"folder": "INBOX", "days": 30, "revision": 0}, "POST")
        assert status == 200 and preview["total"] == 1
        status, rule = fixture.api(session, "retention", {
            "action": "enable", "revision": 0, "preview": preview["token"], "currentPassword": fixture.password,
        }, "PUT")
        assert status == 200 and rule["policy"] is not None
        _, recovered = eventually(lambda: fixture.api(session, "retention"), lambda result: result[0] == 200 and result[1]["recoverable"])
        assert recovered["recoverable"][0]["reference"] == reference

    fixture.binary = previous
    with fixture.daemon(), fixture.imap(mailbox) as client:
        assert client.select("Trash") == ("OK", [b"1"])
    fixture.binary = binary
    with fixture.daemon():
        status, result = fixture.api(fixture.login(mailbox), "retention/restore", {"reference": reference}, "POST")
        assert status == 200 and result["restored"]
    print("Verified upgrade and rollback preserve a pre-existing stable message reference and its recovery entry.")


if __name__ == "__main__":
    main()
