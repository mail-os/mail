#!/usr/bin/env python3
"""Exercise versioned webmail messages with native clients and an old mailbox."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import runpy
import sqlite3
import subprocess
import tempfile
from threading import Barrier
from urllib.parse import urlencode


fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture = fixture["Fixture"]
request = fixture["request"]


def append(imap, subject, message_id=None):
    mime = f"From: sender@example.test\r\nSubject: {subject}\r\n"
    if message_id:
        mime += f"Message-ID: <{message_id}>\r\n"
    status, data = imap.append("INBOX", None, None, (mime + "\r\nReference test\r\n").encode())
    assert status == "OK", data
    return int(re.search(rb"APPENDUID \d+ (\d+)", data[0])[1])


def validity(imap, folder):
    assert imap.select(folder)[0] == "OK", folder
    return imap.response("UIDVALIDITY")[1][0]


def main(candidate, previous):
    with tempfile.TemporaryDirectory(prefix="mail-message-refs-") as tmp:
        directory = Path(tmp)
        test = Fixture(previous or candidate, directory, staging=True)
        db = directory / "smtp.db"

        def call(path, method=None, payload=None, expected=200, revision=None, session=None):
            headers = dict(alice_session if session is None else session)
            if revision is not None:
                headers["If-Match"] = revision
            status, response, raw = request(test.webmail + "/webmail/api/" + path, payload, headers,
                                            method, test.tls_context)
            body = json.loads(raw) if raw else None
            assert status in (expected if isinstance(expected, tuple) else (expected,)), (path, status, body)
            if status == 200 and isinstance(body, dict) and isinstance(body.get("revision"), str):
                assert response["ETag"] == body["revision"], (response, body)
            return status, body

        def detail(row, **kwargs):
            return call("messages/ref/" + row["reference"], **kwargs)

        def rows(folder="INBOX"):
            return call("messages?" + urlencode({"folder": folder}))[1]["items"]

        with test.daemon():
            alice = test.provision("alice")
            bob = test.provision("bob")
            local = test.create_local("local")
            with test.imap(alice) as imap:
                inbox_validity = validity(imap, "INBOX")
                assert imap.create("Archive")[0] == "OK"
                archive_validity = validity(imap, "Archive")
                first_uid = append(imap, "No Message-ID")
                second_uid = append(imap, "Duplicate A", "same@example.test")
                third_uid = append(imap, "Duplicate B", "same@example.test")
            with test.imap(bob) as imap:
                append(imap, "Duplicate A", "same@example.test")
            with test.imap(local) as imap:
                append(imap, "Local message")
        with closing(sqlite3.connect(db)) as conn:
            if previous:
                assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='mailbox_message_refs'").fetchone() == (0,)
            old_uids = conn.execute("SELECT * FROM imap_uids WHERE username=?", (alice,)).fetchall()
            assert len(old_uids) == 3, old_uids

        test.binary = candidate
        with test.daemon():
            alice_session = test.login(alice)
            bob_session = test.login(bob)
            bob_ref = call("messages?folder=INBOX", session=bob_session)[1]["items"][0]["reference"]
            local_ref = call("messages?folder=INBOX", session=test.login(local))[1]["items"][0]["reference"]
            first, second, third = ({row["uid"]: row for row in rows()}[uid] for uid in (first_uid, second_uid, third_uid))
            assert len({first["reference"], second["reference"], third["reference"], bob_ref}) == 4
            assert not first["message_id"] and second["message_id"] == third["message_id"]
            assert call(f"messages/{first_uid}?folder=INBOX")[1]["revision"] == first["revision"]
            assert detail(first)[1]["revision"] == first["revision"]
            detail(first, session=bob_session, expected=404)
            detail(first, method="PUT", payload={"flags": {}}, expected=428)
            detail(first, method="PUT", payload={"flags": {}}, revision="*", expected=400)

            with test.imap(alice) as imap:
                assert validity(imap, "INBOX") == inbox_validity
                assert imap.uid("STORE", str(first_uid), "+FLAGS.SILENT", "(\\Flagged)")[0] == "OK"
                assert imap.uid("COPY", str(first_uid), "Archive")[0] == "OK"
                copied = rows("Archive")[0]
                assert copied["reference"] != first["reference"] and copied["flags"]["flagged"]
                assert detail(first)[1]["uid"] == first_uid
                detail(first, method="DELETE", revision=first["revision"], expected=412)
                selection = [{key: row[key] for key in ("uid", "folder", "reference", "revision")} for row in (second, first)]
                call("bulk", "POST", {"action": "read", "messages": selection}, expected=412)
                assert not detail(second)[1]["flags"]["seen"]
                assert imap.uid("MOVE", str(first_uid), "Archive")[0] == "OK"
                assert validity(imap, "Archive") == archive_validity
                moved = detail(first)[1]
                assert moved["folder"] == "Archive" and moved["uid"] != copied["uid"] and moved["flags"]["flagged"]
                assert b"\\Flagged" in imap.uid("FETCH", str(moved["uid"]), "(FLAGS)")[1][0]

            changed = detail(moved, method="PUT", revision=moved["revision"],
                             payload={"folder": "INBOX", "flags": {"seen": True, "flagged": True}})[1]
            assert changed["reference"] == first["reference"] and changed["uid"] != first_uid
            assert detail(first)[1]["revision"] == changed["revision"]
            unread = "messages?" + urlencode({"folder": "INBOX", "queue": "unread", "q": "No Message-ID"})
            assert not call(unread)[1]["items"]
            with test.imap(alice) as imap:
                assert validity(imap, "INBOX") == inbox_validity
                assert imap.uid("STORE", str(changed["uid"]), "-FLAGS.SILENT", "(\\Seen)")[0] == "OK"
                assert call(unread)[1]["items"][0]["reference"] == first["reference"]
                flags = imap.uid("FETCH", str(changed["uid"]), "(FLAGS)")[1][0]
                assert b"\\Seen" not in flags
                assert imap.uid("STORE", str(changed["uid"]), "+FLAGS.SILENT", "(\\Seen)")[0] == "OK"
                assert not call(unread)[1]["items"]

            barrier = Barrier(2)
            with test.imap(alice) as imap, ThreadPoolExecutor(2) as pool:
                assert validity(imap, "INBOX") == inbox_validity

                def web_write():
                    barrier.wait(timeout=5)
                    return detail(second, method="PUT", revision=second["revision"],
                                  payload={"flags": {"seen": True}}, expected=(200, 412))[0]

                def imap_write():
                    barrier.wait(timeout=5)
                    return imap.uid("STORE", str(second_uid), "+FLAGS.SILENT", "(\\Flagged)")[0]

                web, client = pool.submit(web_write), pool.submit(imap_write)
                status = web.result()
                assert client.result() == "OK"
                flags = detail(second)[1]["flags"]
                assert flags["flagged"] and flags["seen"] == (status == 200), (status, flags)
                assert imap.uid("STORE", str(second_uid), "+FLAGS.SILENT", "(\\Deleted)")[0] == "OK"
                assert imap.expunge()[0] == "OK"
                detail(second, expected=404)

            draft = call("drafts", "POST", {"subject": "Draft one", "text": "old text"})[1]
            old = rows("Drafts")[0]
            call("drafts", "POST", {"subject": "Draft two", "text": "new text",
                                    "draftId": draft["draftId"], "draftRevision": draft["revision"]})
            edited = detail(old)[1]
            assert edited["uid"] == old["uid"] and edited["revision"] != old["revision"] and "new text" in edited["text"]
            removed = detail(edited, method="DELETE", revision=edited["revision"])[1]
            trashed = detail(old)[1]
            assert removed["ok"] and trashed["folder"] == "Trash"
            assert call("undo/" + removed["undoId"], "POST")[1]["ok"]
            assert detail(old)[1]["folder"] == "Drafts"

            with test.imap(alice) as imap:
                assert imap.rename("Archive", '"Reference Archive"')[0] == "OK"
            assert detail(copied)[1]["folder"] == "Reference Archive"
            print("Verified old UID rows, missing and duplicate Message-ID, isolation, ETags, MOVE and COPY, concurrent STORE, EXPUNGE, drafts, undo and folder rename.")

        # Stop between the file rename and registry update, then exercise both
        # recovery entry points (listing the destination and reading by ID).
        for source_folder, moved_to, reference, next_action in (
            ("INBOX", "Junk", third, "list"),
            ("INBOX", "Trash", first, "imap"),
            ("Junk", "Sent", third, "detail"),
        ):
            with closing(sqlite3.connect(db)) as conn, conn:
                base = conn.execute("SELECT basename FROM mailbox_message_refs WHERE reference=?", (reference["reference"],)).fetchone()[0]
                maildir = directory / "mail" / alice
                source_dirs = ("new", "cur") if source_folder == "INBOX" else (source_folder,)
                source, = [p for subdir in source_dirs for p in (maildir / subdir).glob(base + "*")]
                target = maildir / moved_to / source.name
                target.parent.mkdir(exist_ok=True)
                conn.execute("UPDATE mailbox_message_refs SET next_folder=?,next_basename=?,next_digest=? WHERE reference=?",
                             (moved_to, base, hashlib.sha256(source.read_bytes()).hexdigest(), reference["reference"]))
            source.rename(target)
            with test.daemon():
                alice_session = test.login(alice)
                if next_action == "list":
                    assert rows(moved_to)[0]["reference"] == reference["reference"]
                if next_action == "imap":
                    with test.imap(alice) as imap:
                        assert imap.select(moved_to)[0] == "OK"
                        assert imap.xatom("MOVE", "1", "Junk")[0] == "OK"
                assert detail(reference)[1]["folder"] == ("Junk" if next_action == "imap" else moved_to)

        # The same basename and bytes can describe a different physical file.
        # Creating a replacement before removing the old one guarantees a new inode.
        original, = (directory / "mail" / alice / "Reference Archive").iterdir()
        replacement = original.with_name(".new-message")
        replacement.write_bytes(original.read_bytes())
        replacement.replace(original)
        with test.daemon():
            alice_session = test.login(alice)
            detail(copied, expected=404)
            assert rows("Reference Archive")[0]["reference"] != copied["reference"]

        old_domain = alice.split("@", 1)[1]
        new_domain = "renamed.example.test"
        subprocess.run([str(candidate), "domain", "migrate", old_domain, new_domain, "--yes"],
                       cwd=directory, env=test.env, check=True)
        alice = f"alice@{new_domain}"
        bob = f"bob@{new_domain}"
        local = f"local@{new_domain}"
        with closing(sqlite3.connect(db)) as conn:
            assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
            assert conn.execute("SELECT mailbox FROM provisioned_mailboxes ORDER BY mailbox").fetchall() == [(alice,), (bob,)]
            assert conn.execute("SELECT DISTINCT mailbox FROM provisioning_operations ORDER BY mailbox").fetchall() == [(alice,), (bob,)]
        with test.daemon():
            alice_session = test.login(alice)
            assert detail(first)[1]["folder"] == "Junk" and detail(third)[1]["folder"] == "Sent"
            renamed_draft = detail(old)[1]
            assert call(f'drafts?uid={renamed_draft["uid"]}&folder=Drafts')[1]["message"]["subject"] == "Draft two"
            last = detail(first)[1]
            detail(last, method="DELETE", revision=last["revision"])
            last = detail(first)[1]
            assert last["folder"] == "Trash"
            detail(last, method="DELETE", revision=last["revision"])
            detail(first, expected=404)
        subprocess.run([str(candidate), "user:local", "delete", local], cwd=directory, env=test.env, check=True)
        with closing(sqlite3.connect(db)) as conn:
            assert not conn.execute("SELECT 1 FROM mailbox_message_refs WHERE reference IN (?,?,?)",
                                    (local_ref, first["reference"], second["reference"])).fetchone()
            assert conn.execute("SELECT 1 FROM mailbox_message_refs WHERE reference=?", (bob_ref,)).fetchone() == (1,)
            assert not conn.execute("SELECT 1 FROM mailbox_message_refs WHERE next_folder IS NOT NULL").fetchone()
        print("Verified pending moves recover on restart, account references survive domain rename, and permanent deletion retires references.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--previous", type=Path, help="seed the database with a build predating message references")
    args = parser.parse_args()
    main(args.binary.resolve(), args.previous.resolve() if args.previous else None)
