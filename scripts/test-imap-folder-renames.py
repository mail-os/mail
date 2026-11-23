#!/usr/bin/env python3
"""Exercise mailbox identity across RENAME on the native IMAPS listener."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import re
import runpy
import sqlite3
import tempfile
from threading import Barrier
from urllib.parse import urlencode


suite = runpy.run_path(str(Path(__file__).with_name("test-eas-folder-hierarchy.py")))
Fixture, hierarchy, snapshot, ids = (suite[name] for name in ("Fixture", "hierarchy", "snapshot", "ids"))
message = suite["hosted"]["imap_message"]


def quoted(name):
    return f'"{name}"'


def identity(client, name):
    assert client.select(quoted(name))[0] == "OK", name
    validity = int(client.response("UIDVALIDITY")[1][0])
    next_uid = int(client.response("UIDNEXT")[1][0])
    status, rows = client.uid("SEARCH", None, "ALL")
    assert status == "OK", rows
    return validity, next_uid, [int(value) for value in rows[0].split()]


def append(client, folder, title):
    status, reply = client.append(quoted(folder), None, None, message(title))
    assert status == "OK", reply
    return tuple(map(int, re.search(rb"APPENDUID (\d+) (\d+)", reply[0]).groups()))


def verify_layout(test, owner, *, canonical):
    old = "Reference Archive" if canonical else "Project Notes"
    new = "Planning Archive" if canonical else "Project Papers"
    root = test.directory / "mail" / owner
    with test.imap(owner) as client:
        if canonical:
            assert client.create(quoted(old))[0] == "OK"
        _, first = append(client, old, "Removed note")
        _, second = append(client, old, "Retained note")
        assert client.select(quoted(old)) == ("OK", [b"2"])
        assert client.uid("STORE", str(first), "+FLAGS", r"(\Deleted)")[0] == "OK"
        assert client.expunge()[0] == "OK"
        before = identity(client, old)
        assert before[1:] == (second + 1, [second]), before

    assert (root / old).is_symlink() == canonical
    session = test.login(owner)
    status, listing = test.api(session, "messages?" + urlencode({"folder": old}))
    assert status == 200, listing
    item, = listing["items"]
    assert item["uid"] == second
    reference = "messages/ref/" + item["reference"]
    key, changes = hierarchy(test, owner)
    folder = suite["added_folder"](changes, old)
    mail_key, data = snapshot(test, owner, folder)
    original_ids = ids(data)
    assert len(original_ids) == 1

    with closing(sqlite3.connect(test.directory / "smtp.db")) as conn, conn:
        conn.execute("""CREATE TRIGGER fixture_abort_rename BEFORE UPDATE OF mailbox ON imap_uids
                     BEGIN SELECT RAISE(ABORT,'fixture UID failure'); END""")
    try:
        with test.imap(owner) as client:
            assert client.rename(quoted(old), quoted(new))[0] == "NO"
            assert identity(client, old) == before
        assert (root / old).is_dir() and not (root / new).exists()
        assert hierarchy(test, owner, key) == (key, [])
        assert test.api(session, reference)[1]["folder"] == old
    finally:
        with closing(sqlite3.connect(test.directory / "smtp.db")) as conn, conn:
            conn.execute("DROP TRIGGER fixture_abort_rename")

    for target in (new, new.upper()):
        source = old.lower() if old != old.lower() and (root / old.lower()).exists() else old
        with test.imap(owner) as client:
            assert client.rename(quoted(source), quoted(target))[0] == "OK"
            assert identity(client, target) == before
        if canonical:
            assert (root / target).readlink().as_posix() == f".{target}/cur"
        assert test.api(session, reference)[1]["folder"] == target
        folders = suite["visible_folders"](test, owner)
        assert folders[target] == 1 and old not in folders, folders
        key, updates = hierarchy(test, owner, key)
        assert updates == [(0x51, folder, "0", target, 12)], updates
        _, incremental = snapshot(test, owner, folder, mail_key)
        assert not ids(incremental) and not ids(incremental, 0x49), incremental
        mail_key, current = snapshot(test, owner, folder)
        assert ids(current) == original_ids
        old = target
    return old, folder, original_ids, before


def verify_reused_names(test, owner):
    with test.imap(owner) as client:
        assert client.create("Revisited")[0] == "OK"
        assert append(client, "Revisited", "Old destination message")[1] == 1
        with closing(sqlite3.connect(test.directory / "smtp.db")) as conn, conn:
            conn.execute("UPDATE imap_mailboxes SET uidvalidity=uidvalidity+10000 WHERE username=? AND mailbox='Revisited'", (owner,))
        retired = identity(client, "Revisited")
        assert client.delete("Revisited")[0] == "OK"
        old_validity, old_uid = append(client, "ReusedSource", "Different message")
        assert old_validity < retired[0] and old_uid == 1
        assert client.rename("ReusedSource", "Revisited")[0] == "OK"
        renamed = identity(client, "Revisited")
        assert renamed[0] > retired[0] and renamed[1:] == (2, [1]), (retired, renamed)
        assert client.create("ReusedSource")[0] == "OK"
        recreated = identity(client, "ReusedSource")
        assert recreated[0] > old_validity and recreated[1:] == (1, []), recreated


def verify_contention(test, owner):
    barrier = Barrier(2)

    def rename(client, name):
        barrier.wait(timeout=5)
        return client.rename(name, "SharedDestination")[0]

    with test.imap(owner) as first, test.imap(owner) as second:
        original = {}
        for client, name in ((first, "FirstSource"), (second, "SecondSource")):
            append(client, name, name)
            original[name] = identity(client, name)
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(rename, first, "FirstSource")
            b = pool.submit(rename, second, "SecondSource")
            status = [a.result(), b.result()]
        assert sorted(status) == ["NO", "OK"], status
        winner, loser = (("FirstSource", "SecondSource") if status[0] == "OK" else ("SecondSource", "FirstSource"))
        assert identity(first, "SharedDestination") == original[winner]
        assert first.uid("SEARCH", None, "SUBJECT", winner)[1] == [b"1"]
        assert identity(second, loser) == original[loser]


def verify_append_contention(test, owner):
    barrier = Barrier(2)

    def rename(client):
        barrier.wait(timeout=5)
        return client.rename("AppendSource", "AppendDestination")[0]

    def append_during_rename(client):
        barrier.wait(timeout=5)
        return append(client, "AppendSource", "Concurrent append")

    with test.imap(owner) as mover, test.imap(owner) as writer:
        append(writer, "AppendSource", "Original contents")
        with ThreadPoolExecutor(max_workers=2) as pool:
            moved = pool.submit(rename, mover)
            appended = pool.submit(append_during_rename, writer)
            assert moved.result() == "OK"
            append_validity, append_uid = appended.result()
        disk = test.directory / "mail" / owner
        containing = "AppendSource" if (disk / "AppendSource").exists() else "AppendDestination"
        validity, _, _ = identity(writer, containing)
        assert validity == append_validity
        assert writer.uid("SEARCH", None, "SUBJECT", quoted("Concurrent append"))[1] == [str(append_uid).encode()]


def verify_imap_only_name(test, owner):
    with test.imap(owner) as client:
        assert client.create(quoted("Notes: Imported"))[0] == "OK"
        append(client, "Notes: Imported", "Imported note")
        before = identity(client, "Notes: Imported")
        assert client.rename(quoted("Notes: Imported"), quoted("Notes: Filed"))[0] == "OK"
        assert identity(client, "Notes: Filed") == before
        assert client.rename(quoted("Notes: Filed"), "INBOX")[0] == "NO"


def retain_interrupted_rename(test, owner):
    with test.imap(owner) as client, closing(sqlite3.connect(test.directory / "smtp.db")) as conn:
        assert client.create("Interrupted")[0] == "OK"
        append(client, "Interrupted", "Keep across startup")
        before = identity(client, "Interrupted")
        with conn:
            conn.executescript("""
                CREATE TRIGGER fixture_abort_commit BEFORE UPDATE OF committed ON eas_folder_edits
                BEGIN SELECT RAISE(ABORT,'fixture edit did not commit'); END;
                CREATE TRIGGER fixture_keep_record BEFORE DELETE ON eas_folder_edits
                BEGIN SELECT RAISE(ABORT,'fixture retains journal'); END;
            """)
        try:
            assert client.rename("Interrupted", "Tentative")[0] == "NO"
            assert conn.execute("SELECT source,destination,committed FROM eas_folder_edits").fetchall() == [
                ("Interrupted", "Tentative", 0),
            ]
        finally:
            with conn:
                conn.executescript("DROP TRIGGER fixture_abort_commit; DROP TRIGGER fixture_keep_record;")
    return before


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-imap-rename-", dir="/tmp") as directory:
        test = Fixture(args.binary.resolve(strict=True), Path(directory), staging=True)
        with test.daemon():
            owner = test.provision("rename")
            results = [verify_layout(test, owner, canonical=canonical) for canonical in (False, True)]
            verify_reused_names(test, owner)
            verify_contention(test, owner)
            verify_append_contention(test, owner)
            verify_imap_only_name(test, owner)
            interrupted = retain_interrupted_rename(test, owner)
        # Recreate the filesystem layout at the moment before the transaction
        # commits. The journal row and directory identity came from RENAME.
        root = test.directory / "mail" / owner
        (root / "Interrupted").unlink()
        (root / ".Interrupted").rename(root / ".Tentative")
        (root / "Tentative").symlink_to(".Tentative/cur")
        with test.daemon():
            with test.imap(owner) as client:
                assert identity(client, "Interrupted") == interrupted
                assert not (root / "Tentative").exists() and not (root / ".Tentative").exists()
            for name, folder, item_ids, before in results:
                with test.imap(owner) as client:
                    assert identity(client, name) == before
                assert ids(snapshot(test, owner, folder)[1]) == item_ids
        with closing(sqlite3.connect(test.directory / "smtp.db")) as conn:
            assert conn.execute("SELECT COUNT(*) FROM eas_folder_edits").fetchone() == (0,)
    print("Verified IMAPS rename identity for flat and Maildir++ folders, case changes, name reuse, ActiveSync and webmail, failure rollback, contention, and restart.")


if __name__ == "__main__":
    main()
