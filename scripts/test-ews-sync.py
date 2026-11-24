#!/usr/bin/env python3
"""Exercise durable EWS item sync over HTTPS against a disposable native daemon."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import runpy
import sqlite3
import tempfile
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape, quoteattr


FIXTURE = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]
INVALID_STATE = "ErrorInvalidSyncStateData"


def exchange(test, owner, operation, body, expected="NoError"):
    status, _, raw = test.ews(owner, f"<m:{operation}>{body}</m:{operation}>", full_login=True)
    assert status == 200, (status, raw)
    reply = ET.fromstring(raw).find(f".//{{*}}{operation}ResponseMessage")
    assert reply is not None and reply.findtext("{*}ResponseCode") == expected, raw
    assert reply.get("ResponseClass") == ("Success" if expected == "NoError" else "Error"), raw
    return reply


def sync(test, owner, state=None, *, folder="inbox", limit=512, error="NoError"):
    marker = f"<m:SyncState>{escape(state)}</m:SyncState>" if state is not None else ""
    response = exchange(test, owner, "SyncFolderItems",
                        '<m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>'
                        f"<m:SyncFolderId><t:DistinguishedFolderId Id={quoteattr(folder)}/></m:SyncFolderId>"
                        f"{marker}<m:MaxChangesReturned>{limit}</m:MaxChangesReturned>", error)
    token = response.findtext("{*}SyncState")
    if error != "NoError":
        assert token == "", token
        return
    assert token and len(token) <= 128, token
    last = response.findtext("{*}IncludesLastItemInRange")
    assert last in ("true", "false"), last
    changes = [
        (entry.tag.split("}")[-1], entry.find(".//{*}ItemId").get("Id"), entry.findtext("{*}IsRead"))
        for entry in response.find("{*}Changes")
    ]
    assert len(changes) <= limit, changes
    return token, last == "true", changes


def message(subject):
    return (f"From: sender@example.test\r\nTo: recipient@example.test\r\nSubject: {subject}\r\n"
            f"Message-ID: <{subject}@example.test>\r\n\r\n{subject}\r\n").encode()


def append(client, subject):
    receipt = client.append("INBOX", None, None, message(subject))
    assert receipt[0] == "OK", receipt


def only_inbox_uid(client):
    assert client.select("INBOX")[0] == "OK"
    status, uids = client.uid("SEARCH", None, "ALL")
    assert status == "OK" and len(uids[0].split()) == 1, (status, uids)
    return uids[0]


def subject_for(test, owner, item_id):
    reply = exchange(test, owner, "GetItem", f"<m:ItemIds><t:ItemId Id={quoteattr(item_id)}/></m:ItemIds>")
    assert reply.find(".//{*}ItemId").get("Id") == item_id
    return reply.findtext(".//{*}Subject")


def test_changes(test):
    with test.daemon():
        owner = test.provision("ews-sync")
        other = test.provision("ews-other")
        with test.imap(owner) as imap:
            append(imap, "old")
            first = sync(test, owner)
            observer = sync(test, owner)
            other_start = sync(test, other)
            trash = sync(test, owner, folder="deleteditems")
            assert first[1] and len(first[2]) == 1 and first[2][0][0] == "Create", first
            assert base64.b64decode(first[0], validate=True)
            old_id = first[2][0][1]
            assert observer[0] != first[0] and observer[2] == first[2]
            assert other_start[1:] == (True, []) and trash[1:] == (True, [])
            assert subject_for(test, owner, old_id) == "old"
            unknown = first[0][:-1] + ("A" if first[0][-1] != "A" else "B")
            for invalid in ("off:1", unknown, other_start[0]):
                sync(test, owner, invalid, error=INVALID_STATE)
            sync(test, other, first[0], error=INVALID_STATE)
            sync(test, owner, first[0], folder="deleteditems", error=INVALID_STATE)
            sync(test, owner, folder="unknown", error="ErrorFolderNotFound")
            for invalid_limit in (0, -1, 513, "abc", 2 ** 100):
                sync(test, owner, limit=invalid_limit, error="ErrorInvalidRequest")

            old_uid = only_inbox_uid(imap)
            assert imap.uid("STORE", old_uid, "+FLAGS.SILENT", r"(\Deleted)")[0] == "OK"
            assert imap.uid("EXPUNGE", old_uid)[0] == "OK"
            append(imap, "replacement")
            assert only_inbox_uid(imap) != old_uid

        def next_page(_):
            return sync(test, owner, first[0], limit=1)

        with ThreadPoolExecutor(max_workers=2) as pool:
            first_page, replay = pool.map(next_page, range(2))
        assert first_page == replay, (first_page, replay)
        first_cursor, last, changes = first_page
        assert first_cursor != first[0] and not last and len(changes) == 1, first_page

    with test.daemon():
        assert sync(test, owner, first[0], limit=1) == first_page
        second_page = sync(test, owner, first_cursor, limit=1)
        cursor, last, rest = second_page
        assert cursor != first_cursor and last and len(rest) == 1, second_page
        assert sync(test, owner, cursor, limit=1) == (cursor, True, [])
        changes += rest
        assert sorted(change[0] for change in changes) == ["Create", "Delete"], changes
        assert ("Delete", old_id, None) in changes, changes
        new_id, = (item for change, item, _ in changes if change == "Create")
        assert new_id != old_id and subject_for(test, owner, new_id) == "replacement"
        observed = sync(test, owner, observer[0], limit=2)
        assert observed[1:] == (True, changes), observed
        sync(test, owner, observer[0], limit=1, error=INVALID_STATE)

        with test.imap(owner) as imap:
            uid = only_inbox_uid(imap)
            assert imap.uid("STORE", uid, "+FLAGS.SILENT", r"(\Flagged)")[0] == "OK"
            assert sync(test, owner, cursor) == (cursor, True, [])
            assert imap.uid("STORE", uid, "+FLAGS.SILENT", r"(\Seen)")[0] == "OK"
            read_cursor, last, flags = sync(test, owner, cursor)
            assert (last, flags) == (True, [("ReadFlagChange", new_id, "true")]), flags
            assert imap.uid("STORE", uid, "-FLAGS.SILENT", r"(\Seen)")[0] == "OK"
            unread_cursor, last, flags = sync(test, owner, read_cursor)
            assert (last, flags) == (True, [("ReadFlagChange", new_id, "false")]), flags
            assert imap.create("Trash")[0] == "OK"
            assert imap.uid("MOVE", uid, "Trash")[0] == "OK"
        assert sync(test, owner, unread_cursor)[1:] == (True, [("Delete", new_id, None)])
        _, last, moved = sync(test, owner, trash[0], folder="deleteditems")
        assert last and len(moved) == 1 and moved[0][0] == "Create", moved
        assert moved[0][1].startswith("deleteditems:") and subject_for(test, owner, moved[0][1]) == "replacement"


def test_paging(test):
    with test.daemon():
        owner = test.provision("ews-pages")
        # Seed enough fixture files to exercise the actual 512-change EWS limit.
        root = test.directory / "mail" / owner
        new = root / "new"
        new.mkdir(parents=True, exist_ok=True)
        for i in range(513):
            (new / f"1000000{i:03}-item.eml").write_bytes(message(f"item-{i}"))
        cursor, last, first = sync(test, owner)
        assert not last and len(first) == 512
        assert len(set(first)) == 512 and all(kind == "Create" for kind, _, _ in first)

        # Remove the unsent item and add another while the initial sync is paging.
        assert ("Create", "inbox:1000000512-item.eml", None) not in first
        (new / "1000000512-item.eml").unlink()
        special = '2000000000-production&qa.eml'
        (new / special).write_bytes(message("between-pages"))
        next_cursor, last, remaining = sync(test, owner, cursor)
        assert (last, remaining) == (True, [("Create", "inbox:" + special, None)]), remaining
        assert subject_for(test, owner, "inbox:" + special) == "between-pages"

        # A directory read error must leave the cursor usable and publish no deletes.
        cur = root / "cur"
        cur.mkdir(exist_ok=True)
        backup = root / "cur-backup"
        cur.rename(backup)
        cur.write_text("This fixture path is intentionally a file")
        sync(test, owner, next_cursor, error="ErrorInternalServerError")
        cur.unlink()
        backup.rename(cur)
        assert sync(test, owner, next_cursor) == (next_cursor, True, [])

        # Age the fixture's persisted cursor and confirm the client can resync.
        with closing(sqlite3.connect(test.directory / "smtp.db")) as db:
            aged = db.execute("UPDATE ews_item_sync SET touched_at=? WHERE sync_key=?",
                              (int(time.time()) - 31 * 86400, next_cursor))
            assert aged.rowcount == 1
            db.commit()
        sync(test, owner, next_cursor, error=INVALID_STATE)
        new_start = sync(test, owner, limit=1)
        assert new_start[1:] == (False, first[:1])
        # Repeated abandoned starts cannot grow this folder's cursor count.
        starts = [sync(test, owner, limit=1) for _ in range(16)]
        sync(test, owner, new_start[0], error=INVALID_STATE)
        assert sync(test, owner, starts[-1][0], limit=1)[2] == first[1:2]
        with closing(sqlite3.connect(test.directory / "smtp.db")) as db:
            count, = db.execute("SELECT count(*) FROM ews_item_sync JOIN users ON users.id=ews_item_sync.user_id "
                                "WHERE username=? AND folder='inbox'", (owner,)).fetchone()
            assert count == 16, count


def test_calendar_and_contacts(test):
    with test.daemon():
        owner = test.provision("ews-pim")
        for folder, element in (
            ("calendar", "<t:CalendarItem><t:Subject>Sync event</t:Subject></t:CalendarItem>"),
            ("contacts", "<t:Contact><t:DisplayName>Sync contact</t:DisplayName></t:Contact>"),
        ):
            start = sync(test, owner, folder=folder)
            assert start[1:] == (True, [])
            created = exchange(test, owner, "CreateItem", f"<m:Items>{element}</m:Items>")
            item_id = created.find(".//{*}ItemId").get("Id")
            assert item_id.startswith(folder + ":")
            cursor, last, creates = sync(test, owner, start[0], folder=folder)
            assert (last, creates) == (True, [("Create", item_id, None)])
            exchange(test, owner, "DeleteItem", f"<m:ItemIds><t:ItemId Id={quoteattr(item_id)}/></m:ItemIds>")
            assert sync(test, owner, cursor, folder=folder)[1:] == (True, [("Delete", item_id, None)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=lambda path: Path(path).resolve())
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-ews-sync-") as directory:
        test = FIXTURE(args.binary, Path(directory), staging=True)
        test_changes(test)
        test_paging(test)
        test_calendar_and_contacts(test)
    print("EWS item sync: replacement, retry, restart, flags, move, isolation, 512-change paging, scan errors, cursor retention, calendar, and contacts passed over HTTPS")


if __name__ == "__main__":
    main()
