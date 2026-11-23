#!/usr/bin/env python3
"""Verify ActiveSync folder discovery and mutations on the native HTTPS listener."""

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


SCRIPTS = Path(__file__).resolve().parent
move_suite = runpy.run_path(str(SCRIPTS / "test-eas-move-items.py"))
search_suite = runpy.run_path(str(SCRIPTS / "test-eas-search.py"))
Fixture, snapshot, ids, move = (move_suite[name] for name in ("Fixture", "snapshot", "ids", "response"))
state, hosted = move_suite["state"], move_suite["hosted"]
element, sync, estimate = state["element"], state["sync"], state["estimate"]
WBXML, END, DEVICE = state["WBXML"], state["END"], state["DEVICE"]
FOLDER = WBXML + b"\x00\x07"
IMAP_NAME, EAS_NAME = "Client projects", "Device projects"


def field(data, tag):
    match = re.search(bytes([0x40 | tag]) + rb"\x03([^\x00]+)\x00\x01", data)
    return match[1].decode() if match else None


def hierarchy(test, mailbox, key="0", *, device=DEVICE, encoded=False, expected=1):
    body = FOLDER + b"\x56" + element(0x12, key) + END
    status, _, data = test.eas(mailbox, body, command="FolderSync", device=device, encoded=encoded)
    assert status == 200 and int(field(data, 0x0c)) == expected, (status, data)
    returned_key = field(data, 0x12)
    if expected != 1:
        assert returned_key is None
        return None, []
    assert returned_key and len(returned_key) <= 64
    changes = []
    pattern = (rb"([\x4f\x50\x51])\x48\x03([^\x00]+)\x00\x01"
               rb"(?:\x49\x03([^\x00]+)\x00\x01\x47\x03([^\x00]+)\x00\x01\x4a\x03([0-9]+)\x00\x01)?\x01")
    for command, item, parent, name, kind in re.findall(pattern, data):
        changes.append((command[0], item.decode(), parent.decode(), name.decode(), int(kind or 0)))
    assert len(changes) == int(field(data, 0x17)), data
    return returned_key, changes


def create(test, mailbox, key, name, *, parent="0", kind="12", device=DEVICE, encoded=False, expected=1):
    body = FOLDER + b"\x53" + element(0x12, key) + element(9, parent) + element(7, name) + element(0x0a, kind) + END
    status, _, data = test.eas(mailbox, body, command="FolderCreate", device=device, encoded=encoded)
    if expected == 401:
        assert status in (401, 403), (status, data)
        return None, None
    assert status == 200 and int(field(data, 0x0c)) == expected, (status, data)
    result = field(data, 0x12), field(data, 8)
    if expected == 1:
        assert result[0] != key and len(result[1]) == 11, result
    else:
        assert result == (None, None), result
    return result


def edit(test, mailbox, key, folder, name=None, *, parent="0", device=DEVICE, encoded=False, expected=1):
    tag = b"\x54" if name is None else b"\x55"
    command = "FolderDelete" if name is None else "FolderUpdate"
    fields = element(0x12, key) + element(8, folder)
    if name is not None:
        fields += element(9, parent) + element(7, name)
    status, _, data = test.eas(mailbox, FOLDER + tag + fields + END, command=command, device=device, encoded=encoded)
    if expected == 401:
        assert status in (401, 403), (status, data)
        return None
    assert status == 200 and data.startswith(FOLDER + tag) and int(field(data, 0x0c)) == expected, (status, data)
    next_key = field(data, 0x12)
    if expected == 1:
        assert next_key and next_key != key
    else:
        assert next_key is None
    assert field(data, 8) is None
    return next_key


def added_folder(changes, name):
    command, folder, parent, label, kind = next(change for change in changes if change[3] == name)
    assert command == 0x4f and parent == "0" and label == name and kind == 12
    assert len(folder) == 11
    return folder


def initial_and_create(test, owner, peer):
    code, headers, _ = hosted["request"](test.eas_url, method="OPTIONS", context=test.tls_context)
    assert code == 200 and {"FolderCreate", "FolderUpdate", "FolderDelete"} <= set(headers["MS-ASProtocolCommands"].split(",")), headers
    key, folders = hierarchy(test, owner, encoded=True)
    assert {row[1] for row in folders} == {"1", "2", "3", "4", "5", "6"}
    hierarchy(test, owner, "1", expected=9)
    peer_key, _ = hierarchy(test, peer)
    assert peer_key != key
    hierarchy(test, peer, key, expected=9)
    hierarchy(test, owner, key, device="DifferentDevice", expected=9)

    for mailbox in (owner, peer):
        with test.imap(mailbox) as client:
            assert client.create(f'"{IMAP_NAME}"')[0] == "OK"
    key, changes = hierarchy(test, owner, key)
    imap_folder = added_folder(changes, IMAP_NAME)
    _, peer_folders = hierarchy(test, peer, peer_key)
    peer_folder = added_folder(peer_folders, IMAP_NAME)
    assert peer_folder != imap_folder
    assert hierarchy(test, owner, key) == (key, [])

    assert test.deliver(owner, subject="Folder workflow sample")[0] == 250
    size = test.bytes(owner)
    test.provision("owner", quota=size)
    create(test, owner, key, "Wrong parent", parent=imap_folder, expected=5)
    create(test, owner, key, "Calendar data", kind="13", expected=10)
    create(test, owner, key, "Screening", expected=10)
    create(test, owner, key, "../Other", expected=10)
    create(test, owner, key, IMAP_NAME, expected=2)
    create(test, peer, key, "Foreign key", expected=9)
    old_key = key
    key, eas_folder = create(test, owner, key, EAS_NAME, encoded=True)
    assert test.bytes(owner) == size
    assert hierarchy(test, owner, key) == (key, [])
    hierarchy(test, owner, old_key, expected=9)
    with test.imap(owner) as client:
        status, folders = client.list()
        assert status == "OK" and any(f'"{EAS_NAME}"'.encode() in row for row in folders)
    status, folders = test.api(test.login(owner), "folders")
    assert status == 200 and any(row["name"] == EAS_NAME and row["total"] == 0 for row in folders)
    return key, imap_folder, eas_folder, peer_folder, size


def cross_client_mail(test, owner, peer, native_folder, imap_folder, peer_folder, size):
    _, inbox = snapshot(test, owner, "1")
    source, = ids(inbox)
    assert move(test, owner, (source, "1", peer_folder)) == [(2, None)]
    (status, target), = move(test, owner, (source, "1", imap_folder))
    assert status == 3
    with test.imap(owner) as client:
        assert client.select(f'"{IMAP_NAME}"') == ("OK", [b"1"])
        assert client.uid("SEARCH", None, "SUBJECT workflow")[1] == [target.split(":")[1].encode()]
    key, result = snapshot(test, owner, imap_folder)
    assert ids(result) == [target]
    assert estimate(test, owner, {imap_folder: key}) == {imap_folder: (1, 0)}
    assert search_suite["ids"](search_suite["search"](test, owner, "workflow", folder=imap_folder))
    assert b"Folder workflow sample" in search_suite["search"](test, owner, "workflow")
    search_suite["search"](test, peer, "workflow", folder=imap_folder, expected=11)
    native_key, _ = snapshot(test, owner, native_folder)
    (status, target), = move(test, owner, (target, imap_folder, native_folder))
    assert status == 3 and test.bytes(owner) == size
    assert state["ping"](test, owner, folders=(native_folder,)) == (2, (native_folder,))
    assert ids(snapshot(test, owner, native_folder, native_key)[1]) == [target]


def mutation_failure_and_contention(test, owner, key, size):
    root = test.directory / "mail" / owner
    with closing(sqlite3.connect(test.directory / "smtp.db")) as conn, conn:
        conn.execute("""CREATE TRIGGER fixture_abort_folder_sync BEFORE UPDATE ON eas_mailbox_state
                     WHEN NEW.collection_id='folder-hierarchy'
                     BEGIN SELECT RAISE(ABORT,'fixture hierarchy write failure'); END""")
    try:
        create(test, owner, key, "Rolled back", expected=6)
        assert not (root / "Rolled back").exists()
        with closing(sqlite3.connect(test.directory / "smtp.db")) as conn:
            assert conn.execute("SELECT COUNT(*) FROM imap_mailboxes WHERE username=? AND mailbox='Rolled back'",
                                (owner,)).fetchone() == (0,)
    finally:
        with closing(sqlite3.connect(test.directory / "smtp.db")) as conn, conn:
            conn.execute("DROP TRIGGER fixture_abort_folder_sync")
    assert hierarchy(test, owner, key) == (key, [])

    test.provision("owner", quota=size, enabled=False)
    create(test, owner, key, "Suspended folder", expected=401)
    assert not (root / "Suspended folder").exists()
    test.provision("owner", quota=size)

    barrier = Barrier(2)

    def imap_create():
        with test.imap(owner) as client:
            barrier.wait(timeout=5)
            return client.create('"Raced folder"')[0]

    def eas_create():
        body = FOLDER + b"\x53" + element(0x12, key) + element(9, "0") + element(7, "Raced folder") + element(0x0a, "12") + END
        barrier.wait(timeout=5)
        status, _, raw = test.eas(owner, body, command="FolderCreate", device=DEVICE)
        assert status == 200
        return int(field(raw, 0x0c)), field(raw, 0x12)

    with ThreadPoolExecutor(max_workers=2) as workers:
        imap, eas = workers.submit(imap_create), workers.submit(eas_create)
        status, new_key = eas.result()
        assert (imap.result(), status) in (("OK", 2), ("NO", 1))
    if status == 1:
        assert hierarchy(test, owner, new_key) == (new_key, [])
        assert not (root / ".Raced folder").exists()
        return new_key
    refreshed, changes = hierarchy(test, owner, key)
    added_folder(changes, "Raced folder")
    return refreshed


def observe_external_changes(test, owner, key, original):
    updated_name = IMAP_NAME + " updated"
    with test.imap(owner) as client:
        assert client.rename(f'"{IMAP_NAME}"', f'"{updated_name}"')[0] == "OK"
    key, changes = hierarchy(test, owner, key)
    assert changes == [(0x51, original, "0", updated_name, 12)], changes
    with test.imap(owner) as client:
        assert client.delete(f'"{updated_name}"')[0] == "OK"
        assert client.create(f'"{updated_name}"')[0] == "OK"
    key, changes = hierarchy(test, owner, key)
    assert any(row[:2] == (0x50, original) for row in changes)
    assert added_folder(changes, updated_name) != original
    status, _, raw = sync(test, owner, 0, original)
    assert status == 12, raw
    return key


def visible_folders(test, owner):
    status, folders = test.api(test.login(owner), "folders")
    assert status == 200, folders
    return {folder["name"]: folder["total"] for folder in folders}


def verify_native_edits(test, owner, peer, key, original, foreign, size):
    session = test.login(owner)
    root = test.directory / "mail" / owner
    other_key, _ = hierarchy(test, owner, device="OtherDevice")
    _, data = snapshot(test, owner, original)
    item, = ids(data)
    before = test.api(session, "messages?" + urlencode({"folder": EAS_NAME}))[1]["items"][0]
    edit(test, owner, key, foreign, expected=4)
    edit(test, peer, key, original, "Foreign folder", expected=9)
    edit(test, owner, key, original, "Foreign device", device="OtherDevice", expected=9)
    edit(test, owner, key, "1", "Renamed Inbox", expected=2)
    edit(test, owner, key, "5", expected=3)
    edit(test, owner, key, original, "Nested folder", parent="1", expected=5)
    edit(test, owner, key, original, "../escape", expected=10)
    edit(test, owner, key, original, IMAP_NAME + " updated", expected=2)

    renamed = "Device planning"
    key = edit(test, owner, key, original, renamed, encoded=True)
    assert visible_folders(test, owner)[renamed] == 1 and EAS_NAME not in visible_folders(test, owner)
    assert test.bytes(owner) == size and not (root / EAS_NAME).exists()
    assert test.api(session, "messages/ref/" + before["reference"])[1]["folder"] == renamed
    _, data = snapshot(test, owner, original)
    assert ids(data) == [item] and b"Folder workflow sample" in data
    edit(test, owner, other_key, original, "Stale device rename", device="OtherDevice", expected=9)
    other_key, changes = hierarchy(test, owner, other_key, device="OtherDevice")
    assert changes == [(0x51, original, "0", renamed, 12)], changes
    assert hierarchy(test, owner, key) == (key, [])

    canonical = IMAP_NAME + " updated"
    with test.imap(owner) as client:
        assert client.create('"Rename contender"')[0] == "OK"
    key, changes = hierarchy(test, owner, key)
    contender = added_folder(changes, "Rename contender")
    canonical_id = next(row[1] for row in hierarchy(test, owner, device="Discovery")[1] if row[3] == canonical)
    (status, target), = move(test, owner, (item, original, canonical_id))
    assert status == 3 and test.bytes(owner) == size

    with closing(sqlite3.connect(test.directory / "smtp.db")) as conn, conn:
        conn.execute("""CREATE TRIGGER fixture_abort_folder_edit BEFORE UPDATE ON eas_mailbox_state
                     WHEN NEW.collection_id='folder-hierarchy'
                     BEGIN SELECT RAISE(ABORT,'fixture folder edit failure'); END""")
    try:
        edit(test, owner, key, canonical_id, "Uncommitted project", expected=6)
        edit(test, owner, key, canonical_id, expected=6)
        assert (root / canonical).is_symlink() and not (root / "Uncommitted project").exists()
        assert test.bytes(owner) == size
        assert visible_folders(test, owner)[canonical] == 1
        assert hierarchy(test, owner, key) == (key, [])
    finally:
        with closing(sqlite3.connect(test.directory / "smtp.db")) as conn, conn:
            conn.execute("DROP TRIGGER fixture_abort_folder_edit")

    case_name = canonical.upper()
    key = edit(test, owner, key, canonical_id, case_name)
    assert (root / case_name).readlink().as_posix() == f".{case_name}/cur"
    _, after = snapshot(test, owner, canonical_id)
    assert ids(after) == [target] and b"Folder workflow sample" in after
    with test.imap(owner) as client:
        assert client.select(f'"{case_name}"') == ("OK", [b"1"])
        old_validity = int(client.response("UIDVALIDITY")[1][0])
        assert client.uid("SEARCH", None, "SUBJECT workflow")[1] == [target.split(":")[1].encode()]

    test.provision("owner", quota=size, enabled=False)
    edit(test, owner, key, canonical_id, expected=401)
    test.provision("owner", quota=size)
    assert test.deliver(owner)[0] == 452
    other_key, _ = hierarchy(test, owner, other_key, device="OtherDevice")
    key = edit(test, owner, key, canonical_id, encoded=True)
    assert test.bytes(owner) == 0 and case_name not in visible_folders(test, owner)
    assert not (root / case_name).is_symlink() and not (root / f".{case_name}").exists()
    assert test.api(test.login(owner), "messages/ref/" + before["reference"])[0] == 404
    assert hierarchy(test, owner, other_key, device="OtherDevice")[1] == [(0x50, canonical_id, "", "", 0)]
    assert sync(test, owner, 0, canonical_id)[0] == 12
    edit(test, owner, key, canonical_id, expected=4)
    edit(test, owner, key, contender, case_name, parent="99", expected=5)

    key, replacement = create(test, owner, key, case_name)
    assert replacement != canonical_id
    with test.imap(owner) as client:
        assert client.select(f'"{case_name}"') == ("OK", [b"0"])
        assert int(client.response("UIDVALIDITY")[1][0]) > old_validity
        raw = hosted["imap_message"]("Fits after deletion", payload=0)
        raw = hosted["imap_message"]("Fits after deletion", payload=size - len(raw))
        assert len(raw) == size
        assert client.append(f'"{case_name}"', None, None, raw + b"x")[0] == "NO"
        assert client.append(f'"{case_name}"', None, None, raw)[0] == "OK"
        assert test.bytes(owner) == size
    key = edit(test, owner, key, replacement)
    assert test.bytes(owner) == 0
    return key, contender


def rename_contention(test, owner, key, original):
    destination = "Shared destination"
    barrier = Barrier(2)

    def imap_rename():
        with test.imap(owner) as client:
            barrier.wait(timeout=5)
            return client.rename('"Rename contender"', f'"{destination}"')[0]

    def eas_rename():
        body = FOLDER + b"\x55" + element(0x12, key) + element(8, original) + element(9, "0") + element(7, destination) + END
        barrier.wait(timeout=5)
        status, _, data = test.eas(owner, body, command="FolderUpdate", device=DEVICE)
        assert status == 200, data
        return int(field(data, 0x0c)), field(data, 0x12)

    with ThreadPoolExecutor(max_workers=2) as workers:
        imap, eas = workers.submit(imap_rename), workers.submit(eas_rename)
        code, next_key = eas.result()
        result = imap.result(), code
        assert result in (("OK", 2), ("NO", 1)), result
    root = test.directory / "mail" / owner
    assert (root / destination).is_dir()
    assert (root / "Rename contender").is_dir() == (code == 1)
    assert (root / "Device planning").is_dir() == (code == 2)
    return hierarchy(test, owner, next_key or key)[0]


def retain_fixture_journal(test, mailbox, key, folder, destination):
    with closing(sqlite3.connect(test.directory / "smtp.db")) as conn, conn:
        conn.executescript("""
            CREATE TRIGGER fixture_abort_edit BEFORE UPDATE ON eas_mailbox_state
            WHEN NEW.collection_id='folder-hierarchy'
            BEGIN SELECT RAISE(ABORT,'fixture folder edit failure'); END;
            CREATE TRIGGER fixture_retain_journal BEFORE DELETE ON eas_folder_edits
            BEGIN SELECT RAISE(ABORT,'fixture retain interrupted edit'); END;
        """)
    try:
        edit(test, mailbox, key, folder, destination, expected=6)
    finally:
        with closing(sqlite3.connect(test.directory / "smtp.db")) as conn, conn:
            conn.executescript("DROP TRIGGER fixture_abort_edit; DROP TRIGGER fixture_retain_journal;")


def simulate_interrupted_edits(test):
    # Recreate the on-disk states at the two commit boundaries from journal
    # entries written by the actual server. Use the original inode in both.
    with closing(sqlite3.connect(test.directory / "smtp.db")) as conn, conn:
        rows = conn.execute(
            "SELECT id,mailbox_root,source,destination,maildir_plus FROM eas_folder_edits"
        ).fetchall()
        assert len(rows) == 2, rows
        for ident, mailbox, source, destination, plus in rows:
            root = test.directory / "mail" / mailbox
            prefix = "." if plus else ""
            physical = root / (prefix + source)
            if plus:
                (root / source).unlink()
            if destination is not None:
                physical.rename(root / (prefix + destination))
                if plus:
                    (root / destination).symlink_to(f".{destination}/cur")
            else:
                physical.rename(root / f".pending-folder-{ident}")
                conn.execute("UPDATE eas_folder_edits SET committed=1 WHERE id=?", (ident,))
                conn.execute("DELETE FROM imap_mailboxes WHERE username=? AND mailbox=?", (mailbox, source))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-eas-folders-", dir="/tmp") as directory:
        test = Fixture(args.binary.resolve(strict=True), Path(directory), staging=True)
        with test.daemon():
            owner = test.provision("owner")
            peer = test.provision("peer")
            key, imap_folder, eas_folder, peer_folder, size = initial_and_create(test, owner, peer)
            cross_client_mail(test, owner, peer, eas_folder, imap_folder, peer_folder, size)
            key = mutation_failure_and_contention(test, owner, key, size)
            key = observe_external_changes(test, owner, key, imap_folder)
        with test.daemon():
            assert hierarchy(test, owner, key) == (key, [])
            _, raw = snapshot(test, owner, eas_folder)
            assert len(ids(raw)) == 1 and b"Folder workflow sample" in raw
            assert test.bytes(owner) == size
            key, _ = verify_native_edits(test, owner, peer, key, eas_folder, peer_folder, size)
            key = rename_contention(test, owner, key, eas_folder)
        with test.daemon():
            assert hierarchy(test, owner, key) == (key, []) and test.bytes(owner) == 0
            rollback_owner = test.provision("rollback")
            purge_owner = test.provision("purge")
            with test.imap(rollback_owner) as client:
                assert client.create('"Restart kept"')[0] == "OK"
                assert client.append('"Restart kept"', None, None, hosted["imap_message"]())[0] == "OK"
            rollback_key, changes = hierarchy(test, rollback_owner)
            retained = added_folder(changes, "Restart kept")
            purge_key, _ = hierarchy(test, purge_owner)
            purge_key, removed = create(test, purge_owner, purge_key, "Restart purge")
            with test.imap(purge_owner) as client:
                assert client.append('"Restart purge"', None, None, hosted["imap_message"]())[0] == "OK"
            retain_fixture_journal(test, rollback_owner, rollback_key, retained, "Interrupted name")
            retain_fixture_journal(test, purge_owner, purge_key, removed, None)
        simulate_interrupted_edits(test)
        with test.daemon():
            assert hierarchy(test, rollback_owner, rollback_key) == (rollback_key, [])
            assert visible_folders(test, rollback_owner)["Restart kept"] == 1
            assert hierarchy(test, purge_owner, purge_key)[1] == [(0x50, removed, "", "", 0)]
            assert test.bytes(purge_owner) == 0
            with closing(sqlite3.connect(test.directory / "smtp.db")) as conn:
                assert conn.execute("SELECT COUNT(*) FROM eas_folder_edits").fetchone() == (0,)
    print("Verified native FolderSync, create, rename and delete, quota release, independent devices, IMAP and webmail visibility, rollback, and restart.")


if __name__ == "__main__":
    main()
