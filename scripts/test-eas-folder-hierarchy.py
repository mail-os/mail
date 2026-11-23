#!/usr/bin/env python3
"""Verify ActiveSync FolderSync and FolderCreate on the native HTTPS listener."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import re
import runpy
import sqlite3
import tempfile
from threading import Barrier


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


def added_folder(changes, name):
    command, folder, parent, label, kind = next(change for change in changes if change[3] == name)
    assert command == 0x4f and parent == "0" and label == name and kind == 12
    assert len(folder) == 11
    return folder


def initial_and_create(test, owner, peer):
    code, headers, _ = hosted["request"](test.eas_url, method="OPTIONS", context=test.tls_context)
    assert code == 200 and "FolderCreate" in headers["MS-ASProtocolCommands"].split(","), headers
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
    print("Verified per-device FolderSync, FolderCreate at quota, dynamic mail collections, IMAP interoperability, restart, rollback, and concurrent creation.")


if __name__ == "__main__":
    main()
