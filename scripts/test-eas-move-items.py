#!/usr/bin/env python3
"""Exercise ActiveSync MoveItems against a disposable certificate-verified Mail daemon."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import re
import runpy
import sqlite3
import subprocess
import tempfile
from threading import Barrier


SCRIPTS = Path(__file__).resolve().parent
state = runpy.run_path(str(SCRIPTS / "test-eas-sync-state.py"))
hosted = state["hosted"]
Fixture, sync, element = state["Fixture"], state["sync"], state["element"]
request, message = hosted["request"], hosted["imap_message"]
assert_imap, expect_smtp = hosted["assert_imap"], hosted["expect_smtp"]
WBXML, END = state["WBXML"], state["END"]
MOVE = WBXML + b"\x00\x05\x45"


def build_move(item, source, destination):
    return b"\x46" + element(7, item) + element(8, source) + element(9, destination) + END


def response(test, mailbox, *moves, encoded=False):
    body = MOVE + b"".join(build_move(*move) for move in moves) + END
    status, headers, raw = test.eas(mailbox, body, command="MoveItems", encoded=encoded)
    assert status == 200 and headers["Content-Type"] == "application/vnd.ms-sync.wbxml", (status, raw)
    assert raw.startswith(MOVE) and raw.endswith(END), raw
    rows = re.findall(rb"\x4a\x47\x03([^\x00]+)\x00\x01\x4b\x03([0-9]+)\x00\x01"
                      rb"(?:\x4c\x03([^\x00]+)\x00\x01)?\x01", raw)
    assert len(rows) == len(moves), raw
    assert [item.decode() for item, _, _ in rows] == [move[0] for move in moves], raw
    return [(int(code), target.decode() if target else None) for _, code, target in rows]


def ids(data, command=0x47):
    return [item.decode() for item in re.findall(bytes([command]) + rb"\x4d\x03([^\x00]+)\x00\x01", data)]


def snapshot(test, mailbox, folder, key=None):
    if key is None:
        status, key, _ = sync(test, mailbox, "0", folder)
        assert status == 1
    status, key, raw = sync(test, mailbox, key, folder)
    assert status == 1, raw
    return key, raw


def advertised(test):
    status, headers, _ = request(test.eas_url, method="OPTIONS", context=test.tls_context)
    assert status == 200 and "MoveItems" in headers["MS-ASProtocolCommands"].split(","), headers


def rejection_cases(test, owner, peer, source_id, peer_id):
    assert peer_id.split(":")[:2] == source_id.split(":")[:2] and peer_id != source_id
    assert response(test, owner, (peer_id, "1", "4")) == [(1, None)]
    tampered = source_id[:-1] + ("a" if source_id[-1] != "a" else "b")
    assert response(test, owner, (tampered, "1", "4"), (source_id, "4", "1"),
                    (source_id, "1", "5"), (source_id, "1", "99"), (source_id, "1", "1")) == [
        (1, None), (1, None), (2, None), (2, None), (4, None),
    ]
    valid = build_move(source_id, "1", "4")
    duplicate_destination = valid[:-1] + element(9, "3") + END
    malformed = MOVE + valid + duplicate_destination + END
    status, _, raw = test.eas(owner, malformed, command="MoveItems")
    assert status == 200 and raw == MOVE + element(0x0b, 5) + END, (status, raw)
    truncated = MOVE + valid + valid[:-4]
    assert test.eas(owner, truncated, command="MoveItems")[0] == 400
    with test.imap(owner) as client:
        assert assert_imap(client.select("INBOX")) == [b"1"]
    with test.imap(peer) as client:
        assert assert_imap(client.select("INBOX")) == [b"1"]


def exercise_quota(test, owner, peer):
    assert test.deliver(owner, subject="Move this exact message")[0] == 250
    assert test.deliver(peer, subject="Peer message with the same UID")[0] == 250
    session = test.login(owner)
    row, = test.api(session, "messages?folder=INBOX&conversations=false")[1]["items"]
    uid = str(row["uid"])
    with test.imap(owner) as client:
        assert_imap(client.select("INBOX"))
        assert_imap(client.uid("STORE", uid, "+FLAGS", r"(\Seen \Flagged)"))
        original = assert_imap(client.uid("FETCH", uid, "(BODY.PEEK[])"))[0][1]

    folder_query = WBXML + b"\x00\x07\x56" + element(0x12, "0") + END
    status, _, raw = test.eas(owner, folder_query, command="FolderSync")
    assert status == 200 and element(8, "1") in raw and element(8, "4") in raw
    source_key, raw = snapshot(test, owner, "1")
    source_id, = ids(raw)
    _, raw = snapshot(test, peer, "1")
    peer_id, = ids(raw)
    assert len(source_id.rsplit(":", 1)[1]) == 32
    rejection_cases(test, owner, peer, source_id, peer_id)
    trash_key, raw = snapshot(test, owner, "4")
    assert not ids(raw)

    size = test.bytes(owner)
    test.provision("owner", quota=size)
    expect_smtp(test.deliver(owner), 452, "4.2.2")
    (code, target), rejected = response(test, owner, (source_id, "1", "4"), ("bogus", "1", "3"), encoded=True)
    assert rejected == (1, None)
    assert code == 3 and target.startswith("4:") and test.bytes(owner) == size
    assert test.count(owner) == 0 and response(test, owner, (source_id, "1", "4")) == [(1, None)]
    assert ids(snapshot(test, owner, "1", source_key)[1], 0x49) == [source_id]
    assert ids(snapshot(test, owner, "4", trash_key)[1]) == [target]
    assert test.api(session, "messages/ref/" + row["reference"])[1]["folder"] == "Trash"
    with test.imap(owner) as client:
        assert assert_imap(client.select("INBOX")) == [b"0"]
        assert assert_imap(client.select("Trash")) == [b"1"]
        meta, content = assert_imap(client.uid("FETCH", target.split(":")[1], "(FLAGS BODY.PEEK[])"))[0]
        assert b"\\Seen" in meta and b"\\Flagged" in meta and content == original
    test.provision("owner", quota=size, enabled=False)
    denied, _, _ = test.eas(owner, MOVE + build_move(target, "4", "1") + END, command="MoveItems")
    assert denied in (401, 403) and test.bytes(owner) == size
    test.provision("owner", quota=size)
    print("Verified account-scoped IDs, WBXML and encoded requests, exact-quota moves, Sync, IMAP flags and webmail references.")
    return size, target, source_id


def exercise_restart_and_race(test, owner, size, target, stale):
    mailbox = test.directory / "mail" / owner
    blocked = mailbox / "Sent"
    blocked.write_bytes(b"fixture obstruction")
    try:
        assert response(test, owner, (target, "4", "3")) == [(7, None)]
        assert test.bytes(owner) == size
        with closing(sqlite3.connect(test.directory / "smtp.db")) as conn:
            assert conn.execute("SELECT COUNT(*) FROM imap_uids WHERE username=? AND mailbox='Sent'", (owner,)).fetchone() == (0,)
    finally:
        blocked.unlink()

    (code, item), = response(test, owner, (target, "4", "1"))
    assert code == 3 and item != stale and test.bytes(owner) == size
    assert response(test, owner, (stale, "1", "4")) == [(1, None)]
    barrier = Barrier(2)

    def imap_move():
        with test.imap(owner) as client:
            assert_imap(client.select("INBOX"))
            barrier.wait(timeout=5)
            return client.uid("MOVE", item.split(":")[1], "Sent")[0]

    def eas_move():
        barrier.wait(timeout=5)
        return response(test, owner, (item, "1", "4"))[0]

    with ThreadPoolExecutor(max_workers=2) as workers:
        imap_result = workers.submit(imap_move)
        eas_result = workers.submit(eas_move)
        assert imap_result.result() in ("OK", "NO")
        status, _ = eas_result.result()
        assert status in (1, 3)
    with test.imap(owner) as client:
        assert assert_imap(client.select("INBOX")) == [b"0"]
        assert assert_imap(client.select("Trash")) == [b"1" if status == 3 else b"0"]
        assert assert_imap(client.select("Sent")) == [b"0" if status == 3 else b"1"]
    assert test.bytes(owner) == size and test.count(owner) == 0
    print("Verified restart, failed destination cleanup, stale IDs after a move back, and contention with IMAP MOVE.")


def protect_managed_drafts(test, owner):
    test.provision("owner")
    session = test.login(owner)
    status, _ = test.api(session, "drafts", {"text": "Keep staged composer metadata with its draft"})
    assert status == 200
    _, raw = snapshot(test, owner, "2")
    item, = ids(raw)
    assert response(test, owner, (item, "2", "4")) == [(7, None)]
    with test.imap(owner) as client:
        assert assert_imap(client.select("Drafts")) == [b"1"]
        assert_imap(client.append("Drafts", r"(\Draft)", None, message("Native draft")))
    _, raw = snapshot(test, owner, "2")
    native, = set(ids(raw)) - {item}
    assert response(test, owner, (native, "2", "4"))[0][0] == 3
    with test.imap(owner) as client:
        assert assert_imap(client.select("Drafts")) == [b"1"]
    print("Verified that native drafts can move and webmail-managed drafts keep their file and composer record together.")


def exercise_legacy_layout(test):
    user = "legacy"
    mailbox = f"{user}@{hosted['DOMAIN']}"
    subprocess.run([str(test.binary), "user:local", "create", mailbox, "--password-stdin"],
                   input=test.password + "\n", text=True, cwd=test.directory, env=test.env,
                   capture_output=True, check=True)
    legacy = test.directory / "mail" / user
    source = legacy / "Drafts" / "new" / "legacy.eml:2,S"
    source.parent.mkdir(parents=True, exist_ok=True)
    raw = message("Older local mailbox layout")
    source.write_bytes(raw)
    _, listing = snapshot(test, mailbox, "2")
    item, = ids(listing)
    (code, target), = response(test, mailbox, (item, "2", "4"))
    assert code == 3 and not source.exists()
    assert (legacy / "Trash" / source.name).read_bytes() == raw
    assert not (test.directory / "mail" / mailbox / "Trash" / source.name).exists()
    assert ids(snapshot(test, mailbox, "4")[1]) == [target]
    print("Verified moves in the legacy short-name Maildir and its nested source folders.")


def upgrade(candidate, previous):
    with tempfile.TemporaryDirectory(prefix="mail-eas-move-upgrade-", dir="/tmp") as directory:
        test = Fixture(previous, Path(directory), staging=True)
        with test.daemon():
            owner = test.provision("upgrade")
            assert test.deliver(owner)[0] == 250
            key, raw = snapshot(test, owner, "1")
            old_id, = ids(raw)
            calendar_key = snapshot(test, owner, "5")[0]
        test.binary = candidate
        with test.daemon():
            assert sync(test, owner, key, "1")[:2] == (3, "0")
            assert sync(test, owner, calendar_key, "5")[:2] == (1, calendar_key)
            assert response(test, owner, (old_id, "1", "4")) == [(1, None)]
            _, raw = snapshot(test, owner, "1")
            item, = ids(raw)
            assert response(test, owner, (item, "1", "4"))[0][0] == 3
    print("Verified that upgrading refreshes the legacy mail IDs and preserves the existing Calendar Sync key.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--upgrade-from", type=Path)
    args = parser.parse_args()
    candidate = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="mail-eas-move-", dir="/tmp") as directory:
        test = Fixture(candidate, Path(directory), staging=True)
        with test.daemon():
            owner = test.provision("owner")
            peer = test.provision("peer")
            advertised(test)
            size, target, stale = exercise_quota(test, owner, peer)
        with test.daemon():
            exercise_restart_and_race(test, owner, size, target, stale)
            protect_managed_drafts(test, owner)
            exercise_legacy_layout(test)
    if args.upgrade_from:
        upgrade(candidate, args.upgrade_from.resolve())


if __name__ == "__main__":
    main()
