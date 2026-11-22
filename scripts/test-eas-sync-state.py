#!/usr/bin/env python3
"""Verify native ActiveSync isolation and migration with two mailboxes on one device."""

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
hosted = runpy.run_path(str(SCRIPTS / "test-hosted-limits.py"))
dav = runpy.run_path(str(SCRIPTS / "test-dav-https.py"))
Fixture = hosted["Fixture"]
DavClient = dav["DavClient"]
must = dav["must"]
DEVICE = "SharedPhone"
WBXML = b"\x03\x01\x6a\x00"
END = b"\x01"
FOLDERS = ("1", "5", "6")


def element(tag, value):
    return bytes([tag | 0x40, 3]) + str(value).encode() + b"\x00\x01"


def sync(test, mailbox, key, folder="1"):
    status, _, data = test.eas(mailbox, hosted["eas_sync"](key, folder), command="Sync", device=DEVICE)
    assert status == 200, (status, data[:200])
    match = re.search(rb"\x4e\x03([0-9]+)\x00\x01", data)
    assert match, data[:200]
    return int(match[1]), hosted["eas_sync_key"](data), data


def estimate(test, mailbox, keys):
    page = b"\x00\x06"
    body = WBXML + page + b"\x45\x47"
    for folder, key in keys.items():
        body += b"\x48\x00\x00" + element(0x0b, key) + page + element(0x0a, folder) + END
    status, _, data = test.eas(mailbox, body + END * 2, command="GetItemEstimate", device=DEVICE, encoded=True)
    assert status == 200, (status, data)
    result = {}
    for response in data.split(b"\x4d")[1:]:
        code = int(re.search(rb"\x4e\x03([0-9]+)\x00\x01", response)[1])
        folder = re.search(rb"\x4a\x03([0-9]+)\x00\x01", response)[1].decode()
        match = re.search(rb"\x4c\x03([0-9]+)\x00\x01", response)
        result[folder] = (code, int(match[1]) if match else None)
    assert set(result) == set(keys), data
    return result


def ping(test, mailbox, *, folders=FOLDERS, heartbeat=20):
    page = b"\x00\x0d"
    options = element(8, heartbeat) if heartbeat is not None else b""
    if folders is not None:
        options += b"\x49" + b"".join(b"\x4a" + element(0x0b, folder) + END for folder in folders) + END
    body = WBXML + page + b"\x45" + options + END if options else b""
    status, _, data = test.eas(mailbox, body, command="Ping", device=DEVICE, encoded=True, timeout=33)
    assert status == 200 and data.startswith(WBXML + page + b"\x45"), (status, data)
    code = int(re.search(rb"\x47\x03([0-9]+)\x00\x01", data)[1])
    found = tuple(item.decode() for item in re.findall(rb"\x4a\x03([0-9]+)\x00\x01", data))
    return code, found


def add_mail(test, mailbox, subject):
    assert test.deliver(mailbox, subject=subject)[0] == 250


def fixtures(test, mailbox, name):
    client = DavClient(test, mailbox)
    event_path = f"/calendars/{mailbox}/Calendar/event.ics"
    card_path = f"/addressbooks/{mailbox}/Contacts/contact.vcf"
    event = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:agenda\r\n"
             f"SUMMARY:{name} Calendar\r\nDTSTART:20261201T120000Z\r\nDTEND:20261201T130000Z\r\n"
             "END:VEVENT\r\nEND:VCALENDAR\r\n").encode()
    card = ("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:card\r\n"
            f"FN:{name} Contact\r\nEMAIL:{name.lower()}@contacts.example.test\r\nEND:VCARD\r\n").encode()
    must(client.request("PUT", event_path, event, {"Content-Type": "text/calendar"}), 201)
    must(client.request("PUT", card_path, card, {"Content-Type": "text/vcard"}), 201)
    return client, event_path, event, card_path


def seed_legacy(db_path):
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.executescript("""
            CREATE TABLE eas_sync_state(device_id TEXT,collection_id TEXT,sync_key INTEGER,token INTEGER,
              PRIMARY KEY(device_id,collection_id));
            CREATE TABLE eas_item_state(device_id TEXT,collection_id TEXT,server_id TEXT,tag TEXT,
              PRIMARY KEY(device_id,collection_id,server_id));
        """)
        conn.execute("INSERT INTO eas_sync_state VALUES (?,?,2,0)", (DEVICE, "1"))
        conn.execute("INSERT INTO eas_item_state VALUES (?,?,?,?)", (DEVICE, "1", "1:1", "0"))
    return "2"


def initial_sync(test, alice, bob, legacy_key):
    for mailbox in (alice, bob):
        assert sync(test, mailbox, legacy_key)[:2] == (3, "0")
        assert estimate(test, mailbox, {"1": legacy_key}) == {"1": (3, None)}
        assert ping(test, mailbox, folders=None, heartbeat=None) == (3, ())

    keys = {}
    for mailbox in (alice, bob):
        keys[mailbox] = {}
        for folder in FOLDERS:
            status, key, _ = sync(test, mailbox, 0, folder)
            assert status == 1 and key.startswith("m1-")
            keys[mailbox][folder] = key
    for folder in FOLDERS:
        assert keys[alice][folder] != keys[bob][folder]
        assert sync(test, bob, keys[alice][folder], folder)[:2] == (3, "0")
    assert estimate(test, bob, {"1": keys[alice]["1"]}) == {"1": (4, None)}

    for mailbox, own, foreign in ((alice, b"Alice", b"Bob"), (bob, b"Bob", b"Alice")):
        assert estimate(test, mailbox, keys[mailbox]) == dict.fromkeys(FOLDERS, (1, 1))
        assert ping(test, mailbox) == (2, FOLDERS)
        for folder, suffix in zip(FOLDERS, (b" Inbox", b" Calendar", b" Contact")):
            status, key, data = sync(test, mailbox, keys[mailbox][folder], folder)
            assert status == 1 and own + suffix in data and foreign + suffix not in data, data[:200]
            keys[mailbox][folder] = key
        assert estimate(test, mailbox, keys[mailbox]) == dict.fromkeys(FOLDERS, (1, 0))
    return keys


def changed_state(test, alice, bob, keys, *, set_preferences=False):
    assert ping(test, alice, folders=("5", "6") if set_preferences else None, heartbeat=None) == (2, ("5", "6"))
    assert ping(test, bob, folders=("1",) if set_preferences else None, heartbeat=None) == (2, ("1",))
    assert estimate(test, alice, keys[alice]) == {"1": (1, 0), "5": (1, 1), "6": (1, 1)}
    assert estimate(test, bob, keys[bob]) == {"1": (1, 1), "5": (1, 0), "6": (1, 0)}


def reconcile(test, alice, bob, keys):
    changed_state(test, alice, bob, keys)
    barrier = Barrier(2)

    def update_calendar():
        barrier.wait(timeout=5)
        return sync(test, alice, keys[alice]["5"], "5")

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(update_calendar) for _ in range(2)]
        results = [future.result() for future in futures]
    assert sorted(status for status, _, _ in results) == [1, 3], results
    _, keys[alice]["5"], data = next(result for result in results if result[0] == 1)
    assert b"\x48\x4d\x03" in data and b"Alice Calendar final" in data and b"Bob Calendar" not in data
    status, keys[alice]["6"], data = sync(test, alice, keys[alice]["6"], "6")
    assert status == 1 and b"\x49\x4d\x03" in data
    status, keys[bob]["1"], data = sync(test, bob, keys[bob]["1"])
    assert status == 1 and b"Bob new arrival" in data and b"Alice Inbox" not in data
    for mailbox in (alice, bob):
        assert estimate(test, mailbox, keys[mailbox]) == dict.fromkeys(FOLDERS, (1, 0))

    add_mail(test, bob, "Only Bob should wake")
    with ThreadPoolExecutor(max_workers=2) as workers:
        quiet = workers.submit(ping, test, alice, folders=None, heartbeat=None)
        changed = workers.submit(ping, test, bob, folders=None, heartbeat=None)
        assert changed.result() == (2, ("1",))
        assert quiet.result() == (1, ())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--upgrade-from", type=Path, help="Exercise the same fixture on the preceding binary before and after migration.")
    args = parser.parse_args()
    candidate = args.binary.resolve()
    previous = args.upgrade_from.resolve() if args.upgrade_from else None

    with tempfile.TemporaryDirectory(prefix="mail-eas-state-", dir="/tmp") as directory:
        test = Fixture(previous or candidate, Path(directory), staging=True)
        test.env["CALDAV_MAX_SYNC_HISTORY"] = "2"
        db_path = Path(directory) / "smtp.db"
        with test.daemon():
            alice = test.provision("alice")
            bob = test.provision("bob")
            add_mail(test, alice, "Alice Inbox")
            add_mail(test, bob, "Bob Inbox")
            alice_dav, event_path, event, card_path = fixtures(test, alice, "Alice")
            fixtures(test, bob, "Bob")
            if previous:
                status, key, _ = sync(test, alice, 0)
                assert status == 1
                status, legacy_key, data = sync(test, alice, key)
                assert status == 1 and b"Alice Inbox" in data
            else:
                legacy_key = seed_legacy(db_path)

        test.binary = candidate
        with test.daemon():
            keys = initial_sync(test, alice, bob, legacy_key)
            for label in (b" early", b" intermediate", b" latest", b" final"):
                changed = event.replace(b"SUMMARY:Alice Calendar", b"SUMMARY:Alice Calendar" + label)
                must(alice_dav.request("PUT", event_path, changed, {"Content-Type": "text/calendar"}), 204)
            must(alice_dav.request("DELETE", card_path), 204)
            add_mail(test, bob, "Bob new arrival")
            changed_state(test, alice, bob, keys, set_preferences=True)
            print("Verified two accounts on one device with independent mail, calendar and contact snapshots, estimates and Ping responses.")

        with test.daemon():
            reconcile(test, alice, bob, keys)
            print("Verified restart, a pruned DAV journal, quiet Ping, and one winner for simultaneous Sync requests.")

        subprocess.run([str(candidate), "user:local", "delete", bob], cwd=directory, env=test.env, check=True)
        with closing(sqlite3.connect(db_path)) as conn:
            assert conn.execute("SELECT COUNT(*) FROM eas_mailbox_state").fetchone() == (3,)
            assert conn.execute("SELECT COUNT(*) FROM eas_mailbox_ping").fetchone() == (1,)
            assert conn.execute("SELECT sync_key FROM eas_sync_state WHERE device_id=? AND collection_id='1'",
                                (DEVICE,)).fetchone() == (int(legacy_key),)
        if previous:
            test.binary = previous
            with test.daemon():
                assert sync(test, alice, legacy_key)[0] == 1
        test.binary = candidate
        with test.daemon():
            assert estimate(test, alice, keys[alice]) == dict.fromkeys(FOLDERS, (1, 0))
            assert test.eas(bob, hosted["eas_sync"](0, "1"), command="Sync", device=DEVICE)[0] == 401
        print("Verified account deletion, retained legacy rows, and preservation of current keys across reopening the database.")


if __name__ == "__main__":
    main()
