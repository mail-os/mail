#!/usr/bin/env python3
"""Exercise mailbox moves and Typesense recovery through native HTTPS and IMAPS."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import runpy
import sqlite3
import tempfile
from threading import Event, Thread
import time


SCRIPTS = Path(__file__).resolve().parent
imap_suite = runpy.run_path(str(SCRIPTS / "test-imap-index-search.py"))
eas_suite = runpy.run_path(str(SCRIPTS / "test-eas-move-items.py"))
folder_suite = runpy.run_path(str(SCRIPTS / "test-eas-folder-hierarchy.py"))
Fixture, SearchIndex = imap_suite["Fixture"], imap_suite["SearchIndex"]
search, seed_message = imap_suite["search"], imap_suite["seed_message"]
snapshot, ids, move = eas_suite["snapshot"], eas_suite["ids"], eas_suite["response"]


def wait_for(condition, description):
    until = time.monotonic() + 18
    while time.monotonic() < until:
        if condition():
            return
        time.sleep(.1)
    raise AssertionError(description)


def subject_folders(index, owner):
    return {doc["mailbox"] for doc in index.documents if doc["username"] == owner and doc["subject"] == "Compass trip"}


def pending(test):
    with closing(sqlite3.connect(test.directory / "smtp.db")) as connection:
        return connection.execute("SELECT folder,basename FROM mail_search_pending").fetchall()


def verify_search(test, index, owner, folder, count, *, indexed):
    with test.imap(owner) as client:
        assert client.select(folder)[0] == "OK"
        expected = search(client, "HEADER Subject Compass")
        assert len(expected) == count, (folder, expected)
        all_uids = search(client, "ALL")
        index.requests.clear()
        assert search(client, "SUBJECT Compass") == expected
        assert search(client, "NOT SUBJECT Compass") == [uid for uid in all_uids if uid not in expected]
        if indexed:
            qualifier = f"username:=`{owner}`"
            if folder != '"All Mail"':
                qualifier += f" && mailbox:=`{folder}`"
            assert index.requests == [("Compass", 1, 250, qualifier, "id")] * 2, index.requests
        else:
            assert not index.requests, index.requests


def seed(test, index):
    owner = test.provision("index-mover")
    peer = test.provision("index-peer")
    for name in (owner, peer):
        (test.directory / "mail" / name / "new").mkdir(parents=True, exist_ok=True)
        seed_message(index, test.directory, name, "new", 0, "Compass trip", mailbox="INBOX")
    sent = test.directory / "mail" / owner / "Sent"
    sent.mkdir(parents=True, exist_ok=True)
    seed_message(index, test.directory, owner, "Sent", 1, "Plain handoff")
    return owner, peer


def move_during_outage(test, index, owner, peer):
    verify_search(test, index, owner, "INBOX", 1, indexed=True)
    verify_search(test, index, owner, "Sent", 0, indexed=True)
    verify_search(test, index, owner, '"All Mail"', 1, indexed=True)
    _, raw = snapshot(test, owner, "1")
    item, = ids(raw)
    index.failed_writes = {"DELETE", "POST"}
    (code, _), = move(test, owner, (item, "1", "3"), encoded=True)
    assert code == 3
    verify_search(test, index, owner, "Sent", 1, indexed=False)
    verify_search(test, index, owner, '"All Mail"', 1, indexed=False)
    verify_search(test, index, peer, "INBOX", 1, indexed=True)
    assert subject_folders(index, owner) == {"INBOX"}
    assert {folder for folder, _ in pending(test)} == {"INBOX", "Sent"}


def recover_index(test, index, owner, peer):
    verify_search(test, index, owner, '"All Mail"', 1, indexed=False)
    index.failed_writes = {"DELETE"}
    wait_for(lambda: subject_folders(index, owner) == {"INBOX", "Sent"}, "destination upsert should recover while source DELETE still fails")
    wait_for(lambda: {folder for folder, _ in pending(test)} == {"INBOX"}, "failed DELETE must leave its row pending")
    verify_search(test, index, owner, "Sent", 1, indexed=True)
    verify_search(test, index, owner, '"All Mail"', 1, indexed=False)
    index.failed_writes = set()
    wait_for(lambda: not pending(test) and subject_folders(index, owner) == {"Sent"}, "source document should be removed after the retry")
    verify_search(test, index, owner, '"All Mail"', 1, indexed=True)
    verify_search(test, index, peer, "INBOX", 1, indexed=True)


def webmail_move(test, session, path, expected, folder):
    result, row = test.api(session, path)
    assert result == 200 and row["folder"] == expected, row
    status, item = test.api(dict(session, **{"If-Match": row["revision"]}), path, {"folder": folder}, "PUT")
    assert status == 200 and item["folder"] == folder, item


def webmail_message(test, owner):
    session = test.login(owner)
    status, listing = test.api(session, "messages?folder=Sent&conversations=false")
    assert status == 200
    item, = [row for row in listing["items"] if row["subject"] == "Compass trip"]
    return session, "messages/ref/" + item["reference"]


def exercise_inflight_retry(test, index, owner):
    session, path = webmail_message(test, owner)
    entered, resume = Event(), Event()
    index.pause_upsert = ("INBOX", entered, resume)
    try:
        webmail_move(test, session, path, "Sent", "INBOX")
        assert entered.wait(10), "the first destination upsert did not start"
        webmail_move(test, session, path, "INBOX", "Sent")
        verify_search(test, index, owner, "Sent", 1, indexed=False)
        verify_search(test, index, owner, '"All Mail"', 1, indexed=False)
    finally:
        resume.set()
    wait_for(lambda: not pending(test) and subject_folders(index, owner) == {"Sent"}, "old upsert must not checkpoint the newer move")
    verify_search(test, index, owner, "Sent", 1, indexed=True)
    verify_search(test, index, owner, '"All Mail"', 1, indexed=True)


def exercise_inflight_search(test, index, owner, peer):
    session, path = webmail_message(test, owner)
    for mailbox, folder, expected in ((owner, "Sent", []), (peer, "INBOX", [b"1"])):
        entered, resume = Event(), Event()
        condition = f"username:=`{mailbox}` && mailbox:=`{folder}`"
        index.pause_search = (condition, entered, resume)

        def search_old_index():
            with test.imap(mailbox) as client:
                assert client.select(folder)[0] == "OK"
                # The index matches both tokens. The local scan requires this exact phrase.
                return search(client, 'SUBJECT "trip Compass"')

        with ThreadPoolExecutor(max_workers=1) as worker:
            result = worker.submit(search_old_index)
            try:
                assert entered.wait(10), condition
                webmail_move(test, session, path, "Sent", "INBOX")
                webmail_move(test, session, path, "INBOX", "Sent")
                wait_for(lambda: not pending(test), "both moves should finish indexing while the query waits")
            finally:
                resume.set()
            assert result.result() == expected, condition


def exercise_maildir_plus_folder(test, index, owner):
    with test.imap(owner) as client:
        assert client.create("Research")[0] == "OK"
        assert client.select("Sent")[0] == "OK"
        uid, = search(client, "SUBJECT Compass")
        assert client.uid("MOVE", uid, "Research")[0] == "OK"
    wait_for(lambda: not pending(test) and subject_folders(index, owner) == {"Research"},
             "index reconciliation should read the canonical Maildir++ destination")
    verify_search(test, index, owner, "Research", 1, indexed=True)


def exercise_imap_folder_rename(test, index, owner):
    index.failed_writes = {"DELETE", "POST"}
    with test.imap(owner) as client:
        assert client.rename("Research", "Studies")[0] == "OK"
    assert {name for name, _ in pending(test)} == {"Research", "Studies"}
    verify_search(test, index, owner, "Studies", 1, indexed=False)
    verify_search(test, index, owner, '"All Mail"', 1, indexed=False)
    index.failed_writes = set()
    wait_for(lambda: not pending(test) and subject_folders(index, owner) == {"Studies"},
             "IMAP RENAME should update the indexed location and remove the old document")
    verify_search(test, index, owner, "Studies", 1, indexed=True)


def exercise_native_folder_edits(test, index, owner):
    hierarchy, edit = folder_suite["hierarchy"], folder_suite["edit"]
    key, folders = hierarchy(test, owner)
    folder = folder_suite["added_folder"](folders, "Studies")
    index.failed_writes = {"DELETE", "POST"}
    key = edit(test, owner, key, folder, "Planning")
    assert {name for name, _ in pending(test)} == {"Studies", "Planning"}
    verify_search(test, index, owner, "Planning", 1, indexed=False)
    verify_search(test, index, owner, '"All Mail"', 1, indexed=False)
    index.failed_writes = set()
    wait_for(lambda: not pending(test) and subject_folders(index, owner) == {"Planning"},
             "index should publish the renamed folder and retire the former location")
    verify_search(test, index, owner, "Planning", 1, indexed=True)

    index.failed_writes = {"DELETE"}
    edit(test, owner, key, folder)
    verify_search(test, index, owner, '"All Mail"', 0, indexed=False)
    assert {name for name, _ in pending(test)} == {"Planning"}
    index.failed_writes = set()
    wait_for(lambda: not pending(test) and not subject_folders(index, owner),
             "index should retire documents from the deleted folder")
    verify_search(test, index, owner, '"All Mail"', 0, indexed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-move-index-", dir="/tmp") as directory, SearchIndex() as index:
        thread = Thread(target=index.serve_forever, daemon=True)
        thread.start()
        try:
            test = Fixture(args.binary.resolve(strict=True), Path(directory), staging=True)
            test.env.update(TYPESENSE_API_KEY="disposable-search-index",
                            TYPESENSE_HOST="127.0.0.1", TYPESENSE_PORT=str(index.server_port))
            with test.daemon():
                owner, peer = seed(test, index)
                move_during_outage(test, index, owner, peer)
            with test.daemon():
                recover_index(test, index, owner, peer)
                exercise_inflight_retry(test, index, owner)
                exercise_inflight_search(test, index, owner, peer)
                exercise_maildir_plus_folder(test, index, owner)
                exercise_imap_folder_rename(test, index, owner)
                exercise_native_folder_edits(test, index, owner)
        finally:
            index.shutdown()
            thread.join()
    print("Verified native moves and folder edits, folder and aggregate search, and index recovery across restart and concurrent requests.")


if __name__ == "__main__":
    main()
