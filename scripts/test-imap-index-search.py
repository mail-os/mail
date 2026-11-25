#!/usr/bin/env python3
"""Verify complete Typesense searches and Maildir fallback over native IMAPS."""

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
from threading import Thread
import time
from urllib.parse import parse_qs, urlsplit


Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]
MATCH_COUNT = 251
PAGE_SIZE = 250
COLLECTION = "messages_v3"


class SearchIndex(ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), SearchHandler)
        self.collections = {name: [] for name in ("messages", "messages_v2", COLLECTION)}
        self.documents = self.collections[COLLECTION]
        self.legacy_documents = self.collections["messages"]
        self.requests = []
        self.coverage_requests = []
        self.failure = None
        self.failed_writes = set()
        self.writes = []
        self.pause_upsert = None
        self.pause_search = None


class SearchHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        url = urlsplit(self.path)
        for name in self.server.collections:
            if url.path == f"/collections/{name}":
                self.send_json(200, {"name": name})
                return
        if not url.path.endswith("/documents/search"):
            self.send_error(404)
            return
        params = parse_qs(url.query, keep_blank_values=True)
        collection = url.path.split("/")[2]
        assert url.path == f"/collections/{collection}/documents/search", self.path
        documents = self.server.collections[collection]
        query_by, = params["query_by"]
        assert query_by in ("subject", "sender", "recipients"), params
        query, = params["q"]
        page, = map(int, params["page"])
        size, = map(int, params["per_page"])
        condition, = params["filter_by"]
        fields, = params.get("include_fields", [""])
        requests = self.server.coverage_requests if query == "*" else self.server.requests
        requests.append((query, page, size, condition, fields))

        matches = [
            doc for doc in documents
            if condition in (
                f'username:=`{doc["username"]}`',
                f'username:=`{doc["username"]}` && mailbox:=`{doc["mailbox"]}`',
            )
            and (query == "*" or all(word in doc[query_by].lower().split() for word in query.lower().split()))
        ]
        hits = [{"document": {"id": doc["id"]} if fields == "id" else doc}
                for doc in matches[(page - 1) * size : page * size]]
        response = {"found": len(matches), "hits": hits, "page": page, "search_cutoff": False}
        pause = self.server.pause_search
        if query != "*" and pause is not None and condition == pause[0]:
            self.server.pause_search = None
            pause[1].set()
            assert pause[2].wait(15), condition
        if query != "*" and page == 2:
            if self.server.failure == "unavailable":
                self.send_error(503, "Index temporarily unavailable")
                return
            if self.server.failure == "empty":
                response["hits"] = []
            if self.server.failure == "duplicate":
                response["hits"] = [{"document": {"id": matches[0]["id"]}}]
            if self.server.failure == "changed":
                response["found"] -= 1
            if self.server.failure == "cutoff":
                response["search_cutoff"] = True
        self.send_json(200, response)

    def do_POST(self):
        assert self.path == f"/collections/{COLLECTION}/documents?action=upsert", self.path
        doc = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.writes.append(("POST", doc["id"]))
        if "POST" in self.server.failed_writes:
            self.send_json(503, {"message": "Write unavailable"})
            return
        pause = self.server.pause_upsert
        if pause is not None and doc["mailbox"] == pause[0]:
            self.server.pause_upsert = None
            pause[1].set()
            assert pause[2].wait(15), doc
        self.server.documents[:] = [old for old in self.server.documents if old["id"] != doc["id"]] + [doc]
        self.send_json(200, doc)

    def do_DELETE(self):
        prefix = f"/collections/{COLLECTION}/documents/"
        assert self.path.startswith(prefix), self.path
        document_id = self.path.removeprefix(prefix)
        self.server.writes.append(("DELETE", document_id))
        if "DELETE" in self.server.failed_writes:
            self.send_json(503, {"message": "Write unavailable"})
            return
        present = any(doc["id"] == document_id for doc in self.server.documents)
        self.server.documents[:] = [doc for doc in self.server.documents if doc["id"] != document_id]
        self.send_json(200 if present else 404, {"id": document_id})

    def send_json(self, status, document):
        payload = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def seed_message(index, directory, username, folder, number, subject, reviewed=False, mailbox=None, legacy=False):
    filename = f"{1780000000000 + number}.eml"
    path = (directory / "mail" / username / folder).resolve(strict=True)
    suffix = ":2,a" if reviewed else ""
    (path / (filename + suffix)).write_bytes(f"Subject: {subject}\r\n\r\nTest message.\r\n".encode())
    if reviewed:
        (path.parent / "dovecot-keywords").write_text("0 Reviewed\n", encoding="ascii")
    mailbox = mailbox or folder
    key = "\0".join((username, mailbox, filename)).encode()
    documents = index.legacy_documents if legacy else index.documents
    documents.append({
        "id": hashlib.sha256(key).hexdigest()[:32],
        "username": username,
        "mailbox": mailbox,
        "filename": filename,
        "subject": subject.splitlines()[0] if legacy else subject,
    })


def search(client, query, uid=True):
    status, rows = client.uid("SEARCH", None, query) if uid else client.search(None, query)
    assert status == "OK", (query, status, rows)
    return rows[0].split()


def expect_index_search(index, client, filter_by, query, term, expected, *, uid=True):
    index.requests.clear()
    matches = search(client, query, uid)
    assert matches == expected, (query, index.failure, len(matches), len(expected), matches[-3:])
    assert index.requests == [
        (term, 1, PAGE_SIZE, filter_by, "id"),
        (term, 2, PAGE_SIZE, filter_by, "id"),
    ], index.requests


def verify_subject_reindex(index, fixture, directory):
    owner = fixture.provision("reindex-owner")
    peer = fixture.provision("reindex-peer")
    plain = "Staged receipt plain"
    encoded = "=?UTF-8?Q?Staged_receipt?=\r\n =?UTF-8?B?IGNhZsOp?="
    decoded = "Staged receipt café"
    for user in (owner, peer):
        (directory / "mail" / user / "new").mkdir(parents=True, exist_ok=True)
    seed_message(index, directory, owner, "new", 0, plain, mailbox="INBOX")
    seed_message(index, directory, owner, "new", 1, encoded, mailbox="INBOX", legacy=True)
    seed_message(index, directory, peer, "new", 0, plain, mailbox="INBOX")
    # A stale document keeps the count equal even though an actual ID is missing.
    stale = dict(index.documents[0], id="0" * 32)
    index.documents.append(stale)

    with fixture.imap(owner) as client:
        assert client.create("Planning")[0] == "OK"
        seed_message(index, directory, owner, ".Planning/cur", 2, encoded, mailbox="Planning", legacy=True)
        assert client.select("INBOX", readonly=True)[0] == "OK"
        uids = search(client, "ALL")
        assert len(uids) == 2
        scope = f"username:=`{owner}` && mailbox:=`INBOX`"
        query = 'SUBJECT "Staged receipt"'
        index.requests.clear()
        index.coverage_requests.clear()
        assert search(client, query) == uids
        assert not index.requests
        assert index.coverage_requests == [("*", 1, PAGE_SIZE, scope, "id")]

        index.failed_writes = {"POST"}
        try:
            command = [str(fixture.binary), "search", "reindex", "--queue"]
            result = subprocess.run(command, cwd=directory, env=fixture.env, capture_output=True, timeout=15, check=True)
            assert b"Queued Typesense reindex for 2 mailboxes" in result.stderr, result
            wait_for(lambda: any(method == "POST" for method, _ in index.writes), "the worker did not attempt the rebuild")
            index.coverage_requests.clear()
            assert search(client, query) == uids
            assert search(client, 'NOT SUBJECT "Staged receipt"') == []
            assert not index.requests and not index.coverage_requests
        finally:
            index.failed_writes = set()

        def uses_index(expected, scope):
            index.requests.clear()
            return search(client, query) == expected and index.requests == [("Staged receipt", 1, PAGE_SIZE, scope, "id")]

        wait_for(lambda: uses_index(uids, scope), "the rebuilt Inbox did not resume indexed search")
        wait_for(lambda: any(doc["username"] == owner and doc["mailbox"] == "Planning" and doc["subject"] == decoded
                             for doc in index.documents), "the worker did not rebuild the Maildir++ folder")
        assert all(doc["subject"] == encoded.splitlines()[0] for doc in index.legacy_documents)

        for folder, count, scope in (("Planning", 1, f"username:=`{owner}` && mailbox:=`Planning`"),
                                    ('"All Mail"', 3, f"username:=`{owner}`")):
            assert client.select(folder, readonly=True)[0] == "OK"
            expected = search(client, "ALL")
            assert len(expected) == count
            wait_for(lambda: uses_index(expected, scope), f"the rebuilt {folder} did not resume indexed search")

        # Reconcile a new APPEND without relying on the rebuild command.
        assert client.append("Planning", None, None, f"Subject: {encoded}\r\n\r\nNew fixture.\r\n".encode())[0] == "OK"
        assert client.select("Planning", readonly=True)[0] == "OK"
        assert len(search(client, query)) == 2
        wait_for(lambda: sum(doc["username"] == owner and doc["mailbox"] == "Planning" and doc["subject"] == decoded
                             for doc in index.documents) == 2, "the worker did not index the new encoded message")

    with fixture.imap(peer) as client:
        assert client.select("INBOX", readonly=True)[0] == "OK"
        assert search(client, query) == [b"1"]

    with tempfile.TemporaryDirectory(prefix="mail-index-quiescent-") as root:
        new = Path(root) / "offline@example.test" / "new"
        new.mkdir(parents=True)
        (new / "1780000000000.eml").write_bytes(f"Subject: {encoded}\r\n\r\nOffline fixture.\r\n".encode())
        result = subprocess.run([str(fixture.binary), "search", "reindex", "--root", root], cwd=directory,
                                env=fixture.env, capture_output=True, timeout=15, check=True)
        assert b"1 indexed, 0 failed" in result.stderr, result
        assert any(doc["username"] == "offline@example.test" and doc["subject"] == decoded for doc in index.documents)


def wait_for(condition, message):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.1)
    raise AssertionError(message)


def verify_address_reindex(index, fixture, directory):
    owner = fixture.provision("address-reindex")
    peer = fixture.provision("address-peer")
    plain = ("Plain café <sender@example.test>", "Plain café <first@example.test>, Second <second@example.test>")
    decoded = ("Staged café <sender@example.test>", "Staged café <first@example.test>,\tSecond <second@example.test>")
    encoded_name = "=?UTF-8?Q?Staged?=\r\n =?UTF-8?B?IGNhZsOp?="
    folded = (encoded_name + " <sender@example.test>", encoded_name + " <first@example.test>,\r\n\tSecond <second@example.test>")

    inbox = directory / "mail" / owner / "new"
    inbox.mkdir(parents=True, exist_ok=True)

    def wire(sender, recipients):
        return f"From: {sender}\r\nTo: {recipients}\r\nSubject: Existing subject\r\n\r\nTest message.\r\n".encode()

    subject_only = index.collections["messages_v2"]
    for i, headers in enumerate((plain, folded)):
        filename = f"{1780000000100 + i}.eml"
        (inbox / filename).write_bytes(wire(*headers))
        key = "\0".join((owner, "INBOX", filename)).encode()
        subject_only.append({"id": hashlib.sha256(key).hexdigest()[:32], "username": owner, "mailbox": "INBOX",
                             "filename": filename, "subject": "Existing subject",
                             "sender": headers[0].splitlines()[0], "recipients": headers[1].splitlines()[0]})

    def matches(client, predicate):
        status, rows = client.uid("SEARCH", None, "CHARSET", "UTF-8", f'{predicate} "café"'.encode())
        assert status == "OK", (predicate, status, rows)
        return rows[0].split()

    # A matching message owned by another user must stay outside the scope.
    with fixture.imap(peer) as client:
        assert client.append("INBOX", None, None, wire(*plain))[0] == "OK"
    with fixture.imap(owner) as client:
        assert client.select("INBOX", readonly=True)[0] == "OK"
        uids = search(client, "ALL")
        assert len(uids) == 2
        index.requests.clear()
        assert matches(client, "FROM") == matches(client, "TO") == uids
        assert not index.requests
        subprocess.run([str(fixture.binary), "search", "reindex", "--queue"], cwd=directory, env=fixture.env,
                       capture_output=True, timeout=15, check=True)

        scope = f"username:=`{owner}` && mailbox:=`INBOX`"

        def indexed_matches(expected):
            index.requests.clear()
            assert matches(client, "FROM") == matches(client, "TO") == expected
            return index.requests == [("café", 1, PAGE_SIZE, scope, "id")] * 2

        wait_for(lambda: indexed_matches(uids), "FROM and TO did not resume indexed search")
        assert subject_only[1]["sender"] == subject_only[1]["recipients"] == encoded_name.splitlines()[0]
        assert client.append("INBOX", None, None, wire(*folded))[0] == "OK"
        assert client.select("INBOX", readonly=True)[0] == "OK"
        new_uids = search(client, "ALL")
        assert len(new_uids) == 3
        wait_for(lambda: indexed_matches(new_uids), "new folded addresses did not become searchable")

    indexed_headers = [(doc["sender"], doc["recipients"]) for doc in index.documents if doc["username"] == owner]
    assert sorted(indexed_headers) == sorted([plain, decoded, decoded]), indexed_headers
    with fixture.imap(peer) as client:
        assert client.select("INBOX", readonly=True)[0] == "OK"
        assert matches(client, "FROM") == matches(client, "TO") == [b"1"]


def verify(index, fixture, directory):
    owner = fixture.provision("index-owner")
    other = fixture.provision("other-index-owner")
    with fixture.imap(other) as client:
        assert client.create("Indexed")[0] == "OK"
        seed_message(index, directory, other, "Indexed", MATCH_COUNT, "Alpha project")

    with fixture.imap(owner) as client:
        for folder in ("Indexed", "Other"):
            assert client.create(folder)[0] == "OK"
        for number in range(MATCH_COUNT):
            reviewed = number == MATCH_COUNT - 1
            subject = "Alpha project" if reviewed else "Alpha project older"
            seed_message(index, directory, owner, "Indexed", number, subject, reviewed=reviewed)
        seed_message(index, directory, owner, "Indexed", MATCH_COUNT, "Beta")
        # A matching filename in the aggregate view belongs to two folders.
        seed_message(index, directory, owner, "Other", 0, "Beta outside Indexed")

        assert client.select("Indexed") == ("OK", [str(MATCH_COUNT + 1).encode()])
        all_uids = search(client, "ALL")
        matching, nonmatching = all_uids[:-1], all_uids[-1:]
        seq = [str(number).encode() for number in range(1, MATCH_COUNT + 1)]
        folder_filter = f"username:=`{owner}` && mailbox:=`Indexed`"
        expect_index_search(index, client, folder_filter, "SUBJECT alpha", "alpha", matching)
        expect_index_search(index, client, folder_filter, "SUBJECT alpha", "alpha", seq, uid=False)
        expect_index_search(index, client, folder_filter, "SUBJECT alpha KEYWORD Reviewed", "alpha", matching[-1:])
        for term, expected in (("older", matching[:-1]), ("absent", [])):
            index.requests.clear()
            assert search(client, "SUBJECT " + term) == expected
            assert index.requests == [(term, 1, PAGE_SIZE, folder_filter, "id")]
        # The index uses token matching. A local substring scan of "project alpha"
        # would find no matches, so this also proves we used both successful pages.
        expect_index_search(index, client, folder_filter, 'NOT SUBJECT "project alpha"', "project alpha", nonmatching)

        for failure in ("unavailable", "empty", "duplicate", "changed", "cutoff"):
            index.failure = failure
            expect_index_search(index, client, folder_filter, "SUBJECT alpha", "alpha", matching)
            expect_index_search(index, client, folder_filter, "NOT SUBJECT alpha", "alpha", nonmatching)
        index.failure = None

        assert client.select('"All Mail"')[0] == "OK"
        expected = search(client, "HEADER Subject alpha")
        assert len(expected) == MATCH_COUNT
        expect_index_search(index, client, f"username:=`{owner}`", "SUBJECT alpha", "alpha", expected)


def verify_encoded_headers(binary):
    with tempfile.TemporaryDirectory(prefix="mail-imap-encoded-headers-") as scratch:
        fixture = Fixture(binary, Path(scratch), staging=True)
        with fixture.daemon():
            owner = fixture.provision("encoded-search")
            with fixture.imap(owner) as client:
                subjects = (
                    b"Staged receipt plain",
                    b"=?UTF-8?Q?Staged_receipt?=\r\n =?UTF-8?B?IGNhZsOp?=",
                    b"Different message",
                )
                for subject in subjects:
                    raw = b"Subject: " + subject + b"\r\nX-Test: ordinary\r\n\r\nTest message.\r\n"
                    assert client.append("INBOX", None, None, raw)[0] == "OK"
                assert client.select("INBOX", readonly=True)[0] == "OK"
                plain, encoded, unrelated = search(client, "ALL")
                assert search(client, 'CHARSET UTF-8 HEADER Subject "staged receipt"') == [plain, encoded]
                assert search(client, 'CHARSET UTF-8 SUBJECT "staged receipt"') == [plain, encoded]
                assert search(client, 'HEADER subject "receipt caf"') == [encoded]
                assert search(client, 'HEADER Subject ""') == [plain, encoded, unrelated]
                assert search(client, 'HEADER X-Test "ORDINARY"') == [plain, encoded, unrelated]
                assert search(client, 'HEADER X-Missing ""') == []
                assert search(client, 'HEADER Subject "IGNhZsOp"') == []
                status, rows = client.uid("SEARCH", None, "CHARSET", "UTF-8", "HEADER", "Subject", b'"caf\xc3\xa9"')
                assert status == "OK" and rows[0].split() == [encoded]
                status, rows = client.uid("FETCH", encoded, "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
                assert status == "OK"
                wire = b"".join(row[1] for row in rows if isinstance(row, tuple))
                assert subjects[1] in wire, wire


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    verify_encoded_headers(args.binary.resolve(strict=True))
    for check in (verify, verify_subject_reindex, verify_address_reindex):
        with tempfile.TemporaryDirectory(prefix="mail-index-search-") as scratch, SearchIndex() as index:
            thread = Thread(target=index.serve_forever, daemon=True)
            thread.start()
            try:
                directory = Path(scratch)
                fixture = Fixture(args.binary.resolve(strict=True), directory, staging=True)
                fixture.env.update(TYPESENSE_API_KEY="disposable-search-index",
                                   TYPESENSE_HOST="127.0.0.1", TYPESENSE_PORT=str(index.server_port))
                with fixture.daemon():
                    check(index, fixture, directory)
            finally:
                index.shutdown()
                thread.join()
    print("Verified indexed IMAP pagination, encoded subjects and addresses, live and offline backfill, and complete fallback over IMAPS.")


if __name__ == "__main__":
    main()
