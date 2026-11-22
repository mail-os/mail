#!/usr/bin/env python3
"""Verify complete Typesense searches and Maildir fallback over native IMAPS."""

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import runpy
import tempfile
from threading import Thread
from urllib.parse import parse_qs, urlsplit


Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]
MATCH_COUNT = 251
PAGE_SIZE = 250


class SearchIndex(HTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), SearchHandler)
        self.documents = []
        self.requests = []
        self.failure = None


class SearchHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        url = urlsplit(self.path)
        params = parse_qs(url.query, keep_blank_values=True)
        assert url.path == "/collections/messages/documents/search", self.path
        assert params["query_by"] == ["subject"], params
        query, = params["q"]
        page, = map(int, params["page"])
        size, = map(int, params["per_page"])
        condition, = params["filter_by"]
        fields, = params.get("include_fields", [""])
        self.server.requests.append((query, page, size, condition, fields))

        matches = [
            doc for doc in self.server.documents
            if condition in (
                f'username:=`{doc["username"]}`',
                f'username:=`{doc["username"]}` && mailbox:=`{doc["mailbox"]}`',
            )
            and all(word in doc["subject"].lower().split() for word in query.lower().split())
        ]
        hits = [{"document": {"id": doc["id"]} if fields == "id" else doc}
                for doc in matches[(page - 1) * size : page * size]]
        response = {"found": len(matches), "hits": hits, "page": page, "search_cutoff": False}
        if page == 2:
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
        payload = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def seed_message(index, directory, username, folder, number, subject, reviewed=False):
    filename = f"{1780000000000 + number}.eml"
    path = (directory / "mail" / username / folder).resolve(strict=True)
    suffix = ":2,a" if reviewed else ""
    (path / (filename + suffix)).write_bytes(f"Subject: {subject}\r\n\r\nTest message.\r\n".encode())
    if reviewed:
        (path.parent / "dovecot-keywords").write_text("0 Reviewed\n", encoding="ascii")
    key = "\0".join((username, folder, filename)).encode()
    index.documents.append({
        "id": hashlib.sha256(key).hexdigest()[:32],
        "username": username,
        "mailbox": folder,
        "filename": filename,
        "subject": subject,
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-index-search-") as scratch, SearchIndex() as index:
        thread = Thread(target=index.serve_forever, daemon=True)
        thread.start()
        try:
            directory = Path(scratch)
            fixture = Fixture(args.binary.resolve(strict=True), directory, staging=True)
            fixture.env.update(TYPESENSE_API_KEY="disposable-search-index",
                               TYPESENSE_HOST="127.0.0.1", TYPESENSE_PORT=str(index.server_port))
            with fixture.daemon():
                verify(index, fixture, directory)
        finally:
            index.shutdown()
            thread.join()
    print("Verified two-page IMAP and UID SEARCH, keyword conjunction, negation, mailbox scope, and complete fallback over IMAPS.")


if __name__ == "__main__":
    main()
