#!/usr/bin/env python3
"""Verify persistent, folder-scoped keywords over native HTTPS and TLS IMAP."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import imaplib
from pathlib import Path
import runpy
import tempfile
from threading import Barrier


Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]
RAW = b"Subject: Persistent flags\r\nDate: Tue, 4 Mar 2025 12:00:00 +0000\r\n\r\nMessage body\r\n"


def append(client, folder, flags, expected="OK", raw=RAW):
    status, response = client.append(folder, flags, None, raw)
    assert status == expected, (status, response)
    if expected == "OK":
        return client.response("APPENDUID")[1][0].split()[1]
    return response[0]


def flags(client, uid):
    status, rows = client.uid("FETCH", uid, "(FLAGS)")
    uid = uid.encode() if isinstance(uid, str) else uid
    selected = [row for row in rows if row and b"UID " + uid + b" " in row]
    assert status == "OK" and selected, (status, rows)
    return set(imaplib.ParseFlags(selected[-1]))


def search(client, query, *expected, uid=True):
    status, rows = client.uid("SEARCH", None, query) if uid else client.search(None, query)
    assert status == "OK" and rows[0].split() == list(expected), (query, status, rows, expected)


def verify_search(fixture, owner):
    with fixture.imap(owner) as client:
        for folder in ("SearchA", "SearchB", "SearchEmpty"):
            assert client.create(folder)[0] == "OK"
        marked = append(client, "SearchA", "(Reviewed ALL UID SEEN)", raw=RAW.replace(
            b"Persistent flags", b"Special KEYWORD",
        ).replace(b"\r\n\r\n", b'\r\nX-Status: first\r\n continued\r\nX-Quote: Search "KEYWORD"\r\n\r\n', 1))
        plain = append(client, "SearchA", r"(\Seen Plain)")
        first_letter = append(client, "SearchB", "(Other)")
        second_letter = append(client, "SearchB", "(Reviewed)", raw=RAW.replace(
            b"Persistent flags", b"Different Maildir mapping",
        ))

        assert client.select("SearchEmpty")[1] == [b"0"]
        search(client, "UNKEYWORD Reviewed")
        assert client.select("SearchA")[1] == [b"2"]
        search(client, "KEYWORD reviewed", marked)
        search(client, "UNKEYWORD REVIEWED", plain)
        search(client, "KEYWORD missing")
        search(client, "UNKEYWORD Missing", marked, plain)
        search(client, "ALL (KEYWORD Reviewed NOT SEEN)", marked)
        search(client, 'OR (KEYWORD Reviewed SUBJECT "Special KEYWORD") (SEEN NOT KEYWORD Reviewed)', marked, plain)
        search(client, "KEYWORD ALL KEYWORD UID KEYWORD SEEN", marked)
        search(client, "UID " + marked.decode() + ":* UNKEYWORD Reviewed", plain)
        search(client, "UID *", plain, uid=False)
        search(client, "1 KEYWORD Reviewed", b"1", uid=False)
        search(client, "KEYWORD Reviewed 2")
        search(client, "SUBJECT KEYWORD", marked)
        search(client, 'SUBJECT "Special KEYWORD" KEYWORD Reviewed', marked)
        search(client, 'HEADER X-Status "first continued"', marked)
        search(client, 'HEADER X-Status ""', marked)
        search(client, r'HEADER X-Quote "Search \"KEYWORD\""', marked)
        search(client, 'BODY "Message body" ALL KEYWORD Reviewed', marked)
        search(client, "SENTON 4-Mar-2025 KEYWORD Reviewed", marked)
        try:
            client.uid("SEARCH", None, "KEYWORD")
        except imaplib.IMAP4.error as error:
            assert "Invalid SEARCH criteria" in str(error)
        else:
            raise AssertionError("SEARCH accepted a missing keyword")

        assert client.select("SearchB")[1] == [b"2"]
        search(client, "KEYWORD Reviewed", second_letter)
        search(client, "UNKEYWORD Reviewed", first_letter)

        assert client.select('"All Mail"')[0] == "OK"
        status, rows = client.uid("SEARCH", None, 'OR SUBJECT "Special KEYWORD" SUBJECT "Different Maildir mapping"')
        assert status == "OK" and len(rows[0].split()) == 2, (status, rows)
        search(client, "KEYWORD Reviewed", *rows[0].split())
        assert client.select("SearchB")[1] == [b"2"]

        # A selected session still has cached filenames when another
        # connection renames them by modifying flags.
        with fixture.imap(owner) as writer:
            assert writer.select("SearchB")[0] == "OK"
            assert writer.uid("STORE", second_letter, "-FLAGS.SILENT", "(reviewed)")[0] == "OK"
            assert writer.uid("STORE", first_letter, "+FLAGS.SILENT", "(REVIEWED LateKeyword)")[0] == "OK"
        search(client, "KEYWORD Reviewed KEYWORD latekeyword", first_letter)
        search(client, "UNKEYWORD Reviewed", second_letter)

        # Sequence numbers compact after expunge. UIDs retain their values.
        assert client.uid("STORE", first_letter, "+FLAGS.SILENT", r"(\Deleted)")[0] == "OK"
        assert client.expunge()[0] == "OK"
        search(client, "1 UNKEYWORD Reviewed", b"1", uid=False)
        search(client, "1 UNKEYWORD Reviewed", second_letter)


def verify_lifecycle(fixture, owner, other):
    with fixture.imap(owner) as client:
        for name in ("Projects", "Archive", "Full", "Concurrent"):
            assert client.create(name)[0] == "OK"
        try:
            client.append("INBOX", r"(\Unknown)", None, RAW)
        except imaplib.IMAP4.error as error:
            assert "Invalid APPEND flags" in str(error)
        else:
            raise AssertionError("APPEND accepted an unknown system flag")
        origin = append(client, "INBOX", r"(\Seen ProjectReviewed $Forwarded)")
        project_seed = append(client, "Projects", "(ProjectOnly)")
        archive_seed = append(client, "Archive", "(ArchiveOnly ArchiveSecond)")
        assert client.select("INBOX", readonly=True)[0] == "OK"
        assert client.response("PERMANENTFLAGS")[1] == [b"()"]
        status, _ = client.uid("STORE", origin, "+FLAGS", "(ReadOnlyAttempt)")
        assert status == "NO"

        assert client.select("INBOX")[0] == "OK"
        assert flags(client, origin) == {b"\\Seen", b"ProjectReviewed", b"$Forwarded"}
        status, _ = client.uid("STORE", origin, "+FLAGS.SILENT", "(projectreviewed OtherLabel)")
        assert status == "OK"
        assert client.uid("STORE", origin, "-FLAGS", "($forwarded)")[0] == "OK"
        assert flags(client, origin) == {b"\\Seen", b"ProjectReviewed", b"OtherLabel"}
        try:
            client.uid("STORE", origin, "+FLAGS", r"(\Unknown \Flagged)")
        except imaplib.IMAP4.error as error:
            assert "Invalid STORE flags" in str(error)
        else:
            raise AssertionError("STORE accepted an unknown system flag")
        assert b"\\Flagged" not in flags(client, origin)
        assert client.uid("STORE", origin, "FLAGS", r"(\Answered ProjectReviewed)")[0] == "OK"
        assert flags(client, origin) == {b"\\Answered", b"ProjectReviewed"}

        # Retain the keyword when a non-PEEK read changes the system flags.
        assert client.uid("FETCH", origin, "(BODY[])")[0] == "OK"
        assert flags(client, origin) == {b"\\Seen", b"\\Answered", b"ProjectReviewed"}
        assert client.uid("COPY", origin, "Projects")[0] == "OK"
        assert client.uid("MOVE", origin, "Archive")[0] == "OK"
        assert client.select("INBOX")[1] == [b"0"]
        for folder, seed, labels in (
            ("Projects", project_seed, {b"ProjectOnly"}),
            ("Archive", archive_seed, {b"ArchiveOnly", b"ArchiveSecond"}),
        ):
            assert client.select(folder)[1] == [b"2"]
            assert flags(client, seed) == labels
            status, [rows] = client.uid("SEARCH", None, "ALL")
            assert status == "OK"
            transferred, = set(rows.split()) - {seed}
            assert flags(client, transferred) == {b"\\Seen", b"\\Answered", b"ProjectReviewed"}

        assert client.select("Full")[0] == "OK"
        full = append(client, "Full", "(" + " ".join(f"Label{i}" for i in range(26)) + ")")
        assert b"\\*" not in client.response("PERMANENTFLAGS")[1][-1]
        assert append(client, "Full", "(AnotherLabel)", "NO").startswith(b"[LIMIT]")
        assert client.select("Full")[1] == [b"1"]
        assert client.uid("STORE", full, "+FLAGS", "(AnotherLabel)")[0] == "NO"
        assert flags(client, full) == {f"Label{i}".encode() for i in range(26)}
        assert client.select("Archive")[1] == [b"2"]
        status, response = client.copy("1:2", "Full")
        assert status == "NO" and response[0].startswith(b"[LIMIT]"), response
        assert client.select("Full")[1] == [b"1"]
        concurrent_uid = append(client, "Concurrent", "(Original)")

    start = Barrier(2, timeout=5)

    def store(label):
        with fixture.imap(owner) as client:
            assert client.select("Concurrent")[0] == "OK"
            start.wait()
            assert client.uid("STORE", concurrent_uid, "+FLAGS.SILENT", f"({label})")[0] == "OK"

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(store, ("FirstUpdate", "SecondUpdate")))
    with fixture.imap(owner) as client:
        assert client.select("Concurrent")[0] == "OK"
        assert flags(client, concurrent_uid) == {b"Original", b"FirstUpdate", b"SecondUpdate"}

    # Webmail shares the Maildir. Its system flag changes and moves must keep
    # the keyword meaning even when the destination letters are different.
    session = fixture.login(owner)
    _, listing = fixture.api(session, "messages?folder=Projects")
    copied = next(row for row in listing["items"] if row["flags"]["answered"])
    ref = "messages/ref/" + copied["reference"]
    match = dict(session, **{"If-Match": copied["revision"]})
    status, changed = fixture.api(match, ref, {"flags": dict(copied["flags"], seen=False)}, "PUT")
    assert status == 200, changed
    match = dict(session, **{"If-Match": changed["revision"]})
    status, refused = fixture.api(match, ref, {"folder": "Full"}, "PUT")
    assert status == 409 and refused["error"] == "keyword_limit", refused
    status, moved = fixture.api(match, ref, {"folder": "Archive"}, "PUT")
    assert status == 200, moved
    with fixture.imap(other) as client:
        assert client.select("INBOX")[1] == [b"0"]
        assert b"ProjectReviewed" not in client.response("FLAGS")[1][0]
        unrelated = append(client, "INBOX", "(OtherMailbox)")
        assert client.select("INBOX")[1] == [b"1"]
        assert flags(client, unrelated) == {b"OtherMailbox"}
    return moved["uid"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-keywords-") as scratch:
        fixture = Fixture(args.binary.resolve(strict=True), Path(scratch), staging=True)
        with fixture.daemon():
            owner = fixture.provision("keyword-owner")
            other = fixture.provision("keyword-other")
            moved = verify_lifecycle(fixture, owner, other)
            verify_search(fixture, owner)
        with fixture.daemon(), fixture.imap(owner) as client:
            assert client.select("Archive")[1] == [b"3"]
            assert flags(client, str(moved)) == {b"\\Answered", b"ProjectReviewed"}
            assert client.rename("Archive", '"Renamed archive"')[0] == "OK"
            assert client.select('"Renamed archive"')[1] == [b"3"]
            assert b"ProjectReviewed" in client.response("FLAGS")[1][0]
            assert client.delete('"Renamed archive"')[0] == "OK"
    print("Verified keyword persistence, capacity, namespace remapping, webmail changes, read-only access, restart, rename, isolation, SEARCH, and UID SEARCH.")


if __name__ == "__main__":
    main()
