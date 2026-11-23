#!/usr/bin/env python3
"""Exercise ActiveSync mailbox Search and ComposeMail against native HTTPS."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.parser import BytesParser
from pathlib import Path
import re
import runpy
import tempfile
from threading import Barrier


fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture = fixture["Fixture"]
EXTERNAL = fixture["EXTERNAL"]
request = fixture["request"]
eas_mime = fixture["eas_mime"]
eas_result = fixture["eas_result"]
mb_uint = fixture["mb_uint"]
eas_sync = fixture["eas_sync"]
eas_sync_key = fixture["eas_sync_key"]

WBXML = b"\x03\x01\x6a\x00"
SEARCH = b"\x00\x0f"
AIRSYNC = b"\x00\x00"
EMAIL = b"\x00\x02"
BODY = b"\x00\x11"
END = b"\x01"
ONE_MIB = 1024 * 1024


def string(tag, value):
    return bytes([tag | 0x40, 3]) + value.encode() + b"\x00\x01"


def search_body(query, *, folder=None, page_range="0-49", body_size=None, after=None):
    criteria = AIRSYNC + string(0x10, "Email")
    if folder is not None:
        criteria += string(0x12, folder)
    criteria += SEARCH + string(0x15, query)
    if after is not None:
        criteria += b"\x5b" + EMAIL + b"\x0f" + SEARCH + string(0x12, after) + END
    options = string(0x0b, page_range)
    if body_size is not None:
        options += BODY + b"\x45" + string(6, "1") + string(7, str(body_size)) + END + SEARCH
    return (WBXML + SEARCH + b"\x45\x47" + string(8, "Mailbox") + b"\x49\x53"
            + criteria + END * 2 + b"\x4a" + options + END * 3)


def search(test, mailbox, query, *, encoded=False, expected=1, **options):
    status, headers, data = test.eas(mailbox, search_body(query, **options), command="Search", encoded=encoded)
    assert status == 200, (status, data)
    assert headers["Content-Type"].startswith("application/vnd.ms-sync.wbxml")
    assert data.startswith(WBXML + SEARCH + b"\x45" + string(12, "1") + b"\x4d\x47" + string(12, str(expected))), data
    return data


def ids(data):
    return [result.decode() for result in re.findall(rb"\x58\x03(s1:[^\x00]+)\x00\x01", data)]


def compose(test, mailbox, sink, command, client_id, *, long_id=None, folder=None, item=None, occurrence=None, save=False):
    source = b"\x4b"
    for tag, value in ((12, folder), (13, item), (14, long_id), (15, occurrence)):
        if value is not None:
            source += string(tag, value)
    mime = eas_mime(mailbox, sink, subject=f"Search-linked {command}")
    body = (WBXML + b"\x00\x15" + bytes([0x47 if command == "SmartReply" else 0x46])
            + string(0x11, client_id) + (b"\x08" if save else b"") + source + END
            + b"\x50\xc3" + mb_uint(len(mime)) + mime + END * 2)
    return eas_result(test.eas(mailbox, body, command=command, device="SearchDevice"), command)


def seed(test, mailbox, subject, data):
    mime = (f"From: {EXTERNAL}\r\nTo: {mailbox}\r\nSubject: {subject}\r\n".encode()
            + b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=search-fixture\r\n\r\n"
            + b"--search-fixture\r\nContent-Type: text/plain; charset=utf-8\r\n"
            + b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(data)
            + b"\r\n--search-fixture\r\nContent-Type: application/octet-stream\r\n"
            + b'Content-Disposition: attachment; filename="archive.bin"\r\n'
            + b"Content-Transfer-Encoding: base64\r\n\r\nYWJjAA==\r\n--search-fixture--\r\n")
    with test.smtp() as client:
        assert client.mail(EXTERNAL)[0] == 250
        assert client.rcpt(mailbox)[0] == 250
        assert client.data(mime)[0] == 250


def check_matches(test, owner, other, sink):
    seed(test, owner, "First project", b"private decoded brief")
    seed(test, owner, "Second project", b"the second brief")
    seed(test, other, "First project", b"private decoded brief")
    root = test.directory / "mail" / owner

    status, headers, _ = request(test.eas_url, method="OPTIONS", context=test.tls_context)
    assert status == 200 and "Search" in headers["MS-ASProtocolCommands"].split(",")
    assert "FolderDelete" not in headers["MS-ASProtocolCommands"].split(",")
    assert test.eas(owner, b"", command="FolderDelete")[0] == 501
    first = search(test, owner, "brief", page_range="0-0", encoded=True)
    second = search(test, owner, "brief", page_range="1-1")
    assert string(0x10, "2") in first and string(0x0b, "0-0") in first
    assert string(0x10, "2") in second and string(0x0b, "1-1") in second
    assert len(ids(first)) == len(ids(second)) == 1 and ids(first) != ids(second)
    past_end = search(test, owner, "brief", page_range="2-2")
    assert string(0x10, "2") in past_end and not ids(past_end)
    assert string(0x10, "0") in search(test, owner, "brief", folder="3")
    assert string(0x10, "0") in search(test, owner, "brief", after="2100-01-01T00:00:00.000Z")
    search(test, owner, "brief", folder="99", expected=11)
    search(test, owner, "brief", page_range="2-1", expected=2)
    search(test, owner, "brief", after="2100-02-29T00:00:00.000Z", expected=2)

    selected = search(test, owner, "decoded private", folder="1", body_size=7)
    assert b"First project" in selected and b"Second project" not in selected
    assert string(0x0b, "private") in selected and string(0x0d, "1") in selected
    long_id, = ids(selected)
    foreign_id, = ids(search(test, other, "decoded private"))
    assert long_id.split(":")[:3] == foreign_id.split(":")[:3] and long_id != foreign_id
    assert compose(test, other, sink, "SmartForward", "foreign", long_id=long_id) == 150
    forged = long_id[:-1] + ("a" if long_id[-1] != "a" else "b")
    assert compose(test, owner, sink, "SmartReply", "altered", long_id=forged) == 150
    assert compose(test, owner, sink, "SmartReply", "mixed", long_id=long_id, folder="1", item="1:1") == 105
    assert compose(test, owner, sink, "SmartForward", "invalidDate", folder="5", item="1", occurrence="bad") == 104
    assert compose(test, owner, sink, "SmartForward", "calendar", folder="5", item="1",
                   occurrence="2026-10-03T13:00:00.000Z") == 147
    assert test.count(other) == test.count(owner) == test.bytes(sink) == 0

    for command in ("SmartReply", "SmartForward"):
        test.provision("owner", quota=ONE_MIB, daily=10)
        before = test.bytes(owner)
        assert compose(test, owner, sink, command, command + "Measure", long_id=long_id, save=True) == 0
        length = test.bytes(owner) - before
        sent = next(path.read_bytes() for path in (root / "Sent").glob("*.eml*")
                    if f"Subject: Search-linked {command}\r\n".encode() in path.read_bytes())
        assert len(sent) == length
        parsed = BytesParser(policy=policy.default).parsebytes(sent)
        assert any(b"private decoded brief" in (part.get_payload(decode=True) or b"")
                   for part in parsed.walk() if part.get_content_type() == "text/plain")
        if command == "SmartForward":
            assert any(part.get_filename() == "archive.bin" and part.get_payload(decode=True) == b"abc\x00"
                       for part in parsed.walk())
        before = test.bytes(owner)
        received = test.bytes(sink)
        consumed = test.count(owner)
        test.provision("owner", quota=before + length - 1, daily=10)
        assert compose(test, owner, sink, command, command + "Exact", long_id=long_id, save=True) == 113
        assert test.bytes(owner) == before and test.bytes(sink) == received and test.count(owner) == consumed
        test.provision("owner", quota=before + length, daily=10)
        assert compose(test, owner, sink, command, command + "Exact", long_id=long_id, save=True) == 0
        assert test.bytes(owner) == before + length and test.count(owner) == consumed + 1
    return long_id


def check_restart_and_move(test, owner, sink, long_id):
    assert ids(search(test, owner, "decoded private", folder="1")) == [long_id]
    assert compose(test, owner, sink, "SmartReply", "afterRestart", long_id=long_id) == 0
    session = test.login(owner)
    uid = int(long_id.split(":")[2])
    message = {"uid": uid, "folder": "INBOX"}
    before = test.bytes(owner)
    status, result = test.api(session, "bulk", {"action": "read", "messages": [message]})
    assert status == 200 and result["results"][0]["ok"], result
    assert ids(search(test, owner, "decoded private", folder="1")) == [long_id]
    assert compose(test, owner, sink, "SmartReply", "afterFlag", long_id=long_id) == 0
    status, result = test.api(session, "bulk", {"action": "move", "folder": "Trash", "messages": [message]})
    assert status == 200 and result["results"][0]["ok"] and test.bytes(owner) == before, result
    received, consumed = test.bytes(sink), test.count(owner)
    assert compose(test, owner, sink, "SmartForward", "oldFolder", long_id=long_id) == 150
    assert test.bytes(sink) == received and test.count(owner) == consumed
    moved_id, = ids(search(test, owner, "decoded private", folder="4"))
    assert moved_id != long_id and moved_id.split(":")[1] == "4"
    assert compose(test, owner, sink, "SmartForward", "newFolder", long_id=moved_id) == 0

    allowance = test.count(owner) + 1
    test.provision("owner", quota=before, daily=allowance)
    barrier = Barrier(2)

    def forward():
        barrier.wait(timeout=5)
        return compose(test, owner, sink, "SmartForward", "finalRecipient", long_id=moved_id)

    def submit():
        with test.smtp(owner) as client:
            barrier.wait(timeout=5)
            return fixture["smtp_message"](client, owner, [sink])[0]

    with ThreadPoolExecutor(max_workers=2) as workers:
        mobile = workers.submit(forward)
        smtp = workers.submit(submit)
        assert (mobile.result(), smtp.result()) in ((0, 452), (115, 250))
    assert test.count(owner) == allowance and test.bytes(owner) == before
    return moved_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--rollback-from", type=Path, help="Open the same database with the preceding build.")
    args = parser.parse_args()
    candidate = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="mail-eas-search-") as directory:
        test = Fixture(candidate, Path(directory), staging=True)
        with test.daemon():
            owner = test.provision("owner", daily=10)
            other = test.provision("other")
            sink = test.provision("sink", quota=ONE_MIB)
            long_id = check_matches(test, owner, other, sink)
            print("Verified Search pagination, decoded content, account isolation, and exact ComposeMail quota boundaries.")
        with test.daemon():
            moved_id = check_restart_and_move(test, owner, sink, long_id)
            print("Verified Search IDs through restart, flag changes, and moves, plus concurrent SMTP and SmartForward at the recipient boundary.")
        if args.rollback_from:
            test.binary = args.rollback_from.resolve()
            with test.daemon():
                status, _, bootstrap = test.eas(owner, eas_sync(0, "4"), command="Sync", device="Rollback")
                assert status == 200
                _, _, data = test.eas(owner, eas_sync(eas_sync_key(bootstrap), "4"), command="Sync", device="Rollback")
                assert b"First project" in data
            test.binary = candidate
            with test.daemon():
                assert ids(search(test, owner, "decoded private", folder="4")) == [moved_id]
            print("Verified rollback to the preceding binary and Search ID recovery after rolling forward.")


if __name__ == "__main__":
    main()
