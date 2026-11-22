#!/usr/bin/env python3
"""Verify TLS IMAP APPEND dates, sequence order, and restart persistence."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import re
import runpy
import tempfile
import time

Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]
INTERNALDATE = re.compile(rb'^([0-9]+) \(UID ([0-9]+) .*INTERNALDATE "([^"]+)"\)')
OLD_DATE = datetime(1969, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
OTHER_DATE = datetime(2025, 3, 5, 4, 35, 45, tzinfo=timezone.utc)


def message(subject):
    return f"Subject: {subject}\r\nDate: Sun, 15 Mar 2020 10:00:00 +0000\r\n\r\nBody\r\n".encode()


def append(imap, subject, date=None, flags=None):
    status, _ = imap.append("INBOX", flags, date, message(subject))
    assert status == "OK", status
    kind, values = imap.response("APPENDUID")
    assert kind == "APPENDUID" and values[0], (kind, values)
    validity, uid = map(int, values[0].split())
    assert validity > 0 and uid > 0
    return uid


def dates(imap):
    status, entries = imap.fetch("1:*", "(UID FLAGS INTERNALDATE)")
    assert status == "OK", (status, entries)
    result = {}
    for entry in entries:
        match = INTERNALDATE.match(entry)
        assert match, entry
        sequence, uid = int(match[1]), int(match[2])
        value = datetime.strptime(match[3].decode(), "%d-%b-%Y %H:%M:%S %z")
        result[sequence] = (uid, value)
    return result


def seed(fixture, user):
    with fixture.imap(user) as writer, fixture.imap(user) as observer:
        assert writer.create('"Copied history"')[0] == "OK"
        assert writer.create('"Moved history"')[0] == "OK"
        before = int(time.time())
        baseline_uid = append(writer, "Date omitted")
        after = int(time.time())
        assert observer.select("INBOX") == ("OK", [b"1"])
        baseline, received = dates(observer)[1]
        assert baseline == baseline_uid and before <= received.timestamp() <= after

        older = append(writer, "Historical date", '"31-Dec-1969 15:59:59 -0800"', r"(\Seen \Flagged)")
        other = append(writer, "Offset date", '" 5-Mar-2025 10:05:45 +0530"')
        assert baseline < older < other
        status, detail = writer.append("INBOX", None, '"29-Feb-2025 04:35:45 +0000"', message("Invalid date"))
        assert status == "NO" and b"Invalid APPEND date-time" in detail[0], (status, detail)

        assert observer.noop()[0] == "OK"
        assert dates(observer) == {1: (baseline, received), 2: (older, OLD_DATE), 3: (other, OTHER_DATE)}
        status, rows = observer.fetch("2", "(FLAGS)")
        assert status == "OK" and b"\\Seen" in rows[0] and b"\\Flagged" in rows[0]
        assert observer.copy("2", '"Copied history"')[0] == "OK"
        assert observer.xatom("MOVE", "3", '"Moved history"')[0] == "OK"
    return baseline, received, older


def verify_after_restart(fixture, user, original):
    baseline, received, older = original
    with fixture.imap(user) as client:
        assert client.select("INBOX") == ("OK", [b"2"])
        assert dates(client) == {1: (baseline, received), 2: (older, OLD_DATE)}
        assert client.select('"Copied history"') == ("OK", [b"1"])
        assert dates(client)[1][1] == OLD_DATE
        assert client.select('"Moved history"') == ("OK", [b"1"])
        assert dates(client)[1][1] == OTHER_DATE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-append-date-") as root:
        fixture = Fixture(args.binary.resolve(strict=True), Path(root), staging=True)
        with fixture.daemon():
            user = fixture.provision("restore-dates")
            original = seed(fixture, user)
        with fixture.daemon():
            verify_after_restart(fixture, user, original)
    print("Verified TLS IMAP APPEND dates, flags, sequence and UID order, COPY, MOVE, and restart.")


if __name__ == "__main__":
    main()
