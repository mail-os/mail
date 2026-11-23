#!/usr/bin/env python3
"""Exercise calendar SmartReply and SmartForward through CalDAV, Sync and ComposeMail."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.parser import BytesParser
from pathlib import Path
import re
import runpy
import tempfile
from threading import Barrier


SCRIPTS = Path(__file__).resolve().parent
hosted = runpy.run_path(str(SCRIPTS / "test-hosted-limits.py"))
dav = runpy.run_path(str(SCRIPTS / "test-dav-https.py"))
Fixture, DavClient, must = hosted["Fixture"], dav["DavClient"], dav["must"]
EXACT = "2027-03-14T13:00:00.000Z"
FUTURE = "2027-03-17T13:00:00.000Z"


def calendar(*parts):
    return "\r\n".join((
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail//ActiveSync fixture//EN",
        *parts, "END:VCALENDAR", "",
    )).encode()


def event(uid, summary, *fields):
    return (
        "BEGIN:VEVENT", f"UID:{uid}", "DTSTAMP:20270101T000000Z",
        f"SUMMARY:{summary}", *fields, "END:VEVENT",
    )


def put(client, name, data, collection="Primary"):
    path = f"/calendars/{client.mailbox}/{collection}/{name}.ics"
    must(client.request("PUT", path, data, {"Content-Type": "text/calendar"}), 201)
    return path


def ids(test, mailbox):
    def sync(key):
        status, _, data = test.eas(mailbox, hosted["eas_sync"](key, "5"), command="Sync", device="CalendarPhone")
        assert status == 200, (status, data)
        return data

    first = sync("0")
    data = sync(hosted["eas_sync_key"](first))
    pairs = re.findall(rb"\x4d\x03([0-9]+)\x00\x01\x5d\x00\x04\x68\x03([^\x00]+)\x00\x01", data)
    return {uid.decode(): item.decode() for item, uid in pairs}


def compose(test, mailbox, sink, command, client_id, item, occurrence=None, *, save=True, replace=False, folder="5", subject=None):
    mime = hosted["eas_mime"](mailbox, sink, subject=subject or client_id, payload=b"Client calendar note")
    request = hosted["eas_send"](mime, client_id, command=command, source=(folder, item),
                                 occurrence=occurrence, replace=replace, save=save)
    response = test.eas(mailbox, request, command=command, device="CalendarPhone")
    return hosted["eas_result"](response, command)


def received(test, sink, subject):
    messages = (path.read_bytes() for path in (test.directory / "mail" / sink).rglob("*.eml*"))
    matching = [message for message in messages if f"Subject: {subject}\r\n".encode() in message]
    assert matching, f"Missing delivered message {subject}"
    return BytesParser(policy=policy.default).parsebytes(matching[-1])


def attachment(message):
    note = message.get_body(preferencelist=("plain",))
    assert note and "Client calendar note" in note.get_content(), message
    part, = list(message.iter_attachments())
    assert part.get_filename() == "event.ics" and part.get_content_type() == "text/calendar"
    data = part.get_payload(decode=True)
    assert b"\r\nMETHOD:" not in data.upper()
    return data


def sent_boundaries(test, owner, sink, command, item, occurrence, expected):
    subject = f"Calendar {command}"
    before = test.bytes(owner)
    status = compose(test, owner, sink, command, command + "Measure", item, occurrence, subject=subject)
    assert status == 0, (command, status)
    length = test.bytes(owner) - before
    assert length > 0
    data = attachment(received(test, sink, subject))
    for line in expected:
        assert line in data, data
    assert data.count(b"BEGIN:VEVENT\r\n") == 1 and b"RRULE" not in data, data
    before, delivered, allowance = test.bytes(owner), test.bytes(sink), test.count(owner)
    test.provision("owner", quota=before + length - 1)
    assert compose(test, owner, sink, command, command + "Exact", item, occurrence, subject=subject) == 113
    assert (test.bytes(owner), test.bytes(sink), test.count(owner)) == (before, delivered, allowance)
    test.provision("owner", quota=before + length)
    assert compose(test, owner, sink, command, command + "Exact", item, occurrence, subject=subject) == 0
    assert test.bytes(owner) == before + length and test.count(owner) == allowance + 1
    test.provision("owner")


def verify(binary):
    with tempfile.TemporaryDirectory(prefix="mail-eas-calendar-compose-") as directory:
        test = Fixture(binary, Path(directory), staging=True)
        with test.daemon():
            owner, other, sink = (test.provision(user) for user in ("owner", "other", "sink"))
            local, foreign = DavClient(test, owner), DavClient(test, other)
            zone = ";TZID=America/New_York"
            start = "DTSTART" + zone + ":"
            recurrence = "RECURRENCE-ID" + zone + ":"
            uid = "planning-series"
            master = event(uid, "Planning series", start + "20270312T090000", "DURATION:PT1H",
                           "RRULE:FREQ=DAILY;COUNT=6", "EXDATE" + zone + ":20270313T090000",
                           "DESCRIPTION:Original agenda", f"ORGANIZER:mailto:{other}", f"ATTENDEE:mailto:{owner}")
            moved = event(uid, "Rescheduled session", recurrence + "20270314T090000",
                          start + "20270314T110000", "DURATION:PT90M", "DESCRIPTION:Revised agenda")
            range_edit = event(uid, "Later planning sessions", "RECURRENCE-ID;RANGE=THISANDFUTURE" + zone + ":20270315T090000",
                               start + "20270315T100000", "DURATION:PT2H")
            cancelled = event(uid, "Cancelled session", recurrence + "20270316T090000",
                              start + "20270316T090000", "STATUS:CANCELLED")
            path = put(local, "planning", calendar(*master, *moved, *cancelled))
            allday_uid = "planning-day"
            allday = event(allday_uid, "Planning day", "DTSTART;VALUE=DATE:20270320", "DURATION:P1D")
            all_day_path = put(local, "planning-day", calendar(*allday))
            foreign_uid = "foreign-event"
            put(foreign, "study", calendar(*event(foreign_uid, "Foreign study", "DTSTART:20270314T130000Z")))
            own_ids, foreign_ids = ids(test, owner), ids(test, other)
            assert set(own_ids) == {"planning", allday_uid} and set(foreign_ids) == {"study"}, (own_ids, foreign_ids)
            item = own_ids["planning"]
            # A device can still refer to an owned source it received before the
            # event gained a range override or an added date.
            headers = {"Content-Type": "text/calendar"}
            must(local.request("PUT", path, calendar(*master, *moved, *range_edit, *cancelled), headers), 204)
            must(local.request("PUT", all_day_path, calendar(*allday[:-1], "RDATE;VALUE=DATE:20270322", allday[-1]), headers), 204)

            # Run one authorized occurrence first so this fixture fails on builds that reject all InstanceIds.
            sent_boundaries(test, owner, sink, "SmartReply", item, EXACT, (
                b"RECURRENCE-ID:20270314T130000Z", b"DTSTART:20270314T150000Z", b"DTEND:20270314T163000Z",
                b"UID:planning-series", b"SUMMARY:Rescheduled session", b"DESCRIPTION:Revised agenda",
            ))
            sent_boundaries(test, owner, sink, "SmartForward", item, FUTURE, (
                b"RECURRENCE-ID:20270317T130000Z", b"DTSTART:20270317T140000Z", b"DTEND:20270317T160000Z",
                b"SUMMARY:Later planning sessions", b"DESCRIPTION:Original agenda",
            ))

            must(local.request("MKCALENDAR", f"/calendars/{owner}/Secondary/"), 201)
            status, listing = test.api(test.login(owner), "calendars")
            assert status == 200, listing
            secondary, = [entry["id"] for entry in listing["calendars"] if entry["name"] == "Secondary"]
            status, hidden = test.api(test.login(owner), "calendar-events", {
                "calendarId": secondary, "summary": "Outside ActiveSync", "time": {"start": 1815723000, "end": 1815726600},
            }, "POST")
            assert status == 201, hidden

            before = (test.bytes(owner), test.bytes(sink), test.count(owner), test.count(other))
            for invalid, expected in (
                ("2027-02-29T13:00:00.000Z", 104),
                ("2027-03-13T14:00:00.000Z", 150),  # EXDATE
                ("2027-03-14T15:00:00.000Z", 150),  # moved start, not its ID
                ("2027-03-14T13:00:00.001Z", 150),
                ("2027-03-16T13:00:00.000Z", 150),  # cancellation
                ("2027-03-18T13:00:00.000Z", 150),  # after COUNT
            ):
                for command in ("SmartReply", "SmartForward"):
                    assert compose(test, owner, sink, command, f"Invalid{expected}", item, invalid, replace=True) == expected
            assert compose(test, other, sink, "SmartReply", "ForeignId", item, EXACT, replace=True) == 150
            assert compose(test, owner, sink, "SmartForward", "ForeignId", foreign_ids["study"], replace=True) == 150
            assert compose(test, owner, sink, "SmartForward", "OtherCalendar", str(hidden["id"]), replace=True) == 150
            assert compose(test, owner, sink, "SmartReply", "MailInstance", "1", EXACT, folder="1") == 147
            assert (test.bytes(owner), test.bytes(sink), test.count(owner), test.count(other)) == before

            assert compose(test, owner, sink, "SmartForward", "AllDay", own_ids[allday_uid], "2027-03-22T00:00:00.000Z") == 0
            data = attachment(received(test, sink, "AllDay"))
            for line in (b"RECURRENCE-ID;VALUE=DATE:20270322", b"DTSTART;VALUE=DATE:20270322", b"DTEND;VALUE=DATE:20270323"):
                assert line in data, data
            assert compose(test, owner, sink, "SmartReply", "EditedMime", item, EXACT, replace=True) == 0
            edited = received(test, sink, "EditedMime")
            assert not edited.is_multipart() and edited.get_content().strip() == "Client calendar note", edited
            assert compose(test, owner, sink, "SmartForward", "WholeSeries", item) == 0
            whole = attachment(received(test, sink, "WholeSeries"))
            assert whole.count(b"BEGIN:VEVENT\r\n") == 4 and b"RRULE:FREQ=DAILY;COUNT=6" in whole, whole

            allowance = test.count(owner)
            test.provision("owner", quota=test.bytes(owner), daily=allowance)
            before = test.bytes(sink)
            assert compose(test, owner, sink, "SmartForward", "DailyBound", item, FUTURE, save=False) == 115
            assert test.count(owner) == allowance and test.bytes(sink) == before

            test.provision("owner", quota=test.bytes(owner), daily=allowance + 1)
            gate = Barrier(2, timeout=5)

            def forward():
                gate.wait()
                return compose(test, owner, sink, "SmartForward", "LastRecipient", item, FUTURE, save=False)

            def smtp():
                with test.smtp(owner) as connection:
                    gate.wait()
                    return hosted["smtp_message"](connection, owner, [sink])[0]

            with ThreadPoolExecutor(max_workers=2) as workers:
                eas_result, smtp_result = workers.submit(forward), workers.submit(smtp)
                assert (eas_result.result(), smtp_result.result()) in ((0, 452), (115, 250))
            assert test.count(owner) == allowance + 1
            must(local.request("DELETE", path), 204)

        with test.daemon():
            before = (test.bytes(owner), test.bytes(sink), test.count(owner))
            assert compose(test, owner, sink, "SmartForward", "SmartForwardExact", item, FUTURE, subject="Calendar SmartForward") == 118
            assert compose(test, owner, sink, "SmartForward", "Removed", item, FUTURE) == 150
            assert (test.bytes(owner), test.bytes(sink), test.count(owner)) == before


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    verify(parser.parse_args().binary.resolve(strict=True))
    print("ActiveSync calendar ComposeMail, occurrence IDs, hosted limits, and restart verified.")
