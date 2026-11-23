#!/usr/bin/env python3
"""Verify recurring Calendar wire data and use its occurrence IDs in ComposeMail."""

import argparse
import base64
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import runpy
import struct
import tempfile


fixture = runpy.run_path(str(Path(__file__).with_name("test-eas-calendar-compose.py")))
Fixture, DavClient, must = (fixture[name] for name in ("Fixture", "DavClient", "must"))
calendar, event, put, compose, received, attachment = (
    fixture[name] for name in ("calendar", "event", "put", "compose", "received", "attachment")
)
hosted = fixture["hosted"]
DEVICE = "CalendarPhone"
AIRSYNC, CALENDAR = 0, 4


@dataclass
class Node:
    page: int
    tag: int
    children: list = field(default_factory=list)
    text: str = ""

    def all(self, tag, page=CALENDAR):
        return [child for child in self.children if (child.page, child.tag) == (page, tag)]

    def get(self, tag, page=CALENDAR):
        child, = self.all(tag, page)
        return child


def decode(data):
    assert data[:4] == b"\x03\x01\x6a\x00", data[:120]
    root = Node(-1, -1)
    stack = [root]
    page, offset = 0, 4
    while offset < len(data):
        token = data[offset]
        offset += 1
        if token == 0:
            page = data[offset]
            offset += 1
        elif token == 1:
            stack.pop()
        elif token == 3:
            end = data.index(0, offset)
            stack[-1].text = data[offset:end].decode()
            offset = end + 1
        else:
            assert token & 63 >= 5 and token < 128, (offset, token)
            node = Node(page, token & 63)
            stack[-1].children.append(node)
            if token & 64:
                stack.append(node)
    assert stack == [root]
    return root


def sync(test, mailbox, key="0"):
    status, _, data = test.eas(mailbox, hosted["eas_sync"](key, "5"), command="Sync", device=DEVICE)
    assert status == 200, status
    collection = decode(data).get(5, AIRSYNC).get(0x1C, AIRSYNC).get(0x0F, AIRSYNC)
    assert collection.get(0x0E, AIRSYNC).text == "1", data
    commands = collection.all(0x16, AIRSYNC)
    return collection.get(0x0B, AIRSYNC).text, commands[0].children if commands else []


def contents(changes):
    result = {}
    for change in changes:
        body = change.get(0x1D, AIRSYNC)
        result[body.get(0x28).text] = (change.get(0x0D, AIRSYNC).text, body)
    return result


def occurrence_id(compact):
    return datetime.strptime(compact, "%Y%m%dT%H%M%SZ").strftime("%Y-%m-%dT%H:%M:%S.000Z")


def verify(binary):
    with tempfile.TemporaryDirectory(prefix="mail-eas-calendar-sync-") as directory:
        test = Fixture(binary, Path(directory), staging=True)
        with test.daemon():
            owner, other, sink = (test.provision(name) for name in ("calendar", "other", "sink"))
            local, foreign = DavClient(test, owner), DavClient(test, other)
            uid = "repeat-review"
            tzid = ";TZID=America/New_York"
            timing = ("DTSTART" + tzid + ":20270309T090000", "DURATION:PT1H", "RRULE:FREQ=WEEKLY;BYDAY=TU,TH;COUNT=6")
            master = event(uid, "Weekly review", *timing, "EXDATE" + tzid + ":20270311T090000",
                           "DESCRIPTION:Regular agenda", f"ORGANIZER:mailto:{other}", f"ATTENDEE:mailto:{owner}")
            moved = event(uid, "Moved review", "RECURRENCE-ID" + tzid + ":20270316T090000",
                          "DTSTART" + tzid + ":20270316T120000", "DURATION:PT90M", "DESCRIPTION:Moved agenda")
            cancelled = event(uid, "Cancelled review", "RECURRENCE-ID" + tzid + ":20270318T090000",
                              "DTSTART" + tzid + ":20270318T090000", "STATUS:CANCELLED")
            source_path = put(local, "review", calendar(*master, *moved, *cancelled))
            put(local, "all-day", calendar(*event("all-day", "Design day", "DTSTART;VALUE=DATE:20270320",
                                                "DURATION:P1D", "RRULE:FREQ=DAILY;INTERVAL=2;UNTIL=20270325")))
            put(local, "nth", calendar(*event("nth", "Third Monday", "DTSTART:20270315T130000Z", "DURATION:PT1H",
                                             "RRULE:FREQ=MONTHLY;BYDAY=3MO")))
            put(local, "monthly", calendar(*event("monthly", "Midmonth", "DTSTART;TZID=Asia/Kolkata:20270315T090000",
                                                 "DURATION:PT1H", "RRULE:FREQ=MONTHLY;BYMONTHDAY=15")))
            put(local, "month-end", calendar(*event("month-end", "Month end", "DTSTART:20270228T090000Z",
                                                   "DURATION:PT1H", "RRULE:FREQ=MONTHLY;BYMONTHDAY=-1")))
            put(local, "weekdays", calendar(*event("weekdays", "Weekday review", "DTSTART:20270308T130000Z",
                                                   "DURATION:PT1H", "RRULE:FREQ=DAILY;BYDAY=MO,TU,WE,TH,FR")))
            put(local, "yearly", calendar(*event("yearly", "Annual review", "DTSTART:20270325T130000Z", "DURATION:PT1H",
                                                "RRULE:FREQ=YEARLY;BYMONTH=3;BYMONTHDAY=25")))
            put(local, "subdaily", calendar(*event("subdaily", "Hourlies", "DTSTART:20270312T130000Z",
                                                  "RRULE:FREQ=HOURLY;COUNT=3")))
            put(local, "added-date", calendar(*event("extra-date", "Extra day", "DTSTART:20270312T130000Z",
                                                    "RRULE:FREQ=DAILY;COUNT=3", "RDATE:20270318T130000Z")))
            put(local, "crosses-dst", calendar(*event("crosses-dst", "Overnight", "DTSTART" + tzid + ":20270309T000000",
                                                     "DURATION:PT4H", "RRULE:FREQ=DAILY")))
            put(local, "irregular-zone", calendar(
                "BEGIN:VTIMEZONE", "TZID:Fixture/Changes", "BEGIN:STANDARD", "DTSTART:20270101T000000",
                "TZOFFSETFROM:+0000", "TZOFFSETTO:+0000", "END:STANDARD", "BEGIN:DAYLIGHT",
                "DTSTART:20270317T010000", "TZOFFSETFROM:+0000", "TZOFFSETTO:+0130", "END:DAYLIGHT", "END:VTIMEZONE",
                *event("irregular", "Irregular zone", "DTSTART;TZID=Fixture/Changes:20270310T100000",
                       "DURATION:PT1H", "RRULE:FREQ=DAILY"),
            ))
            put(foreign, "review", calendar(*event(uid, "Other mailbox", "DTSTART:20270309T090000Z",
                                                  "RRULE:FREQ=DAILY;COUNT=2")))

            key, _ = sync(test, owner)
            key, changes = sync(test, owner, key)
            visible = contents(changes)
            assert set(visible) == {"review", "all-day", "nth", "monthly", "month-end", "weekdays", "yearly"}, set(visible)
            foreign_key, _ = sync(test, other)
            foreign_key, foreign_changes = sync(test, other, foreign_key)
            foreign_item, foreign_body = contents(foreign_changes)["review"]
            item, body = visible["review"]
            assert foreign_item != item and foreign_body.get(0x26).text == "Other mailbox"

            assert body.get(0x27).text == "20270309T140000Z" and body.get(0x12).text == "20270309T150000Z"
            assert body.get(0x26).text == "Weekly review"
            recurrence = body.get(0x1B)
            assert {child.tag: child.text for child in recurrence.children} == {
                0x1C: "1", 0x1F: "1", 0x1E: "6", 0x39: "1", 0x20: "20",
            }
            timezone = base64.b64decode(body.get(5).text, validate=True)
            assert len(timezone) == 172 and struct.unpack_from("<i", timezone)[0] == 300
            assert struct.unpack_from("<8H", timezone, 68) == (0, 11, 0, 1, 2, 0, 0, 0)
            assert struct.unpack_from("<8H", timezone, 152) == (0, 3, 0, 2, 2, 0, 0, 0)
            assert struct.unpack_from("<i", timezone, 168)[0] == -60
            exceptions = {node.get(0x16).text: node for node in body.get(0x14).all(0x13)}
            assert set(exceptions) == {"20270311T140000Z", "20270316T130000Z", "20270318T130000Z"}
            assert exceptions["20270311T140000Z"].get(0x15).text == "1"
            assert exceptions["20270318T130000Z"].get(0x15).text == "1"
            moved_wire = exceptions["20270316T130000Z"]
            assert moved_wire.get(0x27).text == "20270316T160000Z"
            assert moved_wire.get(0x12).text == "20270316T173000Z" and moved_wire.get(0x26).text == "Moved review"

            all_day = visible["all-day"][1]
            assert all_day.get(6).text == "1" and not all_day.all(5)
            assert all_day.get(0x27).text == "20270320T000000Z" and all_day.get(0x12).text == "20270321T000000Z"
            assert all_day.get(0x1B).get(0x1D).text == "20270324T000000Z"
            monthly = visible["nth"][1].get(0x1B)
            assert monthly.get(0x1C).text == "3" and monthly.get(0x22).text == "3" and monthly.get(0x20).text == "2"
            fixed = visible["monthly"][1]
            assert fixed.get(0x27).text == "20270315T033000Z"
            assert base64.b64decode(fixed.get(5).text) == struct.pack("<i", -330) + bytes(168)
            assert fixed.get(0x1B).get(0x1C).text == "2" and fixed.get(0x1B).get(0x21).text == "15"
            assert visible["month-end"][1].get(0x1B).get(0x21).text == "31"
            weekdays = visible["weekdays"][1].get(0x1B)
            assert weekdays.get(0x1C).text == "1" and weekdays.get(0x20).text == "62"
            annual = visible["yearly"][1].get(0x1B)
            assert annual.get(0x1C).text == "5" and annual.get(0x23).text == "3" and annual.get(0x21).text == "25"

            selected = occurrence_id(moved_wire.get(0x16).text)
            assert compose(test, owner, sink, "SmartReply", "FromSync", item, selected) == 0
            assert b"DTSTART:20270316T160000Z" in attachment(received(test, sink, "FromSync"))
            assert compose(test, other, sink, "SmartReply", "Foreign", item, selected) == 150
            assert sync(test, owner, key) == (key, [])

            # A range change takes the series out of this wire model. The
            # previously synchronized item is removed and the source is intact.
            range_edit = event(uid, "Later reviews", "RECURRENCE-ID;RANGE=THISANDFUTURE" + tzid + ":20270316T090000",
                               "DTSTART" + tzid + ":20270316T100000", "DURATION:PT1H")
            headers = {"Content-Type": "text/calendar"}
            must(local.request("PUT", source_path, calendar(*master, *range_edit), headers), 204)
            key, changes = sync(test, owner, key)
            removed, = changes
            assert removed.tag == 9 and removed.get(0x0D, AIRSYNC).text == item
            assert sync(test, owner, key) == (key, [])
            must(local.request("GET", source_path), 200)
            must(local.request("PUT", source_path, calendar(*master, *moved), headers), 204)
            key, changes = sync(test, owner, key)
            assert changes[0].tag == 7 and contents(changes)["review"][0] == item

        with test.daemon():
            assert sync(test, owner, key) == (key, [])
            assert sync(test, other, foreign_key) == (foreign_key, [])
            # An updated exception is an incremental modification of the
            # original item and still carries the original occurrence ID.
            updated = event(uid, "Later start", "RECURRENCE-ID" + tzid + ":20270316T090000",
                            "DTSTART" + tzid + ":20270316T130000", "DURATION:PT1H")
            must(local.request("PUT", source_path, calendar(*master, *updated), headers), 204)
            key, changes = sync(test, owner, key)
            assert changes[0].tag == 8
            updated_id, body = contents(changes)["review"]
            assert updated_id == item
            updated_wire = next(node for node in body.get(0x14).all(0x13) if node.get(0x15).text == "0")
            assert occurrence_id(updated_wire.get(0x16).text) == selected
            assert updated_wire.get(0x27).text == "20270316T170000Z"
            assert compose(test, owner, sink, "SmartForward", "AfterRestart", updated_id, selected) == 0
            assert b"DTSTART:20270316T170000Z" in attachment(received(test, sink, "AfterRestart"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    verify(parser.parse_args().binary.resolve(strict=True))
    print("Verified ActiveSync recurrence, DST, exceptions, incremental Sync, ComposeMail and restart.")
