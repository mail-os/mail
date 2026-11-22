#!/usr/bin/env python3
"""Verify owned-calendar availability and authorized combined windows over HTTPS."""

import argparse
from pathlib import Path
import runpy
import tempfile
from urllib.parse import urlencode


helpers = runpy.run_path(str(Path(__file__).with_name("test-webmail-calendar-shares.py")))
Fixture, command, expect, write_resource, timestamp, change, DavClient = (
    helpers[name] for name in ("Fixture", "command", "expect", "write_resource", "timestamp", "change", "DavClient")
)


def query(start="20281106T090000Z", end="20281106T170000Z", **options):
    return "calendar-free-busy?" + urlencode(dict(start=timestamp(start), end=timestamp(end), **options))


def busy(start, end):
    return {"busy": [{"start": timestamp(start), "end": timestamp(end)}]}


def event(fixture, mailbox, calendar, name, start, stop, *properties):
    uid = name.lower().replace(" ", "-")
    return write_resource(fixture, mailbox, calendar, uid, [
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail free-time fixture//EN", "BEGIN:VEVENT",
        f"UID:{uid}@calendar.example", "DTSTAMP:20261122T120000Z", f"SUMMARY:{name}",
        f"DTSTART:{start}", f"DTEND:{stop}", *properties,
        "END:VEVENT", "END:VCALENDAR", "",
    ])


def verify(fixture):
    with fixture.daemon():
        owner = fixture.provision("availability-owner")
        guest = fixture.provision("availability-guest")
        outsider = fixture.provision("availability-outsider")
        captain, invited, outside = fixture.login(owner), fixture.login(guest), fixture.login(outsider)
        expect(fixture.api({}, query()), 401)
        assert expect(fixture.api(outside, query())) == {"busy": []}
        shared_id = expect(fixture.api(captain, "calendars", {"name": "Shared schedule"}, "POST"), 201)["id"]
        work_id = expect(fixture.api(invited, "calendars", {"name": "Work"}, "POST"), 201)["id"]
        expect(fixture.api(invited, "calendars", {"name": "Personal"}, "POST"), 201)
        event(fixture, owner, "Shared schedule", "Private customer review", "20281106T100000Z", "20281106T110000Z", "CLASS:PRIVATE")
        event(fixture, guest, "Work", "Recurring standup", "20281105T110000Z", "20281105T120000Z", "RRULE:FREQ=DAILY;COUNT=2")
        event(fixture, guest, "Personal", "Lunch", "20281106T120000Z", "20281106T130000Z")
        event(fixture, guest, "Work", "Optional reading", "20281106T130000Z", "20281106T160000Z", "TRANSP:TRANSPARENT")
        event(fixture, guest, "Personal", "Cancelled appointment", "20281106T150000Z", "20281106T160000Z", "STATUS:CANCELLED")
        event(fixture, guest, "Personal", "After the window", "20281106T170000Z", "20281106T180000Z")

        assert expect(fixture.api(invited, query())) == busy("20281106T110000Z", "20281106T130000Z")
        assert expect(fixture.api(invited, query(calendarId=work_id))) == busy("20281106T110000Z", "20281106T120000Z")
        assert expect(fixture.api(invited, query(calendarId=work_id, includeOwned=1))) == busy("20281106T110000Z", "20281106T130000Z")
        expect(fixture.api(invited, query(calendarId=shared_id, includeOwned=1)), 404)

        command(fixture, "team", "create", "studio", "Studio", owner)
        command(fixture, "team", "member", "studio", guest, "member")
        expect(change(fixture, captain, shared_id, guest, "free_busy"))
        shared = query(calendarId=shared_id)
        combined = query(calendarId=shared_id, includeOwned=1)
        assert expect(fixture.api(invited, shared)) == busy("20281106T100000Z", "20281106T110000Z")
        assert expect(fixture.api(invited, combined)) == busy("20281106T100000Z", "20281106T130000Z")
        clipped = query("20281106T103000Z", "20281106T113000Z", calendarId=shared_id, includeOwned=1)
        assert expect(fixture.api(invited, clipped)) == busy("20281106T103000Z", "20281106T113000Z")
        expect(fixture.api(outside, combined), 404)
        expect(fixture.api(invited, f"calendar-events?calendarId={shared_id}&q=Private"), 404)

        bad = event(fixture, owner, "Shared schedule", "Unsupported", "20281106T150000Z", "20281106T160000Z",
                    "RRULE:FREQ=YEARLY;BYWEEKNO=1;BYDAY=MO")
        assert expect(fixture.api(invited, combined), 422)["error"] == "availability_incomplete"
        assert DavClient(fixture, owner).request("DELETE", bad)[0] == 204
        expect(change(fixture, captain, shared_id, guest, None))
        expect(fixture.api(invited, combined), 404)
        assert expect(fixture.api(invited, query())) == busy("20281106T110000Z", "20281106T130000Z")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-free-time-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Calendar free-time API verification passed.")


if __name__ == "__main__":
    main()
