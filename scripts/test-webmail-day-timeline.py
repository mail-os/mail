#!/usr/bin/env python3
"""Verify day timeline behavior over native HTTPS and CalDAV."""

import argparse
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
from urllib.parse import unquote

HERE = Path(__file__).resolve().parent
shared = runpy.run_path(str(HERE / "test-webmail-calendar-shares.py"))
Fixture, command, expect, DavClient = (shared[key] for key in ("Fixture", "command", "expect", "DavClient"))
ENGINES = ("chromium", "firefox", "webkit")
CALENDAR = "Studio schedule"
DAY = "2026-11-24"


def seed_event(test, owner, calendar, uid, title, start, end, classification="PUBLIC"):
    value_type = ";VALUE=DATE" if len(start) == 8 else ""
    source = [
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail//Day Timeline Test//EN",
        "BEGIN:VEVENT", f"UID:{uid}", "DTSTAMP:20261118T120000Z", f"SUMMARY:{title}",
        f"DTSTART{value_type}:{start}", f"DTEND{value_type}:{end}", f"CLASS:{classification}",
        "END:VEVENT", "END:VCALENDAR", "",
    ]
    shared["write_resource"](test, owner, calendar, uid, source)


def verify(binary, output, engine):
    with tempfile.TemporaryDirectory(prefix="mail-day-timeline-") as scratch:
        test = Fixture(binary, Path(scratch), staging=True)
        with test.daemon():
            owner, viewer, availability = (test.provision(name) for name in ("owner", "viewer", "availability"))
            command(test, "team", "create", "studio", "Studio", owner)
            for member in (viewer, availability):
                command(test, "team", "member", "studio", member, "member")
            seed_event(test, owner, CALENDAR, "design", "Design review", "20261124T090000Z", "20261124T103000Z")
            seed_event(test, owner, CALENDAR, "handoff", "Studio handoff", "20261124T093000Z", "20261124T110000Z")
            seed_event(test, owner, CALENDAR, "private", "Private review", "20261124T104500Z", "20261124T113000Z", "PRIVATE")
            seed_event(test, owner, CALENDAR, "overnight", "Overnight maintenance", "20261123T233000Z", "20261124T003000Z")
            seed_event(test, owner, "Planning", "offsite", "Offsite planning", "20261124", "20261125")
            seed_event(test, owner, "Planning", "quick", "Quick checkpoint", "20261124T100000Z", "20261124T100500Z")
            seed_event(test, owner, CALENDAR, "fall-first", "First audit", "20261101T051500Z", "20261101T054500Z")
            seed_event(test, owner, CALENDAR, "fall-second", "Second audit", "20261101T061500Z", "20261101T064500Z")
            seed_event(test, owner, CALENDAR, "spring", "Spring maintenance", "20260308T063000Z", "20260308T073000Z")
            owner_session = test.login(owner)
            calendars = expect(test.api(owner_session, "calendars"))["calendars"]
            ids = {unquote(item["name"]): item["id"] for item in calendars}
            calendar_id = ids[CALENDAR]
            expect(test.api(owner_session, f"calendars/{ids['Planning']}", {"color": "#7254ad"}, method="PATCH"), 204)
            for member, role in ((viewer, "viewer"), (availability, "free_busy")):
                expect(shared["change"](test, owner_session, calendar_id, member, role))
            environment = dict(os.environ, MAIL_TIMELINE_URL=test.webmail, MAIL_TIMELINE_OWNER=owner,
                               MAIL_TIMELINE_VIEWER=viewer, MAIL_TIMELINE_AVAILABILITY=availability,
                               MAIL_TIMELINE_PASSWORD=test.password, MAIL_TIMELINE_DAY=DAY,
                               MAIL_TIMELINE_CALENDAR=str(calendar_id))
            subprocess.run(["node", str(HERE / "webmail-day-timeline.mjs"), engine, str(output / engine)],
                           env=environment, check=True, timeout=135)
            dav = DavClient(test, viewer)
            path = shared["calendar_path"](owner, CALENDAR)
            public = shared["dav_query"](dav, path, "20261124T000000Z", "20261125T000000Z")
            assert all("SUMMARY:Private review" not in resource for resource in public.values())
            keyboard = next(resource for resource in public.values() if "SUMMARY:Keyboard timeline event" in resource)
            touch = next(resource for resource in public.values() if "SUMMARY:Touch timeline event" in resource)
            assert "DTSTART:20261124T111500Z" in keyboard
            assert "DTSTART:20261124T141500Z" in touch
            repeated = shared["dav_query"](dav, path, "20261101T061500Z", "20261101T061600Z")
            reminder = next(resource for resource in repeated.values() if "SUMMARY:Later hour reminder" in resource)
            assert "DTSTART:20261101T061500Z" in reminder
            assert "TRIGGER:-PT5M" in reminder
            shared["dav_query"](DavClient(test, availability), path, "20261124T000000Z", "20261125T000000Z", expected=404)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("screenshots", type=Path)
    parser.add_argument("--engine", action="append", choices=ENGINES)
    args = parser.parse_args()
    for engine in args.engine or ENGINES:
        verify(args.binary.resolve(strict=True), args.screenshots.resolve(), engine)


if __name__ == "__main__":
    main()
