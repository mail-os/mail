#!/usr/bin/env python3
"""Verify team calendar grants, private event isolation, and revocation."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from http.client import HTTPSConnection
from pathlib import Path
import runpy
import socketserver
import sqlite3
import struct
import tempfile
from threading import Barrier, Event, Thread
from urllib.parse import quote, urlencode


SCRIPTS = Path(__file__).resolve().parent
teams = runpy.run_path(str(SCRIPTS / "test-webmail-teams.py"))
Fixture, command, expect = (teams[name] for name in ("Fixture", "command", "expect"))
DavClient = runpy.run_path(str(SCRIPTS / "test-dav-https.py"))["DavClient"]
CALENDAR = "Studio planning"
AVAILABILITY = "Availability cases"
CALDAV = "urn:ietf:params:xml:ns:caldav"
START = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())
END = int(datetime(2027, 1, 1, tzinfo=timezone.utc).timestamp())
REVOKE_DURING_SCAN = "Editor access revoked during scanning"


class CalendarScan(socketserver.StreamRequestHandler):
    def handle(self):
        assert self.rfile.read(10) == b"zINSTREAM\x00"
        data = bytearray()
        while size := struct.unpack("!I", self.rfile.read(4))[0]:
            data.extend(self.rfile.read(size))
        if REVOKE_DURING_SCAN.encode() in data:
            self.server.scanning.set()
            assert self.server.resume.wait(timeout=8), "Calendar edit was never released"
        self.wfile.write(b"stream: OK\x00")


@contextmanager
def scanner():
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), CalendarScan) as server:
        server.scanning, server.resume = Event(), Event()
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.resume.set()
            server.shutdown()
            thread.join()


def write_event(test, owner, name, classification="", recurring=False, expected=201):
    data = [
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail calendar share test//EN",
        "BEGIN:VEVENT", f"UID:{name}", "DTSTAMP:20261122T120000Z",
        "DTSTART:20261208T100000Z", "DTEND:20261208T110000Z", f"SUMMARY:{name}",
        f"DESCRIPTION:description of {name}",
    ]
    if classification:
        data.append("CLASS:" + classification)
    if recurring:
        data.extend([
            "RRULE:FREQ=WEEKLY;COUNT=3", "END:VEVENT",
            "BEGIN:VEVENT", f"UID:{name}", "RECURRENCE-ID:20261215T100000Z",
            "DTSTAMP:20261122T120000Z", "DTSTART:20261215T110000Z", "DTEND:20261215T120000Z",
            "SUMMARY:private occurrence", "CLASS:PRIVA", " TE",
        ])
    data.extend(["END:VEVENT", "END:VCALENDAR", ""])
    write_resource(test, owner, CALENDAR, name, data, expected)


def write_resource(test, owner, calendar, name, data, expected=201):
    path = f"/calendars/{owner}/{quote(calendar, safe='')}/{name}.ics"
    result = DavClient(test, owner).request("PUT", path, "\r\n".join(data), {"Content-Type": "text/calendar"})
    assert result[0] == expected, result
    return path


def change(test, session, calendar_id, grantee, access, team="studio"):
    return test.api(session, f"teams/{team}/calendar-shares", {
        "calendarId": calendar_id, "grantee": grantee, "access": access,
    }, "PUT")


def shares(test, session):
    return expect(test.api(session, "calendar-shares"))["shares"]


def event_query(calendar_id, **filters):
    return "calendar-events?" + urlencode(dict(calendarId=calendar_id, start=START, end=END,
                                              instances=1, **filters))


def busy_query(calendar_id, start=START, end=END):
    return "calendar-free-busy?" + urlencode(dict(calendarId=calendar_id, start=start, end=end))


def timestamp(value):
    return int(datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp())


def busy_period(start, end):
    return {"start": timestamp(start), "end": timestamp(end)}


def calendar_path(owner, calendar):
    return f"/calendars/{quote(owner, safe='')}/{quote(calendar, safe='')}"


def busy_report(start="20261201T000000Z", end="20270101T000000Z"):
    return (f'<C:free-busy-query xmlns:C="{CALDAV}">'
            f'<C:time-range start="{start}" end="{end}"/></C:free-busy-query>')


def dav_busy(client, path, start="20261201T000000Z", end="20270101T000000Z", *,
             depth="1", tls=True, authenticated=True, status=200, body=None):
    if body is None:
        body = busy_report(start, end)
    headers = {"Content-Type": "application/xml"}
    if depth is not None:
        headers["Depth"] = depth
    actual, fields, content = client.request("REPORT", path, body, headers, tls=tls, authenticated=authenticated)
    assert actual == status, (actual, status, content)
    if status != 200:
        return
    assert fields.get_content_type() == "text/calendar"
    assert fields["Cache-Control"] == "no-store"
    lines = content.decode().splitlines()
    assert lines[:4] == ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail//CalDAV//EN", "BEGIN:VFREEBUSY"], lines
    assert lines[-2:] == ["END:VFREEBUSY", "END:VCALENDAR"], lines
    assert lines[4].startswith("UID:") and lines[5].startswith("DTSTAMP:"), lines
    assert lines[6:8] == ["DTSTART:" + start, "DTEND:" + end], lines
    assert all(line.startswith("FREEBUSY;FBTYPE=") for line in lines[8:-2]), lines
    return [line.removeprefix("FREEBUSY;FBTYPE=") for line in lines[8:-2]]


def create_calendar(test, owner_session):
    return expect(test.api(owner_session, "calendars", {"name": CALENDAR}), 201)["id"]


def verify(test, db, owner, viewer, colleague, foreign):
    for mailbox in (viewer, colleague):
        command(test, "team", "member", "studio", mailbox, "member")
    command(test, "team", "create", "other", "Other company", foreign)
    captain, invited, teammate, outsider = (test.login(account) for account in (owner, viewer, colleague, foreign))
    calendar_id = create_calendar(test, captain)
    for name, classification in (("Roadmap", "PUBLIC"), ("Budget", "PRIVATE"), ("Confidential", "CONFIDENTIAL")):
        write_event(test, owner, name, classification)
    write_event(test, owner, "Public-series", recurring=True)

    query = event_query(calendar_id)
    owner_dav, viewer_dav = DavClient(test, owner), DavClient(test, viewer)
    path = calendar_path(owner, CALENDAR)
    propfind = owner_dav.request("PROPFIND", path, headers={"Depth": "0"})
    assert propfind[0] == 207 and b"<C:free-busy-query/>" in propfind[2], propfind
    dav_busy(owner_dav, path + "/Budget.ics", status=403)
    dav_busy(viewer_dav, path, authenticated=False, status=401)
    dav_busy(viewer_dav, path, status=404)
    owners = expect(test.api(captain, query))["events"]
    assert {event["summary"] for event in owners} == {"Roadmap", "Budget", "Confidential", "Public-series"}
    expect(test.api({}, "calendar-shares"), 401)
    expect(test.api(invited, query), 404)
    # The pre-existing generic grant is descriptive. It carries no calendar role.
    command(test, "team", "grant", "studio", owner, viewer, "calendar", str(calendar_id))
    assert shares(test, invited) == []
    expect(test.api(invited, query), 404)
    dav_busy(viewer_dav, path, status=404)

    expect(change(test, dict(captain, Origin="https://outside.example.test"), calendar_id, viewer, "viewer"), 403)
    expect(change(test, captain, calendar_id, foreign, "viewer"), 404)
    expect(change(test, captain, calendar_id, viewer, "viewer", team="other"), 404)
    expect(change(test, invited, calendar_id, colleague, "editor"), 404)
    expect(change(test, captain, calendar_id, viewer, "owner"), 400)
    expect(change(test, captain, calendar_id, viewer, "viewer"))
    expect(change(test, captain, calendar_id, viewer, "viewer"))

    expected = {"team": "studio", "source": owner, "grantee": viewer, "calendarId": calendar_id,
                "calendarName": quote(CALENDAR, safe=""), "access": "viewer"}
    incoming, outgoing = shares(test, invited), shares(test, captain)
    assert incoming == outgoing == [expected], (incoming, outgoing, expected)
    assert shares(test, teammate) == shares(test, outsider) == []
    for session in (invited, outsider):
        assert expect(test.api(session, "calendars"))["calendars"] == []
    expect(test.api(teammate, query), 404)
    expect(test.api(outsider, query), 404)
    rows = expect(test.api(invited, query))["events"]
    assert [event["summary"] for event in rows] == ["Roadmap"], rows
    assert "private occurrence" not in repr(rows)
    row, = rows
    detail = expect(test.api(invited, f"calendar-events/{row['id']}?source=1"))
    assert detail["description"] == "description of Roadmap"
    assert "SUMMARY:Roadmap" in detail["icalendar"]
    expect(test.api(dict(invited, **{"If-Match": row["etag"]}), f"calendar-events/{row['id']}",
                    {"summary": "Viewer edit"}, "PATCH"), 404)
    assert expect(test.api(invited, event_query(calendar_id, q="description of Budget")))["events"] == []
    private = next(event["id"] for event in owners if event["summary"] == "Budget")
    expect(test.api(invited, f"calendar-events/{private}?source=1"), 404)
    expect(test.api(invited, f"calendar-export?calendarId={calendar_id}"), 404)
    write_event(test, owner, "Roadmap", "PRIVATE", expected=204)
    assert expect(test.api(invited, query))["events"] == []
    write_event(test, owner, "Roadmap", "PUBLIC", expected=204)

    # Role changes apply in the same signed-in session. A failed audit
    # operation rolls back the role change rather than granting it silently.
    with db:
        db.execute("""CREATE TRIGGER reject_calendar_audit BEFORE INSERT ON audit_log
                      WHEN NEW.action='team.calendar.share' BEGIN SELECT RAISE(ABORT,'test audit failure'); END""")
    expect(change(test, captain, calendar_id, viewer, "editor"), 500)
    assert shares(test, invited) == [expected]
    with db:
        db.execute("DROP TRIGGER reject_calendar_audit")
    expect(change(test, captain, calendar_id, viewer, "editor"))
    assert shares(test, invited) == [dict(expected, access="editor")]
    expect(change(test, captain, calendar_id, viewer, "free_busy"))
    assert shares(test, invited) == [dict(expected, access="free_busy")]
    expect(test.api(invited, query), 404)
    available = busy_query(calendar_id)
    expect(test.api({}, available), 401)
    assert expect(test.api(invited, available)) == {"busy": [
        busy_period("20261208T100000Z", "20261208T110000Z"),
        busy_period("20261215T110000Z", "20261215T120000Z"),
        busy_period("20261222T100000Z", "20261222T110000Z"),
    ]}
    expect(test.api(invited, f"calendar-events/{row['id']}?source=1"), 404)
    expect(test.api(invited, f"calendar-export?calendarId={calendar_id}"), 404)
    expect(test.api(teammate, available), 404)
    expect(test.api(outsider, available), 404)
    intervals = [
        "BUSY:20261208T100000Z/20261208T110000Z",
        "BUSY:20261215T110000Z/20261215T120000Z",
        "BUSY:20261222T100000Z/20261222T110000Z",
    ]
    for tls in (True, False):
        assert dav_busy(viewer_dav, path, tls=tls) == intervals
        assert dav_busy(owner_dav, path, tls=tls) == intervals
        dav_busy(DavClient(test, colleague), path, tls=tls, status=404)
        dav_busy(DavClient(test, foreign), path, tls=tls, status=404)
        dav_busy(viewer_dav, path + "/Budget.ics", tls=tls, status=404)
        for method, target in (("PROPFIND", path), ("GET", path + "/Budget.ics"), ("HEAD", path + "/Roadmap.ics")):
            assert viewer_dav.request(method, target, tls=tls)[0] == 404
        listing = f'<C:calendar-query xmlns:C="{CALDAV}"/>'
        assert viewer_dav.request("REPORT", path, listing, tls=tls)[0] == 404
    # A connection authenticated before revocation must see the new grant state.
    with closing(HTTPSConnection("127.0.0.1", viewer_dav.https, context=viewer_dav.context, timeout=15)) as keepalive:
        headers = {**viewer_dav.auth, "Content-Type": "application/xml", "Depth": "1"}
        keepalive.request("REPORT", path, busy_report(), headers)
        with keepalive.getresponse() as first:
            assert first.status == 200
            assert b"FREEBUSY;FBTYPE=BUSY:" in first.read()
        connection = keepalive.sock
        assert connection is not None
        expect(change(test, captain, calendar_id, viewer, None))
        keepalive.request("REPORT", path, busy_report(), headers)
        assert keepalive.sock is connection
        with keepalive.getresponse() as revoked:
            assert revoked.status == 404 and revoked.read() == b""
    expect(change(test, captain, calendar_id, viewer, None))
    assert shares(test, invited) == []
    expect(test.api(invited, query), 404)
    expect(test.api(invited, available), 404)
    for tls in (True, False):
        dav_busy(viewer_dav, path, tls=tls, status=404)

    expect(change(test, captain, calendar_id, viewer, "viewer"))
    command(test, "team", "member", "studio", viewer, "remove")
    expect(test.api(invited, "calendar-shares"), 401)
    command(test, "team", "member", "studio", viewer, "member")
    invited = test.login(viewer)
    assert shares(test, invited) == []
    expect(test.api(invited, query), 404)
    dav_busy(viewer_dav, path, status=404)
    expect(change(test, captain, calendar_id, viewer, "viewer"))
    audit = db.execute("SELECT action FROM audit_log WHERE action LIKE 'team.calendar.%' ORDER BY id").fetchall()
    assert [action for (action,) in audit] == [
        "team.calendar.share", "team.calendar.share", "team.calendar.share", "team.calendar.revoke",
        "team.calendar.share", "team.calendar.share",
    ], audit
    return calendar_id


def verify_availability(test, owner, viewer):
    captain, invited = test.login(owner), test.login(viewer)
    calendar_id = expect(test.api(captain, "calendars", {"name": AVAILABILITY}), 201)["id"]
    stamp = "DTSTAMP:20260301T000000Z"

    def store(name, *properties, exceptions=()):
        return write_resource(test, owner, AVAILABILITY, name, [
            "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail availability fixture//EN",
            "BEGIN:VEVENT", f"UID:{name}", stamp, f"SUMMARY:Sensitive {name}",
            *properties, "END:VEVENT", *exceptions, "END:VCALENDAR", "",
        ])

    store("private-series", "CLASS:PRIVATE", "DTSTART;TZID=America/New_York:20260307T023000",
          "DURATION:PT1H", "RRULE:FREQ=DAILY;COUNT=4",
          "RDATE;VALUE=PERIOD;TZID=America/New_York:20260309T023000/PT30M",
          "RDATE;TZID=America/New_York:20260313T023000",
          "EXDATE;TZID=America/New_York:20260313T023000",
          exceptions=(
              "BEGIN:VEVENT", "UID:private-series", stamp,
              "RECURRENCE-ID;TZID=America/New_York:20260310T023000", "DTSTART:20260311T130000Z",
              "END:VEVENT",
              "BEGIN:VEVENT", "UID:private-series", stamp,
              "RECURRENCE-ID;TZID=America/New_York:20260311T023000", "STATUS:CANCELLED", "END:VEVENT",
          ))
    store("confidential", "CLASS:CONFIDENTIAL", "DTSTART:20260309T065000Z", "DTEND:20260309T071000Z")
    store("adjacent", "DTSTART:20260309T071000Z", "DTEND:20260309T072000Z", "STATUS:TENTATIVE")
    store("overlapping-tentative", "DTSTART:20260309T070500Z", "DTEND:20260309T071500Z", "STATUS:TENTATIVE")
    store("date-only", "DTSTART;VALUE=DATE:20260312")
    store("transparent", "DTSTART:20260313T090000Z", "DURATION:PT1H", "TRANSP:TRANSPARENT")
    store("cancelled", "DTSTART:20260314T090000Z", "DURATION:PT1H", "STATUS:CANCELLED")
    store("excluded-boundary", "DTSTART:20260315T000000Z", "DURATION:PT1H")
    write_resource(test, owner, AVAILABILITY, "stored-availability", [
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail availability fixture//EN",
        "BEGIN:VFREEBUSY", "UID:stored-availability", stamp,
        "ATTENDEE:mailto:private@example.test",
        "FREEBUSY;FBTYPE=BUSY-UNAVAILABLE:20260313T130000Z/PT30M",
        "FREEBUSY;FBTYPE=FREE:20260314T120000Z/20260314T140000Z",
        "END:VFREEBUSY", "END:VCALENDAR", "",
    ])
    start_date, end_date = "20260307T080000Z", "20260315T000000Z"
    start, end = timestamp(start_date), timestamp(end_date)
    query = busy_query(calendar_id, start, end)
    path = calendar_path(owner, AVAILABILITY)
    viewer_dav = DavClient(test, viewer)
    expect(test.api(invited, query), 404)
    dav_busy(viewer_dav, path, start_date, end_date, status=404)
    expected = {"busy": [
        busy_period("20260307T080000Z", "20260307T083000Z"),
        busy_period("20260309T063000Z", "20260309T072000Z"),
        busy_period("20260311T130000Z", "20260311T140000Z"),
        busy_period("20260312T000000Z", "20260313T000000Z"),
        busy_period("20260313T130000Z", "20260313T133000Z"),
    ]}
    typed = [
        "BUSY:20260307T080000Z/20260307T083000Z",
        "BUSY:20260309T063000Z/20260309T071000Z",
        "BUSY-TENTATIVE:20260309T070500Z/20260309T072000Z",
        "BUSY:20260311T130000Z/20260311T140000Z",
        "BUSY:20260312T000000Z/20260313T000000Z",
        "BUSY-UNAVAILABLE:20260313T130000Z/20260313T133000Z",
    ]
    for role in ("viewer", "editor", "free_busy"):
        expect(change(test, captain, calendar_id, viewer, role))
        assert expect(test.api(invited, query)) == expected
        assert dav_busy(viewer_dav, path, start_date, end_date) == typed
    assert expect(test.api(captain, query)) == expected
    assert expect(test.api(invited, busy_query(calendar_id, timestamp("20260314T000000Z"), end))) == {"busy": []}
    assert dav_busy(viewer_dav, path, "20260314T000000Z", end_date) == []
    assert dav_busy(viewer_dav, path, start_date, end_date, depth=None) == []
    assert dav_busy(viewer_dav, path, start_date, end_date, depth="infinity") == typed
    assert dav_busy(viewer_dav, path, start_date, end_date, body=(
        f"<?xml version='1.0'?><!-- report --><free-busy-query xmlns='{CALDAV}'>"
        f"<time-range end='{end_date}' start='{start_date}'/></free-busy-query>"
    )) == typed
    for lower, upper in ((start, start), (end, start), (0, 367 * 86400), (-9223372036854775808, 0)):
        expect(test.api(invited, busy_query(calendar_id, lower, upper)), 400)
    for lower, upper in ((start_date, start_date), (end_date, start_date), ("20260230T010000Z", end_date),
                         (start_date.removesuffix("Z"), end_date), (start_date, "20280315T000000Z")):
        dav_busy(viewer_dav, path, lower, upper, status=400)
    dav_busy(viewer_dav, path, start_date, end_date, depth="2", status=400)
    range_xml = f'<C:time-range start="{start_date}" end="{end_date}"/>'
    for ns, children in (("DAV:", range_xml), (CALDAV, range_xml * 2), (CALDAV, ""),
                         (CALDAV, range_xml.replace("<C:time-range", '<C:time-range xmlns:C="DAV:"'))):
        dav_busy(viewer_dav, path, body=f'<C:free-busy-query xmlns:C="{ns}">{children}</C:free-busy-query>', status=400)

    unsupported = store("unsupported", "DTSTART:20260314T120000Z", "DURATION:PT15M", "RRULE:FREQ=HOURLY;COUNT=3")
    result = expect(test.api(invited, query), 422)
    assert result["error"] == "availability_incomplete" and "Sensitive" not in repr(result), result
    dav_busy(viewer_dav, path, start_date, end_date, status=422)
    assert DavClient(test, owner).request("DELETE", unsupported)[0] == 204
    assert expect(test.api(invited, query)) == expected
    assert dav_busy(viewer_dav, path, start_date, end_date) == typed
    expect(change(test, captain, calendar_id, viewer, None))
    expect(test.api(invited, query), 404)
    dav_busy(viewer_dav, path, start_date, end_date, status=404)
    assert DavClient(test, owner).request("DELETE", f"/calendars/{owner}/{quote(AVAILABILITY, safe='')}")[0] == 204


def verify_editors(test, scan, owner, viewer, colleague, calendar_id):
    owner_session, editor, coeditor = (test.login(account) for account in (owner, viewer, colleague))
    query = event_query(calendar_id)
    event = {"calendarId": calendar_id, "summary": "Planning sync",
             "time": {"start": START + 86400, "end": START + 90000}}
    expect(test.api(editor, "calendar-events", event, "POST"), 404)
    for mailbox in (viewer, colleague):
        expect(change(test, owner_session, calendar_id, mailbox, "editor"))

    created = expect(test.api(editor, "calendar-events", event, "POST"), 201)
    item = f"calendar-events/{created['id']}"
    detail = expect(test.api(owner_session, item + "?source=1"))
    assert detail["event"]["summary"] == "Planning sync"
    base = dict(editor, **{"If-Match": created["etag"]})
    other = dict(coeditor, **{"If-Match": created["etag"]})
    gate = Barrier(2, timeout=5)

    def edit(pair):
        session, title = pair
        gate.wait()
        return test.api(session, item, {"summary": title}, "PATCH")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(edit, [(base, "Editorial review"), (other, "Studio check-in")]))
    assert sorted(result[0] for result in results) == [200, 412], results
    detail = expect(test.api(editor, item + "?source=1"))
    latest = dict(editor, **{"If-Match": detail["event"]["etag"], "Content-Type": "text/calendar"})
    content = detail["icalendar"].replace("SUMMARY:" + detail["event"]["summary"], "SUMMARY:Final review")
    private_content = content.replace("END:VEVENT", "CLASS:PRIVATE\r\nEND:VEVENT")
    expect(test.api(latest, item, private_content.encode(), "PUT"), 422, "shared_event_must_be_public")
    replaced = expect(test.api(latest, item, content.encode(), "PUT"))
    assert expect(test.api(owner_session, item))["event"]["summary"] == "Final review"
    dav_path = f"/calendars/{owner}/{quote(CALENDAR, safe='')}/{created['uid']}.ics"
    status, headers, raw = DavClient(test, owner).request("GET", dav_path)
    assert status == 200 and headers["ETag"] == replaced["etag"] and b"SUMMARY:Final review" in raw

    private, = expect(test.api(owner_session, event_query(calendar_id, q="description of Budget")))["events"]
    private_item = f"calendar-events/{private['id']}"
    expect(test.api(editor, private_item + "?source=1"), 404)
    private_tag = dict(editor, **{"If-Match": private["etag"]})
    expect(test.api(private_tag, private_item, {"summary": "Hidden edit"}, "PATCH"), 404)
    expect(test.api(private_tag, private_item, method="DELETE"), 404)

    # Hold the edit after its initial authorization, while scanning the
    # replacement body. A downgrade must take effect before the DAV write.
    latest["If-Match"] = replaced["etag"]
    pending_content = content.replace("Final review", REVOKE_DURING_SCAN).encode()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(test.api, latest, item, pending_content, "PUT")
        try:
            assert scan.scanning.wait(timeout=5), "Editor request did not reach scanning"
            expect(change(test, owner_session, calendar_id, viewer, "viewer"))
        finally:
            scan.resume.set()
        expect(pending.result(), 404)
    assert expect(test.api(editor, item))["event"]["summary"] == "Final review"
    expect(test.api(latest, item, method="DELETE"), 404)
    expect(test.api(dict(coeditor, **{"If-Match": replaced["etag"]}), item, method="DELETE"), 204)
    expect(test.api(owner_session, item), 404)
    assert [row["summary"] for row in expect(test.api(editor, query))["events"]] == ["Roadmap"]
    expect(change(test, owner_session, calendar_id, colleague, None))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-calendar-shares-") as scratch, scanner() as scan:
        directory = Path(scratch)
        # Open the previous DAV schema to exercise migration in the real daemon.
        with closing(sqlite3.connect(directory / "caldav.db")) as legacy:
            legacy.execute("""CREATE TABLE dav_calendars (
                id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, description TEXT,
                color TEXT, timezone TEXT, created_at INTEGER, modified_at INTEGER,
                sync_token INTEGER, ctag TEXT
            )""")
            legacy.commit()
        test = Fixture(args.binary.resolve(strict=True), directory, staging=True)
        test.env.update(SMTP_CLAMAV_TRANSPORT=f"tcp:127.0.0.1:{scan.server_address[1]}",
                        SMTP_CLAMAV_FAIL_MODE="closed", SMTP_CLAMAV_TIMEOUT_MS="8000")
        with test.daemon(), closing(sqlite3.connect(directory / "smtp.db")) as db:
            owner, viewer, colleague, foreign = (test.provision(name) for name in ("owner", "viewer", "teammate", "elsewhere"))
            command(test, "team", "create", "studio", "Studio", owner)
            calendar_id = verify(test, db, owner, viewer, colleague, foreign)
            verify_editors(test, scan, owner, viewer, colleague, calendar_id)
            verify_availability(test, owner, viewer)

        with test.daemon():
            invited = test.login(viewer)
            query = event_query(calendar_id)
            assert [item["access"] for item in shares(test, invited)] == ["viewer"]
            assert [row["summary"] for row in expect(test.api(invited, query))["events"]] == ["Roadmap"]
            path = calendar_path(owner, CALENDAR)
            assert dav_busy(DavClient(test, viewer), path)
            deleted = DavClient(test, owner).request("DELETE", path)
            assert deleted[0] == 204, deleted
            assert shares(test, invited) == []
            expect(test.api(invited, query), 404)
            dav_busy(DavClient(test, viewer), path, status=404)

        with test.daemon():
            captain, invited = test.login(owner), test.login(viewer)
            assert create_calendar(test, captain) == calendar_id
            write_event(test, owner, "Replacement")
            assert shares(test, invited) == []
            expect(test.api(invited, event_query(calendar_id)), 404)
            dav_busy(DavClient(test, viewer), calendar_path(owner, CALENDAR), status=404)

    print("Verified calendar share roles, private free/busy over webmail and CalDAV, recurrence, time zones, editor revision races, revocation, restart, and calendar ID reuse.")


if __name__ == "__main__":
    main()
