#!/usr/bin/env python3
"""Verify team calendar grants, private event isolation, and revocation."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from http.client import HTTPSConnection
from pathlib import Path, PurePosixPath
import runpy
import socketserver
import sqlite3
import struct
import tempfile
from threading import Barrier, Event, Thread
from urllib.parse import quote, urlencode
from xml.etree import ElementTree as ET


SCRIPTS = Path(__file__).resolve().parent
teams = runpy.run_path(str(SCRIPTS / "test-webmail-teams.py"))
Fixture, command, expect = (teams[name] for name in ("Fixture", "command", "expect"))
dav_tests = runpy.run_path(str(SCRIPTS / "test-dav-https.py"))
DavClient, configure_vdirsyncer = (dav_tests[name] for name in ("DavClient", "configure_vdirsyncer"))
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


def dav_query(client, path, start, end, *, tls=True, timezone="", expected=207, component="VEVENT", quote_mark='"'):
    bounds = " ".join(f"{field}={quote_mark}{value}{quote_mark}" for field, value in (("start", start), ("end", end)) if value)
    zone = f"<C:timezone><![CDATA[{timezone}]]></C:timezone>" if timezone else ""
    body = (f"<?xml version='1.0'?><C:calendar-query xmlns:C='{CALDAV}' xmlns:D='DAV:'>"
            "<D:prop><D:getetag/><C:calendar-data/></D:prop>"
            "<C:filter><C:comp-filter name='VCALENDAR'>"
            f"<C:comp-filter name='{component}'><C:time-range {bounds}/></C:comp-filter>"
            f"</C:comp-filter></C:filter>{zone}</C:calendar-query>")
    headers = {"Depth": "1", "Content-Type": "application/xml"}
    status, _, data = client.request("REPORT", path, body, headers, tls=tls)
    assert status == expected, (start, end, status, data)
    if expected != 207:
        return data
    responses = ET.fromstring(data).findall("{DAV:}response")
    return {item.findtext("{DAV:}href"): item.findtext(f".//{{{CALDAV}}}calendar-data") for item in responses}


def dav_sync_body(token="", limit=None):
    results = "" if limit is None else f"<D:limit><D:nresults>{limit}</D:nresults></D:limit>"
    return (f'<D:sync-collection xmlns:D="DAV:"><D:sync-token>{token}</D:sync-token>'
            f"<D:sync-level>1</D:sync-level>{results}<D:prop><D:getetag/></D:prop></D:sync-collection>")


def dav_sync(client, path, token="", *, expected=207, limit=None, tls=True):
    status, _, body = client.request("REPORT", path, dav_sync_body(token, limit),
                                     {"Depth": "0", "Content-Type": "application/xml"}, tls=tls)
    assert status == expected, (path, status, body)
    if expected != 207:
        if expected in (403, 507):
            error = "valid-sync-token" if expected == 403 else "number-of-matches-within-limits"
            assert ET.fromstring(body).find(f"{{DAV:}}{error}") is not None
        return body
    document = ET.fromstring(body)
    return document.findtext("{DAV:}sync-token"), {
        row.findtext("{DAV:}href"): (row.findtext(".//{DAV:}getetag"), row.findtext("{DAV:}status"))
        for row in document.findall("{DAV:}response")
    }


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
                "calendarName": quote(CALENDAR, safe=""), "displayName": None, "access": "viewer"}
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

    unsupported = store("unsupported", "DTSTART:20260314T120000Z", "DURATION:PT15M", "RRULE:FREQ=YEARLY;BYWEEKNO=1;BYDAY=MO")
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


def verify_dav_editors(test, scan, owner, viewer, foreign, calendar_id):
    captain, invited = test.login(owner), test.login(viewer)
    owner_dav, guest_dav, other_dav = (DavClient(test, mailbox) for mailbox in (owner, viewer, foreign))
    path = calendar_path(owner, CALENDAR)
    roadmap = path + "/Roadmap.ics"
    draft = path + "/Retrospective.ics"
    hidden = [path + f"/{name}.ics" for name in ("Budget", "Confidential", "Public-series", "Missing")]
    dav_xml = {"d": "DAV:", "c": CALDAV}
    query = (f'<C:calendar-query xmlns:C="{CALDAV}" xmlns:D="DAV:">'
             '<D:prop><D:getetag/><C:calendar-data/></D:prop><C:filter>'
             '<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">'
             '<C:time-range start="20261208T000000Z" end="20261209T000000Z"/>'
             '</C:comp-filter></C:comp-filter></C:filter></C:calendar-query>')
    unrelated = calendar_path(viewer, CALENDAR) + "/Roadmap.ics"
    multiget = (f'<C:calendar-multiget xmlns:C="{CALDAV}" xmlns:D="DAV:"><D:prop><D:getetag/><C:calendar-data/></D:prop>'
                + "".join(f"<D:href>{href}</D:href>" for href in [roadmap, *hidden, unrelated])
                + "</C:calendar-multiget>")
    xml = {"Depth": "1", "Content-Type": "application/xml"}
    ics = {"Content-Type": "text/calendar"}

    def result(res, expected):
        assert res[0] == expected, res
        return res[1], res[2]

    def responses(res):
        _, raw = result(res, 207)
        root = ET.fromstring(raw)
        return {item.findtext("d:href", namespaces=dav_xml): item for item in root.findall("d:response", dav_xml)}

    assert guest_dav.request("GET", roadmap, authenticated=False)[0] == 401
    assert other_dav.request("GET", roadmap)[0] == 404
    assert other_dav.request("OPTIONS", path)[0] == 404
    expect(change(test, captain, calendar_id, viewer, "viewer"))
    for tls in (True, False):
        headers, content = result(guest_dav.request("GET", roadmap, tls=tls), 200)
        assert b"SUMMARY:Roadmap" in content and headers["Cache-Control"] == "private, no-store"
        head, head_body = result(guest_dav.request("HEAD", roadmap, tls=tls), 200)
        assert head["ETag"] == headers["ETag"] and int(head["Content-Length"]) == len(content) and head_body == b""
        result(guest_dav.request("GET", roadmap, headers={"If-None-Match": headers["ETag"]}, tls=tls), 304)
        for href in hidden:
            failure_headers, failure_body = result(guest_dav.request("GET", href, headers={"If-Match": "*"}, tls=tls), 404)
            assert "ETag" not in failure_headers and failure_body == b""
            result(guest_dav.request("PROPFIND", href, tls=tls), 404)
            result(guest_dav.request("OPTIONS", href, tls=tls), 404)
        options, _ = result(guest_dav.request("OPTIONS", path, tls=tls), 200)
        assert "calendar-access" in options["DAV"]

        listing = responses(guest_dav.request("PROPFIND", path, headers=xml, tls=tls))
        assert len(listing) == 2 and roadmap in listing, listing
        collection = next(value for href, value in listing.items() if href != roadmap)
        assert collection.findtext(".//d:sync-token", namespaces=dav_xml).startswith("urn:mail:shared-sync:")
        assert collection.find(".//d:sync-collection", dav_xml) is not None
        assert collection.find(".//d:privilege/d:read", dav_xml) is not None
        assert collection.find(".//d:privilege/d:write-content", dav_xml) is None
        assert listing[roadmap].findtext(".//d:getetag", namespaces=dav_xml) == headers["ETag"]
        assert list(responses(guest_dav.request("PROPFIND", roadmap, tls=tls))) == [roadmap]
        matching = responses(guest_dav.request("REPORT", path, query, xml, tls=tls))
        assert list(matching) == [roadmap]
        assert "SUMMARY:Roadmap" in matching[roadmap].findtext(".//c:calendar-data", namespaces=dav_xml)
        later = query.replace("20261208", "20261224").replace("20261209", "20261225")
        assert not responses(guest_dav.request("REPORT", path, later, xml, tls=tls))
        requested = responses(guest_dav.request("REPORT", path, multiget, xml, tls=tls))
        assert requested[roadmap].findtext(".//d:getetag", namespaces=dav_xml) == headers["ETag"]
        for href in [*hidden, unrelated]:
            assert requested[href].findtext("d:status", namespaces=dav_xml) == "HTTP/1.1 404 Not Found"
            assert requested[href].find(".//c:calendar-data", dav_xml) is None
        result(guest_dav.request("PUT", roadmap, content, ics, tls=tls), 404)
        result(guest_dav.request("PUT", draft, content, ics, tls=tls), 404)
        result(guest_dav.request("DELETE", roadmap, tls=tls), 404)

    expect(change(test, captain, calendar_id, viewer, "editor"))
    _, properties = result(guest_dav.request("PROPFIND", path), 207)
    assert b"<D:write-content/>" in properties and b"<D:write-properties/>" not in properties
    owner_properties = responses(owner_dav.request("PROPFIND", path))
    token = next(iter(owner_properties.values())).findtext(".//d:sync-token", namespaces=dav_xml)
    assert token
    sync = f'<D:sync-collection xmlns:D="DAV:"><D:sync-token>{token}</D:sync-token><D:sync-level>1</D:sync-level></D:sync-collection>'
    result(guest_dav.request("REPORT", path, sync, {"Depth": "0", "Content-Type": "application/xml"}), 403)
    replacement = content.replace(b"UID:Roadmap", b"UID:Retrospective").replace(b"SUMMARY:Roadmap", b"SUMMARY:Retrospective")
    create = {**ics, "If-None-Match": "*"}
    created, _ = result(guest_dav.request("PUT", draft, replacement, create), 201)
    result(guest_dav.request("PUT", draft, replacement, create), 412)
    assert result(owner_dav.request("GET", draft), 200)[0]["ETag"] == created["ETag"]
    original = {**ics, "If-Match": created["ETag"]}
    result(guest_dav.request("PUT", draft, replacement.replace(b"CLASS:PUBLIC", b"CLASS:PRIVATE"), original), 422)
    result(guest_dav.request("PUT", hidden[0], replacement, create), 404)
    result(guest_dav.request("DELETE", hidden[0]), 404)
    result(guest_dav.request("DELETE", path), 404)
    result(guest_dav.request("PROPPATCH", path, "<propertyupdate/>", xml), 404)
    result(guest_dav.request("PROPFIND", f"/calendars/{owner}/"), 404)
    amended = replacement.replace(b"SUMMARY:Retrospective", b"SUMMARY:New retrospective")
    updated, _ = result(guest_dav.request("PUT", draft, amended, original, tls=False), 204)
    assert updated["ETag"] != created["ETag"]
    result(guest_dav.request("DELETE", draft, headers=original), 412)
    assert expect(test.api(invited, event_query(calendar_id, q="New retrospective")))["events"][0]["etag"] == updated["ETag"]

    scan.scanning.clear()
    scan.resume.clear()
    latest = {**ics, "If-Match": updated["ETag"]}
    content_to_scan = amended.replace(b"New retrospective", REVOKE_DURING_SCAN.encode())
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(guest_dav.request, "PUT", draft, content_to_scan, latest)
        try:
            assert scan.scanning.wait(timeout=5), "Delegated CalDAV edit did not reach scanning"
            expect(change(test, captain, calendar_id, viewer, "viewer"))
        finally:
            scan.resume.set()
        result(pending.result(), 404)
    assert result(owner_dav.request("GET", draft), 200)[1] == amended
    result(guest_dav.request("DELETE", draft, headers=latest), 404)
    expect(change(test, captain, calendar_id, viewer, "editor"))
    result(guest_dav.request("DELETE", draft, headers=latest), 204)
    result(owner_dav.request("GET", draft), 404)

    with closing(HTTPSConnection("127.0.0.1", guest_dav.https, context=guest_dav.context, timeout=15)) as client:
        client.request("GET", roadmap, headers=guest_dav.auth)
        with client.getresponse() as reader:
            assert reader.status == 200 and b"Roadmap" in reader.read()
            etag = reader.headers["ETag"]
        connection = client.sock
        assert connection is not None
        write_event(test, owner, "Roadmap", "PRIVATE", expected=204)
        client.request("GET", roadmap, headers={**guest_dav.auth, "If-None-Match": etag})
        assert client.sock is connection
        with client.getresponse() as private:
            assert private.status == 404 and "ETag" not in private.headers and private.read() == b""
        assert not responses(guest_dav.request("REPORT", path, query, xml))
        write_event(test, owner, "Roadmap", "PUBLIC", expected=204)
        expect(change(test, captain, calendar_id, viewer, None))
        client.request("PROPFIND", path, headers={**guest_dav.auth, **xml})
        assert client.sock is connection
        with client.getresponse() as revoked:
            assert revoked.status == 404 and revoked.read() == b""
    expect(change(test, captain, calendar_id, viewer, "viewer"))


def verify_dav_discovery(test, owner, viewer, colleague, foreign, calendar_id, executable):
    captain, teammate, invited = test.login(owner), test.login(colleague), test.login(viewer)
    editor = DavClient(test, colleague)
    owner_dav, guest, outsider = (DavClient(test, user) for user in (owner, viewer, foreign))
    collision_id = expect(test.api(teammate, "calendars", {"name": CALENDAR}), 201)["id"]
    hidden_id = expect(test.api(captain, "calendars", {"name": "Unshared calendar"}), 201)["id"]
    expect(test.api(invited, "calendars", {"name": "Personal discovery fixture"}), 201)
    assert hidden_id != calendar_id
    expect(change(test, teammate, collision_id, viewer, "editor"))
    dav_xml = {"d": "DAV:", "c": CALDAV, "a": "http://apple.com/ns/ical/"}

    def propfind(client, path, depth, *, expected=207, tls=True):
        status, _, body = client.request("PROPFIND", path, headers={"Depth": str(depth)}, tls=tls)
        assert status == expected, (path, status, body)
        return ET.fromstring(body) if expected == 207 else None

    def hrefs(data):
        return {item.findtext("d:href", namespaces=dav_xml): item for item in data.findall("d:response", dav_xml)}

    def calendars(home, *, tls=True):
        return {path: row for path, row in hrefs(propfind(guest, home, 1, tls=tls)).items()
                if row.find(".//d:resourcetype/c:calendar", dav_xml) is not None}

    assert guest.request("PROPFIND", "/", authenticated=False)[0] == 401
    current = propfind(guest, "/", 0).findtext(".//d:current-user-principal/d:href", namespaces=dav_xml)
    principal = propfind(guest, current, 0)
    personal_home, shared_home = [href.text for href in principal.findall(".//c:calendar-home-set/d:href", dav_xml)]
    assert shared_home.startswith("/shared-calendars/") and personal_home.startswith("/calendars/")
    assert list(hrefs(propfind(guest, shared_home, 0))) == [shared_home]
    propfind(outsider, shared_home, 1, expected=404)
    propfind(owner_dav, shared_home, 1, expected=404)
    assert list(calendars(personal_home)) == [personal_home + "Personal%20discovery%20fixture/"]

    listing = calendars(shared_home)
    assert len(listing) == 2
    assert calendars(shared_home, tls=False).keys() == listing.keys()
    assert all(href.startswith(shared_home) for href in listing)
    assert {item.findtext(".//d:displayname", namespaces=dav_xml) for item in listing.values()} == {CALENDAR}
    owned_alias, = [href for href, item in listing.items() if item.find(".//d:write-content", dav_xml) is None]
    editor_alias, = [href for href, item in listing.items() if item.find(".//d:write-content", dav_xml) is not None]

    metadata = (f'<D:propertyupdate xmlns:D="DAV:" xmlns:C="{CALDAV}" xmlns:A="{dav_xml["a"]}">'
                '<D:set><D:prop><D:displayname>Shared %20 &amp; renamed</D:displayname>'
                '<C:calendar-description>Shared planning</C:calendar-description><A:calendar-color>#007AFF</A:calendar-color>'
                '</D:prop></D:set></D:propertyupdate>')
    owned_path = calendar_path(owner, CALENDAR) + "/"
    xml_headers = {"Content-Type": "application/xml"}
    assert guest.request("PROPPATCH", editor_alias, metadata, xml_headers)[0] == 404
    assert guest.request("PROPPATCH", owned_path, metadata, xml_headers)[0] == 404
    status, _, payload = owner_dav.request("PROPPATCH", owned_path, metadata, xml_headers, tls=False)
    assert status == 207 and len(ET.fromstring(payload).findall(".//d:status", dav_xml)) == 3
    for tls in (True, False):
        updated = calendars(shared_home, tls=tls)
        assert updated.keys() == listing.keys()
        assert updated[editor_alias].findtext(".//d:displayname", namespaces=dav_xml) == CALENDAR
        for row in (updated[owned_alias], hrefs(propfind(guest, owned_alias, 0, tls=tls))[owned_alias]):
            assert row.findtext(".//d:displayname", namespaces=dav_xml) == "Shared %20 & renamed"
            assert row.findtext(".//c:calendar-description", namespaces=dav_xml) == "Shared planning"
            assert row.findtext(".//a:calendar-color", namespaces=dav_xml) == "#007AFF"
    grant, = [row for row in shares(test, invited) if row["source"] == owner]
    assert grant["calendarName"] == quote(CALENDAR, safe="") and grant["displayName"] == "Shared %20 & renamed"

    roadmap = owned_alias + "Roadmap.ics"
    hidden = owned_alias + "Budget.ics"
    assert list(hrefs(propfind(guest, owned_alias, 1))) == [owned_alias, roadmap]
    assert guest.request("GET", roadmap)[0] == 200
    assert guest.request("GET", hidden)[0] == 404
    assert guest.request("GET", shared_home + "0" * 32 + "/Roadmap.ics")[0] == 404
    cross_grantee = "/shared-calendars/" + outsider.mailbox + "/" + owned_alias.split("/")[-2] + "/Roadmap.ics"
    assert outsider.request("GET", cross_grantee)[0] == 404
    assert set(dav_query(guest, owned_alias, "20261208T100000Z", "20261208T110000Z")) == {roadmap}
    multiget = (f'<C:calendar-multiget xmlns:C="{CALDAV}" xmlns:D="DAV:"><D:prop><C:calendar-data/></D:prop>'
                f'<D:href>{roadmap}</D:href><D:href>{hidden}</D:href></C:calendar-multiget>')
    result = guest.request("REPORT", owned_alias, multiget, {"Content-Type": "application/xml"})
    assert result[0] == 207, result
    responses = hrefs(ET.fromstring(result[2]))
    assert "SUMMARY:Roadmap" in responses[roadmap].findtext(".//c:calendar-data", namespaces=dav_xml)
    assert responses[hidden].findtext("d:status", namespaces=dav_xml) == "HTTP/1.1 404 Not Found"
    original = guest.request("GET", roadmap)[2]
    draft = original.replace(b"UID:Roadmap", b"UID:Discovery").replace(b"SUMMARY:Roadmap", b"SUMMARY:Discovery")
    headers = {"Content-Type": "text/calendar", "If-None-Match": "*"}
    assert guest.request("PUT", owned_alias + "Discovery.ics", draft, headers)[0] == 404
    result = guest.request("PUT", editor_alias + "Discovery.ics", draft, headers)
    assert result[0] == 201, result
    assert editor.request("GET", calendar_path(colleague, CALENDAR) + "/Discovery.ics")[2] == draft
    assert guest.request("DELETE", editor_alias + "Discovery.ics", headers={"If-Match": result[1]["ETag"]})[0] == 204
    expect(change(test, teammate, collision_id, viewer, None))
    assert editor.request("DELETE", calendar_path(colleague, CALENDAR))[0] == 204
    assert owner_dav.request("DELETE", calendar_path(owner, "Unshared calendar"))[0] == 204
    assert guest.request("DELETE", personal_home + "Personal%20discovery%20fixture/")[0] == 204

    if executable:
        collection = PurePosixPath(owned_alias).name
        run, files = configure_vdirsyncer(test, guest, guest.profile(), {"CalDAV": collection}, executable,
                                        "vdirsyncer-calendar-share", discovery_path=shared_home)
        run("discover")
        run("sync")
        (folder, extension), = files
        file, = folder.glob("*" + extension)
        assert file.read_bytes().splitlines() == original.splitlines()
        expect(change(test, captain, calendar_id, viewer, "editor"))
        new_file = folder / "Discovery.ics"
        new_file.write_bytes(draft)
        run("sync")
        canonical = calendar_path(owner, CALENDAR) + "/Discovery.ics"
        assert owner_dav.request("GET", canonical)[2].splitlines() == draft.splitlines()
        new_file.unlink()
        run("sync")
        assert owner_dav.request("GET", canonical)[0] == 404
        expect(change(test, captain, calendar_id, viewer, "viewer"))
        print("Verified vdirsyncer discovery of a shared home and bidirectional sync over native HTTPS.")

    with closing(HTTPSConnection("127.0.0.1", guest.https, context=guest.context, timeout=15)) as client:
        client.request("GET", roadmap, headers=guest.auth)
        with client.getresponse() as response:
            assert response.status == 200 and response.read() == original
        connection = client.sock
        expect(change(test, captain, calendar_id, viewer, "free_busy"))
        assert not calendars(shared_home)
        assert dav_busy(guest, owned_alias) == dav_busy(guest, calendar_path(owner, CALENDAR))
        client.request("GET", roadmap, headers=guest.auth)
        assert client.sock is connection
        with client.getresponse() as response:
            assert response.status == 404 and not response.read()
        expect(change(test, captain, calendar_id, viewer, None))
        assert not calendars(shared_home)
        dav_busy(guest, owned_alias, status=404)
        expect(change(test, captain, calendar_id, viewer, "viewer"))
        assert list(calendars(shared_home)) == [owned_alias]
        assert guest.request("GET", roadmap)[2] == original
    return owned_alias


def verify_shared_dav_sync(test, owner, viewer, colleague, foreign):
    calendar = "Shared checkpoint fixture"
    captain = test.login(owner)
    calendar_id = expect(test.api(captain, "calendars", {"name": calendar}), 201)["id"]
    owner_dav, guest, editor, outsider = (DavClient(test, account) for account in (owner, viewer, colleague, foreign))
    canonical = calendar_path(owner, calendar)

    def store(uid, label="", classification="PUBLIC", *, expected=201):
        write_resource(test, owner, calendar, uid, [
            "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail shared checkpoint test//EN", "BEGIN:VEVENT",
            f"UID:{uid}", "DTSTAMP:20261122T120000Z", "DTSTART:20261210T120000Z", "DURATION:PT1H",
            f"SUMMARY:{uid} {label}", f"CLASS:{classification}", "END:VEVENT", "END:VCALENDAR", "",
        ], expected)

    def collection(client):
        home = f"/shared-calendars/{client.mailbox}/"
        status, _, payload = client.request("PROPFIND", home, headers={"Depth": "1"})
        assert status == 207, payload
        alias, = [row.findtext("{DAV:}href") for row in ET.fromstring(payload).findall("{DAV:}response")
                  if row.findtext(".//{DAV:}displayname") == calendar]
        return alias

    for role, user in (("viewer", viewer), ("editor", colleague)):
        expect(change(test, captain, calendar_id, user, role))
    alias, editor_alias = collection(guest), collection(editor)
    for uid in ("publish", "edit", "hide", "delete"):
        store(uid, classification="PRIVATE" if uid == "publish" else "PUBLIC")

    token, first = dav_sync(guest, alias)
    assert set(first) == {alias + uid + ".ics" for uid in ("edit", "hide", "delete")}
    props = guest.request("PROPFIND", alias, headers={"Depth": "0"})
    assert props[0] == 207 and ET.fromstring(props[2]).findtext(".//{DAV:}sync-token") == token
    dav_sync(guest, alias, limit=1, expected=507)
    dav_sync(guest, alias, token[:-1], expected=403)
    dav_sync(guest, canonical, token, expected=403)
    dav_sync(editor, editor_alias, token, expected=403)
    dav_sync(outsider, alias, token, expected=404)
    owner_token, _ = dav_sync(owner_dav, canonical)
    dav_sync(guest, alias, owner_token, expected=403)

    store("publish", label="still private", classification="PRIVATE", expected=204)
    store("never-visible", classification="CONFIDENTIAL")
    assert dav_sync(guest, alias, token, tls=False) == (token, {})
    store("publish", expected=204)
    store("edit", label="updated", expected=204)
    store("hide", classification="PRIVATE", expected=204)
    store("create")
    assert owner_dav.request("DELETE", canonical + "/delete.ics")[0] == 204
    next_token, delta = dav_sync(guest, alias, token)
    current = ("publish", "edit", "create")
    assert set(delta) == {alias + uid + ".ics" for uid in (*current, "hide", "delete")}
    assert next_token != token
    for uid in current:
        event_href = alias + uid + ".ics"
        result = guest.request("GET", event_href)
        assert result[0] == 200 and delta[event_href] == (result[1]["ETag"], None)
    for uid in ("hide", "delete"):
        assert delta[alias + uid + ".ics"] == (None, "HTTP/1.1 404 Not Found")
    assert dav_sync(guest, alias, next_token) == (next_token, {})

    content_type = {**guest.auth, "Depth": "0", "Content-Type": "application/xml"}
    with closing(HTTPSConnection("127.0.0.1", guest.https, context=guest.context, timeout=15)) as client:
        client.request("REPORT", alias, dav_sync_body(next_token), content_type)
        with client.getresponse() as response:
            assert response.status == 207 and response.read()
        connection = client.sock
        # Recreate the same grant without making a DAV request in between.
        expect(change(test, captain, calendar_id, viewer, None))
        expect(change(test, captain, calendar_id, viewer, "viewer"))
        client.request("REPORT", alias, dav_sync_body(next_token), content_type)
        assert client.sock is connection
        with client.getresponse() as response:
            assert response.status == 403 and b"valid-sync-token" in response.read()
        expect(change(test, captain, calendar_id, viewer, "free_busy"))
        client.request("REPORT", alias, dav_sync_body(next_token), content_type)
        assert client.sock is connection
        with client.getresponse() as response:
            assert response.status == 404 and not response.read()
        assert dav_busy(guest, alias)
    expect(change(test, captain, calendar_id, viewer, "viewer"))
    checkpoint, full = dav_sync(guest, alias)
    assert set(full) == {alias + uid + ".ics" for uid in current}
    for revision in range(5):
        store("edit", label=f"revision {revision}", expected=204)
        dav_sync(guest, alias)
    dav_sync(guest, alias, checkpoint, expected=403)
    _, full = dav_sync(guest, alias)
    assert set(full) == {alias + uid + ".ics" for uid in current}
    for user in (viewer, colleague):
        expect(change(test, captain, calendar_id, user, None))
    assert owner_dav.request("DELETE", canonical)[0] == 204
    print("Verified shared CalDAV sync deltas, private-event isolation, scoped checkpoints, pruning, and revoke/regrant on a live TLS connection.")


def verify_dav_recurrence_query(test, owner, viewer):
    calendar = "Recurring query cases"
    captain = test.login(owner)
    calendar_id = expect(test.api(captain, "calendars", {"name": calendar}), 201)["id"]
    path = calendar_path(owner, calendar)
    stamp = "DTSTAMP:20261122T120000Z"

    def event(uid, *fields):
        return ("BEGIN:VEVENT", f"UID:{uid}", stamp, f"SUMMARY:{uid}", *fields, "END:VEVENT")

    def store(uid, *components):
        write_resource(test, owner, calendar, uid, [
            "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail recurrence query fixture//EN",
            *components, "END:VCALENDAR", "",
        ])
        return f"{path}/{uid}.ics"

    weekly = store("weekly", *event(
        "weekly", "DTSTART:20261208T100000Z", "DTEND:20261208T110000Z", "RRULE:FREQ=WEEKLY;COUNT=5",
        "EXDATE:20261222T100000Z", "RDATE;VALUE=PERIOD:20270104T103000Z/PT15M",
    ), *event("weekly", "RECURRENCE-ID:20261215T100000Z", "DTSTART:20261216T120000Z"),
        *event("weekly", "RECURRENCE-ID:20261229T100000Z", "STATUS:CANCELLED"))
    zoned = store("zoned", *event(
        "zoned", "DTSTART;TZID=America/New_York:20260307T090000", "DURATION:PT1H", "RRULE:FREQ=DAILY;COUNT=3",
    ))
    all_day = store("all-day", *event("all-day", "DTSTART;VALUE=DATE:20261201", "RRULE:FREQ=DAILY;COUNT=2"))
    floating = store("floating", *event("floating", "DTSTART:20261205T090000"))
    transparent = store("transparent", *event(
        "transparent", "DTSTART:20261210T100000Z", "DURATION:PT30M", "TRANSP:TRANSPARENT",
    ))
    store("cancelled", *event("cancelled", "DTSTART:20261210T100000Z", "DURATION:PT30M", "STATUS:CANCELLED"))
    protected = store("protected", *event(
        "protected", "DTSTART:20261208T100000Z", "DURATION:PT1H", "RRULE:FREQ=WEEKLY;COUNT=2",
    ), *event("protected", "RECURRENCE-ID:20261215T100000Z", "DTSTART:20261216T120000Z", "CLASS:PRIVATE"))
    fixed_timezone = "\r\n".join([
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail test timezone//EN", "BEGIN:VTIMEZONE",
        "TZID:Fixture", "BEGIN:STANDARD", "DTSTART:19700101T000000",
        "TZOFFSETFROM:-0500", "TZOFFSETTO:-0500", "END:STANDARD", "END:VTIMEZONE", "END:VCALENDAR",
    ])
    headers = {"Depth": "1", "Content-Type": "application/xml"}
    owner_dav, guest_dav = DavClient(test, owner), DavClient(test, viewer)
    expect(change(test, captain, calendar_id, viewer, "viewer"))

    def report(client, tls, start, end, **options):
        return dav_query(client, path, start, end, tls=tls, **options)

    for client in (owner_dav, guest_dav):
        for tls in (True, False):
            # The moved instance inherits the master's duration. The original
            # slot, EXDATE, and cancelled override have no matching occurrence.
            moved = report(client, tls, "20261216T125959Z", "20261216T130000Z")
            assert set(moved) == ({weekly, protected} if client is owner_dav else {weekly}), moved
            assert "RECURRENCE-ID:20261215T100000Z" in moved[weekly]
            for night in ("15", "22", "29"):
                assert not report(client, tls, f"202612{night}T100000Z", f"202612{night}T110000Z")
            assert not report(client, tls, "20261216T130000Z", "20261216T140000Z")
            assert not report(client, tls, "20261216T110000Z", "20261216T120000Z")
            assert set(report(client, tls, "20270104T104459Z", "20270104T104500Z")) == {weekly}
            assert not report(client, tls, "20270104T104500Z", "20270104T110000Z")
            assert set(report(client, tls, "20270105T100000Z", "20270105T100100Z", quote_mark="'")) == {weekly}
            assert set(report(client, tls, "20260309T130000Z", "20260309T130100Z")) == {zoned}
            assert not report(client, tls, "20260309T140000Z", "20260309T140100Z")
            assert set(report(client, tls, "20261202T235959Z", "20261203T000000Z")) == {all_day}
            assert not report(client, tls, "20261203T000000Z", "20261203T000100Z")
            assert set(report(client, tls, "20261203T000000Z", "20261203T000100Z", timezone=fixed_timezone)) == {all_day}
            assert set(report(client, tls, "20261205T090000Z", "20261205T090001Z")) == {floating}
            assert not report(client, tls, "20261205T085959Z", "20261205T090000Z")
            assert set(report(client, tls, "20261205T140000Z", "20261205T140001Z", timezone=fixed_timezone)) == {floating}
            assert set(report(client, tls, "20261210T100000Z", "20261210T103000Z")) == {transparent}
            assert set(report(client, tls, "20270104T103000Z", None)) == {weekly}
            assert set(report(client, tls, None, "20260307T140001Z")) == {zoned}
            report(client, tls, "20260230T000000Z", "20260301T000000Z", expected=400)
            report(client, tls, "20261203T000000Z", "20261203T000000Z", expected=400)
            invalid = report(client, tls, "20261201T000000Z", "20261202T000000Z", component="VTODO", expected=403)
            assert ET.fromstring(invalid).find(f"{{{CALDAV}}}supported-filter") is not None
    hourly = store("hourly", *event(
        "hourly", "DTSTART:20261225T090000Z", "DURATION:PT5M", "RRULE:FREQ=HOURLY;COUNT=3",
    ))
    assert set(report(owner_dav, True, "20261225T100000Z", "20261225T100500Z")) == {hourly}
    assert dav_busy(guest_dav, path, "20261225T100000Z", "20261225T100500Z") == [
        "BUSY:20261225T100000Z/20261225T100500Z",
    ]
    assert guest_dav.request("PROPFIND", path, headers=headers)[0] == 207
    assert owner_dav.request("DELETE", hourly)[0] == 204
    store("dense-history", *event(
        "dense-history", "DTSTART:10000101T000000Z", "DURATION:PT5M", "RRULE:FREQ=DAILY",
    ))
    limited = report(guest_dav, True, "20261225T000000Z", "20261225T000500Z", expected=507)
    assert ET.fromstring(limited).find("{DAV:}number-of-matches-within-limits") is not None
    expect(change(test, captain, calendar_id, viewer, None))
    assert owner_dav.request("DELETE", path)[0] == 204


def verify_dav_advanced_recurrence(test, owner, viewer):
    calendar = "Advanced recurrence"
    captain, invited = test.login(owner), test.login(viewer)
    calendar_id = expect(test.api(captain, "calendars", {"name": calendar}), 201)["id"]
    path = calendar_path(owner, calendar)
    owner_dav, guest = DavClient(test, owner), DavClient(test, viewer)

    def store(uid, *events):
        lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail advanced recurrence fixture//EN"]
        for fields in events:
            lines.extend(("BEGIN:VEVENT", f"UID:{uid}", "DTSTAMP:20261122T120000Z", f"SUMMARY:{uid}", *fields, "END:VEVENT"))
        write_resource(test, owner, calendar, uid, [*lines, "END:VCALENDAR", ""])
        return f"{path}/{uid}.ics"

    hourly = store("zoned-hourly",
                   ("DTSTART;TZID=America/New_York:20260308T013000", "DURATION:PT5M", "RRULE:FREQ=HOURLY;COUNT=4",
                    "EXDATE;TZID=America/New_York:20260308T043000"),
                   ("RECURRENCE-ID;TZID=America/New_York:20260308T053000", "DTSTART;TZID=America/New_York:20260308T061500"))
    minutely = store("minutely", ("DTSTART:20261221T090035Z", "DURATION:PT5S",
                                  "RRULE:FREQ=MINUTELY;INTERVAL=15;BYSECOND=5,35;BYSETPOS=-1;UNTIL=20261221T091535Z"))
    secondly = store("secondly", ("DTSTART:20261222T090000Z", "DURATION:PT2S", "RRULE:FREQ=SECONDLY;INTERVAL=10;COUNT=3"))
    selected = store("selected-hourly", ("DTSTART:20261223T093000Z", "DURATION:PT5M",
                                        "RRULE:FREQ=HOURLY;BYHOUR=9,11;BYMINUTE=30,45;COUNT=4"))
    ranged = store("ranged",
                   ("DTSTART;TZID=America/New_York:20260305T090000", "DURATION:PT30M", "RRULE:FREQ=DAILY;COUNT=10",
                    "RDATE;VALUE=PERIOD;TZID=America/New_York:20260311T180000/PT15M"),
                   ("RECURRENCE-ID;RANGE=THISANDFUTURE:20260307T140000Z",
                    "DTSTART;TZID=America/New_York:20260306T170000", "DURATION:PT90M", "STATUS:TENTATIVE"),
                   ("RECURRENCE-ID;TZID=America/New_York:20260310T090000",
                    "DTSTART;TZID=America/New_York:20260310T110000", "DURATION:PT50M"),
                   ("RECURRENCE-ID;TZID=America/New_York:20260311T090000", "STATUS:CANCELLED"),
                   ("RECURRENCE-ID;TZID=America/New_York;RANGE=THISANDFUTURE:20260312T090000", "STATUS:CANCELLED"))
    protected = store("protected-range",
                      ("DTSTART:20261224T090000Z", "DURATION:PT15M", "RRULE:FREQ=DAILY;COUNT=4"),
                      ("RECURRENCE-ID;RANGE=THISANDFUTURE:20261225T090000Z", "DTSTART:20261225T100000Z", "CLASS:PRIVATE"))

    windows = [
        ("20260308T062900Z", "20260308T110000Z", hourly,
         ["BUSY:20260308T063000Z/20260308T063500Z", "BUSY:20260308T073000Z/20260308T073500Z",
          "BUSY:20260308T101500Z/20260308T102000Z"]),
        ("20261221T090035Z", "20261221T093600Z", minutely,
         ["BUSY:20261221T090035Z/20261221T090040Z", "BUSY:20261221T091535Z/20261221T091540Z"]),
        ("20261222T090002Z", "20261222T090020Z", secondly, ["BUSY:20261222T090010Z/20261222T090012Z"]),
        ("20261223T094000Z", "20261223T120000Z", selected,
         ["BUSY:20261223T094500Z/20261223T095000Z", "BUSY:20261223T113000Z/20261223T113500Z",
          "BUSY:20261223T114500Z/20261223T115000Z"]),
        ("20260305T135900Z", "20260305T150000Z", ranged, ["BUSY:20260305T140000Z/20260305T143000Z"]),
        ("20260306T215900Z", "20260307T000000Z", ranged, ["BUSY-TENTATIVE:20260306T220000Z/20260306T233000Z"]),
        ("20260307T215900Z", "20260308T000000Z", ranged, ["BUSY-TENTATIVE:20260307T220000Z/20260307T233000Z"]),
        ("20260308T205900Z", "20260308T230000Z", ranged, ["BUSY-TENTATIVE:20260308T210000Z/20260308T223000Z"]),
        ("20260310T140000Z", "20260310T160000Z", ranged, ["BUSY:20260310T150000Z/20260310T155000Z"]),
        ("20260311T055900Z", "20260311T080000Z", ranged, ["BUSY-TENTATIVE:20260311T060000Z/20260311T073000Z"]),
    ]
    empty_windows = [
        ("20260308T083000Z", "20260308T083500Z"),
        ("20260308T093000Z", "20260308T093500Z"),
        ("20261221T091540Z", "20261221T093600Z"),
        ("20261222T090022Z", "20261222T090100Z"),
        ("20260309T130000Z", "20260309T133000Z"),
        ("20260309T205900Z", "20260309T230000Z"),
        ("20260311T130000Z", "20260311T133000Z"),
        ("20260311T205900Z", "20260314T230000Z"),
    ]
    expect(change(test, captain, calendar_id, viewer, "viewer"))
    for tls in (True, False):
        for begin, end, href, busy in windows:
            assert set(dav_query(owner_dav, path, begin, end, tls=tls)) == {href}
            assert set(dav_query(guest, path, begin, end, tls=tls)) == {href}
            assert dav_busy(guest, path, begin, end, tls=tls) == busy
        for begin, end in empty_windows:
            assert not dav_query(guest, path, begin, end, tls=tls)
            assert not dav_busy(guest, path, begin, end, tls=tls)

    historic = store("long-running-seconds",
                     ("DTSTART:20200101T221002Z", "DURATION:PT3S", "RRULE:FREQ=SECONDLY;INTERVAL=10"),
                     ("RECURRENCE-ID;RANGE=THISANDFUTURE:20261220T115952Z", "DTSTART:20261220T120007Z"))
    assert set(dav_query(guest, path, "20261220T120008Z", "20261220T120018Z")) == {historic}
    assert dav_busy(guest, path, "20261220T120008Z", "20261220T120018Z") == [
        "BUSY:20261220T120008Z/20261220T120010Z", "BUSY:20261220T120017Z/20261220T120018Z",
    ]
    assert owner_dav.request("DELETE", historic)[0] == 204

    begin, end = "20261226T100000Z", "20261226T101500Z"
    assert set(dav_query(owner_dav, path, begin, end)) == {protected}
    for role in ("viewer", "editor", "free_busy"):
        expect(change(test, captain, calendar_id, viewer, role))
        report = dav_query(guest, path, begin, end, expected=404 if role == "free_busy" else 207)
        assert not report
        assert guest.request("GET", protected)[0] == 404
        assert dav_busy(guest, path, begin, end) == ["BUSY:20261226T100000Z/20261226T101500Z"]
        query = busy_query(calendar_id, timestamp(begin), timestamp(end))
        assert expect(test.api(invited, query)) == {"busy": [busy_period(begin, end)]}
    expect(change(test, captain, calendar_id, viewer, None))
    assert owner_dav.request("DELETE", path)[0] == 204


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--vdirsyncer", type=Path)
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
        test.env.update(SMTP_HOSTNAME="127.0.0.1", CALDAV_PUBLIC_SSL_PORT=test.env["CALDAV_SSL_PORT"])
        test.env["CALDAV_MAX_SYNC_HISTORY"] = "4"
        test.env.update(SMTP_CLAMAV_TRANSPORT=f"tcp:127.0.0.1:{scan.server_address[1]}",
                        SMTP_CLAMAV_FAIL_MODE="closed", SMTP_CLAMAV_TIMEOUT_MS="8000")
        with test.daemon(), closing(sqlite3.connect(directory / "smtp.db")) as db:
            owner, viewer, colleague, foreign = (test.provision(name) for name in ("owner", "viewer", "teammate", "elsewhere"))
            command(test, "team", "create", "studio", "Studio", owner)
            calendar_id = verify(test, db, owner, viewer, colleague, foreign)
            verify_editors(test, scan, owner, viewer, colleague, calendar_id)
            verify_dav_editors(test, scan, owner, viewer, foreign, calendar_id)
            alias = verify_dav_discovery(test, owner, viewer, colleague, foreign, calendar_id,
                                         args.vdirsyncer.resolve(strict=True) if args.vdirsyncer else None)
            verify_shared_dav_sync(test, owner, viewer, colleague, foreign)
            verify_dav_recurrence_query(test, owner, viewer)
            verify_dav_advanced_recurrence(test, owner, viewer)
            verify_availability(test, owner, viewer)
            old_token, _ = dav_sync(DavClient(test, viewer), alias)

        # Reopen with the grant table shape that predates shared sync epochs.
        with closing(sqlite3.connect(directory / "smtp.db")) as legacy:
            legacy.executescript("""
                DROP TRIGGER mail_calendar_grant_epoch_insert;
                DROP TRIGGER mail_calendar_grant_epoch_update;
                DROP TABLE mail_team_calendar_share_epochs;
            """)

        with test.daemon():
            invited = test.login(viewer)
            query = event_query(calendar_id)
            assert [item["access"] for item in shares(test, invited)] == ["viewer"]
            assert [row["summary"] for row in expect(test.api(invited, query))["events"]] == ["Roadmap"]
            path = calendar_path(owner, CALENDAR)
            guest = DavClient(test, viewer)
            status, _, body = guest.request("PROPFIND", alias, headers={"Depth": "0"})
            assert status == 207 and ET.fromstring(body).findtext(".//{DAV:}displayname") == "Shared %20 & renamed"
            assert dav_busy(guest, path)
            assert guest.request("GET", path + "/Roadmap.ics")[0] == 200
            assert guest.request("GET", alias + "Roadmap.ics")[0] == 200
            dav_sync(guest, alias, old_token, expected=403)
            _, recovered = dav_sync(guest, alias)
            assert list(recovered) == [alias + "Roadmap.ics"]
            assert guest.request("GET", path + "/Budget.ics")[0] == 404
            deleted = DavClient(test, owner).request("DELETE", path)
            assert deleted[0] == 204, deleted
            assert shares(test, invited) == []
            expect(test.api(invited, query), 404)
            dav_busy(DavClient(test, viewer), path, status=404)
            assert guest.request("PROPFIND", alias)[0] == 404

        with test.daemon():
            captain, invited = test.login(owner), test.login(viewer)
            assert create_calendar(test, captain) == calendar_id
            write_event(test, owner, "Replacement")
            assert shares(test, invited) == []
            expect(test.api(invited, event_query(calendar_id)), 404)
            dav_busy(DavClient(test, viewer), calendar_path(owner, CALENDAR), status=404)
            assert DavClient(test, viewer).request("GET", calendar_path(owner, CALENDAR) + "/Replacement.ics")[0] == 404
            assert DavClient(test, viewer).request("GET", alias + "Replacement.ics")[0] == 404

    print("Verified calendar sharing in webmail and CalDAV, including sub-daily rules, range overrides, public event reads and writes, private free/busy, revision races, revocation, restart, and calendar ID reuse.")


if __name__ == "__main__":
    main()
