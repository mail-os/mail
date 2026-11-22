#!/usr/bin/env python3
"""Verify shared CalDAV and CardDAV resource operations over HTTP and TLS."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import plistlib
import re
import runpy
import socket
import sqlite3
import subprocess
import tempfile
from threading import Barrier
import time
from types import SimpleNamespace
import urllib.parse
import xml.etree.ElementTree as ET


SCRIPTS = Path(__file__).resolve().parent
hosted = SimpleNamespace(**runpy.run_path(str(SCRIPTS / "test-hosted-limits.py")))
clamav = SimpleNamespace(**runpy.run_path(str(SCRIPTS / "test-smtp-clamav.py")))
COLLECTIONS = {"CalDAV": "staging-events", "CardDAV": "staging-contacts"}
DAV = {"d": "DAV:"}


class DavClient:
    def __init__(self, fixture, mailbox):
        self.context = fixture.tls_context
        self.https = int(fixture.env["CALDAV_SSL_PORT"])
        self.http = int(fixture.env["CALDAV_PORT"])
        self.mailbox = mailbox
        self.password = fixture.password
        token = base64.b64encode(f"{mailbox}:{self.password}".encode()).decode()
        self.auth = {"Authorization": "Basic " + token}

    def request(self, method, path, body=None, headers=None, *, tls=True, authenticated=True):
        fields = self.auth.copy() if authenticated else {}
        fields.update(headers or {})
        if tls:
            conn = http.client.HTTPSConnection("127.0.0.1", self.https, context=self.context, timeout=15)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", self.http, timeout=15)
        try:
            conn.request(method, path, body=body, headers=fields)
            response = conn.getresponse()
            return response.status, response.headers, response.read()
        finally:
            conn.close()

    def raw(self, path, pieces, *, length, tls=True, content_type="text/calendar"):
        port = self.https if tls else self.http
        fields = (f"PUT {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                  f"Authorization: {self.auth['Authorization']}\r\nContent-Type: {content_type}\r\n"
                  f"Connection: close\r\nContent-Length: {length}\r\n\r\n").encode()
        with socket.create_connection(("127.0.0.1", port), timeout=15) as connection:
            stream = self.context.wrap_socket(connection, server_hostname="127.0.0.1") if tls else connection
            with stream:
                for fragment in (fields[:23], fields[23:-2], fields[-2:], *pieces):
                    stream.sendall(fragment)
                    time.sleep(0.01)
                response = http.client.HTTPResponse(stream)
                response.begin()
                return response.status, response.headers, response.read()

    def profile(self):
        path = "/email.mobileconfig?" + urllib.parse.urlencode({"email": self.mailbox, "services": "dav"})
        status, _, raw = self.request("GET", path, authenticated=False)
        assert status == 200, status
        profiles = plistlib.loads(raw)["PayloadContent"]
        result = {}
        for prefix in COLLECTIONS:
            profile = next(doc for doc in profiles if prefix + "HostName" in doc)
            endpoint = tuple(profile[prefix + field] for field in ("HostName", "Port", "Username", "UseSSL"))
            assert endpoint == ("127.0.0.1", self.https, self.mailbox, True), (prefix, endpoint)
            principal = profile[prefix + "PrincipalURL"]
            assert principal == "/principals/" + self.mailbox, principal
            must(self.request("PROPFIND", principal, headers={"depth": "0"}), 207)
            result[prefix] = profile
        return result


def resources(mailbox):
    user = urllib.parse.quote(mailbox, safe="@")
    lines = b"\r\n ".join([b"x" * 68] * 480)
    event = (b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail Fixture//EN\r\nBEGIN:VEVENT\r\n"
             b"UID:dav-event\r\nDTSTAMP:20261121T100000Z\r\nDTSTART:20261121T120000Z\r\n"
             b"DTEND:20261121T130000Z\r\nSUMMARY:Fixture record\r\nDESCRIPTION:" + lines +
             b"\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    contact = (b"BEGIN:VCARD\r\nVERSION:3.0\r\nUID:dav-contact\r\nFN:Fixture record\r\n"
               b"N:Record;Fixture;;;\r\nEMAIL:fixture@example.test\r\nEND:VCARD\r\n")
    yield f"/calendars/{user}/{COLLECTIONS['CalDAV']}/event.ics", "text/calendar", event
    yield f"/addressbooks/{user}/{COLLECTIONS['CardDAV']}/contact.vcf", "text/vcard", contact


def must(response, code):
    assert response[0] == code, response
    return response[1], response[2]


def check_resources(test, owner, other):
    client, foreign = DavClient(test, owner), DavClient(test, other)
    for tls in (True, False):
        headers, _ = must(client.request("OPTIONS", "/", tls=tls), 200)
        assert {"GET", "HEAD", "PUT", "DELETE", "PROPFIND", "REPORT"} <= set(headers["Allow"].split(", "))
        assert "LOCK" not in headers["Allow"].split(", ") and "2" not in headers["DAV"].split(", ")

    expected = []
    for path, media, body in resources(owner):
        names = {"Content-Type": media}
        must(client.request("GET", path, authenticated=False), 401)
        must(foreign.request("PUT", path, body, names), 404)
        must(client.request("PUT", path, body, {**names, "If-Match": "*"}), 412)
        must(client.request("GET", path), 404)

        chunks = tuple(body[offset:offset + 4000] for offset in range(0, len(body), 4000))
        headers, _ = must(client.raw(path, chunks, length=len(body), content_type=media), 201)
        etag = headers["ETag"]
        headers, data = must(client.request("GET", path, tls=False), 200)
        assert data == body and headers["ETag"] == etag
        headers, data = must(client.request("HEAD", path), 200)
        assert not data and int(headers["Content-Length"]) == len(body) and headers["ETag"] == etag
        headers, data = must(client.request("GET", path, headers={"If-None-Match": "W/" + etag}), 304)
        assert not data and "Content-Length" not in headers
        must(client.request("PUT", path, body, {**names, "If-None-Match": "*"}), 412)
        must(foreign.request("GET", path, tls=False), 404)
        must(foreign.request("DELETE", path), 404)

        barrier = Barrier(2)
        proposals = [body.replace(b"Fixture record", f"Proposed version {i}".encode(), 1) for i in range(2)]

        def write(i):
            barrier.wait(timeout=5)
            return client.request("PUT", path, proposals[i], {**names, "if-match": '"old", ' + etag}, tls=i == 0)

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(write, range(2)))
        assert sorted(result[0] for result in results) == [204, 412], results
        index = next(i for i, result in enumerate(results) if result[0] == 204)
        new_etag = results[index][1]["ETag"]
        assert new_etag and new_etag != etag
        must(client.request("DELETE", path, headers={"If-Match": etag}), 412)
        expected.append((path, proposals[index], new_etag))

    for tls in (True, False):
        must(client.raw(expected[0][0], (), length=10 * 1024 * 1024 + 1, tls=tls), 413)
    return expected


def check_scanning(client, expected):
    for path, saved, etag in expected:
        is_event = path.endswith(".ics")
        marker = b"END:VEVENT" if is_event else b"END:VCARD"
        field = b"ATTACH;ENCODING=BASE64;VALUE=BINARY:" if is_event else b"PHOTO;ENCODING=b:"
        bad = saved.replace(marker, field + base64.b64encode(clamav.EICAR) + b"\r\n" + marker)
        media = "text/calendar" if is_event else "text/vcard"
        must(client.request("PUT", path, bad, {"Content-Type": media, "If-Match": etag}), 422)
        headers, body = must(client.request("GET", path), 200)
        assert body == saved and etag == headers["ETag"]


def check_calendar_download(test, owner, other):
    owner_session = test.login(owner)
    status, result = test.api(owner_session, "calendars")
    assert status == 200, result
    calendar, = result["calendars"]
    path = test.webmail + "/webmail/api/calendar-export?calendarId=" + str(calendar["id"])
    status, headers, data = hosted.request(path, headers=owner_session, context=test.tls_context)
    assert status == 200 and headers.get_content_type() == "text/calendar"
    assert b"BEGIN:VCALENDAR\r\n" in data and b"UID:dav-event\r\n" in data
    assert hosted.request(path, headers=test.login(other), context=test.tls_context)[0] == 404


def check_calendar_import(test, owner, other):
    organizer = test.provision("calendar-importer")
    session = test.login(organizer)
    label = "Europe schedule & planning"
    payload = "\r\n".join([
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail//Test//EN", "METHOD:PUBLISH",
        "BEGIN:VTIMEZONE", "TZID:Europe/Vienna", "BEGIN:DAYLIGHT", "DTSTART:19810329T020000",
        "RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU", "TZOFFSETFROM:+0100", "TZOFFSETTO:+0200",
        "END:DAYLIGHT", "BEGIN:STANDARD", "DTSTART:19961027T030000",
        "RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU", "TZOFFSETFROM:+0200", "TZOFFSETTO:+0100",
        "END:STANDARD", "END:VTIMEZONE", "BEGIN:VEVENT", "UID:vienna",
        "RECURRENCE-ID;TZID=Europe/Vienna:20261101T110000", "DTSTART;TZID=Europe/Vienna:20261101T120000",
        "SUMMARY:Exception", "END:VEVENT", "BEGIN:VEVENT", "UID:vienna", "DTSTAMP:20261101T100000Z",
        "DTSTART;TZID=Europe/Vienna:20260701T110000", "DTEND;TZID=Europe/Vienna:20260701T120000",
        "SUMMARY:Vienna\\, meeting", "RRULE:FREQ=MONTHLY", "X-FIXTURE:keep-me", "END:VEVENT",
        "BEGIN:VEVENT", "UID:invalid", "DTSTART:20260230T103000Z", "SUMMARY:Invalid date", "END:VEVENT",
        "BEGIN:VEVENT", "UID:all-day", "DTSTART;VALUE=DATE:20260702", "DURATION:PT86400S", "SUMMARY:All day", "END:VEVENT",
        "BEGIN:VEVENT", "UID:scanner-refusal", "DTSTART:20260702T120000Z", "SUMMARY:Scanner refusal",
        "ATTACH;ENCODING=BASE64;VALUE=BINARY:" + base64.b64encode(clamav.EICAR).decode(),
        "END:VEVENT", "END:VCALENDAR", "",
    ]).encode()

    def submit(mode, *, target=None, headers=session, data=payload):
        destination = {"calendarName": label} if target is None else {"calendarId": target}
        url = test.webmail + "/webmail/api/calendar-import?" + urllib.parse.urlencode({"mode": mode, **destination})
        status, _, body = hosted.request(url, data, {**headers, "Content-Type": "text/calendar"}, context=test.tls_context)
        return status, json.loads(body)

    def states(result):
        return {event["summary"]: event["status"] for event in result["events"]}

    assert submit("preview", headers={"Origin": test.webmail})[0] == 401
    assert submit("import", headers={**session, "Origin": "https://different.example.test"})[0] == 403
    assert submit("preview", data=b"malformed data")[0] == 422
    status, preview = submit("preview")
    assert status == 200 and preview["calendarId"] is None, preview
    assert states(preview) == {"Vienna, meeting": "ready", "Invalid date": "error", "All day": "ready", "Scanner refusal": "error"}, preview
    assert preview["events"][0]["start"] == int(datetime(2026, 7, 1, 9, tzinfo=timezone.utc).timestamp()), preview
    assert "malware scanner" in preview["events"][-1]["message"]
    assert test.api(session, "calendars")[1]["calendars"] == []

    barrier = Barrier(2)

    def import_once():
        barrier.wait(timeout=5)
        return submit("import")

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: import_once(), range(2)))
    assert all(status == 200 for status, _ in results), results
    assert sorted(states(result)["Vienna, meeting"] for _, result in results) == ["imported", "skipped"], results
    assert sorted(states(result)["All day"] for _, result in results) == ["imported", "skipped"], results
    calendar_id = results[0][1]["calendarId"]
    assert calendar_id == results[1][1]["calendarId"]
    assert submit("import", target=calendar_id, headers=test.login(other))[0] == 404

    client = DavClient(test, organizer)
    collection = "/calendars/" + organizer + "/" + urllib.parse.quote(label, safe="") + "/"
    _, members = sync_report(client, collection)
    assert len(members) == 2, members
    exported_path = test.webmail + "/webmail/api/calendar-export?calendarId=" + str(calendar_id)
    status, _, exported = hosted.request(exported_path, headers=session, context=test.tls_context)
    assert status == 200 and b"X-FIXTURE:keep-me" in exported and exported.count(b"UID:vienna\r\n") == 2
    assert b"METHOD:PUBLISH" not in exported and b"UID:scanner-refusal" not in exported

    separate = (b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:another-event\r\n"
                b"DTSTART:20260703T120000Z\r\nSUMMARY:Existing destination\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    status, added = submit("import", target=calendar_id, data=separate)
    assert status == 200 and states(added) == {"Existing destination": "imported"}, added
    assert len(sync_report(client, collection)[1]) == 3

    owned_id = test.api(test.login(owner), "calendars")[1]["calendars"][0]["id"]
    legacy = next(resources(owner))[2]
    result = submit("import", target=owned_id, headers=test.login(owner), data=legacy)
    assert result[0] == 200 and states(result[1]) == {"Fixture record": "skipped"}, result
    return organizer, calendar_id, submit


def check_calendar_writes(test, other):
    owner = test.provision("calendar-editor")
    session, other_session = test.login(owner), test.login(other)
    client = DavClient(test, owner)

    def api(path, method="GET", body=None, *, headers=session, tag=None):
        fields = {**headers, **({"If-Match": tag} if tag else {})}
        status, incoming, data = hosted.request(test.webmail + "/webmail/api/" + path, body, fields, method,
                                                context=test.tls_context)
        return status, incoming, json.loads(data) if data else None

    body = {"name": "Working calendar"}
    assert api("calendars", "POST", body, headers={"Origin": test.webmail})[0] == 401
    _, calendar = must(api("calendars", "POST", body), 201)
    assert api("calendars", "POST", body)[0] == 409
    calendar_id = calendar["id"]
    collection = f"/calendars/{owner}/Working%20calendar/"
    zone_path = "calendar-timezone?zone=America%2FNew_York"
    assert api(zone_path, headers={})[0] == 401
    assert api("calendar-timezone?zone=Unknown%2FPlace")[0] == 404
    assert api("calendar-timezone?zone=UTC%0D%0ATZID%3AInjected")[0] == 400
    _, zone = must(api(zone_path), 200)
    definition = zone["icalendar"]
    assert definition.startswith("BEGIN:VTIMEZONE\r\nTZID:America/New_York\r\n")
    recurring = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n" + definition
                 + "BEGIN:VEVENT\r\nUID:web-series-fixture\r\nSUMMARY:Created recurring series\r\n"
                 + "DTSTART;TZID=America/New_York:20260301T091500\r\n"
                 + "DTEND;TZID=America/New_York:20260301T100000\r\n"
                 + "RRULE:FREQ=WEEKLY;COUNT=3\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n").encode()
    create_path = f"calendar-events?calendarId={calendar_id}"
    media = {"Content-Type": "text/calendar"}
    assert api(create_path, "POST", recurring, headers={**other_session, **media})[0] == 404
    series_headers, created_series = must(api(create_path, "POST", recurring, headers={**session, **media}), 201)
    assert api(create_path, "POST", recurring, headers={**session, **media})[0] == 409
    stored_headers, stored_series = must(client.request("GET", collection + created_series["uid"] + ".ics"), 200)
    assert stored_headers["ETag"] == series_headers["ETag"] and stored_series == recurring
    _, details = must(api(f"calendar-events/{created_series['id']}"), 200)
    assert details["event"]["start"] == int(datetime(2026, 3, 1, 14, 15, tzinfo=timezone.utc).timestamp())
    must(api(f"calendar-events/{created_series['id']}", "DELETE", tag=stored_headers["ETag"]), 204)

    _, second_calendar = must(api("calendars", "POST", {"name": "Outside projects"}), 201)
    color_path = f"calendars/{calendar_id}"
    assert api(color_path, "PATCH", {"color": "red;display:none"})[0] == 400
    assert api(color_path, "PATCH", {"color": "#12785B"}, headers=other_session)[0] == 404
    assert api(color_path, "PATCH", {"color": "#12785B"}, headers={**session, "Origin": "https://other.example.test"})[0] == 403
    must(api(color_path, "PATCH", {"color": "#12785B"}), 204)
    colors = {row["id"]: row["color"] for row in must(api("calendars"), 200)[1]["calendars"]}
    assert colors == {calendar_id: "#12785B", second_calendar["id"]: None}

    hello = {"calendarId": calendar_id, "summary": "Created in webmail", "description": "Notes, details\nMore",
             "time": {"start": 1795262400, "end": 1795266000}}
    assert api("calendar-events", "POST", hello, headers=other_session)[0] == 404
    assert api("calendar-events", "POST", {**hello, "time": {"start": 100, "allDay": True}})[0] == 400
    created_headers, event = must(api("calendar-events", "POST", hello), 201)
    _, elsewhere = must(api("calendar-events", "POST", {
        **hello, "calendarId": second_calendar["id"], "summary": "Later planning session",
        "location": "Details Room", "description": None, "time": {"start": 1890000000},
    }), 201)
    matches = must(api("calendar-events?q=DETAILS"), 200)[1]["events"]
    assert [(row["id"], row["calendar_id"]) for row in matches] == [
        (event["id"], calendar_id), (elsewhere["id"], second_calendar["id"]),
    ]
    own = must(api(f"calendar-events?q=DETAILS&calendarId={calendar_id}"), 200)[1]["events"]
    assert [row["id"] for row in own] == [event["id"]]
    assert not must(api("calendar-events?q=DETAILS", headers=other_session), 200)[1]["events"]
    assert api(f"calendar-events?q=DETAILS&calendarId={calendar_id}", headers=other_session)[0] == 404
    assert api("calendar-events?q=" + "x" * 257)[0] == 400
    item = f"calendar-events/{event['id']}"
    resource = collection + event["uid"] + ".ics"
    dav_headers, saved = must(client.request("GET", resource), 200)
    assert created_headers["ETag"] == dav_headers["ETag"] == event["etag"]
    assert b"SUMMARY:Created in webmail\r\n" in saved and b"DESCRIPTION:Notes\\, details\\nMore\r\n" in saved
    assert api(item, headers=other_session)[0] == 404
    assert api(item, "PATCH", {"summary": "Foreign edit"}, headers=other_session, tag=event["etag"])[0] == 404
    assert api(item, "DELETE", headers=other_session, tag=event["etag"])[0] == 404
    assert api(item, "PATCH", {"summary": "Missing revision"})[0] == 428
    assert api(item, "PATCH", {"summary": "Wildcard"}, tag="*")[0] == 400
    assert api(item, "DELETE", tag="W/" + event["etag"])[0] == 400
    assert api(item, "PATCH", {"summary": "Foreign site"}, headers={**session, "Origin": "https://other.example.test"}, tag=event["etag"])[0] == 403

    raw = (b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail Test//EN\r\n"
           b"BEGIN:VTIMEZONE\r\nTZID:Europe/Vienna\r\nBEGIN:STANDARD\r\nDTSTART:19700101T000000\r\n"
           b"TZOFFSETFROM:+0100\r\nTZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n"
           b"BEGIN:VEVENT\r\nUID:" + event["uid"].encode() + b"\r\n"
           b"DTSTAMP:20261121T090000Z\r\nDTSTART;TZID=Europe/Vienna:20261121T120000\r\n"
           b"DTEND;TZID=Europe/Vienna:20261121T130000\r\nSUMMARY:Edited over DAV\r\nDESCRIPTION:Old notes\r\n"
           b"LOCATION:Studio\r\nX-APPLE-TRAVEL-DURATION;VALUE=DURATION:PT20M\r\n"
           b"ATTENDEE;CN=Guest:mailto:other@example.test\r\nBEGIN:VALARM\r\nTRIGGER:-PT10M\r\n"
           b"ACTION:DISPLAY\r\nDESCRIPTION:Nested reminder\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    changed, _ = must(client.request("PUT", resource, raw, {**media, "If-Match": event["etag"]}), 204)
    assert api(item, "PATCH", {"summary": "Stale"}, tag=event["etag"])[0] == 412
    assert api(item, "DELETE", tag=event["etag"])[0] == 412
    headers, detail = must(api(item), 200)
    start = int(datetime(2026, 11, 21, 11, tzinfo=timezone.utc).timestamp())
    assert headers["ETag"] == changed["ETag"] and detail["event"]["start"] == start, detail
    assert detail["event"]["summary"] == "Edited over DAV" and detail["description"] == "Old notes"
    query = f"calendar-events?calendarId={calendar_id}&start={start}&end={start + 1}"
    assert must(api(query), 200)[1]["events"][0]["id"] == event["id"]
    assert must(api(f"calendar-events?start={start}&end={start + 1}"), 200)[1]["events"][0]["id"] == event["id"]
    assert not must(api(f"calendar-events?start={start + 3600}&end={start + 3601}"), 200)[1]["events"]
    assert api(f"calendar-events?calendarId={calendar_id}&start=0&end={367 * 86400}")[0] == 400

    new_headers, change = must(api(item, "PATCH", {"summary": "Web edit", "description": ""}, tag=changed["ETag"]), 200)
    header, after = must(client.request("GET", resource, tls=False), 200)
    assert new_headers["ETag"] == header["ETag"] == change["etag"] != changed["ETag"]
    assert b"SUMMARY:Web edit\r\n" in after and b"DESCRIPTION:Old notes" not in after
    for untouched in (b"DTSTART;TZID=Europe/Vienna:20261121T120000", b"LOCATION:Studio", b"BEGIN:VTIMEZONE",
                      b"X-APPLE-TRAVEL-DURATION;VALUE=DURATION:PT20M", b"ATTENDEE;CN=Guest:mailto:other@example.test",
                      b"DESCRIPTION:Nested reminder\r\nEND:VALARM"):
        assert untouched in after, untouched

    barrier = Barrier(2)

    def peer_update():
        barrier.wait(timeout=10)
        return client.request("PUT", resource, after.replace(b"SUMMARY:Web edit", b"SUMMARY:DAV race"),
                              {**media, "If-Match": change["etag"]})[0]

    def browser_update():
        barrier.wait(timeout=10)
        return api(item, "PATCH", {"summary": "Web race"}, tag=change["etag"])[0]

    with ThreadPoolExecutor(max_workers=2) as workers:
        web, dav = workers.submit(browser_update), workers.submit(peer_update)
        assert (web.result(), dav.result()) in ((200, 412), (412, 204))

    headers, _ = must(api(item), 200)
    day = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())
    final, _ = must(api(item, "PATCH", {"time": {"start": day, "end": day + 86400, "allDay": True}}, tag=headers["ETag"]), 200)
    _, after = must(client.request("GET", resource), 200)
    assert b"DTSTART;VALUE=DATE:20261201\r\nDTEND;VALUE=DATE:20261202\r\n" in after
    assert b"X-APPLE-TRAVEL-DURATION;VALUE=DURATION:PT20M\r\n" in after

    series = (b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:series-fixture\r\n"
              b"DTSTART:20261201T120000Z\r\nRRULE:FREQ=WEEKLY;COUNT=2\r\nSUMMARY:Original series\r\nEND:VEVENT\r\n"
              b"BEGIN:VEVENT\r\nUID:series-fixture\r\nRECURRENCE-ID:20261208T120000Z\r\n"
              b"DTSTART:20261208T150000Z\r\nSUMMARY:Exception title\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    series_path = collection + "series.ics"
    series_headers, _ = must(client.request("PUT", series_path, series, media), 201)
    rows = must(api(f"calendar-events?calendarId={calendar_id}&start={day}&end={day + 86400}"), 200)[1]["events"]
    row, = [entry for entry in rows if entry["uid"] == "series"]
    assert row["summary"] == "Original series", rows
    series_item = f"calendar-events/{row['id']}"
    assert api(series_item, "PATCH", {"time": {"start": day}}, tag=series_headers["ETag"])[0] == 422
    edited, _ = must(api(series_item, "PATCH", {"summary": "Edited series"}, tag=series_headers["ETag"]), 200)
    _, series_after = must(client.request("GET", series_path), 200)
    assert b"SUMMARY:Edited series\r\n" in series_after and b"RECURRENCE-ID:20261208T120000Z\r\n" in series_after
    assert b"SUMMARY:Exception title\r\n" in series_after and b"RRULE:FREQ=WEEKLY;COUNT=2\r\n" in series_after
    source = must(api(series_item + "?source=1"), 200)[1]["icalendar"]
    assert source.encode() == series_after
    assert api(series_item + "?source=1", headers=other_session)[0] == 404
    assert must(api(series_item), 200)[1]["icalendar"] is None

    def replace_series(payload, *, tag=edited["ETag"], headers=session):
        return api(series_item, "PUT", payload, tag=tag, headers={**headers, **media})

    moved = series_after.replace(b"DTSTART:20261208T150000Z", b"DTSTART:20261129T150000Z")
    assert replace_series(moved, tag=None)[0] == 428
    assert replace_series(moved, tag=series_headers["ETag"])[0] == 412
    assert replace_series(moved, headers=other_session)[0] == 404
    assert replace_series(moved, headers={**session, "Origin": "https://other.example.test"})[0] == 403
    assert replace_series(moved.replace(b"UID:series-fixture", b"UID:foreign"))[0] == 422
    assert api(series_item, "PUT", {"icalendar": source}, tag=edited["ETag"])[0] == 415
    replaced, _ = must(replace_series(moved), 200)
    read_headers, read_data = must(client.request("GET", series_path), 200)
    assert read_headers["ETag"] == replaced["ETag"] != edited["ETag"] and read_data == moved
    earlier = f"calendar-events?start={day - 2 * 86400}&end={day - 86400}&instances=1"
    candidates = must(api(earlier), 200)[1]["events"]
    assert [(item["id"], item["recurring"], item["icalendar"]) for item in candidates] == [
        (row["id"], True, moved.decode()),
    ]
    assert not must(api(earlier, headers=other_session), 200)[1]["events"]
    additional = (b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:series-fixture\r\n"
                  b"DTSTART:20261201T120000Z\r\nRDATE:20261129T150000Z\r\nSUMMARY:One additional date\r\n"
                  b"END:VEVENT\r\nEND:VCALENDAR\r\n")
    additional_tag, _ = must(replace_series(additional, tag=replaced["ETag"]), 200)
    extra, = must(api(earlier), 200)[1]["events"]
    assert extra["recurring"] and extra["recurrence_rule"] is None and extra["icalendar"].encode() == additional
    must(api(series_item, "DELETE", tag=additional_tag["ETag"]), 204)
    must(client.request("GET", series_path), 404)

    return owner, item, resource, final["ETag"]


def configure_vdirsyncer(test, client, profiles, collections, executable, directory):
    # Use the discovered mail profile coordinates with the fixture trust root.
    root = test.directory / directory
    root.mkdir(mode=0o700)
    config = root / "config"
    content = f"[general]\nstatus_path = {json.dumps(str(root / 'status'))}\n"
    local_files = []
    for prefix, collection in collections.items():
        kind = prefix.lower()
        ext = ".ics" if prefix == "CalDAV" else ".vcf"
        profile = profiles[prefix]
        host, port = profile[prefix + "HostName"], profile[prefix + "Port"]
        local = root / kind
        (local / collection).mkdir(parents=True)
        local_files.append((local / collection, ext))
        content += (f'\n[pair {kind}]\na = "{kind}_local"\nb = "{kind}_remote"\ncollections = ["from b"]\n'
                    f'\n[storage {kind}_local]\ntype = "filesystem"\npath = {json.dumps(str(local))}\n'
                    f'fileext = "{ext}"\n\n[storage {kind}_remote]\ntype = "{kind}"\n'
                    f'url = "https://{host}:{port}/"\nusername = {json.dumps(client.mailbox)}\n'
                    f'password = {json.dumps(client.password)}\nverify = {json.dumps(str(test.directory / "test.pem"))}\n')
    config.write_text(content)
    config.chmod(0o600)
    env = dict(os.environ, VDIRSYNCER_CONFIG=str(config))

    def run(*args):
        result = subprocess.run([executable, *args], cwd=root, env=env, input="y\n", capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr

    return run, local_files


def check_native_client(test, client, profiles, expected, executable):
    run, local_files = configure_vdirsyncer(test, client, profiles, COLLECTIONS, executable, "vdirsyncer")
    run("discover")
    run("sync")
    created = []
    for (folder, ext), (path, body, _) in zip(local_files, expected):
        file, = folder.glob("*" + ext)
        actual = file.read_bytes()
        assert actual.splitlines() == body.splitlines()
        file.write_bytes(actual.replace(b"Proposed version", b"Client edit"))
        uid = "client-event" if ext == ".ics" else "client-contact"
        new_file = folder / (uid + ext)
        new_body = actual.replace(b"UID:dav-", b"UID:client-").replace(b"Proposed version", b"Client create")
        new_file.write_bytes(new_body)
        created.append((new_file, path.rsplit("/", 1)[0] + "/" + new_file.name))
    run("sync")
    for path, _, etag in expected:
        headers, body = must(client.request("GET", path), 200)
        assert b"Client edit" in body and headers["ETag"] != etag
    for file, path in created:
        _, body = must(client.request("GET", path), 200)
        assert b"Client create" in body
        file.unlink()
    run("sync")
    for _, path in created:
        must(client.request("GET", path), 404)


def check_editor_with_native_client(test, client, resource, endpoint, session, executable):
    run, local = configure_vdirsyncer(test, client, client.profile(), {"CalDAV": "Working%20calendar"}, executable, "vdirsyncer-editor")
    run("discover")
    run("sync")
    folder, extension = local[0]
    file, = folder.parent.rglob("*" + extension)
    original = file.read_bytes()
    assert b"DTSTART;VALUE=DATE:20261201" in original
    changed, replacements = re.subn(rb"(?m)^SUMMARY:[^\r\n]+", b"SUMMARY:Vdirsyncer changed the event", original)
    assert replacements == 1
    file.write_bytes(changed)
    run("sync")
    headers, detail = must(hosted.request(endpoint, headers=session, context=test.tls_context), 200)
    assert json.loads(detail)["event"]["summary"] == "Vdirsyncer changed the event"
    patched, _ = must(hosted.request(endpoint, {"summary": "Webmail changed the event"},
                      {**session, "If-Match": headers["ETag"]}, "PATCH", test.tls_context), 200)
    run("sync")
    assert b"SUMMARY:Webmail changed the event" in file.read_bytes()
    headers, body = must(client.request("GET", resource), 200)
    assert headers["ETag"] == patched["ETag"] and b"X-APPLE-TRAVEL-DURATION;VALUE=DURATION:PT20M" in body
    print("Verified Vdirsyncer and webmail can edit the same event in both directions.")
    return headers["ETag"]


def sync_report(client, collection, token="", *, tls=True, status=207, limit=None):
    prefix, namespace, level = ("S:", "xmlns:S", "1") if tls else ("", "xmlns", "infinite")
    token_tag = f"{prefix}sync-token"
    state = f"<{token_tag} />" if tls and not token else f"<{token_tag}>{token}</{token_tag}>"
    limit_xml = "" if limit is None else f"<{prefix}limit><{prefix}nresults>{limit}</{prefix}nresults></{prefix}limit>"
    body = (f'<{prefix}sync-collection {namespace}="DAV:">{state}'
            f"<{prefix}sync-level>{level}</{prefix}sync-level>{limit_xml}"
            f"<{prefix}prop><{prefix}getetag/></{prefix}prop></{prefix}sync-collection>")
    _, data = must(client.request("REPORT", collection, body.encode(), {"Depth": "0", "Content-Type": "text/xml"}, tls=tls), status)
    if status in (403, 507):
        condition = "valid-sync-token" if status == 403 else "number-of-matches-within-limits"
        assert ET.fromstring(data).find("d:" + condition, DAV) is not None, data
    if status != 207:
        return
    root = ET.fromstring(data)
    members = {}
    for entry in root.findall("d:response", DAV):
        href = entry.findtext("d:href", namespaces=DAV)
        assert href and href not in members, data
        etag = entry.findtext("d:propstat/d:prop/d:getetag", namespaces=DAV)
        if etag is None:
            assert entry.findtext("d:status", namespaces=DAV) == "HTTP/1.1 404 Not Found", data
        members[href] = etag
    token = root.findtext("d:sync-token", namespaces=DAV)
    assert token, data
    return token, members


def check_eas_dav(test, mailbox):
    client = DavClient(test, mailbox)
    for (path, media, body), folder in zip(resources(mailbox), ("5", "6")):
        def sync(key):
            _, data = must(test.eas(mailbox, hosted.eas_sync(key, folder), command="Sync", device="DavSyncFixture"), 200)
            assert b"\x4e\x031\x00\x01" in data, data[:150]
            return hosted.eas_sync_key(data), data

        headers = {"Content-Type": media}
        must(client.request("PUT", path, body, headers), 201)
        key, _ = sync(0)
        key, data = sync(key)
        added = re.search(rb"\x47\x4d\x03([0-9]+)\x00\x01", data)
        assert added and b"Fixture record" in data, data[:150]
        must(client.request("PUT", path, body.replace(b"Fixture record", b"Changed over DAV"), headers), 204)
        key, data = sync(key)
        assert b"\x48\x4d\x03" + added[1] in data and b"Changed over DAV" in data, data[:150]
        must(client.request("DELETE", path), 204)
        _, data = sync(key)
        assert b"\x49\x4d\x03" + added[1] in data, data[:150]


def check_sync_collections(binary):
    with tempfile.TemporaryDirectory(prefix="mail-dav-sync-", dir="/tmp") as directory:
        test = hosted.Fixture(binary, Path(directory), staging=True)
        test.env.update(CALDAV_MAX_SYNC_HISTORY="4", SMTP_AUTH_DEFAULT_DOMAIN=hosted.DOMAIN)
        restart = []
        with test.daemon():
            check_eas_dav(test, test.provision("eas-dav"))
            owner, other = test.provision("sync-owner"), test.provision("sync-other")
            client, foreign = DavClient(test, owner), DavClient(test, other)
            for (original, media, body), foreign_resource in zip(resources(owner), resources(other)):
                home, collection_name, _ = original.rsplit("/", 2)
                collection = f"{home}/{collection_name}%20fixture/"
                foreign_path = foreign_resource[0]
                other_collection = home + "/another/"
                suffix = ".ics" if media == "text/calendar" else ".vcf"
                path, sibling = collection + "shared%20member" + suffix, collection + "second" + suffix
                headers = {"Content-Type": media}
                make_collection = "MKCALENDAR" if suffix == ".ics" else "MKCOL"
                must(client.request(make_collection, collection), 201)
                empty, members = sync_report(client, collection)
                assert members == {}
                must(foreign.request("PUT", foreign_path, body, headers), 201)
                must(client.request("PUT", other_collection + "outside" + suffix, body, headers), 201)
                foreign_token, _ = sync_report(foreign, foreign_path.rsplit("/", 1)[0] + "/")
                outside_token, _ = sync_report(client, other_collection)

                first, _ = must(client.request("PUT", path, body, headers), 201)
                second, _ = must(client.request("PUT", sibling, body, headers, tls=False), 201)
                token, members = sync_report(client, collection, empty)
                assert members == {path: first["ETag"], sibling: second["ETag"]}, members
                assert sync_report(client, collection, tls=False) == (token, members)
                kind, namespace = (("calendar", "caldav") if suffix == ".ics" else ("addressbook", "carddav"))
                multiget = (f'<M:{kind}-multiget xmlns="DAV:" xmlns:M="urn:ietf:params:xml:ns:{namespace}">'
                            f'<prop><getetag/></prop><href>{path}</href></M:{kind}-multiget>').encode()
                _, data = must(client.request("REPORT", collection, multiget), 207)
                entry = ET.fromstring(data).find("d:response", DAV)
                assert entry.findtext("d:href", namespaces=DAV) == path
                assert entry.findtext("d:propstat/d:prop/d:getetag", namespaces=DAV) == members[path]
                sync_report(client, collection, limit=1, status=507)
                future = token.rsplit(":", 1)[0] + ":99999999"
                for invalid_token in ("http://mail/sync/1", foreign_token, outside_token, future):
                    sync_report(client, collection, invalid_token, status=403)
                if restart:
                    sync_report(client, collection, restart[0][1], status=403)
                sync_report(foreign, collection, token, tls=False, status=404)

                for propfind_path, depth in ((collection, "1"), (home + "/", "1")):
                    _, data = must(client.request("PROPFIND", propfind_path, headers={"Depth": depth}), 207)
                    responses = {response.findtext("d:href", namespaces=DAV): response
                                 for response in ET.fromstring(data).findall("d:response", DAV)}
                    assert responses[collection].findtext("d:propstat/d:prop/d:sync-token", namespaces=DAV) == token
                    advertised = {prop.tag.rsplit("}", 1)[-1] for prop in responses[collection].findall(
                        "d:propstat/d:prop/d:supported-report-set/d:supported-report/d:report/*", DAV)}
                    assert {"sync-collection", kind + "-multiget", kind + "-query"} <= advertised
                    if propfind_path == collection:
                        assert {href: responses[href].findtext("d:propstat/d:prop/d:getetag", namespaces=DAV)
                                for href in members} == members

                for replacement in (b"Earlier sync edit", b"Latest sync edit"):
                    latest, _ = must(client.request("PUT", path, body.replace(b"Fixture record", replacement), headers), 204)
                must(client.request("DELETE", sibling, tls=False), 204)
                snapshot = {path: latest["ETag"], sibling: None}
                changed, _ = sync_report(client, collection, token)
                for tls in (False, True):
                    assert sync_report(client, collection, token, tls=tls) == (changed, snapshot)
                    assert sync_report(client, collection, changed, tls=tls) == (changed, {})
                    sync_report(client, collection, empty, tls=tls, status=403)

                recreated, _ = must(client.request("PUT", sibling, body, headers), 201)
                final, snapshot = sync_report(client, collection, token, tls=False)
                assert snapshot == {path: latest["ETag"], sibling: recreated["ETag"]}
                assert sync_report(client, other_collection, outside_token) == (outside_token, {})
                restart.append((collection, final, snapshot))

        with test.daemon():
            for collection, old_token, snapshot in restart:
                for tls in (False, True):
                    sync_report(client, collection, old_token, tls=tls, status=403)
                    token, members = sync_report(client, collection, tls=tls)
                    assert token != old_token and members == snapshot
                    assert sync_report(client, collection, token, tls=tls) == (token, {})
                    for href, etag in members.items():
                        headers, _ = must(client.request("GET", href, tls=tls), 200)
                        assert headers["ETag"] == etag
                removed = next(iter(snapshot))
                must(client.request("DELETE", removed, tls=False), 204)
                new_token, members = sync_report(client, collection, token)
                assert new_token != token and members == {removed: None}
    print("Verified DAV sync tokens, current listings, deletion and pruned history over HTTP and HTTPS, plus ActiveSync calendar and contacts.")


def check_calendar_upgrade(binary, previous):
    with tempfile.TemporaryDirectory(prefix="mail-dav-upgrade-", dir="/tmp") as directory:
        root = Path(directory)
        test = hosted.Fixture(previous, root, staging=True)
        with test.daemon():
            owner = test.provision("upgrade-owner")
            client = DavClient(test, owner)
            resource = f"/calendars/{owner}/Legacy/old-path.ics"
            alarm = datetime.fromtimestamp(int(time.time()) - 60, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            raw = (b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:legacy-event\r\n"
                   b"DTSTART:20261121T120000Z\r\nSUMMARY:Previous version\r\nX-MAIL-FIXTURE:keep\r\n"
                   b"BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Legacy display alarm\r\n"
                   b"TRIGGER;VALUE=DATE-TIME:" + alarm.encode() + b"\r\nEND:VALARM\r\n"
                   b"END:VEVENT\r\nEND:VCALENDAR\r\n")
            previous_headers, _ = must(client.request("PUT", resource, raw, {"Content-Type": "text/calendar"}), 201)
            calendar, = test.api(test.login(owner), "calendars")[1]["calendars"]
            start = int(datetime(2026, 11, 21, 12, tzinfo=timezone.utc).timestamp())
            listing = f"calendar-events?calendarId={calendar['id']}&start={start}&end={start + 3600}"
            event, = test.api(test.login(owner), listing)[1]["events"]

        def schema():
            with sqlite3.connect(root / "caldav.db") as db:
                return db.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").fetchall()

        previous_schema = schema()
        test.binary = binary
        with test.daemon():
            session = test.login(owner)
            assert test.api(session, listing)[1]["events"] == [event]
            reminders = test.api(session, "calendar-reminders")[1]["events"]
            assert [entry["id"] for entry in reminders] == [event["id"]]
            endpoint = test.webmail + f"/webmail/api/calendar-events/{event['id']}"
            head, _ = must(hosted.request(endpoint, headers=session, context=test.tls_context), 200)
            assert head["ETag"] == previous_headers["ETag"]
            headers = {**session, "If-Match": head["ETag"]}
            changed, _ = must(hosted.request(endpoint, {"summary": "Updated by new version"}, headers, "PATCH", test.tls_context), 200)
            assert changed["ETag"] != head["ETag"]

        upgraded_schema = schema()
        assert set(previous_schema) <= set(upgraded_schema)
        assert {row[1] for row in set(upgraded_schema) - set(previous_schema)} <= {
            "dav_reminder_dismissals", "idx_dav_reminder_due", "sqlite_autoindex_dav_reminder_dismissals_1",
        }
        test.binary = previous
        with test.daemon():
            row, = test.api(test.login(owner), listing)[1]["events"]
            assert row["id"] == event["id"] and row["summary"] == "Updated by new version" and row["etag"] == changed["ETag"]
            _, data = must(client.request("GET", resource), 200)
            assert b"UID:legacy-event\r\n" in data and b"X-MAIL-FIXTURE:keep\r\n" in data
    print("Verified upgrade and reopening with the previous binary after the additive reminders migration.")


def check_reminders(test, owner, other):
    client = DavClient(test, owner)
    session, unrelated = test.login(owner), test.login(other)
    now = int(time.time())
    due = now - 60

    def utc(stamp):
        return datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    def resource(name, when, action, trigger):
        data = "\r\n".join([
            "BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", f"UID:{name}",
            f"DTSTART:{utc(when)}", f"SUMMARY:{name}", "BEGIN:VALARM", f"ACTION:{action}",
            trigger, "DESCRIPTION:Test alarm", "END:VALARM", "END:VEVENT", "END:VCALENDAR", "",
        ]).encode()
        path = f"/calendars/{owner}/ReminderTests/{name}.ics"
        must(client.request("PUT", path, data, {"Content-Type": "text/calendar"}), 201)
        return path, data

    path, raw = resource("absolute", now - 5 * 86400, "DISPLAY", f"TRIGGER;VALUE=DATE-TIME:{utc(due)}")
    resource("near", now + 600, "DISPLAY", "TRIGGER:-PT15M")
    resource("old", now - 5 * 86400, "DISPLAY", "TRIGGER:-PT15M")
    resource("audio", now + 600, "AUDIO", "TRIGGER:-PT15M")
    assert test.api({}, "calendar-reminders")[0] == 401
    status, snapshot = test.api(session, "calendar-reminders")
    assert status == 200 and snapshot["start"] <= due <= snapshot["now"] < snapshot["end"], snapshot
    items = {row["uid"]: row for row in snapshot["events"]}
    assert set(items) == {"absolute", "near"} and snapshot["dismissed"] == [], snapshot
    assert items["absolute"]["icalendar"].encode() == raw
    assert test.api(unrelated, "calendar-reminders")[1]["events"] == []
    event_id = items["absolute"]["id"]
    key = f"{event_id}:{due}:absolute:master"
    args = {"eventId": event_id, "key": key, "due": due}
    assert test.api(unrelated, "calendar-reminders/dismiss", args, "POST")[0] == 404
    assert test.api({**session, "Origin": "https://outside.example.test"}, "calendar-reminders/dismiss", args, "POST")[0] == 403
    assert test.api(session, "calendar-reminders/dismiss", {**args, "due": now + 3600}, "POST")[0] == 400
    assert test.api(session, "calendar-reminders/dismiss", {**args, "key": "invalid key"}, "POST")[0] == 400
    for _ in range(2):
        assert test.api(session, "calendar-reminders/dismiss", args, "POST")[0] == 204
    assert test.api(test.login(owner), "calendar-reminders")[1]["dismissed"] == [key]
    assert test.api(unrelated, "calendar-reminders")[1]["dismissed"] == []
    assert must(client.request("GET", path), 200)[1] == raw
    return key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--vdirsyncer", type=Path)
    parser.add_argument("--clamd", type=Path, help="Use a real clamd and its installed signatures")
    parser.add_argument("--database", type=Path, default=Path("/var/lib/clamav"))
    parser.add_argument("--upgrade-from", type=Path, help="Verify a database written by a previous Mail binary")
    args = parser.parse_args()
    scanner = args.clamd.resolve(strict=True) if args.clamd else None
    with tempfile.TemporaryDirectory(prefix="mail-dav-https-", dir="/tmp") as directory:
        root = Path(directory)
        test = hosted.Fixture(args.binary.resolve(strict=True), root, staging=True)
        test.env.update(SMTP_HOSTNAME="127.0.0.1", CALDAV_PUBLIC_SSL_PORT=test.env["CALDAV_SSL_PORT"])
        with clamav.scanner(root, scanner, args.database.resolve()) as endpoint:
            test.env.update(SMTP_CLAMAV_TRANSPORT=f"unix:{endpoint}", SMTP_CLAMAV_FAIL_MODE="closed")
            with test.daemon():
                owner = test.provision("dav-owner")
                other = test.provision("dav-other")
                expected = check_resources(test, owner, other)
                check_scanning(DavClient(test, owner), expected)
                check_calendar_download(test, owner, other)
                importer, calendar_id, submit = check_calendar_import(test, owner, other)
                editor, item, resource, revision = check_calendar_writes(test, other)
                dismissal = check_reminders(test, owner, other)
            with test.daemon():
                client = DavClient(test, owner)
                assert test.api(test.login(owner), "calendar-reminders")[1]["dismissed"] == [dismissal]
                print("Verified webmail reminder selection, account isolation, idempotent dismissal and persistence after restart.")
                for path, body, etag in expected:
                    headers, saved = must(client.request("GET", path), 200)
                    assert body == saved and headers["ETag"] == etag
                importer_session = test.login(importer)
                status, result = submit("import", target=calendar_id, headers=importer_session)
                assert status == 200 and {event["status"] for event in result["events"]} == {"skipped", "error"}, result
                path = test.webmail + "/webmail/api/calendar-export?calendarId=" + str(calendar_id)
                status, _, data = hosted.request(path, headers=importer_session, context=test.tls_context)
                assert status == 200 and b"UID:vienna\r\n" in data and b"UID:scanner-refusal" not in data
                print("Verified webmail calendar preview, timezone conversion, ownership, scanner refusal and repeat-safe import across restart.")
                editor_session = test.login(editor)
                status, settings = test.api(editor_session, "calendars")
                assert status == 200 and {row["name"]: row["color"] for row in settings["calendars"]} == {
                    "Outside%20projects": None, "Working%20calendar": "#12785B",
                }, settings
                link = test.webmail + "/webmail/api/" + item
                status, headers, data = hosted.request(link, headers=editor_session, context=test.tls_context)
                assert status == 200 and headers["ETag"] == revision and json.loads(data)["event"]["all_day"]
                editor_client = DavClient(test, editor)
                must(editor_client.request("GET", resource), 200)
                if args.vdirsyncer:
                    revision = check_editor_with_native_client(test, editor_client, resource, link, editor_session,
                                                               args.vdirsyncer.resolve(strict=True))
                fields = {**editor_session, "If-Match": revision}
                assert hosted.request(link, headers=fields, method="DELETE", context=test.tls_context)[0] == 204
                must(editor_client.request("GET", resource), 404)
                print("Verified webmail and DAV bidirectional edits, conditional races, preserved event fields, and deletion after restart.")
                profiles = client.profile()
                if args.vdirsyncer:
                    check_native_client(test, client, profiles, expected, args.vdirsyncer.resolve(strict=True))
                    print("Verified vdirsyncer discovery and bidirectional Calendar and Contacts sync from the mail profile.")
                for path, _, _ in expected:
                    headers, _ = must(client.request("GET", path), 200)
                    must(client.request("DELETE", path, headers={"If-Match": headers["ETag"]}), 204)
                    must(client.request("GET", path, tls=False), 404)
        print("Verified native HTTPS DAV CRUD, HTTP parity, conditional races, size limits, scanner refusal and restart.")
    check_sync_collections(args.binary.resolve(strict=True))
    if args.upgrade_from:
        check_calendar_upgrade(args.binary.resolve(strict=True), args.upgrade_from.resolve(strict=True))


if __name__ == "__main__":
    main()
