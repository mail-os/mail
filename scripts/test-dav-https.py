#!/usr/bin/env python3
"""Verify shared CalDAV and CardDAV resource operations over HTTP and TLS."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
import hashlib
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
team_command = runpy.run_path(str(SCRIPTS / "test-webmail-teams.py"))["command"]
COLLECTIONS = {"CalDAV": "staging-events", "CardDAV": "staging-contacts"}
DAV = {"d": "DAV:"}
CALDAV = "urn:ietf:params:xml:ns:caldav"
CARDDAV = "urn:ietf:params:xml:ns:carddav"
ICAL = "http://apple.com/ns/ical/"


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


def check_collection_properties(test, owner, other, expected):
    client, foreign = DavClient(test, owner), DavClient(test, other)
    d = "{DAV:}"
    xml = {"Content-Type": "application/xml"}
    checks = []

    def update(instructions):
        return f'<propertyupdate xmlns="DAV:">{instructions}</propertyupdate>'.encode()

    def statuses(payload, collection):
        response, = ET.fromstring(payload).findall(d + "response")
        assert response.findtext(d + "href") == collection
        return {prop.tag: int(row.findtext(d + "status").split()[1])
                for row in response.findall(d + "propstat") for prop in row.find(d + "prop")}

    def properties(payload, collection):
        row, = [row for row in ET.fromstring(payload).findall(d + "response")
                if row.findtext(d + "href") == collection]
        return {prop.tag: prop.text for prop in row.findall(f"{d}propstat/{d}prop/*")}

    def discover(collection, *, tls=True, home=False):
        path = collection.rstrip("/").rsplit("/", 1)[0] + "/" if home else collection
        _, payload = must(client.request("PROPFIND", path, headers={"Depth": "1" if home else "0"}, tls=tls), 207)
        return properties(payload, collection)

    for tls, (path, _, etag) in zip((True, False), expected):
        collection = path.rsplit("/", 1)[0] + "/"
        slug = collection.rstrip("/").rsplit("/", 1)[1]
        is_calendar = path.endswith(".ics")
        ns, local = (CALDAV, "calendar-description") if is_calendar else (CARDDAV, "addressbook-description")
        name, description, color = d + "displayname", f"{{{ns}}}{local}", f"{{{ICAL}}}calendar-color"
        sync_token = discover(collection)[d + "sync-token"]
        color_instruction = f'<h:calendar-color xmlns:h="{ICAL}">#127A42CC</h:calendar-color>' if is_calendar else ""
        set_values = update(f'<set><prop><displayname>Projects &amp; clients %20</displayname>'
                            f'<note:{local} xmlns:note="{ns}"><![CDATA[Notes <for>]]> everyone &#x2603;</note:{local}>'
                            f'{color_instruction}</prop></set>')
        # The 207 must be fully readable while the server keeps the same socket
        # open for the following authenticated request.
        connection = (http.client.HTTPSConnection("127.0.0.1", client.https, context=client.context, timeout=15)
                      if tls else http.client.HTTPConnection("127.0.0.1", client.http, timeout=15))
        try:
            connection.connect()
            stream = connection.sock
            connection.request("PROPPATCH", collection, set_values, {**client.auth, **xml})
            response = connection.getresponse()
            payload = response.read()
            assert response.status == 207 and int(response.headers["Content-Length"]) == len(payload)
            assert response.headers["Cache-Control"] == "no-store"
            wanted = {name: 200, description: 200}
            if is_calendar:
                wanted[color] = 200
            assert statuses(payload, collection) == wanted
            connection.request("PROPFIND", collection, headers={**client.auth, "Depth": "0"})
            assert connection.sock is stream
            response = connection.getresponse()
            assert response.status == 207 and properties(response.read(), collection)[name] == "Projects & clients %20"
        finally:
            connection.close()

        baseline = discover(collection, tls=not tls, home=True)
        assert baseline[name] == "Projects & clients %20" and baseline[description] == "Notes <for> everyone ☃"
        assert baseline.get(color) == ("#127A42CC" if is_calendar else None)
        assert baseline[d + "sync-token"] == sync_token
        alternate = collection.replace(slug + "/", urllib.parse.quote(baseline[name]) + "/")
        must(client.request("PROPFIND", alternate, headers={"Depth": "0"}, tls=tls), 404)
        for secure in (True, False):
            must(foreign.request("PROPPATCH", collection, set_values, xml, tls=secure), 404)
            must(client.request("PROPPATCH", alternate, set_values, xml, tls=secure), 404)
            must(client.request("PROPPATCH", collection, set_values, xml, tls=secure, authenticated=False), 401)

        blocked = update('<set><prop><displayname>Rollback</displayname><getetag/>'
                         '<displayname xmlns="urn:other&amp;namespace"/></prop></set>')
        _, body = must(client.request("PROPPATCH", collection, blocked, xml, tls=tls), 207)
        assert statuses(body, collection) == {name: 424, d + "getetag": 403, "{urn:other&namespace}displayname": 403}
        assert ET.fromstring(body).find(f".//{d}cannot-modify-protected-property") is not None
        invalid = (f'<h:calendar-color xmlns:h="{ICAL}">blue</h:calendar-color>' if is_calendar
                   else f'<{local} xmlns="{ns}"><bad/></{local}>')
        _, body = must(client.request("PROPPATCH", collection, update(f'<set><prop><displayname/><!---->{invalid}</prop></set>'), xml), 207)
        assert statuses(body, collection) == {name: 424, color if is_calendar else description: 409}
        wrong_root = b'<propertyupdate xmlns="urn:fake"><set><prop><displayname>X</displayname></prop></set></propertyupdate>'
        must(client.request("PROPPATCH", collection, wrong_root, xml), 400)
        must(client.request("PROPPATCH", collection, update('<set><prop><ghost:displayname/></prop></set>'), xml), 400)
        must(client.request("PROPPATCH", collection, update('text<set><prop><displayname/></prop></set>'), xml), 400)

        table = "dav_calendars" if is_calendar else "dav_addressbooks"
        with sqlite3.connect(test.env["CALDAV_DB_PATH"]) as db:
            db.execute(f"CREATE TRIGGER reject_dav_property_fixture BEFORE UPDATE OF display_name ON {table} "
                       "BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END")
            db.commit()
            try:
                _, body = must(client.request("PROPPATCH", collection, update('<remove><prop><displayname/></prop></remove>'), xml), 207)
                assert statuses(body, collection) == {name: 500}
                assert discover(collection)[name] == baseline[name]
                assert db.execute(f"SELECT display_name FROM {table} WHERE name=?", (slug,)).fetchone() == (baseline[name],)
            finally:
                db.execute("DROP TRIGGER reject_dav_property_fixture")

        ready = Barrier(3)

        def write_pairs():
            ready.wait(timeout=5)
            for i in range(12):
                value = f"Version {i}"
                changes = update(f'<set><prop><displayname>{value}</displayname>'
                                 f'<{local} xmlns="{ns}">{value}</{local}></prop></set>')
                _, result = must(client.request("PROPPATCH", collection, changes, xml, tls=tls), 207)
                assert statuses(result, collection) == {name: 200, description: 200}

        def read_pairs(secure):
            ready.wait(timeout=5)
            for _ in range(14):
                values = discover(collection, tls=secure, home=secure)
                assert ((values[name], values[description]) == (baseline[name], baseline[description])
                        or values[name] == values[description] and values[name].startswith("Version ")), values

        with ThreadPoolExecutor(max_workers=3) as workers:
            for result in (workers.submit(write_pairs), workers.submit(read_pairs, True), workers.submit(read_pairs, False)):
                result.result()

        removals = update(f'<remove><prop><displayname/><{local} xmlns="{ns}"/>'
                          + (f'<calendar-color xmlns="{ICAL}"/>' if is_calendar else "") + '</prop></remove>')
        _, body = must(client.request("PROPPATCH", collection, removals, xml, tls=tls), 207)
        assert statuses(body, collection) == wanted
        values = discover(collection, tls=not tls)
        assert values[name] == slug and description not in values and color not in values

        repeated = update('<set><prop><displayname>First instruction</displayname></prop></set>'
                          '<remove><prop><displayname/></prop></remove>'
                          f'<set><prop><displayname>Projects &amp; clients %20</displayname>'
                          f'<{local} xmlns="{ns}">Notes &lt;for&gt; everyone ☃</{local}>'
                          f'{color_instruction}</prop></set>')
        _, body = must(client.request("PROPPATCH", collection, repeated, xml, tls=tls), 207)
        assert statuses(body, collection) == wanted
        assert discover(collection)[d + "sync-token"] == sync_token
        checks.append((collection, path, etag, {key: baseline[key] for key in wanted}))

    def verify_saved():
        for collection, path, etag, baseline in checks:
            sync_token = discover(collection)[d + "sync-token"]
            for tls in (True, False):
                for home in (True, False):
                    values = discover(collection, tls=tls, home=home)
                    assert all(values[key] == value for key, value in baseline.items()), values
                    assert values[d + "sync-token"] == sync_token
                assert must(client.request("GET", path, tls=tls), 200)[0]["ETag"] == etag
        status, rows = test.api(test.login(owner), "calendars")
        assert status == 200
        row, = [row for row in rows["calendars"] if row["name"] == COLLECTIONS["CalDAV"]]
        assert row["display_name"] == "Projects & clients %20" and row["color"] == "#127A42CC"

    verify_saved()
    return verify_saved


def check_invitation_previews(test, owner, other):
    session, foreign = test.login(owner), test.login(other)
    assert test.api(session, "sender-review", {"setting": "disable"}, "PUT")[0] == 200
    client = DavClient(test, owner)
    home = f"/calendars/{owner}/"
    before = must(client.request("PROPFIND", home, headers={"Depth": "1"}), 207)[1]
    dav_state = test.api(session, "calendars")

    def event(method, *fields, organizer=other, attendee=owner, sequence=0):
        return "\r\n".join(("BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail//Invitation Fixture//EN",
                          "METHOD:" + method, "BEGIN:VEVENT", "UID:planning@example.test",
                          "DTSTAMP:20261121T100000Z", f"SEQUENCE:{sequence}", f"ORGANIZER:mailto:{organizer}",
                          f"ATTENDEE:mailto:{attendee}", *fields, "END:VEVENT", "END:VCALENDAR", ""))

    def deliver(subject, message):
        message["From"] = other
        message["To"] = owner
        message["Subject"] = subject
        with test.smtp(other) as smtp:
            assert smtp.send_message(message) == {}
        query = urllib.parse.urlencode({"folder": "INBOX", "q": subject})
        status, result = test.api(session, "messages?" + query)
        assert status == 200
        row, = [row for row in result["items"] if row["subject"] == subject]
        endpoint = "messages/ref/" + row["reference"]
        status, detail = test.api(session, endpoint)
        assert status == 200, detail
        assert test.api(foreign, endpoint)[0] == 404
        assert test.api({}, endpoint)[0] == 401
        return detail

    source = event("REQUEST", "DTSTART;TZID=America/New_York:20261124T103000", "DTEND;TZID=America/New_York:20261124T113000",
                   "RECURRENCE-ID;TZID=America/New_York:20261124T090000", r"SUMMARY:Design\, café <Preview>",
                   "LOCATION:South studio", sequence=2)
    message = EmailMessage()
    message.set_content("The revised invitation includes the studio.")
    message.add_alternative(source, subtype="calendar", params={"METHOD": "REQUEST"}, cte="quoted-printable")
    message.add_attachment(source, subtype="calendar", params={"method": "request"}, filename="invite.ics", cte="base64")
    detail = deliver("Calendar preview updated", message)
    row, = detail["calendar_invites"]

    def wall_at(hour, minute=0):
        return int(datetime(2026, 11, 24, hour, minute, tzinfo=timezone.utc).timestamp())

    def wall(hour, minute=0):
        return {"wall": wall_at(hour, minute), "zone": "America/New_York", "all_day": False}

    assert row == {"method": "request", "uid": "planning@example.test", "organizer": other,
                   "organizer_verified": True, "for_mailbox": True, "sequence": 2,
                   "dtstamp": int(datetime(2026, 11, 21, 10, tzinfo=timezone.utc).timestamp()),
                   "occurrence": wall(9), "this_and_future": False, "summary": "Design, café <Preview>",
                   "location": "South studio", "start": wall(10, 30), "end": wall(11, 30)}, row
    assert "revised invitation" in detail["text"] and not detail.get("calendar_only")
    attachment, = detail["attachments"]
    assert attachment["filename"] == "invite.ics"
    query = urllib.parse.urlencode({"reference": detail["reference"], "content_revision": detail["content_revision"], "index": 0})
    downloaded = hosted.request(test.webmail + "/webmail/api/attachment?" + query, headers=session, context=test.tls_context)
    assert downloaded[0] == 200 and downloaded[2].decode().splitlines() == source.splitlines()

    cancel = EmailMessage()
    cancel.set_content(event("CANCEL", "RECURRENCE-ID;RANGE=THISANDFUTURE;TZID=America/New_York:20261124T090000",
                             sequence=3), subtype="calendar", params={"method": "CANCEL"})
    detail = deliver("Calendar preview canceled occurrence", cancel)
    row, = detail["calendar_invites"]
    assert detail["calendar_only"] is True and row["method"] == "cancel" and row["sequence"] == 3
    assert row["occurrence"] == wall(9) and row["this_and_future"] and row["start"] is None

    copied = EmailMessage()
    copied.set_content(event("REQUEST", "DTSTART;VALUE=DATE:20261124", "DTEND;VALUE=DATE:20261125", "SUMMARY:Personal day",
                            organizer="forwarded@example.test", attendee="someone-else@example.test"),
                      subtype="calendar", params={"method": "REQUEST"})
    detail = deliver("Calendar preview forwarded all day", copied)
    row, = detail["calendar_invites"]
    assert not row["organizer_verified"] and not row["for_mailbox"] and row["organizer"] == "forwarded@example.test"
    assert row["start"] == {"wall": wall_at(0), "zone": None, "all_day": True}
    assert row["end"]["wall"] == wall_at(0) + 86400

    invalid = EmailMessage()
    invalid.set_content("Keep this literal --calendar-fixture string in the body.")
    invalid.add_attachment(source, subtype="calendar", params={"method": "CANCEL"}, filename="mismatch.ics")
    invalid.add_attachment(source, subtype="calendar", filename="ordinary.ics")
    invalid.add_attachment(source, subtype="calendar", params={"x-method": "REQUEST"}, filename="other.ics")
    duplicated = source.replace("SUMMARY:", "UID:other-event@example.test\r\nSUMMARY:")
    invalid.add_attachment(duplicated, subtype="calendar", params={"method": "REQUEST"}, filename="duplicate.ics")
    invalid.add_attachment(source, subtype="calendar", params={"method": "REQUEST"}, filename="encoding.ics")
    invalid.get_payload()[-1].replace_header("Content-Transfer-Encoding", "x-unknown")
    invalid.set_boundary("calendar-fixture")
    fake_part = f"Content-Type: text/calendar; method=REQUEST\r\n\r\n{source.replace('café', 'cafe')}"
    invalid.preamble = fake_part
    invalid.epilogue = fake_part
    detail = deliver("Calendar preview ignored MIME", invalid)
    assert "calendar_invites" not in detail and "--calendar-fixture string in the body." in detail["text"]
    assert [part["filename"] for part in detail["attachments"]] == [
        "mismatch.ics", "ordinary.ics", "other.ics", "duplicate.ics", "encoding.ics",
    ]
    assert test.api(session, "calendars") == dav_state
    assert must(client.request("PROPFIND", home, headers={"Depth": "1"}), 207)[1] == before
    assert test.api(foreign, "messages?folder=INBOX&q=planning")[1]["total"] == 0
    print("Verified MIME invitation previews, explicit time zones, cancellations, ownership, downloads, and unchanged DAV state.")


def check_invitation_replies(test):
    attendee = test.provision("rsvp-attendee", daily=1)
    organizer = test.provision("rsvp-organizer", daily=100)
    other_organizer = test.provision("rsvp-other-organizer")
    session, foreign = test.login(attendee), test.login(organizer)
    for account in (session, foreign):
        assert test.api(account, "sender-review", {"setting": "disable"}, "PUT")[0] == 200
    zone = (
        "BEGIN:VTIMEZONE", "TZID:Fixture/Studio", "TZURL:https://unused.example.test/zone",
        "BEGIN:STANDARD", "DTSTART:19700101T000000", "TZOFFSETFROM:-0500", "TZOFFSETTO:-0500",
        "END:STANDARD", "END:VTIMEZONE",
    )

    def invite(subject, sequence=2, stamp="110000", occurrence="090000", method="REQUEST", author=organizer,
               invited=attendee, series="rsvp-series", future=False, sender=organizer, held=False):
        start_time = occurrence or "090000"
        start = (f"DTSTART;TZID=Fixture/Studio:20261124T{start_time}",) if method == "REQUEST" else ()
        scope = ";RANGE=THISANDFUTURE" if future else ""
        recurrence = (f"RECURRENCE-ID{scope};TZID=Fixture/Studio:20261124T{occurrence}",) if occurrence else ()
        source = "\r\n".join((
            "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail//RSVP Fixture//EN", f"METHOD:{method}",
            *zone, "BEGIN:VEVENT", f"UID:{series}@example.test", f"SEQUENCE:{sequence}", f"DTSTAMP:20261121T{stamp}Z",
            *recurrence, *start, f"ORGANIZER:mailto:{author}",
            f"ATTENDEE:mailto:{invited}", f"ATTENDEE:mailto:{organizer}", "SUMMARY:Studio RSVP",
            "DESCRIPTION:Private notes from the organizer", "END:VEVENT", "END:VCALENDAR", "",
        ))
        message = EmailMessage()
        message["From"], message["To"], message["Subject"] = sender, attendee, subject
        message["Reply-To"] = "unrelated@hosted.example.test"
        message.set_content(source, subtype="calendar", params={"method": method})
        with test.smtp(sender) as smtp:
            assert smtp.send_message(message) == {}
        if held:
            item, = [row for row in test.api(session, "sender-review?view=pending")[1]["items"] if row["subject"] == subject]
            return item
        query = urllib.parse.urlencode({"folder": "INBOX", "q": subject})
        row, = [row for row in test.api(session, "messages?" + query)[1]["items"] if row["subject"] == subject]
        return detail(row["reference"])

    def detail(reference):
        return test.api(session, "messages/ref/" + reference)[1]

    def respond(source, response, previous=None, *, account=None, revision=True):
        fields = (session if account is None else account).copy()
        if revision:
            fields["If-Match"] = source["revision"]
        payload = {"reference": source["reference"], "index": 0, "response": response}
        if previous:
            payload["previousSendId"] = previous
        return test.api(fields, "calendar-rsvp", payload, "POST")

    def wait_for(source, state):
        for _ in range(80):
            current = detail(source["reference"])["calendar_rsvps"][0]["status"]
            if current and current["state"] == state:
                return current["decision"]["sendId"]
            time.sleep(0.15)
        raise AssertionError((state, current))

    def inbox_replies():
        replies = []
        with test.imap(organizer) as imap:
            assert imap.select("INBOX", readonly=True)[0] == "OK"
            status, ids = imap.uid("SEARCH", None, "ALL")
            assert status == "OK"
            for uid in ids[0].split():
                status, parts = imap.uid("FETCH", uid, "(BODY.PEEK[])")
                assert status == "OK"
                raw, = [part[1] for part in parts if isinstance(part, tuple)]
                message = BytesParser(policy=policy.default).parsebytes(raw)
                calendar, = [part for part in message.walk() if part.get_content_type() == "text/calendar"]
                assert calendar.get_param("method") == "REPLY" and calendar.get_content_charset() == "utf-8"
                assert message["From"].addresses[0].addr_spec == attendee
                assert message["To"].addresses[0].addr_spec == organizer
                assert not message.get("Reply-To")
                text = re.sub(r"\r?\n[ \t]", "", calendar.get_content())
                assert "METHOD:REPLY" in text and "UID:rsvp-series@example.test" in text
                assert f"ORGANIZER:mailto:{organizer}" in text
                assert text.count("ATTENDEE;") == 1 and f":mailto:{attendee}" in text
                assert 'TZID:Fixture/Studio' in text and "TZOFFSETTO:-0500" in text and "TZURL:" not in text
                assert "DESCRIPTION:" not in text
                replies.append(text)
        return replies

    first = invite("Verified RSVP occurrence")
    assert first["calendar_rsvps"] == [{"status": None, "availability": "current"}]
    assert respond(first, "accepted", revision=False)[0] == 428
    assert respond(first, "accepted", account=foreign)[0] == 404
    assert respond(first, "accepted", account={**session, "Origin": "https://unrelated.example.test"})[0] == 403
    forged = invite("Forwarded RSVP occurrence", author="forwarded@hosted.example.test")
    assert forged["calendar_rsvps"] == [None] and respond(forged, "accepted")[0] == 403
    uninvited = invite("Different attendee RSVP occurrence", invited="elsewhere@hosted.example.test")
    assert uninvited["calendar_rsvps"] == [None] and respond(uninvited, "accepted")[0] == 403
    cancelled = invite("Cancellation RSVP occurrence", method="CANCEL", series="other-series")
    assert cancelled["calendar_rsvps"] == [None] and respond(cancelled, "accepted")[0] == 403

    barrier = Barrier(2)

    def duplicate():
        barrier.wait()
        return respond(first, "accepted")

    with ThreadPoolExecutor(max_workers=2) as executor:
        left, right = [future.result() for future in (executor.submit(duplicate), executor.submit(duplicate))]
    assert left[0] == right[0] == 200, (left, right)
    first_id = wait_for(first, "sent")
    assert first_id == left[1]["decision"]["sendId"] == right[1]["decision"]["sendId"]
    accepted, = inbox_replies()
    assert "PARTSTAT=ACCEPTED" in accepted and 'RECURRENCE-ID;TZID="Fixture/Studio":20261124T090000' in accepted
    assert respond(first, "declined")[0] == 409  # A tab without the current receipt cannot reverse the decision.
    late = invite("Late earlier sequence RSVP", sequence=1, stamp="130000")
    assert respond(late, "declined")[1]["error"] == "invitation_stale"
    same_sequence = invite("Same sequence older RSVP", stamp="100000")
    assert respond(same_sequence, "accepted")[1]["error"] == "invitation_stale"

    updated = invite("Newer RSVP at same sequence", stamp="120000")
    status, queued = respond(updated, "tentative", first_id)
    assert status == 200, queued
    failed_id = wait_for(updated, "failed")
    assert failed_id == queued["decision"]["sendId"]
    outbox = test.api(session, "outbox/" + failed_id)[1]
    assert outbox["calendarRsvp"] and "Daily recipient allowance" in outbox["error"], outbox
    assert respond(updated, "tentative")[1]["decision"]["sendId"] == failed_id
    assert len(inbox_replies()) == 1
    test.provision("rsvp-attendee", daily=5)
    status, retried = respond(updated, "tentative", failed_id)
    assert status == 200, retried
    tentative_id = wait_for(updated, "sent")
    assert tentative_id != failed_id and tentative_id == retried["decision"]["sendId"]
    assert respond(updated, "tentative", failed_id)[1]["decision"]["sendId"] == tentative_id

    occurrence = invite("Another occurrence RSVP", occurrence="140000")
    assert respond(occurrence, "declined")[0] == 200
    decline_id = wait_for(occurrence, "sent")
    declines = [text for text in inbox_replies() if "PARTSTAT=DECLINED" in text]
    assert len(declines) == 1 and 'RECURRENCE-ID;TZID="Fixture/Studio":20261124T140000' in declines[0]
    print("Verified RSVPs over native HTTPS and IMAP, including all responses, organizer authorization, revision ordering, and quota-safe retries.")

    def availability(source):
        return detail(source["reference"])["calendar_rsvps"][0]["availability"]

    # Deliver the update before the attendee has responded to either request.
    series = "pending-update"
    initial = invite("Unanswered original request", series=series)
    latest = invite("Unanswered updated request", series=series, stamp="120000")
    late_copy = invite("Repeated original before answer", series=series)
    assert availability(initial) == availability(late_copy) == "superseded"
    assert availability(latest) == "current"
    assert respond(initial, "accepted")[1]["error"] == "invitation_stale"
    invite("Cancellation by a different organizer", series=series, sequence=4, method="CANCEL",
           author=other_organizer, sender=other_organizer)
    invite("Unverified organizer field on cancellation", series=series, sequence=5, method="CANCEL",
           sender=other_organizer)
    assert availability(latest) == "current"
    cancellation = invite("Cancellation before any response", series=series, sequence=3, method="CANCEL")
    assert availability(latest) == "cancelled"
    assert respond(latest, "accepted")[1]["error"] == "invitation_cancelled"
    for action in ("trash", "purge"):
        target = {field: cancellation[field] for field in ("uid", "folder", "reference", "revision")}
        status, result = test.api(session, "bulk", {"action": action, "messages": [target]})
        assert status == 200 and result["ok"], result
        if action == "trash":
            cancellation = detail(cancellation["reference"])
    assert test.api(session, "messages/ref/" + cancellation["reference"])[0] == 404
    assert availability(latest) == "cancelled"

    series = "pending-range-cancel"
    invite("Range cancelled first", series=series, sequence=4, method="CANCEL", occurrence="120000", future=True)
    before_range = invite("Occurrence before cancelled range", series=series, occurrence="100000")
    at_range = invite("Occurrence at cancelled range", series=series, occurrence="120000")
    after_range = invite("Occurrence inside cancelled range", series=series, occurrence="140000")
    assert [availability(item) for item in (before_range, at_range, after_range)] == ["current", "cancelled", "cancelled"]
    assert respond(after_range, "accepted")[1]["error"] == "invitation_cancelled"
    reopened = invite("Reopened occurrence inside range", series=series, sequence=5, occurrence="140000")
    assert availability(reopened) == "current"

    series = "pending-range-change"
    earlier = invite("Occurrence before changed range", series=series, occurrence="100000")
    changed = invite("Occurrence inside changed range", series=series, occurrence="140000")
    invite("Organizer changed a range", series=series, sequence=4, occurrence="120000", future=True)
    assert availability(earlier) == "current" and availability(changed) == "superseded"
    assert respond(changed, "accepted")[1]["error"] == "invitation_stale"

    series = "pending-series-cancel"
    invite("Entire series cancelled before request", series=series, sequence=4, method="CANCEL", occurrence=None)
    late_series = invite("Series request delivered after cancellation", series=series, sequence=3, occurrence=None)
    late_instance = invite("Series instance delivered after cancellation", series=series, sequence=3)
    assert availability(late_series) == availability(late_instance) == "cancelled"
    new_series = invite("Entire series reinstated", series=series, sequence=5, occurrence=None)
    assert availability(new_series) == "current" and availability(late_instance) == "cancelled"

    initial = invite("Reviewed series request", series="reviewed-series")
    assert test.api(session, "sender-review", {"setting": "enable"}, "PUT")[0] == 200
    held = invite("Held cancellation", series="reviewed-series", sequence=3, method="CANCEL", held=True)
    assert availability(initial) == "current"
    fields = {**session, "If-Match": held["revision"]}
    status, result = test.api(fields, "sender-review/decision", {
        "reference": held["reference"], "action": "allow", "apply_to_sender": True, "rule_revision": held["rule_revision"],
    }, "POST")
    assert status == 200, result
    for _ in range(80):
        if availability(initial) == "cancelled":
            break
        time.sleep(0.15)
    assert availability(initial) == "cancelled"
    assert test.api(session, "sender-review", {"setting": "disable"}, "PUT")[0] == 200

    obsolete = invite("Cancel earlier queued reply on restart", sequence=3, method="CANCEL")
    assert obsolete["calendar_invites"][0]["method"] == "cancel"
    print("Verified arrival order before RSVP, including verified sender boundaries, single instances, ranges, and whole-series cancellation.")

    def prepare_restart():
        # Model a restart after delivery and Sent filing but before receipt
        # acknowledgement. Also make another terminal Outbox row eligible for expiry.
        with sqlite3.connect(test.directory / "smtp.db") as db:
            db.execute("UPDATE webmail_records SET state='sending',payload=json_remove(payload,'$.result') "
                       "WHERE username=? AND kind='outbox' AND id=?", (attendee, tentative_id))
            db.execute("UPDATE webmail_records SET expires_at=1 WHERE username=? AND kind='outbox' AND id=?", (attendee, decline_id))
            # Replay an older, previously unadmitted Outbox attempt as if it
            # had stayed queued while the organizer's cancellation arrived.
            db.execute("UPDATE webmail_records SET state='pending',due_at=0,payload=json_set(payload,'$.calendarReply.body',?) "
                       "WHERE username=? AND kind='outbox' AND id=?", (accepted, attendee, failed_id))

    def after_restart():
        session.update(test.login(attendee))
        assert wait_for(updated, "sent") == tentative_id
        assert test.api(session, "outbox/" + decline_id)[0] == 404
        assert respond(occurrence, "declined")[1]["decision"]["sendId"] == decline_id
        assert respond(latest, "accepted")[1]["error"] == "invitation_cancelled"
        assert availability(late_instance) == "cancelled"
        for _ in range(80):
            obsolete_send = test.api(session, "outbox/" + failed_id)[1]
            if obsolete_send["state"] == "failed":
                break
            time.sleep(0.15)
        assert obsolete_send["state"] == "failed" and "cancelled" in obsolete_send["error"], obsolete_send
        assert test.count(attendee) == 3
        replies = inbox_replies()
        assert len(replies) == 3 and sum("PARTSTAT=TENTATIVE" in text for text in replies) == 1
        print("Verified RSVP delivery journal recovery, durable receipts after Outbox expiry, and no duplicate mail after restart.")

    return prepare_restart, after_restart


def check_mail_event_source(test, organizer):
    owner = test.provision("dav-linked-owner")
    session, guest = test.login(owner), test.login(organizer)
    for account in (session, guest):
        assert test.api(account, "sender-review", {"setting": "disable"}, "PUT")[0] == 200
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = organizer, owner, "Plan the review meeting"
    message.set_content("Private email body. Keep this out of the event.")
    with test.smtp(organizer) as smtp:
        assert smtp.send_message(message, to_addrs=[owner, organizer]) == {}
    query = urllib.parse.urlencode({"folder": "INBOX", "q": "Plan the review meeting"})
    msg, = test.api(session, "messages?" + query)[1]["items"]
    guest_msg, = test.api(guest, "messages?" + query)[1]["items"]
    assert msg["reference"] != guest_msg["reference"]
    source_path = "calendar-event-source?reference=" + msg["reference"]
    assert test.api(session, source_path) == (200, {"subject": "Plan the review meeting"})
    assert test.api(guest, source_path)[0] == 404 and test.api({}, source_path)[0] == 401
    assert test.api(session, "calendar-event-source?reference=bad")[0] == 404

    _, calendar = test.api(session, "calendars", {"name": "Email planning"})
    calendar_id = calendar["id"]
    team_command(test, "team", "create", "linked-calendar", "Linked Calendar", owner)
    team_command(test, "team", "member", "linked-calendar", organizer, "member")
    rights = {"calendarId": calendar_id, "grantee": organizer, "access": "editor"}
    assert test.api(session, "teams/linked-calendar/calendar-shares", rights, "PUT")[0] == 200
    header = {**session, "X-Webmail-Source-Message": msg["reference"]}
    guest_header = {**guest, "X-Webmail-Source-Message": guest_msg["reference"]}
    payload = {"calendarId": calendar_id, "summary": "Review meeting", "time": {"start": 1795532400, "end": 1795536000}}
    assert test.api(guest_header, "calendar-events", payload)[0] == 404
    assert test.api({**session, "X-Webmail-Source-Message": guest_msg["reference"]}, "calendar-events", payload)[0] == 404
    assert test.api({**header, "Origin": "https://foreign.example.test"}, "calendar-events", payload)[0] == 403
    assert test.api(session, f"calendar-events?calendarId={calendar_id}&q=Review")[1]["events"] == []
    with sqlite3.connect(test.env["CALDAV_DB_PATH"]) as db:
        db.execute("CREATE TRIGGER refuse_linked_event BEFORE INSERT ON dav_events WHEN NEW.source_message_ref IS NOT NULL "
                   "BEGIN SELECT RAISE(ABORT, 'fixture backlink failure'); END")
        db.commit()
        try:
            failed, error = test.api(header, "calendar-events", payload)
            assert failed == 500 and error["error"] == "calendar_storage_error", error
            assert test.api(session, f"calendar-events?calendarId={calendar_id}&q=Review")[1]["events"] == []
        finally:
            db.execute("DROP TRIGGER refuse_linked_event")
    status, created = test.api(header, "calendar-events", payload)
    assert status == 201, created
    event = "calendar-events/" + str(created["id"])
    status, detail = test.api(session, event + "?source=1")
    assert status == 200 and detail["source_message"] == msg["reference"]
    assert msg["reference"] not in detail["icalendar"] and "Private email body" not in detail["icalendar"]
    status, shared = test.api(guest, event + "?source=1")
    assert status == 200 and shared["source_message"] is None
    assert msg["reference"] not in json.dumps(shared)
    client = DavClient(test, owner)
    resource = f"/calendars/{owner}/Email%20planning/{created['uid']}.ics"
    dav_headers, content = must(client.request("GET", resource), 200)
    assert msg["reference"].encode() not in content and b"Private email body" not in content
    body = content.replace(b"SUMMARY:Review meeting", b"SUMMARY:Review completed")
    must(client.request("PUT", resource, body, {"Content-Type": "text/calendar", "If-Match": dav_headers["ETag"]}), 204)

    native = (b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:mail-backed-series\r\n"
              b"DTSTAMP:20261121T100000Z\r\nDTSTART:20261204T150000Z\r\nRRULE:FREQ=WEEKLY;COUNT=3\r\n"
              b"SUMMARY:Linked weekly review\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    status, _, raw = hosted.request(test.webmail + f"/webmail/api/calendar-events?calendarId={calendar_id}", native,
                                    {**header, "Content-Type": "text/calendar"}, "POST", test.tls_context)
    assert status == 201, raw
    series = "calendar-events/" + str(json.loads(raw)["id"])
    assert test.api(session, series)[1]["source_message"] == msg["reference"]
    export = hosted.request(test.webmail + f"/webmail/api/calendar-export?calendarId={calendar_id}", headers=session,
                            context=test.tls_context)
    assert export[0] == 200 and msg["reference"].encode() not in export[2] and b"RRULE:FREQ=WEEKLY;COUNT=3" in export[2]

    def verify_reopened():
        fresh = test.login(owner)
        detail = test.api(fresh, event)[1]
        assert detail["source_message"] == msg["reference"] and detail["event"]["summary"] == "Review completed"
        assert test.api(fresh, series)[1]["source_message"] == msg["reference"]
        message_path = "messages/ref/" + msg["reference"]
        old = test.api(fresh, message_path)[1]
        status, moved = test.api({**fresh, "If-Match": old["revision"]}, message_path, {"folder": "Archive"}, "PUT")
        assert status == 200 and moved["reference"] == msg["reference"]
        assert test.api(fresh, source_path) == (200, {"subject": "Plan the review meeting"})
        assert test.api(fresh, event)[1]["source_message"] == msg["reference"]
        status, trashed = test.api({**fresh, "If-Match": moved["revision"]}, message_path, {"folder": "Trash"}, "PUT")
        assert status == 200
        purged = test.api({**fresh, "If-Match": trashed["revision"]}, message_path, method="DELETE")
        assert purged[0] == 200 and purged[1]["ok"], purged
        assert test.api(fresh, source_path)[0] == 404
        assert test.api(fresh, event)[1]["source_message"] is None and test.api(fresh, series)[1]["source_message"] is None
        must(client.request("GET", resource), 200)
        print("Verified private message backlinks in native Calendar, including rollback, shared-editor denial, DAV edits, restart, move, and purge.")

    return verify_reopened


def check_invitation_calendar(test):
    attendee = test.provision("invite-calendar-owner")
    organizer = test.provision("invite-calendar-organizer", daily=50)
    different_organizer = test.provision("invite-other-organizer")
    session, sender_session = test.login(attendee), test.login(organizer)
    assert test.api(session, "sender-review", {"setting": "disable"}, "PUT")[0] == 200
    status, cal = test.api(session, "calendars", {"name": "Invitations"})
    assert status == 201, cal
    calendar_id = cal["id"]
    client = DavClient(test, attendee)
    collection = f"/calendars/{attendee}/Invitations/"
    uid = "organizer-series@example.test"

    def deliver(subject, sequence, *, method="REQUEST", occurrence=None, start=None, future=False, room="Studio", sender=organizer, offset="-0500",
                duration="DURATION:PT1H", recurrence_fields=("RRULE:FREQ=DAILY;COUNT=6",), daylight=()):
        tzid = "Fixture/Studio"
        recurrence = () if occurrence is None else (
            f"RECURRENCE-ID{';RANGE=THISANDFUTURE' if future else ''};TZID={tzid}:202611{occurrence}T090000",
        )
        dates = () if method == "CANCEL" else (
            f"DTSTART;TZID={tzid}:202611{occurrence or '23'}T{start or '090000'}", *((duration,) if duration else ()),
        )
        rule = recurrence_fields if method == "REQUEST" and occurrence is None else ()
        source = "\r\n".join((
            "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail//Invitation Calendar Fixture//EN", f"METHOD:{method}",
            "BEGIN:VTIMEZONE", f"TZID:{tzid}", "TZURL:https://unused.example.test/zone",
            "BEGIN:STANDARD", "DTSTART:19700101T000000", f"TZOFFSETFROM:{offset}", f"TZOFFSETTO:{offset}", "END:STANDARD",
            *daylight, "END:VTIMEZONE",
            "BEGIN:VEVENT", f"UID:{uid}", f"SEQUENCE:{sequence}", "DTSTAMP:20261121T100000Z",
            f"ORGANIZER:mailto:{sender}", f"ATTENDEE:mailto:{attendee}", "ATTENDEE:mailto:another@example.test",
            *recurrence, *dates, *rule, "SUMMARY:Studio shift", f"LOCATION:{room}", "URL:https://unused.example.test/event",
            "BEGIN:VALARM", "ACTION:DISPLAY", "TRIGGER:-PT5M", "DESCRIPTION:Organizer alarm", "END:VALARM", "END:VEVENT", "END:VCALENDAR", "",
        ))
        message = EmailMessage()
        message["From"], message["To"], message["Subject"] = sender, attendee, subject
        message.set_content(source, subtype="calendar", params={"method": method})
        with test.smtp(sender) as smtp:
            assert smtp.send_message(message) == {}
        query = urllib.parse.urlencode({"folder": "INBOX", "q": subject})
        row, = [row for row in test.api(session, "messages?" + query)[1]["items"] if row["subject"] == subject]
        return test.api(session, "messages/ref/" + row["reference"])[1]

    def apply(mail, event=None, *, account=None):
        fields = {**(session if account is None else account), "If-Match": mail["revision"]}
        data = {"reference": mail["reference"], "index": 0, "calendarId": calendar_id}
        if event:
            data["eventRevision"] = event["etag"]
        return test.api(fields, "calendar-invitation-event", data, "POST")

    def detail(event):
        status, body = test.api(session, f"calendar-events/{event['id']}?source=1")
        assert status == 200, body
        return body

    def action(mail):
        status, current = test.api(session, "messages/ref/" + mail["reference"])
        assert status == 200, current
        return current["calendar_invitation_events"][0]

    def busy(*expected, lengths=None):
        xml = f'<C:free-busy-query xmlns:C="{CALDAV}"><C:time-range start="20261123T000000Z" end="20261129T000000Z"/></C:free-busy-query>'
        _, data = must(client.request("REPORT", collection, xml, {"Content-Type": "application/xml", "Depth": "1"}), 200)
        periods = [line.split(":", 1)[1].split("/", 1) for line in data.decode().splitlines() if line.startswith("FREEBUSY;")]
        starts = [start for start, _ in periods]
        assert starts == list(expected), (starts, expected, data)
        if lengths is not None:
            def parse(date):
                return datetime.strptime(date, "%Y%m%dT%H%M%SZ")
            assert [(parse(end) - parse(start)).total_seconds() for start, end in periods] == lengths, data

    first = deliver("Original organizer series", 1)
    assert first["calendar_invitation_events"] == [{"target": None, "applied": False}]
    unrelated = collection + "other-client-filename.ics"
    same_uid = "\r\n".join((
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail//Unrelated Calendar fixture//EN",
        "BEGIN:VEVENT", f"UID:{uid}", "DTSTAMP:20261121T100000Z", "DTSTART:20261201T090000Z",
        "SUMMARY:Imported from another client", "END:VEVENT", "END:VCALENDAR", "",
    ))
    must(client.request("PUT", unrelated, same_uid, {"Content-Type": "text/calendar", "If-None-Match": "*"}), 201)
    status, conflict = apply(first)
    assert status == 409 and conflict["error"] == "event_exists", conflict
    must(client.request("DELETE", unrelated), 204)
    token, _ = sync_report(client, collection)
    assert apply(first, account=sender_session)[0] == 404
    status, event = apply(first)
    assert status == 201 and event["changed"], event
    token, members = sync_report(client, collection, token)
    path, = members
    assert members[path] == event["etag"]
    data = detail(event)
    assert data["source_message"] == first["reference"]
    assert "UID:" + uid in data["icalendar"] and "CLASS:PRIVATE" in data["icalendar"]
    for omitted in ("METHOD:", "another@example.test", "TZURL:", "URL:", "VALARM"):
        assert omitted not in data["icalendar"], omitted
    assert apply(first)[1] == {**event, "changed": False}
    target = {key: event[key] for key in ("id", "calendarId", "etag")}
    assert action(first) == {"target": target, "applied": True}
    busy(*(f"202611{day}T140000Z" for day in range(23, 29)))

    alarm = "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nDESCRIPTION:Personal reminder\r\nEND:VALARM\r\n"
    local = data["icalendar"].replace("END:VEVENT", alarm + "END:VEVENT", 1)
    fields, _ = must(client.request("PUT", path, local, {"Content-Type": "text/calendar", "If-Match": event["etag"]}), 204)
    update = deliver("Organizer updated an event", 2, room="New studio")
    assert update["calendar_invitation_events"] == [{"target": {**target, "etag": fields["ETag"]}, "applied": False}]
    assert apply(update, event)[0] == 412
    status, event = apply(update, {**event, "etag": fields["ETag"]})
    assert status == 200 and event["changed"], event
    assert detail(event)["event"]["location"] == "New studio"
    assert alarm in detail(event)["icalendar"]
    assert detail(event)["source_message"] == first["reference"]
    assert apply(first, event)[0] == 409
    foreign = deliver("An unrelated organizer used the same UID", 9, sender=different_organizer)
    assert foreign["calendar_invitation_events"] == [{"target": None, "applied": False}]
    assert apply(foreign)[1]["error"] == "event_exists"

    conflict = deliver("Organizer used a conflicting time zone", 3, occurrence=24, start="110000", offset="-1000")
    status, refusal = apply(conflict, event)
    assert status == 422 and refusal["error"] == "invitation_timezone", refusal
    busy(*(f"202611{day}T140000Z" for day in range(23, 29)))

    moved = deliver("Organizer moved Tuesday", 4, occurrence=24, start="110000")
    status, event = apply(moved, event)
    assert status == 200 and event["changed"], event
    busy("20261123T140000Z", "20261124T160000Z", *(f"202611{day}T140000Z" for day in range(25, 29)))

    shifted = deliver("Organizer shifted future occurrences", 5, occurrence=25, start="120000", future=True,
                      duration="DTEND;TZID=Fixture/Studio:20261125T140000")
    status, event = apply(shifted, event)
    assert status == 200 and event["changed"], event
    busy("20261123T140000Z", "20261124T160000Z", *(f"202611{day}T170000Z" for day in range(25, 29)))

    exact = deliver("Organizer moved Wednesday only at the range anchor", 6, occurrence=25, start="130000")
    status, event = apply(exact, event)
    assert status == 200 and event["changed"], event
    busy("20261123T140000Z", "20261124T160000Z", "20261125T180000Z", *(f"202611{day}T170000Z" for day in range(26, 29)),
         lengths=[3600, 3600, 3600, 7200, 7200, 7200])
    assert action(shifted)["applied"] and action(exact)["applied"]
    assert apply(shifted, event)[1] == {**event, "changed": False}
    _, projected = must(client.request("GET", path), 200)
    assert projected.count(b"RANGE=THISANDFUTURE") == 1 and b"20261126T090000" in projected
    assert projected.count(b"UID:" + uid.encode()) == 4

    cancelled = deliver("Organizer cancelled the new physical range anchor", 7, method="CANCEL", occurrence=26)
    status, event = apply(cancelled, event)
    assert status == 200, event
    busy("20261123T140000Z", "20261124T160000Z", "20261125T180000Z", "20261127T170000Z", "20261128T170000Z")

    end_range = deliver("Organizer cancelled the rest of the week", 8, method="CANCEL", occurrence=27, future=True)
    status, event = apply(end_range, event)
    assert status == 200, event
    busy("20261123T140000Z", "20261124T160000Z", "20261125T180000Z")
    assert action(shifted)["applied"]
    token, changes = sync_report(client, collection, token)
    assert changes == {path: event["etag"]}, changes
    print("Verified linked Calendar creation, local alarm preservation, CalDAV revisions, ordered updates and cancellations, and range anchor changes.")

    def after_restart():
        nonlocal event, uid
        session.update(test.login(attendee))
        assert detail(event)["source_message"] == first["reference"]
        assert must(client.request("GET", path), 200)[0]["ETag"] == event["etag"]
        sync_report(client, collection, token, status=403)
        resumed_token, members = sync_report(client, collection)
        assert members == {path: event["etag"]}, members
        busy("20261123T140000Z", "20261124T160000Z", "20261125T180000Z")
        reopened = deliver("Organizer reopened one occurrence of the cancelled range", 9, occurrence=27, start="113000")
        status, event = apply(reopened, event)
        assert status == 200 and event["changed"], event
        busy("20261123T140000Z", "20261124T160000Z", "20261125T180000Z", "20261127T163000Z")
        assert action(end_range)["applied"]
        whole = deliver("Organizer cancelled the series", 10, method="CANCEL")
        status, event = apply(whole, event)
        assert status == 200 and event["changed"], event
        assert detail(event)["event"]["status"] == "cancelled"
        assert action(whole)["applied"]
        assert apply(whole, event)[1] == {**event, "changed": False}
        assert apply(moved, event)[0] == 409
        busy()
        _, changes = sync_report(client, collection, resumed_token)
        assert changes == {path: event["etag"]}, changes
        assert must(client.request("GET", path), 200)[0]["ETag"] == event["etag"]

        uid = "period-series@example.test"
        source = deliver("Original series with explicit dates and exclusions", 1, recurrence_fields=(
            "RRULE:FREQ=DAILY;COUNT=6", "EXDATE;TZID=Fixture/Studio:20261125T090000",
            "RDATE;VALUE=PERIOD;TZID=Fixture/Studio:20261126T100000/PT2H",
        ))
        status, period = apply(source)
        assert status == 201, period
        later = deliver("Organizer shifted a range with a custom period", 2, occurrence=24, start="120000", future=True, duration=None)
        status, period = apply(later, period)
        assert status == 200, period
        # Replace the next regular slot as well, forcing the explicit period
        # to be materialized before the range can move to Friday.
        thursday = deliver("Organiser shifted Thursday individually", 3, occurrence=26, start="190000")
        status, period = apply(thursday, period)
        assert status == 200, period
        tuesday = deliver("Organiser shifted the original range anchor individually", 4, occurrence=24, start="080000")
        status, period = apply(tuesday, period)
        assert status == 200, period
        busy("20261123T140000Z", "20261124T130000Z", "20261126T180000Z", "20261127T000000Z",
             "20261127T170000Z", "20261128T170000Z", lengths=[3600, 3600, 7200, 3600, 3600, 3600])
        assert action(later)["applied"]
        friday = deliver("Organiser cancelled the projected Friday anchor", 5, method="CANCEL", occurrence=27)
        status, period = apply(friday, period)
        assert status == 200, period
        busy("20261123T140000Z", "20261124T130000Z", "20261126T180000Z", "20261127T000000Z",
             "20261128T170000Z", lengths=[3600, 3600, 7200, 3600, 3600])
        assert apply(deliver("Organiser cancelled the series with explicit dates", 6, method="CANCEL"), period)[0] == 200
        busy()

        uid = "daylight-series@example.test"
        daylight = ("BEGIN:DAYLIGHT", "DTSTART:20261126T020000", "TZOFFSETFROM:-0500", "TZOFFSETTO:-0400", "END:DAYLIGHT")
        status, crossing = apply(deliver("Original series crossing a daylight saving change", 1, daylight=daylight))
        assert status == 201, crossing
        shift = deliver("Organiser moved the range before the clock change", 2, occurrence=25, future=True, start="120000",
                        duration="DTEND;TZID=Fixture/Studio:20261125T143000", daylight=daylight)
        status, crossing = apply(shift, crossing)
        assert status == 200, crossing
        single = deliver("Organiser moved only the anchor before the clock change", 3, occurrence=25, start="113000", daylight=daylight)
        status, crossing = apply(single, crossing)
        assert status == 200, crossing
        busy("20261123T140000Z", "20261124T140000Z", "20261125T163000Z",
             *(f"202611{day}T160000Z" for day in range(26, 29)), lengths=[3600, 3600, 3600, 9000, 9000, 9000])
        print("Verified saved range projection after restart, exact reinstatement, RDATE periods, EXDATE, daylight saving changes, and stable CalDAV resource identity.")

    return after_restart


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


def configure_vdirsyncer(test, client, profiles, collections, executable, directory, discovery_path="/"):
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
        folder = local / urllib.parse.unquote(collection)
        folder.mkdir(parents=True)
        local_files.append((folder, ext))
        content += (f'\n[pair {kind}]\na = "{kind}_local"\nb = "{kind}_remote"\ncollections = ["from b"]\n'
                    f'\n[storage {kind}_local]\ntype = "filesystem"\npath = {json.dumps(str(local))}\n'
                    f'fileext = "{ext}"\n\n[storage {kind}_remote]\ntype = "{kind}"\n'
                    f'url = {json.dumps(f"https://{host}:{port}{discovery_path}")}\nusername = {json.dumps(client.mailbox)}\n'
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
    folder, extension = local[0]
    (folder.parent / "Outside projects").mkdir()
    run("discover")
    run("sync")
    file, = folder.glob("*" + extension)
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


def check_calendar_history(binary, previous=None):
    with tempfile.TemporaryDirectory(prefix="mail-calendar-history-", dir="/tmp") as directory:
        root = Path(directory)
        test = hosted.Fixture(previous or binary, root, staging=True)

        def deliver(subject, series, sequence, *, method="REQUEST", occurrence=None, future=False, sender=None):
            sender = sender or organizer
            recurrence = () if occurrence is None else (
                f"RECURRENCE-ID{';RANGE=THISANDFUTURE' if future else ''}:20261126T{occurrence}Z",
            )
            message = EmailMessage()
            message["From"], message["To"], message["Subject"] = sender, owner, subject
            message.set_content("\r\n".join((
                "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail//Calendar history fixture//EN", f"METHOD:{method}",
                "BEGIN:VEVENT", f"UID:{series}@example.test", "DTSTAMP:20261121T100000Z", f"SEQUENCE:{sequence}",
                f"ORGANIZER:mailto:{organizer}", f"ATTENDEE:mailto:{owner}", *recurrence,
                f"DTSTART:20261126T{occurrence or '090000'}Z", "END:VEVENT", "END:VCALENDAR", "",
            )), subtype="calendar", params={"method": method})
            with test.smtp(sender) as smtp:
                assert smtp.send_message(message) == {}
            query = urllib.parse.urlencode({"folder": "INBOX", "q": subject})
            row, = [item for item in test.api(session, "messages?" + query)[1]["items"] if item["subject"] == subject]
            return row

        def detail(mail):
            status, body = test.api(session, "messages/ref/" + mail["reference"])
            assert status == 200, body
            return body

        def queue_legacy(db, series, sequence, occurrence=None):
            uid = f"{series}@example.test"
            when = None
            recurrence = ()
            if occurrence:
                recurrence = (f"RECURRENCE-ID:20261126T{occurrence}Z",)
                wall = datetime.strptime("20261126" + occurrence, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
                when = {"wall": int(wall.timestamp()), "zone": "UTC", "all_day": False}
            key = hashlib.sha256(json.dumps({"organizer": organizer, "uid": uid, "occurrence": when},
                                             separators=(",", ":")).encode()).hexdigest()
            send_id = key[:32]
            reply = "\r\n".join((
                "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail//REPLY fixture//EN", "METHOD:REPLY",
                "BEGIN:VEVENT", f"UID:{uid}", "DTSTAMP:20261122T110000Z", f"SEQUENCE:{sequence}",
                f"ORGANIZER:mailto:{organizer}", f"ATTENDEE;PARTSTAT=ACCEPTED:mailto:{owner}", *recurrence,
                "END:VEVENT", "END:VCALENDAR", "",
            ))
            payload = {"message": {"to": [organizer], "subject": "Legacy RSVP", "text": "Legacy RSVP", "sendId": send_id},
                       "calendarReply": {"key": key, "attendee": owner, "body": reply}}
            decision = {"sequence": sequence, "dtstamp": int(datetime(2026, 11, 21, 10, tzinfo=timezone.utc).timestamp()),
                        "response": "accepted", "sendId": send_id}
            for kind, record_id, record in (("outbox", send_id, payload), ("calendar-rsvp", key, decision)):
                db.execute("INSERT INTO webmail_records(username,kind,id,payload,state,revision) VALUES (?,?,?,?, 'pending',1)",
                           (owner, kind, record_id, json.dumps(record)))
            return send_id

        with test.daemon():
            owner = test.provision("history-owner")
            organizer = test.provision("history-organizer")
            stranger = test.provision("history-stranger")
            session = test.login(owner)
            assert test.api(session, "sender-review", {"setting": "disable"}, "PUT")[0] == 200
            status, calendar = test.api(session, "calendars", {"name": "Calendar history"})
            assert status == 201, calendar
            latest = deliver("Updated invite archived before upgrade", "updated", 3)
            old = deliver("Older invite delivered out of order", "updated", 1)
            deliver("Cancellation by an unrelated authenticated sender", "updated", 99, method="CANCEL", sender=stranger)
            fields = {**session, "If-Match": latest["revision"]}
            assert test.api(fields, "messages/ref/" + latest["reference"], {"folder": "Archive"}, "PUT")[0] == 200
            cancelled = deliver("Initial series to cancel", "cancelled", 0)
            deliver("Entire series cancelled before upgrade", "cancelled", 2, method="CANCEL")
            before = deliver("Occurrence before the old range", "range", 0, occurrence="090000")
            inside = deliver("Occurrence inside the old range", "range", 0, occurrence="130000")
            deliver("Future range cancelled before upgrade", "range", 4, method="CANCEL", occurrence="120000", future=True)

        # A previous executable exercises the schema upgrade. The default
        # CI run also tests an empty ledger with unchecked message references.
        with sqlite3.connect(root / "smtp.db") as db:
            tracked = db.execute("SELECT 1 FROM sqlite_master WHERE name='mail_calendar_revisions'").fetchone()
            if tracked is None:
                print("Confirmed the previous Mail binary wrote the fixture without arrival tracking.")
            db.execute("DROP TABLE IF EXISTS mail_calendar_revisions")
            if "calendar_history_checked" in {row[1] for row in db.execute("PRAGMA table_info(mailbox_message_refs)")}:
                db.execute("UPDATE mailbox_message_refs SET calendar_history_checked=0")
            archived = db.execute("SELECT folder,verified_author FROM mailbox_message_refs WHERE reference=?", (latest["reference"],)).fetchone()
            assert archived == ("Archive", organizer), archived
            obsolete_reply = queue_legacy(db, "updated", 1)
            current_reply = queue_legacy(db, "range", 0, "090000")

        test.binary = binary

        def check_disposition(mail, expected, error=None):
            opened = detail(mail)
            assert not opened.get("calendar_history_pending"), opened
            assert opened["calendar_rsvps"][0]["availability"] == expected, opened
            if error:
                headers = {**session, "If-Match": opened["revision"]}
                params = {"reference": opened["reference"], "index": 0}
                assert test.api(headers, "calendar-rsvp", {**params, "response": "accepted"})[1]["error"] == error
                assert test.api(headers, "calendar-invitation-event", {**params, "calendarId": calendar["id"]})[1]["error"] == error

        with test.daemon():
            session = test.login(owner)
            check_disposition(old, "superseded", "invitation_stale")
            check_disposition(latest, "current")
            check_disposition(cancelled, "cancelled", "invitation_cancelled")
            check_disposition(before, "current")
            check_disposition(inside, "cancelled", "invitation_cancelled")
            for _ in range(80):
                rejected = test.api(session, "outbox/" + obsolete_reply)[1]
                sent = test.api(session, "outbox/" + current_reply)[1]
                if rejected["state"] != "pending" and sent["state"] == "sent":
                    break
                time.sleep(0.15)
            assert rejected["state"] == "failed" and "updated invitation" in rejected["error"], rejected
            assert sent["state"] == "sent", sent
            assert test.count(owner) == 1
            newest = deliver("Newer live delivery after the upgrade", "updated", 7)
            check_disposition(latest, "superseded", "invitation_stale")
            check_disposition(newest, "current")

        with sqlite3.connect(root / "smtp.db") as db:
            assert db.execute("SELECT COUNT(*) FROM mail_calendar_revisions").fetchone() == (6,)
            assert db.execute("SELECT COUNT(*) FROM mailbox_message_refs WHERE calendar_history_checked=0").fetchone() == (0,)
        with test.daemon():
            session = test.login(owner)
            check_disposition(newest, "current")
            check_disposition(old, "superseded", "invitation_stale")
            check_disposition(inside, "cancelled", "invitation_cancelled")
        print("Verified pre-tracking invitations across upgrade and restart, including archived revisions, cancellations, sender boundaries, queued RSVPs, and newer deliveries.")


def check_calendar_upgrade(binary, previous):
    with tempfile.TemporaryDirectory(prefix="mail-dav-upgrade-", dir="/tmp") as directory:
        root = Path(directory)
        test = hosted.Fixture(previous, root, staging=True)

        def deliver_scheduling(subject, method, sequence):
            message = EmailMessage()
            message["From"], message["To"], message["Subject"] = organizer, owner, subject
            message.set_content("\r\n".join((
                "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Mail upgrade fixture//EN", f"METHOD:{method}",
                "BEGIN:VEVENT", "UID:upgrade-invitation@example.test", "DTSTAMP:20261121T100000Z",
                f"SEQUENCE:{sequence}", f"ORGANIZER:mailto:{organizer}", f"ATTENDEE:mailto:{owner}",
                "DTSTART:20261126T100000Z", "END:VEVENT", "END:VCALENDAR", "",
            )), subtype="calendar", params={"method": method})
            with test.smtp(organizer) as smtp:
                assert smtp.send_message(message) == {}

        with test.daemon():
            owner = test.provision("upgrade-owner")
            organizer = test.provision("upgrade-organizer")
            owner_session = test.login(owner)
            assert test.api(owner_session, "sender-review", {"setting": "disable"}, "PUT")[0] == 200
            deliver_scheduling("Legacy calendar invitation", "REQUEST", 0)
            query = urllib.parse.urlencode({"folder": "INBOX", "q": "Legacy calendar invitation"})
            original, = test.api(owner_session, "messages?" + query)[1]["items"]
            client = DavClient(test, owner)
            resource = f"/calendars/{owner}/Legacy/old-path.ics"
            contact = f"/addressbooks/{owner}/Legacy/old-contact.vcf"
            alarm = datetime.fromtimestamp(int(time.time()) - 60, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            raw = (b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:legacy-event\r\n"
                   b"DTSTART:20261121T120000Z\r\nSUMMARY:Previous version\r\nX-MAIL-FIXTURE:keep\r\n"
                   b"BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Legacy display alarm\r\n"
                   b"TRIGGER;VALUE=DATE-TIME:" + alarm.encode() + b"\r\nEND:VALARM\r\n"
                   b"END:VEVENT\r\nEND:VCALENDAR\r\n")
            previous_headers, _ = must(client.request("PUT", resource, raw, {"Content-Type": "text/calendar"}), 201)
            vcard = b"BEGIN:VCARD\r\nVERSION:3.0\r\nUID:old-contact\r\nFN:Old Contact\r\nEND:VCARD\r\n"
            contact_headers, _ = must(client.request("PUT", contact, vcard, {"Content-Type": "text/vcard"}), 201)
            calendar, = test.api(test.login(owner), "calendars")[1]["calendars"]
            start = int(datetime(2026, 11, 21, 12, tzinfo=timezone.utc).timestamp())
            listing = f"calendar-events?calendarId={calendar['id']}&start={start}&end={start + 3600}"
            event, = test.api(test.login(owner), listing)[1]["events"]

        def schema():
            with sqlite3.connect(root / "caldav.db") as db:
                tables = ("dav_calendars", "dav_addressbooks", "dav_events")
                columns = {table: db.execute(f"PRAGMA table_info({table})").fetchall() for table in tables}
                other = db.execute("SELECT type, name, sql FROM sqlite_master WHERE name NOT IN (?, ?, ?) ORDER BY type, name", tables)
                return set(other), columns

        previous_schema, previous_columns = schema()
        test.binary = binary
        with test.daemon():
            session = test.login(owner)
            endpoint = "messages/ref/" + original["reference"]
            assert test.api(session, endpoint)[1]["calendar_rsvps"][0]["availability"] == "current"
            deliver_scheduling("Cancellation after mail upgrade", "CANCEL", 1)
            assert test.api(session, endpoint)[1]["calendar_rsvps"][0]["availability"] == "cancelled"
            assert test.api(session, listing)[1]["events"] == [event]
            reminders = test.api(session, "calendar-reminders")[1]["events"]
            assert [entry["id"] for entry in reminders] == [event["id"]]
            endpoint = test.webmail + f"/webmail/api/calendar-events/{event['id']}"
            head, _ = must(hosted.request(endpoint, headers=session, context=test.tls_context), 200)
            assert head["ETag"] == previous_headers["ETag"]
            headers = {**session, "If-Match": head["ETag"]}
            changed, _ = must(hosted.request(endpoint, {"summary": "Updated by new version"}, headers, "PATCH", test.tls_context), 200)
            assert changed["ETag"] != head["ETag"]

            for path in (resource, contact):
                collection = path.rsplit("/", 1)[0] + "/"
                patch = b'<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><D:displayname>Renamed legacy</D:displayname></D:prop></D:set></D:propertyupdate>'
                _, payload = must(client.request("PROPPATCH", collection, patch, {"Content-Type": "application/xml"}), 207)
                assert "200 OK" in ET.fromstring(payload).findtext(".//d:status", namespaces=DAV)
                _, payload = must(client.request("PROPFIND", collection, headers={"Depth": "0"}), 207)
                assert ET.fromstring(payload).findtext(".//d:displayname", namespaces=DAV) == "Renamed legacy"

        upgraded_schema, upgraded_columns = schema()
        assert previous_schema <= upgraded_schema
        assert {row[1] for row in upgraded_schema - previous_schema} <= {
            "dav_reminder_dismissals", "idx_dav_reminder_due", "sqlite_autoindex_dav_reminder_dismissals_1",
            "idx_dav_calendar_share_id",
        }
        for table, old_columns in previous_columns.items():
            new_columns = upgraded_columns[table]
            assert new_columns[:len(old_columns)] == old_columns
            expected = {"source_message_ref", "invitation_key", "invitation_revisions", "invitation_projections"} if table == "dav_events" else {"display_name"}
            assert expected <= {column[1] for column in new_columns}
        test.binary = previous
        with test.daemon():
            row, = test.api(test.login(owner), listing)[1]["events"]
            assert row["id"] == event["id"] and row["summary"] == "Updated by new version" and row["etag"] == changed["ETag"]
            _, data = must(client.request("GET", resource), 200)
            assert b"UID:legacy-event\r\n" in data and b"X-MAIL-FIXTURE:keep\r\n" in data
            headers, data = must(client.request("GET", contact), 200)
            assert headers["ETag"] == contact_headers["ETag"] and data == vcard
    print("Verified collection metadata migration and reopening event and contact URLs with the previous binary.")


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
                check_invitation_previews(test, owner, other)
                prepare_rsvp_restart, check_rsvp_restart = check_invitation_replies(test)
                check_saved_invitation = check_invitation_calendar(test)
                check_reopened_backlink = check_mail_event_source(test, other)
                check_calendar_download(test, owner, other)
                importer, calendar_id, submit = check_calendar_import(test, owner, other)
                editor, item, resource, revision = check_calendar_writes(test, other)
                dismissal = check_reminders(test, owner, other)
                check_saved_properties = check_collection_properties(test, owner, other, expected)
            prepare_rsvp_restart()
            with test.daemon():
                client = DavClient(test, owner)
                check_reopened_backlink()
                check_rsvp_restart()
                check_saved_invitation()
                check_saved_properties()
                print("Verified CalDAV and CardDAV metadata over HTTP and HTTPS, including rollback, concurrent reads, and restart.")
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
    check_calendar_history(args.binary.resolve(strict=True), args.upgrade_from.resolve(strict=True) if args.upgrade_from else None)
    if args.upgrade_from:
        check_calendar_upgrade(args.binary.resolve(strict=True), args.upgrade_from.resolve(strict=True))


if __name__ == "__main__":
    main()
