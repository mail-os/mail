#!/usr/bin/env python3
"""Verify team calendar grants, private event isolation, and revocation."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import runpy
import sqlite3
import tempfile
from urllib.parse import quote, urlencode


SCRIPTS = Path(__file__).resolve().parent
teams = runpy.run_path(str(SCRIPTS / "test-webmail-teams.py"))
Fixture, command, expect = (teams[name] for name in ("Fixture", "command", "expect"))
DavClient = runpy.run_path(str(SCRIPTS / "test-dav-https.py"))["DavClient"]
CALENDAR = "Studio planning"
START = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())
END = int(datetime(2027, 1, 1, tzinfo=timezone.utc).timestamp())


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
    path = f"/calendars/{owner}/{quote(CALENDAR, safe='')}/{name}.ics"
    result = DavClient(test, owner).request("PUT", path, "\r\n".join(data), {"Content-Type": "text/calendar"})
    assert result[0] == expected, result


def change(test, session, calendar_id, grantee, access, team="studio"):
    return test.api(session, f"teams/{team}/calendar-shares", {
        "calendarId": calendar_id, "grantee": grantee, "access": access,
    }, "PUT")


def shares(test, session):
    return expect(test.api(session, "calendar-shares"))["shares"]


def event_query(calendar_id, **filters):
    return "calendar-events?" + urlencode(dict(calendarId=calendar_id, start=START, end=END,
                                              instances=1, **filters))


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
    owners = expect(test.api(captain, query))["events"]
    assert {event["summary"] for event in owners} == {"Roadmap", "Budget", "Confidential", "Public-series"}
    expect(test.api({}, "calendar-shares"), 401)
    expect(test.api(invited, query), 404)
    # The pre-existing generic grant is descriptive. It carries no calendar role.
    command(test, "team", "grant", "studio", owner, viewer, "calendar", str(calendar_id))
    assert shares(test, invited) == []
    expect(test.api(invited, query), 404)

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
    expect(change(test, captain, calendar_id, viewer, None))
    expect(change(test, captain, calendar_id, viewer, None))
    assert shares(test, invited) == []
    expect(test.api(invited, query), 404)

    expect(change(test, captain, calendar_id, viewer, "viewer"))
    command(test, "team", "member", "studio", viewer, "remove")
    expect(test.api(invited, "calendar-shares"), 401)
    command(test, "team", "member", "studio", viewer, "member")
    invited = test.login(viewer)
    assert shares(test, invited) == []
    expect(test.api(invited, query), 404)
    expect(change(test, captain, calendar_id, viewer, "viewer"))
    audit = db.execute("SELECT action FROM audit_log WHERE action LIKE 'team.calendar.%' ORDER BY id").fetchall()
    assert [action for (action,) in audit] == [
        "team.calendar.share", "team.calendar.share", "team.calendar.share", "team.calendar.revoke",
        "team.calendar.share", "team.calendar.share",
    ], audit
    return calendar_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-calendar-shares-") as scratch:
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
        with test.daemon(), closing(sqlite3.connect(directory / "smtp.db")) as db:
            owner, viewer, colleague, foreign = (test.provision(name) for name in ("owner", "viewer", "teammate", "elsewhere"))
            command(test, "team", "create", "studio", "Studio", owner)
            calendar_id = verify(test, db, owner, viewer, colleague, foreign)

        with test.daemon():
            invited = test.login(viewer)
            query = event_query(calendar_id)
            assert [item["access"] for item in shares(test, invited)] == ["viewer"]
            assert [row["summary"] for row in expect(test.api(invited, query))["events"]] == ["Roadmap"]
            path = f"/calendars/{owner}/{quote(CALENDAR, safe='')}"
            deleted = DavClient(test, owner).request("DELETE", path)
            assert deleted[0] == 204, deleted
            assert shares(test, invited) == []
            expect(test.api(invited, query), 404)

        with test.daemon():
            captain, invited = test.login(owner), test.login(viewer)
            assert create_calendar(test, captain) == calendar_id
            write_event(test, owner, "Replacement")
            assert shares(test, invited) == []
            expect(test.api(invited, event_query(calendar_id)), 404)

    print("Verified calendar share roles, private and recurring event isolation, live revocation, audit rollback, restart, and calendar ID reuse.")


if __name__ == "__main__":
    main()
