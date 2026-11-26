#!/usr/bin/env python3
"""Verify peer-owned copies from actual shared CalDAV before erasure."""

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import runpy
import sqlite3
from tempfile import TemporaryDirectory
from xml.etree import ElementTree

scripts = Path(__file__).resolve().parent
fixture = runpy.run_path(str(scripts / "test-hosted-erasure-dav.py"))
portable = runpy.run_path(str(scripts / "test-mailbox-export.py"))
Fixture, cli, prepare, success = (fixture[key] for key in ("Fixture", "cli", "prepare", "success"))
DavClient, put_dav, EVENT, command = (portable[key] for key in ("DavClient", "put_dav", "EVENT", "command"))
XML = {"d": "DAV:", "c": "urn:ietf:params:xml:ns:caldav"}


def shared_calendar(client):
    def find(path, depth):
        status, _, body = client.request("PROPFIND", path, headers={"Depth": str(depth)})
        assert status == 207, (path, status, body)
        return ElementTree.fromstring(body)

    principal = find("/", 0).findtext(".//d:current-user-principal/d:href", namespaces=XML)
    home, = [row.text for row in find(principal, 0).findall(".//c:calendar-home-set/d:href", XML)
             if row.text.startswith("/shared-calendars/")]
    alias, = [row.findtext("d:href", namespaces=XML) for row in find(home, 1).findall("d:response", XML)
              if row.find(".//d:resourcetype/c:calendar", XML) is not None]
    return alias


def verify(test):
    review = test.directory / "review.json"
    decision = test.directory / "decision.json"
    db_path = test.directory / "smtp.db"
    dav_path = test.directory / "caldav.db"
    team = "retained-calendar"

    def api(session, route, data=None, *, method=None, expected=200):
        status, body = test.api(session, route, data, method=method)
        assert status == expected, (route, status, body)
        return body

    def step(name, *args):
        return cli(test, name, str(review), str(start), *map(str, args))

    def refuse(result, error):
        assert result.returncode and not result.stdout and error in result.stderr, result

    def choose(*copies, without_copy=False):
        decision.write_text(json.dumps({
            "version": 1, "scope_sha256": scope["scope_sha256"],
            "disposition": "release_source" if without_copy else "release_source_with_calendar_copies",
            "approval_reference": "approved-retention-fixture",
            "retained_calendar_copies": list(copies),
        }))
        decision.chmod(0o600)
        return step("hosted-erasure-shared-release", "dav", decision)

    with test.daemon():
        owner = test.provision("copy-source")
        peer = test.provision("copy-peer")
        command(test, "team", "create", team, "Calendar survival fixture", owner)
        command(test, "team", "member", team, peer, "member")
        owner_session, peer_session = test.login(owner), test.login(peer)
        source = api(owner_session, "calendars", {"name": "Source"}, expected=201)["id"]
        free_busy = api(owner_session, "calendars", {"name": "Availability"}, expected=201)["id"]
        destination = api(peer_session, "calendars", {"name": "Retained"}, expected=201)["id"]
        extra = api(peer_session, "calendars", {"name": "Extra"}, expected=201)["id"]
        owner_dav, peer_dav = DavClient(test, owner), DavClient(test, peer)
        original = f"/calendars/{owner}/Source/portable-event.ics"
        private_path = f"/calendars/{owner}/Source/private-event.ics"
        retained = f"/calendars/{peer}/Retained/portable-event.ics"
        private = EVENT.replace(b"UID:portable-event", b"UID:private-event\r\nCLASS:PRIVATE")
        put_dav(owner_dav, original, "text/calendar", EVENT)
        put_dav(owner_dav, private_path, "text/calendar", private)
        route = f"teams/{team}/calendar-shares"
        api(owner_session, route, {"calendarId": source, "grantee": peer, "access": "viewer"}, method="PUT")
        api(owner_session, route, {"calendarId": free_busy, "grantee": peer, "access": "free_busy"}, method="PUT")
        alias = shared_calendar(peer_dav)
        status, _, public_copy = peer_dav.request("GET", alias + "portable-event.ics")
        assert status == 200 and b"RRULE:FREQ=WEEKLY;COUNT=3" in public_copy
        assert peer_dav.request("GET", alias + "private-event.ics")[0] == 404
        put_dav(peer_dav, retained, "text/calendar", public_copy)
        put_dav(peer_dav, f"/calendars/{peer}/Extra/portable-event.ics", "text/calendar", public_copy)
        # The verifier requires a dedicated calendar with the exact visible
        # contents. Even an extra synthetic private event causes refusal.
        put_dav(peer_dav, f"/calendars/{peer}/Extra/private-event.ics", "text/calendar", private)

        _, _, start = prepare(test, "copy-source", review)
        scope = success(step("hosted-erasure-shared-release", "dav"))
        grants = {grant["access"]: grant for grant in scope["scope"]["current"]}
        assert set(grants) == {"viewer", "free_busy"}
        copy = {"source_share_id": grants["viewer"]["share_id"],
                "peer_user_id": grants["viewer"]["peer_user_id"], "destination_calendar_id": destination}

    def erase():
        return step("hosted-erasure-dav", dav_path)

    success(step("hosted-erasure-maildir"))
    legacy = success(choose(without_copy=True))
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("UPDATE audit_log SET details=json_remove(details,'$.retained_calendar_copies') WHERE id=?", (legacy["audit_id"],))
    assert success(choose(without_copy=True)) == legacy
    with closing(sqlite3.connect(dav_path)) as dav, dav:
        # Match the marker schema already written by older native releases.
        dav.execute("""CREATE TABLE IF NOT EXISTS dav_erasure_receipts (
            nonce TEXT PRIMARY KEY,native_user_id INTEGER NOT NULL,dav_owner_id INTEGER,
            max_owner INTEGER NOT NULL,max_calendar INTEGER NOT NULL,max_event INTEGER NOT NULL,
            max_book INTEGER NOT NULL,max_contact INTEGER NOT NULL)""")
    refuse(choose(), "InvalidErasureSharedDecision")
    refuse(choose(dict(copy, source_share_id=grants["free_busy"]["share_id"])), "ErasureCalendarCopyNotAuthorized")
    refuse(choose(copy, copy), "InvalidErasureSharedDecision")

    success(choose(dict(copy, destination_calendar_id=source)))
    refuse(erase(), "ErasureCalendarCopyOwnershipUnresolved")
    success(choose(dict(copy, destination_calendar_id=extra)))
    refuse(erase(), "ErasureCalendarCopyMismatch")
    approval = success(choose(copy))
    assert success(choose(copy)) == approval
    with closing(sqlite3.connect(dav_path)) as dav, dav:
        assert dav.execute("SELECT count(*) FROM dav_events WHERE calendar_id=?", (source,)).fetchone() == (2,)
        uid, saved = dav.execute("SELECT uid,ics_data FROM dav_events WHERE calendar_id=?", (destination,)).fetchone()
        timezone, = dav.execute("SELECT timezone FROM dav_calendars WHERE id=?", (destination,)).fetchone()
        fields = (timezone.encode(), uid.encode(), public_copy)
        expected_sha = hashlib.sha256(b"".join(len(value).to_bytes(8, "big") + value for value in fields)).hexdigest()
        dav.execute("UPDATE dav_events SET ics_data=replace(ics_data,'Portable calendar event','Different data') WHERE calendar_id=?", (destination,))
    refuse(erase(), "ErasureCalendarCopyMismatch")
    with closing(sqlite3.connect(dav_path)) as dav, dav:
        assert dav.execute("SELECT count(*) FROM dav_events WHERE calendar_id=?", (source,)).fetchone() == (2,)
        dav.execute("UPDATE dav_events SET ics_data=? WHERE calendar_id=?", (saved, destination))
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("UPDATE users SET enabled=0 WHERE id=?", (copy["peer_user_id"],))
    refuse(erase(), "ErasureCalendarCopyPeerUnavailable")
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("UPDATE users SET enabled=1 WHERE id=?", (copy["peer_user_id"],))
        db.execute("""CREATE TRIGGER interrupt_receipt BEFORE INSERT ON audit_log
                      WHEN NEW.action='hosted.erasure.dav.removed'
                      BEGIN SELECT RAISE(ABORT,'interrupt final receipt'); END""")
    refuse(erase(), "StepFailed")
    with closing(sqlite3.connect(dav_path)) as dav:
        assert dav.execute("SELECT count(*) FROM dav_events WHERE calendar_id=?", (source,)).fetchone() == (0,)
        marker, = dav.execute("SELECT retained_copy_proof FROM dav_erasure_receipts").fetchone()
        proof = json.loads(marker)
        assert proof["approval_audit_id"] == approval["audit_id"]
        verified, = proof["copies"]
        assert verified["copy"] == copy and verified["resources"] == 1
        assert verified["resources_sha256"] == expected_sha
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("DROP TRIGGER interrupt_receipt")
        saved_approval, = db.execute("SELECT details FROM audit_log WHERE id=?", (approval["audit_id"],)).fetchone()
        db.execute("UPDATE audit_log SET details=json_remove(details,'$.retained_calendar_copies') WHERE id=?", (approval["audit_id"],))
    refuse(erase(), "InvalidErasureJournal")
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("UPDATE audit_log SET details=? WHERE id=?", (saved_approval, approval["audit_id"]))
    receipt = success(erase())
    assert success(erase()) == receipt
    with closing(sqlite3.connect(db_path)) as db:
        details, = db.execute("SELECT details FROM audit_log WHERE id=?", (receipt["audit_id"],)).fetchone()
        assert json.loads(details)["retained_calendar_copy_proof"] == proof
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("""UPDATE audit_log SET details=json_set(details,'$.retained_calendar_copy_proof.approval_audit_id',?)
                      WHERE id=?""", (legacy["audit_id"], receipt["audit_id"]))
    refuse(step("hosted-erasure-shared-sqlite"), "ErasureSharedScopeChanged")
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("UPDATE audit_log SET details=? WHERE id=?", (details, receipt["audit_id"]))
    sqlite_plan = success(step("hosted-erasure-shared-sqlite"))["plan"]
    assert sqlite_plan["releases"]["calendar"] == approval["audit_id"]
    assert sqlite_plan["removed"]["calendars"] == 2
    decision.write_text(json.dumps({"version": 1, "scope_sha256": sqlite_plan["scope_sha256"],
                                    "approval_reference": "fixture-retained-calendar-release"}))
    sqlite_receipt = success(step("hosted-erasure-shared-sqlite", decision))
    assert success(step("hosted-erasure-shared-sqlite", decision)) == sqlite_receipt
    assert sqlite_receipt["receipt"]["calendar_release_audit_id"] == approval["audit_id"]
    assert success(erase()) == receipt
    with closing(sqlite3.connect(db_path)) as db:
        assert not db.execute("SELECT 1 FROM mail_team_calendar_shares").fetchone()
        assert not db.execute("SELECT 1 FROM mail_team_calendar_share_epochs").fetchone()
    with test.daemon():
        status, _, restored = peer_dav.request("GET", retained)
        assert status == 200 and restored == public_copy
        assert peer_dav.request("GET", f"/calendars/{peer}/Retained/private-event.ics")[0] == 404
        assert owner_dav.request("GET", original)[0] == 401


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="mail-erasure-calendar-copy-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Verified peer-owned Calendar copy, excluded private data, stale and unauthorized refusal, and replay after DAV commit.")
