#!/usr/bin/env python3
"""Verify approval for erasing shared source data through the native Mail workflow."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import runpy
import sqlite3
from tempfile import TemporaryDirectory

scripts = Path(__file__).resolve().parent
fixture = runpy.run_path(str(scripts / "test-hosted-erasure-dav.py"))
operator = runpy.run_path(str(scripts / "test-hosted-operator.py"))
portable = runpy.run_path(str(scripts / "test-mailbox-export.py"))
Fixture, cli, prepare, success = (fixture[key] for key in ("Fixture", "cli", "prepare", "success"))
expect_smtp = operator["expect_smtp"]
DavClient, put_dav, EVENT, command = (portable[key] for key in ("DavClient", "put_dav", "EVENT", "command"))


def verify(test):
    review = test.directory / "review.json"
    decision = test.directory / "decision.json"
    db_path = test.directory / "smtp.db"
    dav_path = test.directory / "caldav.db"
    team = "shared-erasure"

    def api(session, route, data=None, *, method=None, expected=200):
        status, body = test.api(session, route, data, method=method)
        assert status == expected, (route, status, body)
        return body

    def share(session, grantee, subject):
        row, = api(session, "messages?conversations=false")["items"]
        assert row["subject"] == subject, row
        selection = {"references": [row["reference"]], "downloads": False}
        preview = api(session, "thread-shares/preview", selection)
        return api(session, "thread-shares", {
            **selection, "team": team, "grantee": grantee, "digest": preview["digest"],
        }, expected=201)["id"]

    def step(name, *args):
        return cli(test, name, str(review), str(start), *map(str, args))

    def inspect(store, *args):
        return step("hosted-erasure-shared-release", store, *args)

    def refuse(result, error):
        assert result.returncode and not result.stdout and error in result.stderr, result

    def choose(plan, *, mode=0o600, **changes):
        decision.write_text(json.dumps({
            "version": 1, "scope_sha256": plan["scope_sha256"], "disposition": "release_source",
            "approval_reference": "synthetic-shared-case", **changes,
        }))
        decision.chmod(mode)
        return inspect(plan["scope"]["store"], decision)

    with test.daemon():
        owner, peer = [test.provision(name) for name in ("shared-source", "shared-peer")]
        command(test, "team", "create", team, "Shared erasure test", owner)
        command(test, "team", "member", team, peer, "member")
        command(test, "team", "grant", team, owner, peer, "mailbox")
        owner_session, peer_session = test.login(owner), test.login(peer)
        expect_smtp(test.deliver(owner, subject="Source thread"), 250)
        expect_smtp(test.deliver(peer, subject="Peer thread"), 250)
        outgoing = share(owner_session, peer, "Source thread")
        incoming = share(peer_session, owner, "Peer thread")
        assert api(peer_session, f"thread-shares/{outgoing}")["messages"]
        api(peer_session, f"thread-shares/{outgoing}/comments", {"text": "Peer decision record"}, expected=201)

        calendar = api(owner_session, "calendars", {"name": "Source"}, expected=201)["id"]
        owner_event = f"/calendars/{owner}/Source/shared.ics"
        put_dav(DavClient(test, owner), owner_event, "text/calendar", EVENT)
        api(owner_session, f"teams/{team}/calendar-shares",
            {"calendarId": calendar, "grantee": peer, "access": "viewer"}, method="PUT")
        assert any(item["calendarId"] == calendar for item in api(peer_session, "calendar-shares")["shares"])
        api(peer_session, "calendars", {"name": "Retained"}, expected=201)
        peer_event = f"/calendars/{peer}/Retained/shared.ics"
        put_dav(DavClient(test, peer), peer_event, "text/calendar", EVENT)

        _, _, start = prepare(test, "shared-source", review)
        mail = success(inspect("maildir"))
        dav = success(inspect("dav"))
        assert mail["requires_approval"] and dav["requires_approval"]
        assert mail["audit_id"] is None and dav["audit_id"] is None
        assert [row["share_id"] for row in mail["scope"]["current"]] == [outgoing]
        assert len(mail["scope"]["source_delegations"]) == 1
        with closing(sqlite3.connect(db_path)) as db:
            calendar_grant_id, = db.execute("SELECT calendar_share_id FROM mail_team_calendar_shares WHERE team_id=?", (team,)).fetchone()
        assert [row["share_id"] for row in dav["scope"]["current"]] == [calendar_grant_id]
        assert mail["scope_sha256"] != dav["scope_sha256"]

    root = test.directory / "mail" / owner
    def mail_bytes():
        return {item.relative_to(root): item.read_bytes() for item in root.rglob("*.eml*") if item.is_file()}

    same_bytes = mail_bytes()
    assert same_bytes
    refuse(step("hosted-erasure-maildir"), "ErasureSharedReleaseRequired")
    assert mail_bytes() == same_bytes
    refuse(choose(mail, mode=0o644), "ErasureSharedDecisionNotPrivate")
    refuse(choose(mail, disposition="retained_copy_verified"), "InvalidEnumTag")
    refuse(choose(mail, scope_sha256=dav["scope_sha256"]), "ErasureSharedScopeChanged")
    with closing(sqlite3.connect(db_path)) as db, db:
        assert db.execute("SELECT 1 FROM hosted_erasure_maildir_steps").fetchone() is None
        db.execute("""CREATE TRIGGER interrupt_approval BEFORE INSERT ON audit_log
                      WHEN NEW.action='hosted.erasure.shared.source_release'
                      BEGIN SELECT RAISE(ABORT,'interrupt shared approval'); END""")
    refuse(choose(mail), "StepFailed")
    refuse(step("hosted-erasure-maildir"), "ErasureSharedReleaseRequired")
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("DROP TRIGGER interrupt_approval")

    approved = success(choose(mail))
    assert approved["audit_id"] and success(choose(mail)) == approved
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("""CREATE TRIGGER interrupt_removal BEFORE UPDATE ON hosted_erasure_maildir_steps
                      WHEN NEW.phase='removing'
                      BEGIN SELECT RAISE(ABORT,'interrupt after staging the mailbox root'); END""")
    refuse(step("hosted-erasure-maildir"), "StepFailed")
    staged, = root.parent.glob(".hosted-erasure-*")
    assert not root.exists() and staged.is_dir()
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("DROP TRIGGER interrupt_removal")
        db.execute("UPDATE mail_team_thread_shares SET downloads=1 WHERE id=?", (outgoing,))
    refuse(step("hosted-erasure-maildir"), "ErasureSharedReleaseRequired")
    assert {item.relative_to(staged): item.read_bytes() for item in staged.rglob("*.eml*")} == same_bytes
    changed_mail = success(inspect("maildir"))
    assert changed_mail["scope"]["current"][0]["access"] == "read_and_download"
    assert success(choose(changed_mail))["audit_id"] != approved["audit_id"]
    receipt = success(step("hosted-erasure-maildir"))
    assert success(step("hosted-erasure-maildir")) == receipt and not staged.exists()

    def dav_rows(db):
        return db.execute("SELECT calendar_id, uid, summary FROM dav_events ORDER BY id").fetchall()

    with closing(sqlite3.connect(dav_path)) as db:
        before = dav_rows(db)
    refuse(step("hosted-erasure-dav", dav_path), "ErasureSharedReleaseRequired")
    with closing(sqlite3.connect(dav_path)) as db:
        assert dav_rows(db) == before

    assert success(choose(dav))["audit_id"] != approved["audit_id"]
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("UPDATE mail_team_calendar_shares SET access='editor' WHERE calendar_share_id=?", (calendar_grant_id,))
    refuse(step("hosted-erasure-dav", dav_path), "ErasureSharedReleaseRequired")
    with closing(sqlite3.connect(dav_path)) as db:
        assert dav_rows(db) == before
    refuse(choose(dav), "ErasureSharedScopeChanged")
    changed = success(inspect("dav"))
    assert changed["scope"]["reviewed"][0]["access"] == "viewer"
    assert changed["scope"]["current"][0]["access"] == "editor"
    assert success(choose(changed))["audit_id"]
    receipt = success(step("hosted-erasure-dav", dav_path))
    assert success(step("hosted-erasure-dav", dav_path)) == receipt

    with closing(sqlite3.connect(db_path)) as db:
        assert {row[0] for row in db.execute("SELECT id FROM mail_team_thread_shares")} == {incoming, outgoing}
        assert db.execute("SELECT text FROM mail_team_thread_comments WHERE share_id=?", (outgoing,)).fetchone() == ("Peer decision record",)
        assert db.execute("SELECT count(*) FROM mail_team_calendar_shares").fetchone() == (1,)
        assert db.execute("SELECT count(*) FROM audit_log WHERE action='hosted.erasure.shared.source_release'").fetchone() == (4,)

    with test.daemon():
        api(owner_session, "messages", expected=401)
        assert api(peer_session, "messages")["items"][0]["subject"] == "Peer thread"
        result = DavClient(test, peer).request("GET", peer_event)
        assert result[0] == 200 and b"BEGIN:VEVENT" in result[2], result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="mail-erasure-shared-release-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Verified shared source approval, rejected stale scope, audit rollback, and retained peer resources over TLS.")
