#!/usr/bin/env python3
"""Verify native shared Inbox routing, workflow, and grant isolation."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from email.message import EmailMessage
import json
from pathlib import Path
import runpy
import sqlite3
import tempfile
from threading import Barrier
from urllib.parse import quote

teams = runpy.run_path(str(Path(__file__).with_name("test-webmail-teams.py")))
limits = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture, command, expect = (teams[name] for name in ("Fixture", "command", "expect"))
request = limits["request"]
attachment = b"Shared inbox attachment \x00\xff"
subject = "Pending client review"


def user_id(db, mailbox):
    return str(db.execute("SELECT id FROM users WHERE username=?", (mailbox,)).fetchone()[0])


def grant(test, action, team, source, actor, scope="mailbox", resource=None):
    args = ("team", action, team, source, actor, scope)
    command(test, *(args if resource is None else args + (resource,)))


def seed(test, sender, studio, outsider):
    for start in range(0, 27, 5):
        with test.smtp(sender) as connection:
            for index in range(start, min(start + 5, 27)):
                message = EmailMessage()
                message["From"] = sender
                message["To"] = studio
                message["Subject"] = "Studio note " + str(index)
                message.set_content("Mail received at the shared address.")
                assert connection.send_message(message) == {}
    with test.smtp(sender) as connection:
        message = EmailMessage()
        message["From"] = sender
        message["To"] = studio
        message["Subject"] = subject
        message.set_content("Could someone review this copy by Thursday?")
        message.add_attachment(attachment, maintype="application", subtype="octet-stream", filename="review.bin")
        assert connection.send_message(message) == {}
    assert test.deliver(outsider, identity=sender, subject="Outside organization")[0] == 250


def open_message(test, session, path):
    return expect(test.api(session, path))


def patch(test, session, path, detail, action, assignee=None, stage=None):
    body = {"action": action, "revision": detail["workflow"]["revision"], "messageRevision": detail["revision"]}
    if assignee is not None:
        body["assignee"] = assignee
    if stage is not None:
        body["stageId"] = stage
    return test.api(session, path + "/workflow", body, method="PUT")


def verify(test, db, studio, first, second, observer, outsider, legacy=False):
    owner, alex, taylor, read_only, foreign = (test.login(mailbox) for mailbox in (studio, first, second, observer, outsider))
    studio_id = user_id(db, studio)
    root = f"shared-inboxes/studio/{studio_id}"
    separate = f"shared-inboxes/second-team/{studio_id}"
    empty = {"assignee": None, "stage": None, "resolved": False, "revision": 0, "changedBy": None, "changedAt": None, "action": None}
    if legacy:
        del empty["stage"]
    expect(test.api({}, "shared-inboxes"), 401)
    assert expect(test.api(alex, "config"))["sharedInboxesAvailable"]
    assert not expect(test.api(read_only, "config"))["sharedInboxesAvailable"]
    assert expect(test.api(read_only, "shared-inboxes")) == []
    assert expect(test.api(foreign, "shared-inboxes")) == []
    assert len(expect(test.api(owner, "shared-inboxes"))) == 2
    expect(test.api(foreign, root), 404)
    expect(test.api(read_only, root), 404)
    expect(test.api(alex, f"shared-inboxes/studio/{user_id(db, outsider)}"), 404)

    expect(test.api(owner, "drafts", {"subject": "Private draft", "text": "Owner only"}))
    stash = expect(test.api(owner, "messages?folder=Drafts"))["items"][0]
    expect(test.api(alex, root + "/messages/" + stash["reference"] + "?folder=Drafts"), 404)
    page = expect(test.api(alex, root + "?folder=Drafts"))
    assert page["total"] == 28 and page["more"] and len(page["items"]) == 25
    later = expect(test.api(alex, root + "?page=2"))
    assert later["page"] == 2 and len(later["items"]) == 3 and not later["more"]
    known = [item["message"]["reference"] for item in page["items"] + later["items"]]
    assert len(set(known)) == 28
    row, = [item for item in page["items"] if item["message"]["subject"] == subject]
    ref = row["message"]["reference"]
    path = root + "/messages/" + ref
    original = open_message(test, alex, path)
    assert original["workflow"] == empty and original["from"] == "sender@hosted.example.test"
    assert original["to"] == studio and "review this copy" in original["text"]
    assert {person["address"] for person in original["assignable"]} == {studio, first, second}
    assert original["hasAttachments"] and not original["attachments"] and not original["embedded_images"]
    expect(test.api(alex, "messages/ref/" + ref), 404)
    expect(test.api(foreign, path), 404)
    expect(test.api(alex, path, method="DELETE"), 404)
    expect(test.api(alex, path + "/attachments/0"), 403, "shared_attachment_forbidden")
    grant(test, "grant", "studio", studio, first, "attachments", ref)
    assert open_message(test, alex, path)["attachments"] == [{"filename": "review.bin", "size": len(attachment)}]
    assert not open_message(test, taylor, path)["attachments"]
    assert not open_message(test, alex, separate + "/messages/" + ref)["attachments"]
    download = path + "/attachments/0?revision=" + quote(original["revision"])
    status, headers, body = request(test.webmail + "/webmail/api/" + download, headers=alex, context=test.tls_context)
    assert status == 200 and body == attachment and headers["Cache-Control"] == "no-store"
    grant(test, "revoke", "studio", studio, first, "attachments", ref)
    expect(test.api(alex, download), 403, "shared_attachment_forbidden")

    expect(patch(test, dict(alex, Origin="https://foreign.example.test"), path, original, "resolve"), 403)
    expect(patch(test, {**alex, "X-Webmail-Account": second}, path, original, "resolve"), 409, "account_changed")
    expect(patch(test, alex, path, original, "assign", user_id(db, observer)), 409, "assignee_unavailable")
    start = Barrier(2)

    def assign(pair):
        session, mailbox = pair
        start.wait(timeout=5)
        return patch(test, session, path, original, "assign", mailbox)

    pairs = [(alex, user_id(db, first)), (taylor, user_id(db, second))]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(assign, pairs))
    assert sorted(response[0] for response in results) == [200, 409], results
    winner = first if results[0][0] == 200 else second
    current = open_message(test, alex, path)
    assert current["workflow"]["assignee"]["address"] == current["workflow"]["changedBy"] == winner
    assert current["workflow"]["revision"] == 1
    assert open_message(test, alex, separate + "/messages/" + ref)["workflow"] == empty

    with db:
        db.execute("""CREATE TRIGGER fixture_inbox_audit_failure BEFORE INSERT ON audit_log
                      WHEN NEW.action='team.inbox.resolve' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END""")
    expect(patch(test, alex, path, current, "resolve"), 500)
    assert open_message(test, taylor, path)["workflow"] == current["workflow"]
    with db:
        db.execute("DROP TRIGGER fixture_inbox_audit_failure")

    changed = expect(patch(test, alex, path, current, "resolve"))
    assert changed["resolved"] and changed["changedBy"] == first and changed["revision"] == 2
    expect(patch(test, taylor, path, current, "resolve"), 409, "shared_inbox_conflict")
    current = open_message(test, taylor, path)
    assert not expect(patch(test, taylor, path, current, "reopen"))["resolved"]
    current = open_message(test, alex, path)
    assert current["workflow"]["revision"] == 3
    grant(test, "revoke", "studio", studio, winner)
    removed, retained = (alex, taylor) if winner == first else (taylor, alex)
    expect(test.api(removed, path), 404)
    expect(patch(test, removed, path, current, "resolve"), 404)
    released = open_message(test, retained, path)
    assert not released["workflow"]["assignee"] and released["workflow"]["revision"] == 4
    assert released["workflow"]["action"] == "access_removed"
    expect(patch(test, retained, path, current, "resolve"), 409, "shared_inbox_conflict")

    owned = open_message(test, owner, "messages/ref/" + ref)
    assert not owned["flags"]["seen"] and not owned["flags"]["answered"]
    expected = {**owner, "If-Match": owned["revision"]}
    expect(test.api(expected, "messages/ref/" + ref, {"flags": {"flagged": True}}, method="PUT"))
    expect(patch(test, retained, path, released, "resolve"), 412, "revision_mismatch")
    current = open_message(test, retained, path)
    assert expect(patch(test, retained, path, current, "resolve"))["resolved"]
    events = db.execute("""SELECT action,actor,details FROM audit_log WHERE target_type='team_inbox_message'
                           AND target=? ORDER BY id""", (f"studio/{studio_id}/{ref}",)).fetchall()
    assert [event[0] for event in events] == ["team.inbox.assign", "team.inbox.resolve", "team.inbox.reopen", "team.inbox.resolve"]
    assert json.loads(events[0][2])["after"]["address"] == winner
    return path, ref, second if winner == first else first


def verify_stages(test, db, studio, retained, observer, outsider, sender):
    owner, teammate, colleague, foreign = (test.login(who) for who in (studio, retained, observer, outsider))
    studio_id = user_id(db, studio)
    root = f"shared-inboxes/studio/{studio_id}"
    settings = root + "/stages"
    separate = f"shared-inboxes/second-team/{studio_id}/stages"

    def configure(session, action, *, path=settings, **fields):
        return test.api(session, path, {"action": action, **fields}, method="PUT")

    def target(title):
        page = expect(test.api(owner, root))
        row, = [row for row in page["items"] if row["message"]["subject"] == title]
        return root + "/messages/" + row["message"]["reference"], row["workflow"]

    grant(test, "grant", "studio", studio, observer)
    assert expect(test.api(owner, settings)) == {"canManage": True, "items": []}
    assert expect(test.api(teammate, settings)) == {"canManage": False, "items": []}
    expect(test.api(foreign, settings), 404)
    expect(configure(teammate, "create", name="Cannot configure"), 403, "stage_admin_required")
    expect(configure({**owner, "Origin": "https://foreign.example.test"}, "create", name="Wrong origin"), 403)
    expect(configure(owner, "create", name="Invalid route", sender="Display name <billing@example.test>"), 400)
    expect(configure(owner, "create", name="Open\nReview"), 400)

    review, = expect(configure(owner, "create", name="Needs review", sender=sender))["items"]
    priority = expect(configure(owner, "create", name="Priority"))["items"][1]
    unverified = expect(configure(owner, "create", name="Verified only", sender=limits["EXTERNAL"]))["items"][2]
    other, = expect(configure(owner, "create", path=separate, name="Needs review"))["items"]
    assert other["id"] != review["id"]
    assert [row["sender"] for row in expect(test.api(teammate, settings))["items"]] == [None, None, None]
    expect(configure(owner, "create", name=" needs review "), 409, "stage_duplicate")
    expect(configure(owner, "create", name="Duplicate route", sender=sender.upper()), 409, "stage_duplicate")

    assert test.deliver(studio, identity=sender, subject="Routed project")[0] == 250
    assert test.deliver(studio, subject="Unverified outside mail")[0] == 250
    path, initial = target("Routed project")
    assert initial["stage"] == {"id": review["id"], "name": review["name"]} and initial["action"] == "route"
    assert target("Unverified outside mail")[1]["stage"] is None
    with test.imap(studio) as imap:
        assert imap.select("INBOX")[0] == "OK"
        assert imap.uid("SEARCH", None, "HEADER", "Subject", '"Routed project"')[1][0]
    ref = path.rsplit("/", 1)[1]
    assert open_message(test, owner, separate.removesuffix("/stages") + "/messages/" + ref)["workflow"]["stage"] is None
    message = open_message(test, teammate, path)
    expect(patch(test, teammate, path, message, "move", stage=other["id"]), 409, "stage_unavailable")
    barrier = Barrier(2)

    def move(session, stage):
        barrier.wait(timeout=5)
        return patch(test, session, path, message, "move", stage=stage)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(move, teammate, priority["id"]), pool.submit(move, colleague, None)]
        assert sorted(result.result()[0] for result in futures) == [200, 409]
    detail = open_message(test, owner, path)
    assert detail["workflow"]["revision"] == 2
    expect(patch(test, owner, path, detail, "move", stage=priority["id"]))
    detail = open_message(test, owner, path)
    expect(patch(test, owner, path, detail, "assign", user_id(db, retained)))
    detail = open_message(test, owner, path)
    assert detail["workflow"]["stage"]["id"] == priority["id"]
    with db:
        db.execute("""CREATE TRIGGER fixture_stage_audit_failure BEFORE INSERT ON audit_log
                      WHEN NEW.action='team.inbox.stage.retire' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END""")
    expect(configure(owner, "retire", id=priority["id"], revision=priority["revision"]), 500)
    assert open_message(test, owner, path)["workflow"] == detail["workflow"]
    with db:
        db.execute("DROP TRIGGER fixture_stage_audit_failure")
    expect(configure(owner, "retire", id=priority["id"], revision=priority["revision"]))
    expect(patch(test, teammate, path, detail, "move", stage=review["id"]), 409, "shared_inbox_conflict")
    after = open_message(test, owner, path)
    assert after["workflow"]["stage"] is None and after["workflow"]["assignee"]["address"] == retained
    assert after["workflow"]["action"] == "stage_retired"
    expect(patch(test, teammate, path, after, "move", stage=priority["id"]), 409, "stage_unavailable")
    expect(patch(test, teammate, path, after, "move", stage=review["id"]))
    grant(test, "revoke", "studio", studio, retained)
    expect(test.api(teammate, settings), 404)
    expect(patch(test, teammate, path, after, "move"), 404)
    latest = open_message(test, colleague, path)["workflow"]
    assert latest["assignee"] is None and latest["stage"]["id"] == review["id"] and latest["action"] == "access_removed"

    expect(configure(owner, "update", id=review["id"], revision=review["revision"], name="Editorial review"))
    expect(configure(owner, "retire", id=review["id"], revision=review["revision"]), 409, "stage_changed")
    assert test.deliver(studio, identity=sender, subject="Routing switched off")[0] == 250
    assert target("Routing switched off")[1]["stage"] is None
    assert open_message(test, colleague, path)["workflow"]["stage"]["name"] == "Editorial review"
    expect(configure(owner, "retire", id=unverified["id"], revision=unverified["revision"]))
    events = [action for action, in db.execute("SELECT action FROM audit_log WHERE action LIKE 'team.inbox.%'")]
    assert all(event in events for event in ("team.inbox.route", "team.inbox.move", "team.inbox.stage.create", "team.inbox.stage.update", "team.inbox.stage.retire"))
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--upgrade-from", type=Path)
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-shared-inbox-", dir="/tmp") as directory:
        root = Path(directory)
        candidate = options.binary.resolve(strict=True)
        test = Fixture(options.upgrade_from.resolve(strict=True) if options.upgrade_from else candidate, root, staging=True)
        with test.daemon(), closing(sqlite3.connect(root / "smtp.db")) as db:
            studio, alex, taylor, observer, outsider = (test.provision(name) for name in ("studio", "alex", "taylor", "observer", "outside"))
            sender = test.provision("sender", daily=100)
            command(test, "team", "create", "studio", "Studio", studio)
            for mailbox in (alex, taylor, observer):
                command(test, "team", "member", "studio", mailbox, "member")
            for mailbox in (alex, taylor):
                grant(test, "grant", "studio", studio, mailbox)
            command(test, "team", "create", "second-team", "Other workflow", studio)
            command(test, "team", "member", "second-team", alex, "member")
            grant(test, "grant", "second-team", studio, alex)
            seed(test, sender, studio, outsider)
            path, reference, retained = verify(test, db, studio, alex, taylor, observer, outsider, legacy=bool(options.upgrade_from))
        test.binary = candidate
        with test.daemon(), closing(sqlite3.connect(root / "smtp.db")) as db:
            owner, teammate = test.login(studio), test.login(retained)
            latest = open_message(test, teammate, path)
            assert latest["workflow"]["resolved"] and latest["workflow"]["revision"] == 5
            own_path = "messages/ref/" + reference
            current = open_message(test, owner, own_path)
            expect(test.api({**owner, "If-Match": current["revision"]}, own_path, {"folder": "Archive"}, method="PUT"))
            expect(test.api(teammate, path), 404)
            expect(patch(test, teammate, path, latest, "reopen"), 404)
            staged = verify_stages(test, db, studio, retained, observer, outsider, sender)
        with test.daemon():
            latest = open_message(test, test.login(observer), staged)["workflow"]
            assert latest["stage"]["name"] == "Editorial review" and latest["assignee"] is None
    print("Verified shared SMTP intake, paging, attachment gates, isolation, concurrent assignment, offboarding, audit rollback, restart, and folder scope over native HTTPS.")
    print("Verified stage configuration, routed SMTP, concurrent moves, retirement, and audit history.")


if __name__ == "__main__":
    main()
