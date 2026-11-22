#!/usr/bin/env python3
"""Verify operator and native HTTPS team authorization against disposable mailboxes."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
import tempfile
from threading import Barrier

fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture = fixture["Fixture"]


def expect(response, status=200, code=None):
    assert response[0] == status, response
    if code:
        assert response[1]["error"] == code, response
    return response[1]


def command(test, *args, error=None):
    run = subprocess.run([str(test.binary), *args], env=test.env, cwd=test.directory,
                         text=True, capture_output=True, timeout=15)
    if error:
        assert run.returncode and error in run.stderr, (run.returncode, run.stderr)
    else:
        assert not run.returncode, run.stderr
    return run.stdout


def change(test, session, team, mailbox, role):
    return test.api(session, f"teams/{team}/members", {"mailbox": mailbox, "role": role}, method="PUT")


def verify(test, db, owner, admin, member, outsider):
    command(test, "team", "create", "studio", "Studio équipe", owner)
    command(test, "team", "create", "outside", "Outside", outsider)
    command(test, "team", "member", "studio", admin, "admin")
    command(test, "team", "member", "studio", member, "member")
    command(test, "team", "create", "studio", "Duplicate", owner, error="TeamAlreadyExists")
    command(test, "team", "revoke", "studio", owner, outsider, "sender", error="TeamMemberNotFound")
    show = json.loads(command(test, "team", "show", "studio"))
    assert show["team"]["name"] == "Studio équipe" and len(show["members"]) == 3
    captain, helper, colleague, foreign = (test.login(mailbox) for mailbox in (owner, admin, member, outsider))

    expect(test.api({}, "teams"), 401)
    assert expect(test.api(foreign, "teams")) == [{"id": "outside", "name": "Outside", "role": "owner"}]
    expect(test.api(foreign, "teams/studio"), 404, "team_not_found")
    expect(change(test, foreign, "studio", outsider, "owner"), 404, "team_not_found")
    expect(change(test, captain, "studio", outsider, "member"), 404, "team_member_not_found")
    expect(change(test, dict(captain, Origin="https://foreign.example.test"), "studio", member, None), 403)
    expect(change(test, {**captain, "X-Webmail-Account": outsider}, "studio", member, None), 409, "account_changed")
    expect(change(test, colleague, "studio", member, "owner"), 403, "team_forbidden")
    expect(change(test, helper, "studio", member, "admin"), 403, "team_forbidden")
    expect(change(test, helper, "studio", owner, None), 403, "team_forbidden")
    expect(change(test, captain, "studio", owner, None), 409, "last_team_owner")
    expect(change(test, captain, "studio", owner, "member"), 409, "last_team_owner")
    expect(test.api(captain, "teams/studio/members", {"mailbox": member}, method="PUT"), 400, "invalid_team_data")
    command(test, "user:local", "delete", owner, error="LastTeamOwner")
    expect(test.api(captain, "teams/studio"))

    sender = {"source": owner, "grantee": member, "scope": "sender", "allowed": True}
    calendar = {"source": member, "grantee": owner, "scope": "calendar", "resource": "studio-calendar", "allowed": True}
    def put(session, grant):
        return test.api(session, "teams/studio/grants", grant, method="PUT")
    expect(put(helper, sender), 403, "team_forbidden")
    expect(put(captain, dict(sender, grantee=outsider)), 404, "team_member_not_found")
    expect(put(captain, dict(sender, scope="calendar")), 400, "invalid_team_data")
    expect(put(captain, sender))
    expect(put(captain, sender))  # Idempotent retry produces no extra audit event.
    expect(put(colleague, calendar))
    summary = expect(test.api(colleague, "teams/studio"))
    assert summary["members"] == [{"mailbox": member, "role": "member", "enabled": True}]
    assert {grant["scope"] for grant in summary["grants"]} == {"calendar", "sender"}
    command(test, "team", "grant", "studio", admin, owner, "comments", "thread-reference")
    assert len(expect(test.api(colleague, "teams/studio"))["grants"]) == 2
    expect(put(helper, dict(sender, allowed=False)))
    expect(put(captain, sender))

    with db:
        db.execute("""CREATE TRIGGER fixture_audit_failure BEFORE INSERT ON audit_log
                      WHEN NEW.action='team.membership' BEGIN SELECT RAISE(ABORT,'fixture failure'); END""")
    expect(change(test, helper, "studio", member, None), 500)
    assert len(expect(test.api(colleague, "teams/studio"))["grants"]) == 2
    with db:
        db.execute("DROP TRIGGER fixture_audit_failure")
    expect(change(test, helper, "studio", member, None))
    expect(test.api(colleague, "teams"), 401)
    assert expect(test.api(test.login(member), "teams")) == []
    assert len(expect(test.api(captain, "teams/studio"))["grants"]) == 1
    command(test, "team", "member", "studio", member, "member")
    assert expect(test.api(test.login(member), "teams/studio"))["grants"] == []

    # Both owners attempt to leave. Exactly one can commit, across independent clients.
    expect(change(test, captain, "studio", admin, "owner"))
    helper = test.login(admin)
    start = Barrier(2)

    def leave(params):
        session, mailbox = params
        start.wait(timeout=5)
        return change(test, session, "studio", mailbox, None)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.map(leave, [(captain, owner), (helper, admin)])
    assert sorted([first[0], second[0]]) == [200, 409], (first, second)
    survivor = owner if first[0] == 409 else admin
    removed = admin if survivor == owner else owner
    assert expect(test.api(test.login(survivor), "teams"))[0]["role"] == "owner"
    assert expect(test.api(test.login(removed), "teams")) == []

    # The owner can survive account disablement as a designated role.
    # Replacing a lost owner remains possible for the self-hosted operator.
    test.provision(survivor.split("@")[0], enabled=False)
    expect(test.api(test.login(member), "teams/studio"))
    assert json.loads(command(test, "team", "show", "studio"))["members"]
    test.provision(survivor.split("@")[0], enabled=True)
    command(test, "team", "grant", "studio", survivor, member, "attachments", "stable-message-reference")
    command(test, "user:local", "delete", member)
    assert expect(test.api(test.login(survivor), "teams/studio"))["grants"] == []
    command(test, "user:local", "create", member, test.password, member)
    assert expect(test.api(test.login(member), "teams")) == []
    audit = db.execute("SELECT actor,action,target,details FROM audit_log WHERE target_type='team' ORDER BY id").fetchall()
    assert ("local-operator:" + str(os.geteuid()), "team.create", "studio") == audit[0][:3]
    assert any(row[0] == admin and row[1] == "team.membership" for row in audit)
    assert sum(action == "team.grant" and json.loads(details)["scope"] == "sender" for _, action, _, details in audit) == 2
    assert any(action == "team.account_deleted" and json.loads(details)["mailbox"] == member for _, action, _, details in audit)
    assert all(test.password not in details for _, _, _, details in audit)
    return survivor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-teams-", dir="/tmp") as directory:
        root = Path(directory)
        test = Fixture(args.binary.resolve(strict=True), root, staging=True)
        with test.daemon(), closing(sqlite3.connect(root / "smtp.db")) as db:
            accounts = [test.provision(name) for name in ("owner", "manager", "member", "outsider")]
            survivor = verify(test, db, *accounts)
            command(test, "team", "member", "studio", accounts[2], "member")
            command(test, "team", "grant", "studio", survivor, accounts[2], "search")
        command(test, "domain", "migrate", survivor.split("@")[1], "renamed.example.test", "--yes")
        with test.daemon():
            renamed = survivor.split("@")[0] + "@renamed.example.test"
            info = expect(test.api(test.login(renamed), "teams/studio"))
            assert info["team"]["role"] == "owner"
            assert info["grants"] == [{"source": renamed, "grantee": "member@renamed.example.test", "scope": "search", "resource": ""}]
    print("Verified team roles, last-owner races, grant isolation and cleanup, audit rollback, session revocation, and domain migration over native HTTPS.")


if __name__ == "__main__":
    main()
