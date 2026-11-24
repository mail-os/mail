#!/usr/bin/env python3
"""Verify paid-domain invitations through native HTTPS and team grants."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import os
from pathlib import Path
import runpy
import secrets
import sqlite3
import subprocess
import tempfile
from threading import Barrier
import time
from urllib.parse import urlencode

HERE = Path(__file__).resolve().parent
support = runpy.run_path(str(HERE / "test-webmail-teams.py"))
Fixture, command, expect = support["Fixture"], support["command"], support["expect"]
primary, hosted, foreign = "hosted.example.test", "studio.example.test", "other.example.test"
endpoint = "team-invitations"


def paid_mailbox(test, name, domain=hosted, *, read_only=False):
    mailbox = f"{name}@{domain}"
    now = int(time.time())
    assignment = {
        "mailbox": mailbox, "actor": secrets.token_hex(16), "operation_id": secrets.token_hex(16),
        "revision": 1, "quota_bytes": 1024 * 1024, "enabled": True,
        "initial_password": test.password, "initial_recovery": f"{name}@recovery.example.test",
        "access_window": {"service_until": now + (-30 if read_only else 3600), "read_until": now + 7200},
    }
    status, _, raw = test.http(test.private + "/provisioning/v1/mailbox", assignment, test.auth)
    assert status == 200 and json.loads(raw)["mailbox"] == mailbox, (status, raw)
    test.specs[mailbox] = assignment
    return mailbox


def verify_hosted_teams(test, db):
    address = paid_mailbox(test, "new-studio")
    other_domain = paid_mailbox(test, "new-studio", foreign)
    service = paid_mailbox(test, "native-service", primary)
    paused = paid_mailbox(test, "retired-owner", read_only=True)
    url = test.private + "/provisioning/v1/team"

    def request(mailbox, name=None, *, actor=None, headers=None):
        query = {"mailbox": mailbox, "actor": actor or test.specs[mailbox]["actor"]}
        if name is None:
            response = test.http(url + "?" + urlencode(query), headers=test.auth if headers is None else headers)
        else:
            response = test.http(url, dict(query, name=name), test.auth if headers is None else headers)
        return response[0], json.loads(response[2])

    expect(request(address, headers={}), 401, "unauthorized")
    expect(request(address, "Studio", headers=dict(test.auth, Origin=test.webmail)), 401, "unauthorized")
    expect(request(address, "Studio", actor=test.specs[other_domain]["actor"]), 404, "mailbox_not_found")
    expect(request(service, "Service"), 409, "team_domain_unavailable")
    expect(request(paused, "Retired"), 404, "mailbox_not_found")
    expect(request(address, "界" * 34), 400, "invalid_request")
    assert expect(request(address)) == {"team": None, "created": False, "can_invite": False}
    assert expect(request(other_domain)) == {"team": None, "created": False, "can_invite": False}

    db.execute("""CREATE TRIGGER reject_hosted_team_audit BEFORE INSERT ON audit_log
                  WHEN NEW.action='team.create' BEGIN SELECT RAISE(ABORT,'fixture failure'); END""")
    expect(request(address, "Studio"), 503, "provisioning_unavailable")
    assert expect(request(address))["team"] is None
    db.execute("DROP TRIGGER reject_hosted_team_audit")

    gate = Barrier(2)

    def create(name):
        gate.wait(timeout=3)
        return request(address, name)

    with ThreadPoolExecutor(max_workers=2) as pool:
        rows = sorted(pool.map(create, ("Studio East", "Studio West")), key=lambda row: row[0])
    assert [row[0] for row in rows] == [200, 201]
    authority = rows[1][1]["team"]
    assert rows[0][1]["team"] == authority and authority["domain"] == hosted
    assert expect(request(address))["team"] == authority
    assert expect(request(other_domain))["team"] is None
    owner, = expect(test.api(test.login(address), "teams"))
    assert owner == {"id": authority["id"], "name": authority["name"], "role": "owner"}
    assert expect(test.api(test.login(other_domain), "teams")) == []
    other_team = expect(request(other_domain, "Other Team"), 201)["team"]
    assert other_team["id"] != authority["id"] and other_team["domain"] == foreign
    assert expect(request(address))["team"] == authority
    assert db.execute("SELECT count(*) FROM mail_hosted_teams").fetchone()[0] == 2
    assert db.execute("SELECT count(*) FROM audit_log WHERE action='team.create' AND target=?", (authority["id"],)).fetchone()[0] == 1
    colleague = test.login(paid_mailbox(test, "new-studio-peer"))
    expect(send(test, test.login(address), f"new-studio-peer@{hosted}", authority["id"]))
    invitation, = incoming(test, colleague)
    expect(decide(test, colleague, invitation["id"], "accept"))
    assert expect(test.api(colleague, "teams")) == [{"id": authority["id"], "name": authority["name"], "role": "member"}]

    mailbox = f"invite-bootstrap@{hosted}"
    instant = int(time.time())
    joint = {
        "mailbox": mailbox, "actor": secrets.token_hex(16), "operation_id": secrets.token_hex(16),
        "revision": 1, "quota_bytes": 1024 * 1024, "enabled": True,
        "initial_password": test.password, "initial_recovery": "invite-bootstrap@recovery.example.test",
        "access_window": {"service_until": instant + 3600, "read_until": instant + 7200},
        "team_invitation": {"team": authority["id"], "owner": address, "owner_actor": test.specs[address]["actor"]},
    }

    def provision_invitee(change, status, code=None):
        response = test.http(test.private + "/provisioning/v1/mailbox", change, test.auth)
        return expect((response[0], json.loads(response[2])), status, code)

    wrong = dict(joint, team_invitation=dict(joint["team_invitation"], owner_actor=test.specs[other_domain]["actor"]))
    provision_invitee(wrong, 409, "team_invitation_unavailable")
    db.execute("""CREATE TRIGGER reject_invited_membership BEFORE INSERT ON audit_log
                  WHEN NEW.action='team.membership' BEGIN SELECT RAISE(ABORT,'fixture failure'); END""")
    provision_invitee(joint, 503, "provisioning_unavailable")
    assert db.execute("SELECT count(*) FROM users WHERE username=?", (mailbox,)).fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM provisioned_mailboxes WHERE mailbox=?", (mailbox,)).fetchone()[0] == 0
    db.execute("DROP TRIGGER reject_invited_membership")
    assert provision_invitee(joint, 200)["mailbox"] == mailbox
    invited = test.login(mailbox)
    assert expect(test.api(invited, "teams")) == [{"id": authority["id"], "name": authority["name"], "role": "member"}]
    assert expect(test.api(invited, "shared-inboxes")) == []
    command(test, "team", "member", authority["id"], mailbox, "remove")
    assert provision_invitee(joint, 200)["mailbox"] == mailbox
    assert expect(test.api(test.login(mailbox), "teams")) == []
    return address, authority


def send(test, session, recipient, team="studio"):
    return test.api(session, endpoint, {"action": "invite", "team": team, "recipient": recipient})


def decide(test, session, invitation, action):
    return test.api(session, endpoint, {"action": action, "id": invitation})


def incoming(test, session):
    return expect(test.api(session, endpoint))["incoming"]


def verify(test, db):
    owner = paid_mailbox(test, "owner")
    admin = paid_mailbox(test, "admin-user")
    recipient = paid_mailbox(test, "first-member")
    alternative = paid_mailbox(test, "backup-owner")
    outside = paid_mailbox(test, "first-member", foreign)
    expired = paid_mailbox(test, "read-only", read_only=True)
    primary_user = paid_mailbox(test, "shared-domain-user", primary)
    command(test, "team", "create", "studio", "Design Studio", owner)
    command(test, "team", "create", "outside", "Other Studio", outside)
    command(test, "team", "create", "primary", "Service Domain", primary_user)
    command(test, "team", "member", "studio", admin, "admin")
    command(test, "team", "member", "studio", alternative, "owner")
    captain, manager, member, outsider = (test.login(mailbox) for mailbox in (owner, admin, recipient, outside))
    expect(test.api({}, endpoint), 401, "unauthorized")
    unscoped = test.login(primary_user)
    assert expect(test.api(unscoped, endpoint)) == {"incoming": [], "sent": [], "teams": []}
    expect(send(test, unscoped, recipient, "primary"), 409, "team_invites_unavailable")
    expect(send(test, manager, recipient), 403, "team_forbidden")
    expect(send(test, outsider, recipient), 404, "team_not_found")
    for address in [outside, f"unknown@{hosted}", expired]:
        expect(send(test, captain, address), 404, "team_invitee_unavailable")
    expect(send(test, dict(captain, Origin="https://elsewhere.example.test"), recipient), 403, "forbidden")
    assert expect(test.api(captain, endpoint))["teams"][0]["id"] == "studio"
    assert expect(test.api(member, "teams")) == []

    expect(send(test, captain, recipient.upper()))
    invite, = incoming(test, member)
    invitation = invite["id"]
    assert invite["inviter"] == owner and invite["recipient"] == recipient and invite["team_name"] == "Design Studio"
    expect(send(test, captain, recipient))
    assert incoming(test, member) == [invite]
    assert incoming(test, outsider) == []
    expect(decide(test, outsider, invitation, "accept"), 404, "team_invitation_not_found")
    expect(decide(test, member, invitation, "revoke"), 404, "team_invitation_not_found")

    db.execute("""CREATE TRIGGER stop_invite_audit BEFORE INSERT ON audit_log
                   WHEN NEW.action='team.invitation_decided' BEGIN SELECT RAISE(ABORT,'fixture failure'); END""")
    assert decide(test, member, invitation, "accept")[0] >= 500
    assert expect(test.api(member, "teams")) == []
    assert incoming(test, member) == [invite]
    db.execute("DROP TRIGGER stop_invite_audit")

    gate = Barrier(2)

    def accept(_):
        gate.wait(timeout=3)
        return decide(test, member, invitation, "accept")[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(accept, range(2))) == [200, 404]
    assert incoming(test, member) == []
    assert expect(test.api(member, "teams")) == [{"id": "studio", "name": "Design Studio", "role": "member"}]
    assert expect(test.api(member, "shared-inboxes")) == []
    expect(send(test, captain, recipient), 409, "team_already_joined")
    command(test, "team", "grant", "studio", owner, recipient, "mailbox")
    inbox, = expect(test.api(member, "shared-inboxes"))
    assert inbox["address"] == owner
    assert expect(test.api(outsider, "shared-inboxes")) == []
    command(test, "team", "member", "studio", recipient, "remove")
    expect(test.api(member, "teams"), 401, "unauthorized")
    member = test.login(recipient)
    assert expect(test.api(member, "shared-inboxes")) == []

    for action in ("decline", "revoke", "expire", "demote"):
        expect(send(test, captain, recipient))
        invitation = incoming(test, member)[0]["id"]
        if action == "expire":
            db.execute("UPDATE mail_team_invitations SET expires_at=unixepoch()-1 WHERE id=?", (invitation,))
            db.commit()
        elif action == "demote":
            command(test, "team", "member", "studio", owner, "member")
            command(test, "team", "member", "studio", owner, "owner")
        else:
            expect(decide(test, member if action == "decline" else captain, invitation, action))
        assert incoming(test, member) == []
        expect(decide(test, member, invitation, "accept"), 404, "team_invitation_not_found")
    assert expect(test.api(member, "teams")) == []
    assert db.execute("SELECT count(*) FROM audit_log WHERE action='team.invitation_decided' AND target='studio'").fetchone()[0] == 3

    captain = test.login(owner)
    replacement_owner = test.login(alternative)
    expect(send(test, captain, recipient))
    stale = incoming(test, member)[0]["id"]
    original_term = db.execute("SELECT service_until FROM provisioned_mailboxes WHERE mailbox=?", (owner,)).fetchone()[0]
    db.execute("UPDATE provisioned_mailboxes SET service_until=unixepoch()-1 WHERE mailbox=?", (owner,))
    db.commit()
    assert incoming(test, member) == []
    expect(decide(test, member, stale, "accept"), 404, "team_invitation_not_found")
    expect(send(test, replacement_owner, recipient))
    replacement, = incoming(test, member)
    assert replacement["inviter"] == alternative and replacement["id"] != stale
    expect(decide(test, replacement_owner, replacement["id"], "revoke"))
    db.execute("UPDATE provisioned_mailboxes SET service_until=? WHERE mailbox=?", (original_term, owner))
    db.commit()
    return owner, recipient


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--browser", choices=("chromium", "firefox", "webkit"))
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-team-invites-") as directory:
        root = Path(directory)
        test = Fixture(args.binary.resolve(strict=True), root, staging=True)
        test.env.update(SMTP_LOCAL_DOMAINS=",".join((primary, hosted, foreign)),
                        SMTP_EXACT_MAILBOX_DOMAINS=",".join((primary, hosted, foreign)),
                        SMTP_PROVISIONING_ADDITIONAL_DOMAINS=",".join((hosted, foreign)))
        with test.daemon(), closing(sqlite3.connect(root / "smtp.db")) as db:
            address, team = verify_hosted_teams(test, db)
            owner, recipient = verify(test, db)
            if args.browser:
                assert args.screenshots is not None
                env = dict(os.environ, MAIL_INVITE_TEST_URL=test.webmail, MAIL_INVITE_TEST_CERT=test.env["SMTP_TLS_CERT"],
                           MAIL_INVITE_TEST_OWNER=owner, MAIL_INVITE_TEST_RECIPIENT=recipient,
                           MAIL_INVITE_TEST_PASSWORD=test.password)
                subprocess.run(["node", str(HERE / "webmail-team-invitations-browser.mjs"), args.browser,
                                str(args.screenshots.resolve())], env=env, check=True)
        renamed = "renamed.example.test"
        command(test, "domain", "migrate", hosted, renamed, "--yes")
        for key in ("SMTP_LOCAL_DOMAINS", "SMTP_EXACT_MAILBOX_DOMAINS", "SMTP_PROVISIONING_ADDITIONAL_DOMAINS"):
            test.env[key] = test.env[key].replace(hosted, renamed)
        with test.daemon():
            mailbox = address.split("@", 1)[0] + "@" + renamed
            query = urlencode({"mailbox": mailbox, "actor": test.specs[address]["actor"]})
            status, _, raw = test.http(test.private + "/provisioning/v1/team?" + query, headers=test.auth)
            assert status == 200 and json.loads(raw)["team"] == dict(team, domain=renamed), (status, raw)
            owner_team, = expect(test.api(test.login(mailbox), "teams"))
            assert owner_team == {"id": team["id"], "name": team["name"], "role": "owner"}
    print("Verified hosted team setup, atomic invited mailbox provisioning, domain rename, invitation consent, and explicit inbox grants over native HTTPS.")


if __name__ == "__main__":
    main()
