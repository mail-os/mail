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

HERE = Path(__file__).resolve().parent
support = runpy.run_path(str(HERE / "test-webmail-teams.py"))
Fixture, command, expect = support["Fixture"], support["command"], support["expect"]
primary, hosted, foreign = "hosted.example.test", "studio.example.test", "other.example.test"
endpoint = "team-invitations"


def paid_mailbox(test, name, domain=hosted, *, read_only=False):
    mailbox = f"{name}@{domain}"
    now = int(time.time())
    status, _, raw = test.http(test.private + "/provisioning/v1/mailbox", {
        "mailbox": mailbox, "actor": secrets.token_hex(16), "operation_id": secrets.token_hex(16),
        "revision": 1, "quota_bytes": 1024 * 1024, "enabled": True,
        "initial_password": test.password, "initial_recovery": f"{name}@recovery.example.test",
        "access_window": {"service_until": now + (-30 if read_only else 3600), "read_until": now + 7200},
    }, test.auth)
    assert status == 200 and json.loads(raw)["mailbox"] == mailbox, (status, raw)
    return mailbox


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
    assert db.execute("SELECT count(*) FROM audit_log WHERE action='team.invitation_decided'").fetchone()[0] == 3

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
            owner, recipient = verify(test, db)
            if args.browser:
                assert args.screenshots is not None
                env = dict(os.environ, MAIL_INVITE_TEST_URL=test.webmail, MAIL_INVITE_TEST_CERT=test.env["SMTP_TLS_CERT"],
                           MAIL_INVITE_TEST_OWNER=owner, MAIL_INVITE_TEST_RECIPIENT=recipient,
                           MAIL_INVITE_TEST_PASSWORD=test.password)
                subprocess.run(["node", str(HERE / "webmail-team-invitations-browser.mjs"), args.browser,
                                str(args.screenshots.resolve())], env=env, check=True)
    print("Verified paid-domain invitations, recipient consent, expiry, concurrent acceptance, and explicit inbox grants over native HTTPS.")


if __name__ == "__main__":
    main()
