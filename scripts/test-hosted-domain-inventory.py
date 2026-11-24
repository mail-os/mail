#!/usr/bin/env python3
"""Verify the read-only hosted-domain report on a staging-profile Mail daemon."""

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import runpy
import sqlite3
import subprocess
import tempfile
import time


HERE = Path(__file__).resolve().parent
support = runpy.run_path(str(HERE / "test-webmail-team-invitations.py"))
Fixture, command, paid_mailbox = (support[name] for name in ("Fixture", "command", "paid_mailbox"))
DOMAIN = "studio.example.test"
FOREIGN = "sub.studio.example.test"


def inventory(test, domain):
    return json.loads(command(test, "domain", "inventory", domain))


def verify(test):
    owner = paid_mailbox(test, "desk", DOMAIN)
    paused = paid_mailbox(test, "paused", DOMAIN, read_only=True)
    disabled = paid_mailbox(test, "disabled", DOMAIN)
    expired = paid_mailbox(test, "expired", DOMAIN)
    foreign = paid_mailbox(test, "desk", FOREIGN)
    standalone = f"standalone@{DOMAIN}"
    command(test, "user:local", "create", standalone, test.password)
    command(test, "user:local", "disable", disabled)
    payload = {"mailbox": owner, "actor": test.specs[owner]["actor"], "name": "Hosted team"}
    code, _, raw = test.http(test.private + "/provisioning/v1/team", payload, test.auth)
    assert code == 201, raw
    team = json.loads(raw)["team"]["id"]
    command(test, "team", "member", team, paused, "member")
    command(test, "team", "grant", team, owner, paused, "mailbox")
    command(test, "team", "create", "foreign", "Foreign team", foreign)
    command(test, "team", "member", "foreign", owner, "member")
    command(test, "team", "grant", "foreign", foreign, owner, "sender")
    with closing(sqlite3.connect(test.env["SMTP_DB_PATH"])) as db, db:
        ids = dict(db.execute("SELECT username,id FROM users"))
        now = int(time.time())
        db.execute("UPDATE provisioned_mailboxes SET service_until=?,read_until=? WHERE mailbox=?", (now - 3600, now - 30, expired))
        db.execute("INSERT INTO mail_team_calendar_shares VALUES (?,?,?,?,?)", (team, ids[owner], ids[paused], "a" * 32, "viewer"))
        db.execute("INSERT INTO mail_team_invitations(team_id,inviter_id,recipient_id,expires_at) VALUES (?,?,?,?)",
                   (team, ids[owner], ids[disabled], now + 3600))
        db.execute("INSERT INTO mailbox_forwarding(user_id,address,pending_address,expires_at) VALUES (?,?,?,?)",
                   (ids[owner], "route@example.test", "next@example.test", now + 3600))
        db.execute("INSERT INTO mailbox_forwarding(user_id,address,destination_id) VALUES (?,?,?)",
                   (ids[foreign], owner, ids[owner]))
        db.execute("INSERT INTO accepted_mail VALUES (?,?,?,?,?,?,?,?,?)",
                   ("pending-fixture", now, now * 1000, "testing@example.test", "testing@example.test", 0, "127.0.0.1", b"fixture body", 0))
        db.execute("INSERT INTO accepted_mail_targets(delivery_id,ordinal,recipient,mailbox,mailbox_id,folder,outcome,queued_bytes,retry_at,is_primary) VALUES (?,?,?,?,?,?,?,?,?,?)",
                   ("pending-fixture", 0, owner, owner, ids[owner], "new", "pending", 12, now + 3600, 1))

    source = f"alias@{DOMAIN}"
    (test.directory / "forwards.json").write_text(json.dumps({source: ["away@example.test"], foreign: [owner], "unrelated@example.test": [foreign]}))
    report = inventory(test, DOMAIN.upper())
    assert report["version"] == 1 and report["domain"] == DOMAIN
    assert report["routing"] == {"local": True, "exact_mailboxes": True, "additional_provisioning": True, "catch_all": False}
    accounts = {row["mailbox"]: row for row in report["mailboxes"]}
    assert set(accounts) == {owner, paused, disabled, expired, standalone}, accounts
    assert accounts[owner]["actor"] == test.specs[owner]["actor"]
    assert accounts[owner]["operation_id"] == test.specs[owner]["operation_id"]
    assert accounts[owner]["recovery"] == "desk@recovery.example.test"
    assert accounts[owner]["access"] == "full" and accounts[paused]["access"] == "read_only"
    assert accounts[disabled]["access"] == "disabled" and accounts[standalone]["actor"] is None
    assert accounts[expired]["access"] == "expired"
    assert report["hosted_teams"] == [{"team": team, "name": "Hosted team"}]
    assert {(row["team"], row["mailbox"], row["role"]) for row in report["memberships"]} == {
        (team, owner, "owner"), (team, paused, "member"), ("foreign", owner, "member"),
    }
    assert {(row["team"], row["source"], row["grantee"], row["scope"]) for row in report["team_grants"]} == {
        (team, owner, paused, "mailbox"), ("foreign", foreign, owner, "sender"),
    }
    assert [share["access"] for share in report["calendar_shares"]] == ["viewer"]
    assert [offer["recipient"] for offer in report["team_invitations"]] == [disabled]
    assert {row["source"]: row["destination"] for row in report["forwarding"]} == {owner: "route@example.test", foreign: owner}
    assert report["pending_delivery"] == [{"mailbox": owner, "count": 1, "reserved_bytes": 12}]
    assert {(row["source"], row["destination"]) for row in report["legacy_forwards"]} == {(source, "away@example.test"), (foreign, owner)}
    assert report["sieve_forwarding_present"] is False
    assert test.password not in json.dumps(report)
    assert test.auth["Authorization"] not in json.dumps(report)

    (test.directory / "forwards.sieve").write_text('redirect "reroute@example.test";')
    assert inventory(test, DOMAIN)["sieve_forwarding_present"] is True
    assert inventory(test, "unused.example.test")["mailboxes"] == []
    (test.directory / "forwards.json").write_text("{invalid")
    command(test, "domain", "inventory", DOMAIN, error="SyntaxError")
    (test.directory / "forwards.json").write_text("{}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="mail-domain-inventory-") as directory:
        test = Fixture(binary, Path(directory), staging=True)
        test.env["SMTP_LOCAL_DOMAINS"] += f",{DOMAIN},{FOREIGN}"
        test.env.update(SMTP_EXACT_MAILBOX_DOMAINS=f"{DOMAIN},{FOREIGN}", SMTP_PROVISIONING_ADDITIONAL_DOMAINS=f"{DOMAIN},{FOREIGN}")
        with test.daemon():
            verify(test)
        database_path = Path(test.env["SMTP_DB_PATH"])
        before = hashlib.sha256(database_path.read_bytes()).digest()
        inventory(test, DOMAIN)
        assert hashlib.sha256(database_path.read_bytes()).digest() == before
        missing = Path(directory) / "missing.db"
        result = subprocess.run([str(binary), "domain", "inventory", DOMAIN], cwd=directory,
                                env=dict(test.env, SMTP_DB_PATH=str(missing)), capture_output=True, timeout=15)
        assert result.returncode and not missing.exists()
    print("Verified exact-domain inventory, access states, grants, routes, pending delivery, and read-only reporting.")


if __name__ == "__main__":
    main()
