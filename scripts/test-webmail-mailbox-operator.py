#!/usr/bin/env python3
"""Exercise the self-hosted mailbox operator on a disposable Mail daemon."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
support = runpy.run_path(str(HERE / "test-hosted-limits.py"))
Fixture, DOMAIN = support["Fixture"], support["DOMAIN"]
endpoint = "operator/mailboxes"
operator = f"server-operator@{DOMAIN}"
ordinary = f"ordinary-user@{DOMAIN}"


def create_local(test, address, username=None):
    return subprocess.run(
        [str(test.binary), "user:local", "create", username or address, "--email", address, "--password-stdin"],
        input=test.password + "\n", text=True, capture_output=True, env=test.env, cwd=test.directory, check=True, timeout=15,
    )


def result(response, status, code=None):
    assert response[0] == status, response
    if code:
        assert response[1]["error"] == code, response
    return response[1]


def get(test, path, session=None):
    return test.http(test.webmail + path, headers=session or {}, context=test.tls_context)


def verify_delivery(test, address):
    mailbox = test.login(address)
    assert b'can_manage_mailboxes' not in get(test, "/webmail/auth/me", mailbox)[2]
    result(test.api(mailbox, "sender-review", {"setting": "disable"}, "PUT"), 200)
    assert test.deliver(address, identity=operator, subject="Mailbox handoff", body="The new mailbox is ready.")[0] == 250
    messages = result(test.api(mailbox, "messages?folder=Inbox"), 200)["items"]
    assert any(item["subject"] == "Mailbox handoff" for item in messages), messages


def verify_directory(test, db, sessions):
    admin, other = sessions
    assert get(test, "/mailboxes")[0] == 200
    assert b'"can_manage_mailboxes":true' in get(test, "/webmail/auth/me", admin)[2]
    assert b'can_manage_mailboxes' not in get(test, "/webmail/auth/me", other)[2]
    result(test.api({}, endpoint), 401)
    result(test.api(other, endpoint), 403, "operator_required")
    result(test.api(dict(admin, **{"X-Webmail-Account": ordinary}), endpoint), 409, "account_changed")
    result(test.api(admin, endpoint + "?linked=" + "a" * 32), 403, "linked_route_unavailable")
    result(test.api(admin, endpoint + "?after=-1"), 400, "bad_request")

    first = result(test.api(admin, endpoint), 200)
    assert len(first["mailboxes"]) == 25 and first["next"]
    assert all(set(item) == {"id", "email", "username", "enabled"} for item in first["mailboxes"])
    second = result(test.api(admin, endpoint + f'?after={first["next"]}'), 200)
    assert not second["next"]
    assert {row["email"] for row in first["mailboxes"] + second["mailboxes"]} >= {operator, ordinary}
    assert {row["id"] for row in first["mailboxes"]}.isdisjoint(row["id"] for row in second["mailboxes"])
    assert first["mailboxes"][0]["enabled"] is False

    def create(address, *, headers=admin, current=test.password, password=test.password):
        return test.api(headers, endpoint, dict(address=address, current_password=current, password=password), "POST")

    address = f"fresh@{DOMAIN}"
    result(create(address, headers={}), 401)
    result(create(address, headers=other), 403, "operator_required")
    result(create(address, headers={"Cookie": admin["Cookie"]}), 403, "forbidden")
    result(create(address, headers=dict(admin, Origin="https://other.example.test")), 403, "forbidden")
    result(create(address, current="not-the-operator-password"), 403, "invalid_credentials")
    result(create(address, password="short"), 400, "invalid_password")
    result(create("fresh@external.example.test"), 400, "invalid_address")
    result(create(f"../fresh@{DOMAIN}"), 400, "invalid_address")
    result(create(f"LEGACY@{DOMAIN.upper()}"), 409, "mailbox_exists")
    assert db.execute("SELECT count(*) FROM users WHERE username=?", (address,)).fetchone() == (0,)

    db.execute("""CREATE TRIGGER reject_mailbox_audit BEFORE INSERT ON audit_log
                  WHEN NEW.action='mailbox.created' BEGIN SELECT RAISE(ABORT,'fixture failure'); END""")
    result(create(address), 500, "server_error")
    assert db.execute("SELECT count(*) FROM users WHERE username=?", (address,)).fetchone() == (0,)
    db.execute("DROP TRIGGER reject_mailbox_audit")

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(create, (address, address.upper())))
    assert sorted(response[0] for response in responses) == [201, 409], responses
    created = next(response[1] for response in responses if response[0] == 201)
    assert created["address"] == address
    assert db.execute("SELECT actor, target FROM audit_log WHERE action='mailbox.created'").fetchall() == [(operator, address)]
    assert db.execute("SELECT password_hash FROM users WHERE username=?", (address,)).fetchone()[0].startswith("$argon2")
    verify_delivery(test, address)
    return address


def verify_listener_configuration(binary, directory):
    test = Fixture(binary, directory, provisioning=False)
    create_local(test, operator)
    with closing(sqlite3.connect(test.env["SMTP_DB_PATH"])) as db:
        operator_id = db.execute("SELECT id FROM users WHERE username=?", (operator,)).fetchone()[0]
    test.env.update(SMTP_WEBMAIL_OPERATOR_ID=str(operator_id), SMTP_WEBMAIL_SECURE_COOKIES="true")
    with test.daemon():
        session = test.login(operator)
        assert get(test, "/mailboxes", session)[0] == 403
        result(test.api(session, endpoint), 403, "operator_required")
        gateway = dict(session, Origin="https://mail.example.test", **{
            "X-Forwarded-Host": "mail.example.test", "X-Forwarded-Proto": "https",
        })
        assert get(test, "/mailboxes", gateway)[0] == 200
        assert result(test.api(gateway, endpoint), 200)["mailboxes"][0]["email"] == operator
        address = f"gateway@{DOMAIN}"
        payload = dict(address=address, current_password=test.password, password=test.password)
        assert result(test.api(gateway, endpoint, payload, "POST"), 201)["address"] == address
    options = [str(binary), "serve", "--host", "127.0.0.1", "--port", str(test.smtp_port), "--enable-auth"]
    invalid = subprocess.run(options, env=dict(test.env, SMTP_PROVISIONING_PORT=test.private.rsplit(":", 1)[1]),
                             cwd=test.directory, text=True, capture_output=True, timeout=10)
    assert invalid.returncode and "InvalidWebmailOperatorConfiguration" in invalid.stderr, invalid.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--browser", action="append", choices=("chromium", "firefox", "webkit"))
    parser.add_argument("--screenshots", type=Path, default=Path("/tmp/mail-operator-screenshots"))
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="mail-operator-") as directory:
        test = Fixture(binary, Path(directory), staging=True, provisioning=False)
        create_local(test, operator)
        create_local(test, ordinary)
        create_local(test, f"Legacy@{DOMAIN}", "legacy")
        with test.daemon():
            assert get(test, "/mailboxes")[0] == 404
            result(test.api(test.login(operator), endpoint), 404, "not_found")
        with closing(sqlite3.connect(test.env["SMTP_DB_PATH"], isolation_level=None)) as db:
            operator_id, digest = db.execute("SELECT id, password_hash FROM users WHERE username=?", (operator,)).fetchone()
            for number in range(24):
                address = f"fixture-{number}@{DOMAIN}"
                db.execute("INSERT INTO users(username, email, password_hash, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, 1, 1)",
                           (address, address, digest, number != 23))
            test.env["SMTP_WEBMAIL_OPERATOR_ID"] = str(operator_id)
            with test.daemon():
                sessions = (test.login(operator), test.login(ordinary))
                mailbox = verify_directory(test, db, sessions)
                for engine in args.browser or []:
                    new_address = f"studio-{engine}@{DOMAIN}"
                    env = dict(os.environ, MAIL_OPERATOR_URL=test.webmail, MAIL_OPERATOR_USER=operator,
                               MAIL_OPERATOR_OTHER=mailbox, MAIL_OPERATOR_PASSWORD=test.password, MAIL_OPERATOR_NEW=new_address)
                    subprocess.run(["node", str(HERE / "webmail-mailbox-operator.mjs"), engine,
                                    str(args.screenshots.resolve() / f"operator-{engine}")], check=True, env=env, timeout=90)
                    assert db.execute("SELECT actor FROM audit_log WHERE action='mailbox.created' AND target=?", (new_address,)).fetchone() == (operator,)
                    verify_delivery(test, new_address)
                db.execute("UPDATE users SET enabled=0 WHERE id=?", (operator_id,))
                result(test.api(sessions[0], endpoint), 401, "unauthorized")
        with test.daemon():
            result(test.api(test.login(ordinary), endpoint), 403, "operator_required")
            assert test.deliver(mailbox, identity=ordinary)[0] == 250
    with tempfile.TemporaryDirectory(prefix="mail-operator-gateway-") as directory:
        verify_listener_configuration(binary, Path(directory))
    print("Self-hosted operator permissions, directory, atomic creation, and SMTP delivery passed.")


if __name__ == "__main__":
    main()
