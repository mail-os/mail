#!/usr/bin/env python3
"""Verify full-address routing and scoped provisioning on disposable hosted domains."""

import argparse
import json
from pathlib import Path
import runpy
import secrets
import subprocess
import tempfile
import time
from urllib.parse import urlencode

support = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture, request, primary = support["Fixture"], support["request"], support["DOMAIN"]
first_domain, second_domain, local_only = "one.example.test", "two.example.test", "local.example.test"


def provisioning(test, route, data=None, query=None):
    url = f"{test.private}/provisioning/v1/{route}"
    if query:
        url += "?" + urlencode(query)
    status, _, content = request(url, data, test.auth)
    return status, json.loads(content)


def assignment(name):
    return dict(mailbox=name, actor=secrets.token_hex(16), operation_id=secrets.token_hex(16), revision=1,
                quota_bytes=1024 * 1024, send_recipients_per_day=20, enabled=True,
                initial_recovery="owner@recovery.example.test", initial_password=secrets.token_hex(16))


def webmail(test, mailbox, password):
    headers = {"Origin": test.webmail}
    status, response, _ = request(test.webmail + "/webmail/auth/login",
                                  {"username": mailbox, "password": password}, headers, context=test.tls_context)
    if status == 200:
        headers["Cookie"] = response["Set-Cookie"].split(";", 1)[0]
    return status, headers


def inbox(test, session):
    status, listing = test.api(session, "messages?folder=INBOX")
    assert status == 200, (status, listing)
    return {item["subject"] for item in listing["items"]}


def verify(test):
    first = assignment(f"desk@{first_domain}")
    second = assignment(f"desk@{second_domain}")
    unique = assignment(f"review@{second_domain}")
    assert provisioning(test, "status") == (200, {"version": 1, "domain": primary})
    for domain in (primary, first_domain, second_domain):
        assert provisioning(test, "domain", query={"name": domain}) == (200, {"name": domain, "configured": True})
    assert provisioning(test, "domain", query={"name": local_only})[0] == 404
    assert provisioning(test, "mailbox", assignment(f"desk@{local_only}"))[0] == 400
    for account in (first, second, unique):
        status, state = provisioning(test, "mailbox", account)
        assert status == 200 and state["mailbox"] == account["mailbox"], (status, state)
    legacy = test.provision("legacy-user")
    assert webmail(test, legacy.split("@")[0], test.password)[0] == 200
    assert webmail(test, "review", unique["initial_password"])[0] == 401

    first_mailbox, second_mailbox = first["mailbox"], second["mailbox"]
    assert provisioning(test, "mailbox", query={"mailbox": second_mailbox, "actor": first["actor"]})[0] == 404
    window = {"service_until": int(time.time()) + 600, "read_until": int(time.time()) + 1200}
    for account, expected_status in ((first, 404), (second, 200)):
        change = dict(mailbox=second_mailbox, actor=account["actor"], operation_id=secrets.token_hex(16),
                      revision=2, access_window=window)
        status, body = provisioning(test, "mailbox/access", change)
        assert status == expected_status, (status, body)
        if status == 200:
            assert body["access_window"] == window, body

    status, left = webmail(test, first_mailbox.upper(), first["initial_password"])
    assert status == 200, status
    status, right = webmail(test, second_mailbox, second["initial_password"])
    assert status == 200, status
    for mailbox, session in ((first_mailbox, left), (second_mailbox, right)):
        status, who = test.api(session, "folders")
        assert status == 200 and who, (status, who)
        assert test.api(session, "sender-review", {"setting": "disable"}, "PUT")[0] == 200
    assert webmail(test, second_mailbox, first["initial_password"])[0] == 401

    postmaster = f"postmaster@{second_domain}"
    result = subprocess.run([str(test.binary), "user:local", "create", postmaster], cwd=test.directory,
                            env=test.env, input=b"Postmaster fixture password\n", capture_output=True, timeout=15)
    assert result.returncode == 0 and b"User created successfully" in result.stdout + result.stderr, result.stderr
    support["expect_smtp"](test.deliver(postmaster, subject="Tenant postmaster"), 250)
    assert test.bytes(postmaster) > 0
    support["expect_smtp"](test.deliver(first_mailbox.upper(), subject="First domain SMTP"), 250)
    support["expect_smtp"](test.deliver(second_mailbox, subject="Second domain SMTP", chunked=True), 250)
    support["expect_smtp"](test.deliver(f"review@{first_domain}"), 550, "5.1.1")

    test.password = first["initial_password"]
    with test.imap(first_mailbox.upper()) as client:
        assert client.select("INBOX", readonly=True)[1] == [b"1"]
    status, result = test.api(left, "compose", {"to": [second_mailbox], "subject": "First domain webmail", "text": "Tenant check"})
    assert status == 200 and result["delivered"] == 1, (status, result)
    ews = support["create_ews_item"]("SendAndSaveCopy", to=[second_mailbox], subject="First domain EWS")
    assert support["ews_codes"](test.ews(first_mailbox, ews, full_login=True)) == ["NoError"]

    test.password = second["initial_password"]
    eas = support["eas_send"](support["eas_mime"](second_mailbox, first_mailbox, subject="Second domain ActiveSync"))
    assert support["eas_result"](test.eas(second_mailbox, eas, full_login=True)) == 0
    assert inbox(test, left) == {"First domain SMTP", "Second domain ActiveSync"}
    assert inbox(test, right) == {"Second domain SMTP", "First domain webmail", "First domain EWS"}
    assert test.count(first_mailbox) == 2 and test.count(second_mailbox) == 1
    assert test.bytes(unique["mailbox"]) == 0 and not (test.directory / "mail" / "desk").exists()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="mail-hosted-domains-") as directory:
        test = Fixture(binary, Path(directory), staging=True)
        test.env.update(SMTP_LOCAL_DOMAINS=",".join((primary, first_domain, second_domain, local_only)),
                        SMTP_EXACT_MAILBOX_DOMAINS=",".join((first_domain, second_domain)),
                        SMTP_PROVISIONING_ADDITIONAL_DOMAINS=",".join((first_domain, second_domain)))
        invalid = dict(test.env, SMTP_EXACT_MAILBOX_DOMAINS=first_domain)
        result = subprocess.run([str(binary), "serve", "--host", "127.0.0.1", "--port", str(test.smtp_port), "--enable-auth"],
                                env=invalid, cwd=test.directory, capture_output=True, timeout=10)
        assert result.returncode != 0 and b"InvalidProvisioningConfiguration" in result.stderr, result.stderr
        with test.daemon():
            verify(test)
    print("Verified two hosted domains over private provisioning, SMTP, IMAP, webmail, EWS, and ActiveSync.")


if __name__ == "__main__":
    main()
