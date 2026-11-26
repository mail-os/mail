#!/usr/bin/env python3
"""Verify mailbox forwarding through webmail, the SMTP journal, and SES transport."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from email import policy
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import re
import runpy
import sqlite3
import subprocess
import sys
import tempfile
import time


fixtures = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture, expect_smtp = fixtures["Fixture"], fixtures["expect_smtp"]
parser = BytesParser(policy=policy.default)


def eventually(read, check=bool):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = read()
        if check(result):
            return result
        time.sleep(0.1)
    raise AssertionError("Expected delivery or journal outcome did not arrive")


def verification_code(message):
    assert message["Auto-Submitted"] == "auto-generated"
    found = re.search(r"(?m)^[a-f0-9]{32}$", message.get_body().get_content().replace("\r\n", "\n"))
    assert found, "Verification email did not contain a code"
    return found.group()


def fake_ses(root):
    command = root / "aws"
    command.write_text(f"#!{sys.executable}\n" + '''
import json, os, stat, sys
from pathlib import Path
assert sys.argv[1:3] == ["ses", "send-raw-email"]
path = Path(sys.argv[-1].removeprefix("file://"))
assert stat.S_IMODE(path.stat().st_mode) == 0o600
data = json.loads(path.read_bytes())
with open("ses.jsonl", "ab") as log:
    log.write(json.dumps(data).encode() + b"\\n")
''')
    command.chmod(0o700)


def run(binary, previous):
    with tempfile.TemporaryDirectory(prefix="mail-forwarding-") as tmp:
        root = Path(tmp)
        fake_ses(root)
        fixture = Fixture(previous or binary, root, staging=True)
        fixture.env.update(SMTP_DELIVERY_METHOD="ses", PATH=f"{root}:{fixture.env['PATH']}")
        domain = fixture.env["SMTP_PROVISIONING_DOMAIN"]
        alias = f"billing@{domain}"
        (root / "aliases").write_text(f"billing: filtered@{domain}\n")
        fixture.env["SMTP_ALIASES_PATH"] = str(root / "aliases")

        def sql(query, values=()):
            with closing(sqlite3.connect(root / "smtp.db")) as db, db:
                db.execute("PRAGMA foreign_keys=ON")
                return db.execute(query, values).fetchall()

        def api(session, path, data=None, method=None, expected=200):
            code, payload = fixture.api(session, path, data, method)
            assert code == expected, (path, expected, code, payload)
            return payload

        def settings(session):
            return api(session, "forwarding")

        def change(session, action, revision, *, expected=200, **fields):
            return api(session, "forwarding", dict(action=action, revision=revision, **fields), "POST", expected)

        def copies(user, subject):
            messages = []
            for folder in ("cur", "new"):
                for path in (root / "mail" / user / folder).glob("*"):
                    if path.name.startswith(".") or not path.is_file():
                        continue
                    try:
                        raw = path.read_bytes()
                    except FileNotFoundError:
                        # A published message may move from new to cur between reads.
                        continue
                    if parser.parsebytes(raw)["Subject"] == subject:
                        messages.append(raw)
            return messages

        def lookup(user, subject):
            return [parser.parsebytes(raw) for raw in copies(user, subject)]

        def smtp(subject, recipients, *, sender="outside@sender.example.test", identity=None, extra="", chunked=False):
            raw = (f"From: {sender or 'mailer-daemon@sender.example.test'}\r\nSubject: {subject}\r\n"
                   f"Message-ID: <{subject.replace(' ', '-')}@sender.example.test>\r\n{extra}\r\n"
                   "Keep this exact original, including its UTF-8: café.\r\n").encode()
            with fixture.smtp(identity) as client:
                assert client.mail(sender)[0] == 250
                for recipient in recipients:
                    assert client.rcpt(recipient)[0] == 250
                if chunked:
                    client.send(f"BDAT {len(raw)} LAST\r\n".encode() + raw)
                    expect_smtp(client.getreply(), 250)
                else:
                    expect_smtp(client.data(raw), 250)
            return raw

        def remote(address, subject):
            path = root / "ses.jsonl"
            if not path.exists():
                return []
            messages = []
            for line in path.read_bytes().splitlines(keepends=True):
                if not line.endswith(b"\n"):
                    break
                record = json.loads(line)
                if record["Destinations"] != [address]:
                    continue
                raw = base64.b64decode(record["RawMessage"]["Data"])
                message = parser.parsebytes(raw)
                if message["Subject"] == subject:
                    messages.append((record, message))
            return messages

        def allow_another_request(user):
            # Advance only this fixture's last-request window without a sleep.
            sql("UPDATE mailbox_forwarding_requests SET requested_at=unixepoch()-61 WHERE user_id=(SELECT id FROM users WHERE username=?)", (user,))

        def local_user(action, address):
            command = [str(binary), "user:local", action, address]
            password = None
            if action == "create":
                command.append("--password-stdin")
                password = (fixture.password + "\n").encode()
            subprocess.run(command, input=password, cwd=root, env=fixture.env, check=True, capture_output=True)

        if previous:
            with fixture.daemon():
                legacy = fixture.provision("legacy")
                api(fixture.login(legacy), "sender-review", {"setting": "disable"}, "PUT")
                smtp("Mail accepted before upgrade", [legacy])
            assert not sql("SELECT 1 FROM sqlite_master WHERE name='mailbox_forwarding'")
            fixture.binary = binary
            with fixture.daemon():
                assert settings(fixture.login(legacy))["revision"] == 0
                assert lookup(legacy, "Mail accepted before upgrade")
                assert sql("SELECT verified_forward FROM accepted_mail_targets WHERE mailbox=?", (legacy,)) == [(0,)]

        with fixture.daemon():
            sender = fixture.provision("sender")
            source = fixture.provision("owner", daily=1)
            local = fixture.provision("local")
            prior = fixture.provision("managed")
            observer = fixture.provision("observer")
            external = "verification@external.example.test"
            (root / "forwards.json").write_text(json.dumps({local: [prior]}))
            owner, destination, other = map(fixture.login, (source, local, observer))
            api(owner, "sender-review", {"setting": "disable"}, "PUT")
            empty_scope = {"sender": None, "recipient": None}
            initial = {"address": None, "pendingAddress": None, "expiresAt": None, "revision": 0, "scope": empty_scope}
            assert settings(owner) == initial == settings(other)
            api({}, "forwarding", expected=401)
            change({**owner, "Origin": "https://outside.example.test"}, "request", 0, expected=403)
            change(owner, "request", 0, expected=400, currentPassword=fixture.password, address=source.upper())
            change(owner, "request", 0, expected=400, currentPassword="bad-password", address=local)
            pending = change(owner, "request", 0, currentPassword=fixture.password, address=local)
            assert pending["pendingAddress"] == local and pending["address"] is None and pending["revision"] == 1
            assert settings(other) == initial
            message, = eventually(lambda: lookup(local, "Confirm mail forwarding"))
            assert not lookup(prior, "Confirm mail forwarding")
            code = verification_code(message)
            digest, = sql("SELECT code_hash FROM mailbox_forwarding WHERE pending_address=?", (local,))
            assert digest == (hashlib.sha256(code.encode()).digest(),)
            change(other, "confirm", 0, expected=400, code=code)
            change({**other, "X-Webmail-Account": source}, "confirm", 1, expected=409, code=code)
            change(owner, "confirm", 1, expected=400, code="0" * 32)
            change(owner, "confirm", 0, expected=412, code=code)
            change(owner, "request", 1, expected=429, currentPassword=fixture.password, address=external)
            smtp("Before confirmation", [source])
            assert lookup(source, "Before confirmation") and not lookup(local, "Before confirmation")
            with ThreadPoolExecutor(max_workers=2) as pool:
                attempts = list(pool.map(lambda _: fixture.api(owner, "forwarding", {
                    "action": "confirm", "revision": 1, "code": code.upper(),
                }, "POST")[0], range(2)))
            assert sorted(attempts) == [200, 412]
            active = settings(owner)
            assert active["address"] == local and active["pendingAddress"] is None and active["revision"] == 2
            change(owner, "confirm", 2, expected=400, code=code)
            api(destination, "sender-review", {"setting": "disable"}, "PUT")
            smtp("Verified local delivery", [source], chunked=True)
            assert lookup(source, "Verified local delivery")
            copy, = lookup(local, "Verified local delivery")
            assert copy["X-Mail-Forwarded"] == "yes" and not lookup(prior, "Verified local delivery")
            assert fixture.count(source) == 0
            api(fixture.login(sender), "compose", {"to": [source], "subject": "Webmail delivery", "text": "A local submission."}, "POST")
            assert lookup(source, "Webmail delivery") and lookup(local, "Webmail delivery")
            fixture.provision("local", quota=fixture.bytes(local))
            smtp("Forward destination full", [source])
            assert lookup(source, "Forward destination full") and not lookup(local, "Forward destination full")
            assert sql("SELECT COUNT(*) FROM accepted_mail_targets WHERE mailbox=? AND outcome='forward_storage_full'", (local,)) == [(1,)]
            fixture.provision("local")
            smtp("Already addressed", [source, local])
            assert len(lookup(local, "Already addressed")) == 1
            for subject, args in (("Already forwarded", {"extra": "X-Mail-Forwarded: yes\r\n"}),
                                  ("Automated notice", {"extra": "Auto-Submitted: auto-replied\r\n"}),
                                  ("Delivery status", {"sender": ""})):
                smtp(subject, [source], **args)
                assert lookup(source, subject) and not lookup(local, subject)
            api(owner, "sender-review", {"setting": "enable"}, "PUT")
            smtp("Waiting for Sender Review", [source])
            assert not lookup(local, "Waiting for Sender Review")
            held, = api(owner, "sender-review")["items"]
            review = {"reference": held["reference"], "action": "allow", "rule_revision": held["rule_revision"]}
            api({**owner, "If-Match": held["revision"]}, "sender-review/decision", review, "POST")
            eventually(lambda: lookup(local, "Waiting for Sender Review"))
            api(owner, "sender-review", {"setting": "disable"}, "PUT")
            allow_another_request(source)
            pending = change(owner, "request", 2, currentPassword=fixture.password, address=observer)
            assert pending["address"] == local and pending["pendingAddress"] == observer
            obsolete = verification_code(eventually(lambda: lookup(observer, "Confirm mail forwarding"))[0])
            sql("UPDATE mailbox_forwarding SET expires_at=unixepoch() WHERE pending_address=?", (observer,))
            change(owner, "confirm", 3, expected=400, code=obsolete)
            smtp("Old destination still active", [source])
            assert lookup(local, "Old destination still active") and not lookup(observer, "Old destination still active")
            assert change(owner, "cancel", 3)["pendingAddress"] is None

            filtered = fixture.provision("filtered", daily=1)
            filter_destination = fixture.provision("filter-destination")
            filtered_session = fixture.login(filtered)
            api(filtered_session, "sender-review", {"setting": "disable"}, "PUT")
            scope = {"sender": sender.upper(), "recipient": alias}
            change(filtered_session, "scope", 0, expected=412, currentPassword=fixture.password, scope=scope)
            change(filtered_session, "request", 0, currentPassword=fixture.password, address=filter_destination)
            code = verification_code(eventually(lambda: lookup(filter_destination, "Confirm mail forwarding"))[0])
            change(filtered_session, "confirm", 1, expected=400, code=code, scope={"sender": "@example.test"})
            scoped = change(filtered_session, "confirm", 1, code=code, scope=scope)
            assert scoped["address"] == filter_destination and scoped["scope"] == scope
            assert sql("SELECT address FROM mailbox_forwarding WHERE user_id=(SELECT id FROM users WHERE username=?)", (filtered,)) == [(None,)]
            change(filtered_session, "scope", 2, expected=400, currentPassword="wrong", scope=empty_scope)
            change(filtered_session, "scope", 1, expected=412, currentPassword=fixture.password, scope=empty_scope)
            change({**filtered_session, "Origin": "https://outside.example.test"}, "scope", 2, expected=403)
            assert settings(other) == initial

            smtp("Verified match on alias", [alias], sender=sender, identity=sender, chunked=True)
            assert lookup(filtered, "Verified match on alias") and lookup(filter_destination, "Verified match on alias")
            smtp("Wrong envelope with matching header", [filtered], sender=sender, identity=sender, extra=f"To: {alias}\r\n")
            smtp("Unverified matching From", [alias], sender=sender)
            smtp("Different verified From", [alias], sender=observer, identity=observer)
            for subject in ("Wrong envelope with matching header", "Unverified matching From", "Different verified From"):
                assert lookup(filtered, subject) and not lookup(filter_destination, subject)
            smtp("Do not duplicate direct copy", [alias, filter_destination], sender=sender, identity=sender)
            assert len(lookup(filter_destination, "Do not duplicate direct copy")) == 1

            api(filtered_session, "sender-review", {"setting": "enable"}, "PUT")
            smtp("Held matching message", [alias], sender=sender, identity=sender)
            assert not lookup(filter_destination, "Held matching message")
            held, = api(filtered_session, "sender-review")["items"]
            api({**filtered_session, "If-Match": held["revision"]}, "sender-review/decision", {
                "reference": held["reference"], "action": "allow", "rule_revision": held["rule_revision"],
            }, "POST")
            eventually(lambda: lookup(filter_destination, "Held matching message"))
            api(filtered_session, "sender-review", {"setting": "disable"}, "PUT")
            allow_another_request(filtered)
            filter_pending = change(filtered_session, "request", 2, currentPassword=fixture.password, address=observer)
            assert filter_pending["scope"] == scope
            cancelled = change(filtered_session, "cancel", filter_pending["revision"])
            assert cancelled["scope"] == scope and cancelled["address"] == filter_destination

        with fixture.daemon():
            owner = fixture.login(source)
            assert settings(owner)["address"] == local
            allow_another_request(source)
            pending = change(owner, "request", 4, currentPassword=fixture.password, address=external)
            assert pending["address"] == local and pending["pendingAddress"] == external
            received, = eventually(lambda: remote(external, "Confirm mail forwarding"))
            assert received[0]["Source"] == "no-reply@" + source.split("@")[1]
            remote_code = verification_code(received[1])
            change(owner, "confirm", 5, expected=400, code=obsolete)
            assert change(owner, "confirm", 5, code=remote_code)["address"] == external
            assert change(owner, "request", 6, expected=429, currentPassword=fixture.password,
                          address=observer)["error"] == "rate_limited"
            assert change(owner, "disable", 5, expected=412, currentPassword=fixture.password)["error"] == "revision_mismatch"
            smtp("Verified external delivery", [source])
            sent, = eventually(lambda: remote(external, "Fwd: Verified external delivery"))
            assert sent[0]["Source"] == sent[1]["From"] == "no-reply@" + source.split("@")[1]
            assert sent[1]["X-Mail-Forwarded"] == "yes" and sent[1]["Auto-Submitted"] == "auto-generated"
            attachment, = sent[1].iter_attachments()
            assert attachment.get_filename() == "original.eml"
            original, = copies(source, "Verified external delivery")
            assert attachment.get_payload(decode=True) == original
            assert fixture.count(source) == 1 and lookup(source, "Verified external delivery")
            assert not lookup(local, "Verified external delivery")
            smtp("Forwarding allowance exhausted", [source])
            assert lookup(source, "Forwarding allowance exhausted")
            assert not remote(external, "Fwd: Forwarding allowance exhausted")
            assert sql("SELECT COUNT(*) FROM accepted_mail_targets WHERE recipient=? AND outcome='forward_allowance'", (external,)) == [(1,)]
            assert change(owner, "disable", 6, currentPassword=fixture.password)["address"] is None
            smtp("After disabling forwarding", [source])
            assert lookup(source, "After disabling forwarding")
            assert sql("SELECT COUNT(*) FROM accepted_mail_targets WHERE recipient=?", (external,)) == [(2,)]

            filtered_session = fixture.login(filtered)
            filtered_state = settings(filtered_session)
            assert filtered_state["scope"] == scope
            allow_another_request(filtered)
            filtered_external = "filtered@external.example.test"
            started = change(filtered_session, "request", filtered_state["revision"], currentPassword=fixture.password, address=filtered_external)
            assert started["address"] == filter_destination and started["scope"] == scope
            code = verification_code(eventually(lambda: remote(filtered_external, "Confirm mail forwarding"))[0][1])
            replaced = change(filtered_session, "confirm", started["revision"], code=code)
            assert replaced["address"] == filtered_external and replaced["scope"] == scope
            smtp("Unmatched remote mail", [filtered], sender=sender, identity=sender)
            assert not remote(filtered_external, "Fwd: Unmatched remote mail") and fixture.count(filtered) == 0
            smtp("Matched remote mail", [alias], sender=sender, identity=sender)
            eventually(lambda: remote(filtered_external, "Fwd: Matched remote mail"))
            assert fixture.count(filtered) == 1
            limited = change(filtered_session, "scope", replaced["revision"], currentPassword=fixture.password, scope={"recipient": alias})
            assert limited["scope"] == {"sender": None, "recipient": alias}
            smtp("Recipient-only match over limit", [alias])
            assert lookup(filtered, "Recipient-only match over limit") and not remote(filtered_external, "Fwd: Recipient-only match over limit")
            assert sql("SELECT COUNT(*) FROM accepted_mail_targets WHERE recipient=? AND outcome='forward_allowance'", (filtered_external,)) == [(1,)]
            changed = change(filtered_session, "scope", limited["revision"], currentPassword=fixture.password, scope=empty_scope)
            assert changed["scope"] == empty_scope
            assert sql("SELECT address FROM mailbox_forwarding WHERE user_id=(SELECT id FROM users WHERE username=?)", (filtered,)) == [(filtered_external,)]
            assert change(filtered_session, "disable", changed["revision"], currentPassword=fixture.password)["address"] is None

            guard = fixture.provision("guard")
            guard_session = fixture.login(guard)
            api(guard_session, "sender-review", {"setting": "disable"}, "PUT")
            reusable = "reusable@" + source.split("@")[1]
            local_user("create", reusable)
            change(guard_session, "request", 0, currentPassword=fixture.password, address=reusable)
            guard_code = verification_code(eventually(lambda: lookup(reusable, "Confirm mail forwarding"))[0])
            incorrect = "0" * 32 if guard_code != "0" * 32 else "1" * 32
            for _ in range(8):
                change(guard_session, "confirm", 1, expected=400, code=incorrect)
            change(guard_session, "confirm", 1, expected=400, code=guard_code)
            assert settings(guard_session)["address"] is None
            allow_another_request(guard)
            change(guard_session, "request", 1, currentPassword=fixture.password, address=reusable)
            messages = eventually(lambda: lookup(reusable, "Confirm mail forwarding"), lambda items: len(items) == 2)
            replacement, = [code for msg in messages if (code := verification_code(msg)) != guard_code]
            change(guard_session, "confirm", 2, expected=400, code=guard_code)
            change(guard_session, "confirm", 2, code=replacement)
            smtp("Before local address reassignment", [guard])
            assert lookup(reusable, "Before local address reassignment")
            local_user("delete", reusable)
            local_user("create", reusable)
            smtp("Reassigned local address", [guard])
            assert lookup(guard, "Reassigned local address") and not lookup(reusable, "Reassigned local address")
    print("Verified forwarding proof and filters, local and SES delivery, request limits, routing, restart, and account isolation.")


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("binary", type=Path)
    cli.add_argument("--previous", type=Path)
    args = cli.parse_args()
    run(args.binary.resolve(), args.previous.resolve() if args.previous else None)
