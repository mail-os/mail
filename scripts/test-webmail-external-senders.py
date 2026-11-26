#!/usr/bin/env python3
"""Exercise verified external From addresses and authenticated SMTP over TLS."""

import argparse
import base64
from contextlib import contextmanager
from email import policy
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import socketserver
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time


Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]
IDENTITY = "external-studio"
VERIFICATION = "external-sender-verification"
REVIEW = "external-sender-review"


def openssl(*arguments):
    subprocess.run(["openssl", *map(str, arguments)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def make_tls(directory, name, hostname):
    root, root_key = directory / f"{name}-ca.pem", directory / f"{name}-ca.key"
    key, csr, cert = (directory / f"{name}.{suffix}" for suffix in ("key", "csr", "pem"))
    extensions = directory / f"{name}.ext"
    extensions.write_text(f"subjectAltName=DNS:{hostname}\nextendedKeyUsage=serverAuth\n")
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", 1,
            "-subj", f"/CN={name} test CA", "-keyout", root_key, "-out", root)
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={hostname}", "-keyout", key, "-out", csr)
    openssl("x509", "-req", "-in", csr, "-CA", root, "-CAkey", root_key, "-CAcreateserial",
            "-days", 1, "-extfile", extensions, "-out", cert)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return root, context


class SmtpProvider(socketserver.BaseRequestHandler):
    def handle(self):
        provider = self.server
        provider.connections += 1
        self.request.settimeout(6)
        stream = self.request
        incoming = stream.makefile("rb")
        secure, authorized = False, False
        sender, recipients = None, []
        try:
            stream.sendall(b"220 disposable external submission\r\n")
            while line := incoming.readline(512):
                if line.startswith(b"EHLO "):
                    if secure:
                        stream.sendall(b"250-provider.test\r\n250 AUTH PLAIN\r\n")
                    elif provider.mode == "plaintext":
                        # A hostile plaintext offer must never receive AUTH.
                        stream.sendall(b"250-provider.test\r\n250 AUTH PLAIN\r\n")
                    else:
                        stream.sendall(b"250-provider.test\r\n250 STARTTLS\r\n")
                elif line == b"STARTTLS\r\n":
                    stream.sendall(b"220 begin TLS\r\n")
                    incoming.close()
                    stream = provider.context.wrap_socket(stream, server_side=True)
                    incoming = stream.makefile("rb")
                    secure = True
                elif line.startswith(b"AUTH "):
                    provider.auth_attempts.append(secure)
                    authorized = secure and line.strip() == b"AUTH PLAIN " + provider.token and provider.mode != "bad-auth"
                    stream.sendall(b"235 authenticated\r\n" if authorized else b"535 authentication denied\r\n")
                elif line.startswith(b"MAIL FROM:"):
                    assert authorized
                    sender = line.strip().removeprefix(b"MAIL FROM:").strip(b"<>").decode()
                    stream.sendall(b"250 sender accepted\r\n")
                elif line.startswith(b"RCPT TO:"):
                    assert authorized
                    address = line.strip().removeprefix(b"RCPT TO:").strip(b"<>").decode()
                    if address.startswith("unavailable@"):
                        stream.sendall(b"550 recipient refused\r\n")
                    else:
                        recipients.append(address)
                        stream.sendall(b"250 recipient accepted\r\n")
                elif line == b"DATA\r\n":
                    assert authorized and sender and recipients
                    stream.sendall(b"354 end with dot\r\n")
                    body = []
                    while (item := incoming.readline()) != b".\r\n":
                        if not item:
                            return
                        body.append(item[1:] if item.startswith(b"..") else item)
                    provider.transactions.append((sender, recipients[:], b"".join(body)))
                    if provider.mode == "drop-ack":
                        return
                    if provider.mode == "reject-data":
                        stream.sendall(b"554 message denied\r\n")
                    else:
                        stream.sendall(b"250 queued by provider\r\n")
                elif line == b"QUIT\r\n":
                    return
                else:
                    stream.sendall(b"500 unrecognized command\r\n")
        except (ssl.SSLError, OSError):
            pass
        finally:
            incoming.close()
            stream.close()


@contextmanager
def provider_server(context):
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), SmtpProvider) as server:
        server.daemon_threads = True
        server.mode, server.context = "normal", context
        server.auth_attempts, server.transactions, server.connections = [], [], 0
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server
        finally:
            server.shutdown()
            worker.join()


def verify(fixture, server, root, wrong_host, wrong_issuer):
    trusted_context = server.context
    def call(session, path, payload=None, status=200):
        actual, data = fixture.api(session, path, payload)
        assert actual == status, (path, actual, data)
        return data

    def write_grants(grants):
        staging = config.with_suffix(".new")
        staging.write_text(json.dumps(grants))
        staging.chmod(0o600)
        staging.replace(config)

    def verification(action, code=""):
        return {"id": IDENTITY, "action": action, "code": code}

    def obtain_code():
        end = time.monotonic() + 8
        while time.monotonic() < end:
            with fixture.imap(address) as inbox:
                inbox.select("INBOX")
                _, rows = inbox.search(None, "SUBJECT", '"Verify an external From address"')
                if rows[0]:
                    _, parts = inbox.fetch(rows[0].split()[-1], "(BODY.PEEK[])")
                    message = BytesParser(policy=policy.default).parsebytes(parts[0][1])
                    assert message["Auto-Submitted"] == "auto-generated"
                    return re.search(r"(?m)^[a-f0-9]{32}\s*$", message.get_body().get_content()).group().strip()
            time.sleep(0.125)
        raise AssertionError("Verification email was not received")

    def queue(subject, *, to=None, cc=(), bcc=(), delay=0):
        envelope = {"senderId": IDENTITY, "to": to or ["reader@destination.example"], "cc": list(cc), "bcc": list(bcc)}
        reviewed = call(session, REVIEW, envelope)
        assert reviewed == {"account": actor, "from": address, "token": reviewed["token"], **{key: envelope[key] for key in ("to", "cc", "bcc")}}
        assert re.fullmatch("[a-f0-9]{64}", reviewed["token"])
        return dict(envelope, externalReview=reviewed["token"], subject=subject, text="Sample note.\n.\nStill in the same message.",
                    sendId=secrets.token_hex(16), delaySeconds=delay)

    config = fixture.directory / "providers.json"
    fixture.env["SMTP_WEBMAIL_EXTERNAL_SENDERS_FILE"] = str(config)
    password = secrets.token_hex(16)
    password_path = fixture.directory / "smtp-provider-secret"
    password_path.write_text(password + "\n")
    password_path.chmod(0o600)
    username = "approved-provider-account"
    server.token = base64.b64encode(f"\0{username}\0{password}".encode())
    write_grants([])

    with fixture.daemon():
        actor = fixture.provision("author", daily=30)
        address = fixture.provision("external-address")
        unrelated = fixture.provision("unrelated")
        session, other = fixture.login(actor), fixture.login(unrelated)
        grant = {"id": IDENTITY, "mailbox": actor, "address": address, "host": "localhost", "port": server.server_address[1],
                 "username": username, "password_file": str(password_path), "ca_file": str(root)}
        write_grants([grant])
        assert call(other, VERIFICATION) == []
        assert call(session, "sender-identities") == []
        assert call(session, VERIFICATION) == [{"id": IDENTITY, "address": address, "state": "unverified"}]
        call(other, VERIFICATION, verification("request"), 403)
        call({**session, "Origin": "https://another.example"}, VERIFICATION, verification("request"), 403)
        call(session, REVIEW, {"senderId": IDENTITY, "to": [unrelated]}, 403)
        assert call(session, VERIFICATION, verification("request"))[0]["state"] == "pending"
        call(session, VERIFICATION, verification("request"), 429)
        code = obtain_code()
        call(other, VERIFICATION, verification("confirm", code), 403)
        call(session, VERIFICATION, verification("confirm", "0" * 32), 400)
        assert call(session, "sender-identities") == []
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            row = db.execute("SELECT payload FROM webmail_records WHERE kind='external-sender-proof'").fetchone()[0]
            assert code not in row and hashlib.sha256(code.encode()).hexdigest() in row
        assert call(session, VERIFICATION, verification("confirm", code))[0]["state"] == "verified"
        call(session, VERIFICATION, verification("confirm", code), 400)
        assert call(session, "sender-identities") == [{"id": IDENTITY, "address": address}]
        assert server.connections == 0

        message = queue("Verified external message", to=[unrelated], cc=["cc@destination.example"], bcc=["secret@destination.example"])
        call(other, "compose", message, 403)
        call({**session, "X-Webmail-Account": unrelated}, "compose", message, 409)
        call(session, "compose", dict(message, sendId=None), 409)
        call(session, "compose", dict(message, externalReview=None), 409)
        call(session, "compose", dict(message, bcc=["changed@destination.example"]), 409)
        assert server.connections == 0 and fixture.count(actor) == 0
        call(session, "compose", message)
        sent = fixture.outbox(session, message["sendId"], "sent")
        assert sent["result"]["delivered"] == 3 and fixture.count(actor) == 3
        assert call(session, "compose", message)["state"] == "sent"
        assert server.auth_attempts == [True] and len(server.transactions) == 1
        sender, recipients, raw = server.transactions[0]
        assert sender == address and recipients == [unrelated, "cc@destination.example", "secret@destination.example"]
        delivered = BytesParser(policy=policy.default).parsebytes(raw)
        assert delivered["From"] == address and delivered["To"] == unrelated and delivered["Cc"] == "cc@destination.example"
        assert delivered["Bcc"] is None
        assert delivered.get_body().get_content().splitlines() == message["text"].splitlines()
        assert not call(other, "messages?conversations=false")["items"], "Even local recipients go through the approved provider"
        sent_summary, = call(session, "messages?folder=Sent&conversations=false")["items"]
        sent_copy = call(session, f'messages/{sent_summary["uid"]}?folder=Sent')
        assert sent_copy["from"] == address and sent_copy["bcc"] == "secret@destination.example"

        for mode, context in (("plaintext", server.context), ("wrong-host", wrong_host), ("wrong-issuer", wrong_issuer)):
            server.mode, server.context = mode, context
            bad = queue(mode)
            call(session, "compose", bad)
            failed = fixture.outbox(session, bad["sendId"], "failed")
            assert "TLS" in failed["error"], failed
            assert len(server.transactions) == 1 and server.auth_attempts == [True]
        server.context = trusted_context
        server.mode = "bad-auth"
        bad_auth = queue("Invalid SMTP provider credentials")
        call(session, "compose", bad_auth)
        assert "authentication" in fixture.outbox(session, bad_auth["sendId"], "failed")["error"]

        server.mode = "reject-data"
        refused = queue("Rejected DATA")
        call(session, "compose", refused)
        failure = fixture.outbox(session, refused["sendId"], "failed")
        assert failure["result"]["unknown"] == [] and "rejected the message" in failure["error"]

        server.mode = "drop-ack"
        uncertain = queue("Accepted but confirmation lost", to=["one@destination.example", "unavailable@destination.example"],
                          bcc=["blind@destination.example"])
        call(session, "compose", uncertain)
        outcome = fixture.outbox(session, uncertain["sendId"], "unknown")
        assert outcome["result"]["unknown"] == ["one@destination.example", "blind@destination.example"]
        assert outcome["result"]["failed"] == ["unavailable@destination.example"]
        count = len(server.transactions)
        assert call(session, "compose", uncertain)["state"] == "unknown" and len(server.transactions) == count
        review = subprocess.run([str(fixture.binary), "user:local", "hosted-erasure-preflight",
                                 actor, fixture.specs[actor]["actor"], "provider-exit-case"],
                                cwd=fixture.directory, env=fixture.env, text=True, capture_output=True, timeout=12, check=True)
        evidence = json.loads(review.stdout)["observation"]
        assert evidence["delivery"]["remote_unconfirmed_targets"] == 2, evidence
        assert evidence["webmail_outbox"]["needs_review"] >= 1, evidence

        server.mode = "normal"
        charged = fixture.count(actor)
        fixture.provision("author", daily=charged + 2)
        over = queue("Above the remaining allowance", to=["one@destination.example", "two@destination.example", "three@destination.example"])
        call(session, "compose", over)
        limited = fixture.outbox(session, over["sendId"], "failed")
        assert "Daily recipient allowance" in limited["error"] and len(server.transactions) == count
        assert fixture.count(actor) == charged
        partial = queue("Exactly the remaining allowance", to=["one@destination.example", "unavailable@destination.example"])
        call(session, "compose", partial)
        finished = fixture.outbox(session, partial["sendId"], "partial")
        assert finished["result"]["delivered"] == 1 and finished["result"]["failed"] == ["unavailable@destination.example"]
        assert fixture.count(actor) == charged + 2 and len(server.transactions) == count + 1
        count += 1

        rebound = queue("Queued before provider changed", delay=30)
        call(session, "compose", rebound)
        write_grants([{**grant, "username": "different-provider-account"}])
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            db.execute("UPDATE webmail_records SET due_at=unixepoch() WHERE kind='outbox' AND id=?", (rebound["sendId"],))
        assert "no longer authorized" in fixture.outbox(session, rebound["sendId"], "failed")["error"]
        assert len(server.transactions) == count
        write_grants([grant])

        revoked = queue("Queued before account revocation", delay=30)
        call(session, "compose", revoked)
        assert call(session, VERIFICATION, verification("revoke"))[0]["state"] == "unverified"
        assert call(session, "sender-identities") == []
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            db.execute("UPDATE webmail_records SET due_at=unixepoch() WHERE kind='outbox' AND id=?", (revoked["sendId"],))
        assert "no longer authorized" in fixture.outbox(session, revoked["sendId"], "failed")["error"]
        assert len(server.transactions) == count

        # Provider and credential material never reaches a response or a stored message.
        assert password not in str(sent) and username not in str(sent) and str(password_path) not in str(sent)
    with fixture.daemon():
        session = fixture.login(actor)
        assert call(session, "compose", uncertain)["state"] == "unknown"
        assert len(server.transactions) == count and call(session, "sender-identities") == []
    for log in fixture.directory.glob("mail-*.log"):
        contents = log.read_bytes()
        assert password.encode() not in contents and server.token not in contents


def verify_browser(fixture, server, trust, engine, output):
    config = fixture.directory / "providers.json"
    fixture.env["SMTP_WEBMAIL_EXTERNAL_SENDERS_FILE"] = str(config)
    password = secrets.token_hex(16)
    secret = fixture.directory / "provider-password"
    secret.write_text(password)
    secret.chmod(0o600)
    server.token = base64.b64encode(f"\0approved-smtp\0{password}".encode())
    with fixture.daemon():
        owner = fixture.provision("alex.browser")
        address = fixture.provision("studio.browser")
        config.write_text(json.dumps([{"id": IDENTITY, "mailbox": owner, "address": address, "host": "localhost",
                                      "port": server.server_address[1], "username": "approved-smtp",
                                      "password_file": str(secret), "ca_file": str(trust)}]))
        env = dict(os.environ, MAIL_BROWSER_URL=fixture.webmail, MAIL_BROWSER_OWNER=owner,
                   MAIL_BROWSER_SENDER=address, MAIL_BROWSER_PASSWORD=fixture.password)
        runner = Path(__file__).with_name("webmail-external-sender-browser.mjs")
        subprocess.run(["node", str(runner), engine, str(output / engine)], env=env, check=True, timeout=90)
        end = time.monotonic() + 10
        while not server.transactions and time.monotonic() < end:
            time.sleep(0.1)
        sender, recipients, raw = server.transactions[0]
        assert sender == address
        assert recipients == ["reader@destination.example", "reviewer@destination.example", "updated@destination.example"]
        assert b"Browser external SMTP review" in raw


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--browser", choices=("chromium", "firefox", "webkit"))
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()
    if args.browser and not args.screenshots:
        parser.error("--browser requires --screenshots")
    with tempfile.TemporaryDirectory(prefix="mail-external-smtp-") as directory:
        root = Path(directory)
        trust, trusted_context = make_tls(root, "trusted", "localhost")
        # Let the provider claim its port before the daemon fixture selects its
        # ports. The daemon cannot bind them until its subprocess starts.
        with provider_server(trusted_context) as server:
            fixture = Fixture(args.binary.resolve(strict=True), root, staging=True)
            if args.browser:
                verify_browser(fixture, server, trust, args.browser, args.screenshots.resolve())
                raise SystemExit(0)
            wrong_host_ca, wrong_host = make_tls(root, "wrong-name", "wrong.example")
            _, wrong_issuer = make_tls(root, "untrusted", "localhost")
            # Trust both roots to isolate hostname verification from trust-chain failure.
            roots = root / "approved-roots.pem"
            roots.write_bytes(trust.read_bytes() + wrong_host_ca.read_bytes())
            verify(fixture, server, roots, wrong_host, wrong_issuer)
    print("External From verification, strict TLS SMTP, envelope review, Outbox recovery, and revocation passed.")
