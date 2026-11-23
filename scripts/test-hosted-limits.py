#!/usr/bin/env python3
"""Exercise hosted limits against the real Mail daemon on loopback."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager, nullcontext
from email import policy
from email.parser import BytesParser
import http.client
import imaplib
import json
import os
from pathlib import Path
import secrets
import re
import smtplib
import socket
import ssl
import sqlite3
import subprocess
import tempfile
from threading import Barrier
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape, quoteattr


DOMAIN = "hosted.example.test"
EXTERNAL = "sender@external.example.test"
LARGE = 1024 * 1024


def available_ports(count=6):
    listeners = [socket.socket() for _ in range(count)]
    try:
        for listener in listeners:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()


def request(url, payload=None, headers=None, method=None, context=None, timeout=10):
    headers = dict(headers or {})
    data = None
    if payload is not None:
        if isinstance(payload, bytes):
            data = payload
        else:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()


class MailClient:
    hostname = "127.0.0.1"
    http = staticmethod(request)

    def login(self, mailbox):
        session = {"Origin": self.webmail}
        status, headers, raw = self.http(self.webmail + "/webmail/auth/login",
                                       {"username": mailbox, "password": self.password}, session,
                                       context=self.tls_context)
        assert status == 200, (status, raw)
        cookie = headers["Set-Cookie"].split(";")
        if self.staging:
            assert "secure" in {part.strip().lower() for part in cookie[1:]}
        session["Cookie"] = cookie[0]
        return session

    def api(self, session, path, payload=None, method=None):
        status, _, raw = self.http(self.webmail + "/webmail/api/" + path, payload, session, method,
                                 context=self.tls_context)
        return status, json.loads(raw) if raw else None

    @contextmanager
    def smtp(self, identity=None):
        port = self.submission_port if self.staging and identity else self.smtp_port
        with smtplib.SMTP(self.hostname, port, local_hostname="client.example.test", timeout=10) as client:
            client.ehlo()
            if self.staging:
                client.starttls(context=self.tls_context)
                client.ehlo()
            if identity:
                client.login(identity, self.password)
            yield client

    def check_staging_smtp(self):
        for port in (self.smtp_port, self.submission_port):
            with smtplib.SMTP(self.hostname, port, local_hostname="client.example.test", timeout=10) as client:
                assert client.ehlo()[0] == 250
                assert client.has_extn("starttls") and not client.has_extn("auth")
                code, message = client.mail(EXTERNAL)
                assert code == 530 and b"STARTTLS" in message, (code, message)

    @contextmanager
    def imap(self, mailbox):
        with imaplib.IMAP4(self.hostname, self.imap_port, timeout=10) as client:
            if self.staging:
                assert client.starttls(ssl_context=self.tls_context)[0] == "OK"
            assert client.login(mailbox, self.password)[0] == "OK"
            yield client

    def ews(self, mailbox, operation, *, fragmented=False):
        # Use the bare login to check that EWS charges the canonical account.
        name = mailbox.split("@")[0]
        token = base64.b64encode(f"{name}:{self.password}".encode()).decode()
        soap = (
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            'xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" '
            'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">'
            f"<s:Body>{operation}</s:Body></s:Envelope>"
        )
        if not fragmented:
            return self.http(self.ews_url, soap.encode(),
                           {"Authorization": f"Basic {token}", "Content-Type": "text/xml"},
                           context=self.tls_context)

        url = urllib.parse.urlsplit(self.ews_url)
        body = soap.encode()
        headers = (f"POST {url.path} HTTP/1.1\r\nHost: {url.netloc}\r\n"
                   f"Authorization: Basic {token}\r\nContent-Type: text/xml\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        with socket.create_connection((url.hostname, url.port), timeout=10) as sock:
            stream = (self.tls_context.wrap_socket(sock, server_hostname=url.hostname)
                      if self.staging else nullcontext(sock))
            with stream as conn:
                for fragment in (headers[:30], headers[30:], body[:21], body[21:]):
                    conn.sendall(fragment)
                    time.sleep(0.025)
                response = http.client.HTTPResponse(conn)
                response.begin()
                return response.status, response.headers, response.read()

    def eas(self, mailbox, body, *, command="SendMail", device="QuotaDevice", legacy=False,
            save=False, encoded=False, source=None, version=None, timeout=10):
        name = mailbox.split("@")[0]
        token = base64.b64encode(f"{name}:{self.password}".encode()).decode()
        headers = {"Authorization": f"Basic {token}",
                   "Content-Type": "message/rfc822" if legacy else "application/vnd.ms-sync.wbxml"}
        if encoded:
            commands = {"SendMail": 1, "Sync": 0, "SmartForward": 2, "SmartReply": 3,
                        "FolderSync": 9, "FolderCreate": 10, "FolderDelete": 11, "FolderUpdate": 12, "MoveItems": 13,
                        "GetItemEstimate": 14, "Search": 16, "Ping": 18}
            packed = bytes([121 if legacy else 141, commands[command], 9, 4, len(device)])
            packed += device.encode() + b"\x00\x0aSmartPhone"
            if save:
                packed += b"\x07\x01\x01"
            if source:
                for tag, value in ((1, source[0]), (3, source[1])):
                    packed += bytes([tag, len(value)]) + value.encode()
            query = urllib.parse.quote(base64.b64encode(packed).decode(), safe="")
        else:
            headers["MS-ASProtocolVersion"] = version or ("12.1" if legacy else "14.1")
            # Authentication selects the account for sending and quota usage.
            params = {"Cmd": command, "User": "different-user", "DeviceId": device,
                      "DeviceType": "SmartPhone", "SaveInSent": "T" if save else "F"}
            if source:
                params.update(CollectionId=source[0], ItemId=source[1])
            query = urllib.parse.urlencode(params)
        return self.http(self.eas_url + "?" + query, body, headers, context=self.tls_context, timeout=timeout)

    def deliver(self, to, *, identity=None, chunked=False, subject="Boundary", body=None):
        sender = identity or EXTERNAL
        recipients = [to] if isinstance(to, str) else to
        with self.smtp(identity) as client:
            return smtp_message(client, sender, recipients, subject, body, chunked)

    def expunge(self, session, folder):
        status, listing = self.api(session, "messages?" + urllib.parse.urlencode({"folder": folder}))
        assert status == 200, listing
        for item in listing["items"]:
            status, result = self.api(session, f"messages/{item['uid']}?folder={folder}", method="DELETE")
            assert status in (200, 204), (status, result)


class Fixture(MailClient):
    def __init__(self, binary, directory, *, tls=False, staging=False):
        self.binary = binary
        self.directory = directory
        self.staging = staging
        ports = available_ports(9 if tls or staging else 6)
        self.smtp_port, web_port, private_port, self.submission_port, self.imap_port, dav_port = ports[:6]
        self.webmail = f"http://127.0.0.1:{web_port}"
        self.private = f"http://127.0.0.1:{private_port}"
        self.ews_url = f"http://127.0.0.1:{dav_port}/EWS/Exchange.asmx"
        self.eas_url = f"http://127.0.0.1:{dav_port}/Microsoft-Server-ActiveSync"
        self.password = secrets.token_hex(16)
        token = secrets.token_hex(32)
        self.auth = {"Authorization": f"Bearer {token}"}
        self.env = dict(
            PATH=os.environ["PATH"], SMTP_DB_PATH=str(directory / "smtp.db"),
            SMTP_HOSTNAME=f"mail.{DOMAIN}", SMTP_LOCAL_DOMAINS=DOMAIN,
            SMTP_ENABLE_WEBMAIL="true", SMTP_WEBMAIL_PORT=str(web_port),
            SMTP_WEBMAIL_TLS="false", SMTP_WEBMAIL_SECURE_COOKIES="false",
            SMTP_ANTISPAM_CHECK="false", SMTP_SPAM_FILTER="false",
            SMTP_ENABLE_DNSBL="false", SMTP_ENABLE_GREYLIST="false",
            SMTP_REQUIRE_TLS_FOR_AUTH="false", IMAP_ENABLED="true", IMAP_PORT=str(self.imap_port),
            CALDAV_ENABLED="true", CALDAV_PORT=str(dav_port), CALDAV_DB_PATH=str(directory / "caldav.db"),
            SUBMISSION_PORT=str(self.submission_port), SMTP_PROVISIONING_DOMAIN=DOMAIN,
            SMTP_PROVISIONING_PORT=str(private_port), SMTP_PROVISIONING_TOKEN=token,
        )
        self.tls_context = None
        if tls or staging:
            dav_tls, self.imaps_port, self.smtps_port = ports[6:]
            cert, key = directory / "test.pem", directory / "test.key"
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                 "-keyout", str(key), "-out", str(cert)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
            )
            self.env.update(SMTP_ENABLE_TLS="true", SMTP_TLS_CERT=str(cert), SMTP_TLS_KEY=str(key),
                            CALDAV_SSL_PORT=str(dav_tls), IMAPS_PORT=str(self.imaps_port), SMTPS_PORT=str(self.smtps_port))
            self.tls_context = ssl.create_default_context(cafile=str(cert))
            self.eas_url = f"https://127.0.0.1:{dav_tls}/Microsoft-Server-ActiveSync"
        if staging:
            self.env.update(SMTP_PROFILE="staging", SMTP_REQUIRE_TLS_FOR_AUTH="true",
                            SMTP_WEBMAIL_TLS="true", SMTP_WEBMAIL_SECURE_COOKIES="true")
            self.webmail = f"https://127.0.0.1:{web_port}"
            self.ews_url = f"https://127.0.0.1:{dav_tls}/EWS/Exchange.asmx"
        self.specs = {}

    @contextmanager
    def daemon(self):
        log_path = self.directory / f"mail-{secrets.token_hex(4)}.log"
        with log_path.open("w") as log:
            daemon = subprocess.Popen(
                [str(self.binary), "serve", "--host", "127.0.0.1", "--port",
                 str(self.smtp_port), "--enable-auth"] + (["--disable-tls"] if self.tls_context is None else []),
                cwd=self.directory, env=self.env, stdout=log, stderr=log,
            )
            try:
                for _ in range(100):
                    if daemon.poll() is not None:
                        raise RuntimeError("Mail stopped during startup")
                    try:
                        if request(self.private + "/provisioning/v1/status", headers=self.auth)[0] == 200:
                            with socket.create_connection(("127.0.0.1", self.imap_port), timeout=0.2):
                                pass
                            if request(self.ews_url, b"<probe/>", context=self.tls_context)[0] == 401:
                                if self.tls_context is None or request(self.eas_url, method="OPTIONS", context=self.tls_context)[0] == 200:
                                    break
                    except (OSError, urllib.error.URLError):
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Mail did not start the private listener")
                yield daemon
            except Exception:
                print(log_path.read_text(errors="replace")[-8000:])
                raise
            finally:
                daemon.terminate()
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()

    def provision(self, user, *, quota=LARGE, daily=20, enabled=True):
        mailbox = f"{user}@{DOMAIN}"
        previous = self.specs.get(mailbox)
        change = {
            "mailbox": mailbox, "actor": previous["actor"] if previous else secrets.token_hex(16),
            "operation_id": secrets.token_hex(16), "revision": previous["revision"] + 1 if previous else 1,
            "quota_bytes": quota, "send_recipients_per_day": daily, "enabled": enabled,
        }
        if not previous:
            change.update(initial_recovery=f"{user}@recovery.example.test", initial_password=self.password)
        status, _, raw = request(self.private + "/provisioning/v1/mailbox", change, self.auth)
        assert status == 200, (status, raw)
        assert json.loads(raw) == {key: change[key] for key in (
            "mailbox", "revision", "quota_bytes", "send_recipients_per_day", "enabled",
        )}
        self.specs[mailbox] = change
        return mailbox

    def bytes(self, mailbox):
        return sum(file.stat().st_size for file in (self.directory / "mail" / mailbox).rglob("*.eml*")
                   if file.is_file() and not file.name.startswith("."))

    def outbox(self, session, send_id, expected):
        for _ in range(80):
            state, item = self.api(session, f"outbox/{send_id}")
            assert state == 200, (state, item)
            if item["state"] == expected:
                return item
            assert item["state"] in ("pending", "sending"), item
            time.sleep(0.125)
        raise AssertionError(f"Outbox send {send_id} did not reach {expected}")

    def count(self, mailbox):
        with closing(sqlite3.connect(self.directory / "smtp.db")) as db:
            row = db.execute(
                "SELECT recipients FROM hosted_sending_usage JOIN users ON users.id=user_id WHERE username=?",
                (mailbox,),
            ).fetchone()
            return row[0] if row else 0


def smtp_message(client, sender, recipients, subject="Boundary", body=None, chunked=False):
    code, reply = client.mail(sender)
    if code != 250:
        return code, reply
    for address in recipients:
        code, reply = client.rcpt(address)
        if code != 250:
            return code, reply
    text = body or "x" * 600
    raw = (f"From: <{sender}>\r\nDate: Sat, 21 Nov 2026 12:00:00 +0000\r\n"
           f"Message-ID: <limit@external.example.test>\r\nSubject: {subject}\r\n\r\n{text}\r\n").encode()
    if not chunked:
        return client.data(raw)
    middle = len(raw) // 2
    for index, chunk in enumerate((raw[:middle], raw[middle:])):
        last = " LAST" if index else ""
        client.send(f"BDAT {len(chunk)}{last}\r\n".encode() + chunk)
        result = client.getreply()
        if not index:
            assert result[0] == 250, result
    return result


def expect_smtp(result, code, enhanced=None):
    assert result[0] == code, result
    if enhanced:
        assert result[1].startswith(enhanced.encode()), result


def check_storage(test, sink, sender_session):
    mailbox = test.provision("storage")
    expect_smtp(test.deliver(mailbox), 250)
    size = test.bytes(mailbox)
    assert size > 600, size
    test.provision("storage", quota=2 * size - 1)
    expect_smtp(test.deliver(mailbox), 452, "4.2.2")  # one byte over
    assert test.bytes(mailbox) == size
    test.provision("storage", quota=2 * size)
    expect_smtp(test.deliver(mailbox), 250)  # exactly full
    assert test.bytes(mailbox) == 2 * size
    expect_smtp(test.deliver(mailbox, chunked=True), 452, "4.2.2")
    # The provisioning revision wins even after an SMTP recipient was accepted.
    with test.smtp() as client:
        expect_smtp(client.mail(EXTERNAL), 250)
        expect_smtp(client.rcpt(mailbox), 250)
        test.provision("storage", quota=2 * size, enabled=False)
        expect_smtp(client.data(b"Subject: concurrent suspension\r\n\r\nbody"), 550, "5.2.1")
    test.provision("storage", quota=2 * size)
    session = test.login(mailbox)
    before = test.bytes(sink)
    expect_smtp(test.deliver([sink, mailbox], chunked=True), 452, "4.2.2")
    assert test.bytes(sink) == before, "rejected transaction delivered to another recipient"

    code, error = test.api(sender_session, "compose", {"to": [mailbox.upper()], "text": "blocked"})
    assert code == 507 and error["error"] == "mailbox_full", (code, error)
    test.expunge(session, "INBOX")
    assert test.bytes(mailbox) == 2 * size, "Trash still occupies storage"
    test.expunge(session, "Trash")
    assert test.bytes(mailbox) == 0
    expect_smtp(test.deliver(mailbox, chunked=True), 250)

    # Common SMTP/webmail lock: two individually admissible deliveries to the
    # same Maildir cannot both claim the final bytes. Use two protocol threads.
    test.provision("storage", quota=LARGE)
    expect_smtp(test.deliver(mailbox), 250)
    smtp_size = test.bytes(mailbox)
    code, result = test.api(sender_session, "compose", {"to": [mailbox], "text": "z" * 600})
    assert code == 200 and result["delivered"] == 1, (code, result)
    web_size = test.bytes(mailbox) - smtp_size
    test.expunge(session, "INBOX")
    test.expunge(session, "Trash")
    test.provision("storage", quota=max(size, web_size) + 32)
    barrier = Barrier(2)

    def inbound():
        barrier.wait(timeout=10)
        return test.deliver(mailbox)[0]

    def webmail():
        barrier.wait(timeout=10)
        return test.api(sender_session, "compose", {"to": [mailbox], "text": "z" * 600})[0]

    with ThreadPoolExecutor(max_workers=2) as workers:
        left, right = workers.submit(inbound), workers.submit(webmail)
        assert (left.result(), right.result()) in ((250, 507), (452, 200))
    assert 0 < test.bytes(mailbox) <= max(size, web_size) + 32

    drafts = test.provision("drafts")
    draft_session = test.login(drafts)
    initial = {"subject": "Draft", "text": "d" * 200, "saveToken": "initial"}
    status, saved = test.api(draft_session, "drafts", initial)
    assert status == 200, saved
    draft_bytes = test.bytes(drafts)
    test.provision("drafts", quota=draft_bytes)
    revision = {"draftId": saved["draftId"], "draftUid": saved["uid"], "draftRevision": saved["revision"]}
    status, error = test.api(draft_session, "drafts", dict(initial, **revision, text="d" * 201, saveToken="growth"))
    assert status == 507 and error["error"] == "mailbox_full", (status, error)
    status, result = test.api(draft_session, "drafts", dict(initial, **revision, text="shorter", saveToken="shrink"))
    assert status == 200 and result["uid"] == saved["uid"], (status, result)
    assert test.bytes(drafts) < draft_bytes


def check_sending(test, sink):
    sender = test.provision("sender", daily=2)
    session = test.login(sender)
    expect_smtp(test.deliver([sink, sink], identity=sender, chunked=True), 250)
    assert test.count(sender) == 1
    code, sent = test.api(session, "compose", {"to": [sink], "bcc": [sink.upper()], "text": "Second use"})
    assert code == 200 and sent["delivered"] == 1, (code, sent)
    assert test.count(sender) == 2
    before = test.bytes(sink)
    with test.smtp(sender) as smtp:
        expect_smtp(smtp_message(smtp, sender, [sink]), 452, "4.7.0")
        expect_smtp(smtp_message(smtp, sender, [sink], chunked=True), 452, "4.7.0")
    status, error = test.api(session, "compose", {"to": [sink], "text": "Over limit"})
    assert status == 429 and error["error"] == "sending_limit", (status, error)
    assert test.bytes(sink) == before

    racer = test.provision("racer", daily=1)
    racing_session = test.login(racer)
    barrier = Barrier(2)

    def smtp_race():
        barrier.wait(timeout=10)
        return test.deliver(sink, identity=racer)[0]

    def webmail_race():
        barrier.wait(timeout=10)
        return test.api(racing_session, "compose", {"to": [sink], "text": "Race"})[0]

    with ThreadPoolExecutor(max_workers=2) as workers:
        left, right = workers.submit(smtp_race), workers.submit(webmail_race)
        assert (left.result(), right.result()) in ((250, 429), (452, 200))
    assert test.count(racer) == 1
    return sender


def check_outbox(test, sink):
    queue_user = test.provision("outbox", daily=1)
    session = test.login(queue_user)
    send_id = secrets.token_hex(16)
    message = {"to": [sink], "text": "Outbox over allowance", "sendId": send_id, "delaySeconds": 3}
    for _ in range(2):
        status, queued = test.api(session, "compose", message)
        assert status == 200 and queued["id"] == send_id and queued["state"] == "pending", queued
    assert test.count(queue_user) == 0
    expect_smtp(test.deliver(sink, identity=queue_user), 250)
    before = test.bytes(sink)
    failed = test.outbox(session, send_id, "failed")
    assert "Daily recipient allowance" in failed["error"], failed
    assert test.bytes(sink) == before and test.count(queue_user) == 1

    paused = test.provision("paused", daily=1)
    paused_session = test.login(paused)
    send_id = secrets.token_hex(16)
    code, queued = test.api(paused_session, "compose", dict(message, sendId=send_id))
    assert code == 200 and queued["state"] == "pending", queued
    with test.smtp(paused) as authenticated:
        test.provision("paused", daily=1, enabled=False)
        expect_smtp(test.deliver(paused), 550, "5.2.1")
        expect_smtp(smtp_message(authenticated, paused, [sink], chunked=True), 550, "5.7.1")
    until = time.monotonic() + 10
    state = None
    while time.monotonic() < until:
        with sqlite3.connect(test.directory / "smtp.db") as db:
            state, = db.execute("SELECT state FROM webmail_records WHERE kind='outbox' AND id=?", (send_id,)).fetchone()
        if state == "failed":
            break
        time.sleep(0.125)
    assert state == "failed"
    assert test.count(paused) == 0 and test.bytes(sink) == before
    test.provision("paused", daily=1)
    failed = test.outbox(test.login(paused), send_id, "failed")
    assert "disabled" in failed["error"], failed

    unfiled = test.provision("unfiled", quota=1, daily=1)
    unfiled_session = test.login(unfiled)
    send_id = secrets.token_hex(16)
    status, result = test.api(unfiled_session, "compose", dict(message, sendId=send_id, delaySeconds=0))
    assert status == 200, result
    filed = test.outbox(unfiled_session, send_id, "sent_unfiled")
    assert filed["result"]["delivered"] == 1 and "mailbox is full" in filed["error"], filed
    assert test.bytes(unfiled) == 0


def assert_imap(result, status="OK", response=None):
    assert result[0] == status, result
    if response:
        assert response in b" ".join(part for part in result[1] if isinstance(part, bytes)), result
    return result[1]


def imap_message(label="Stored message", payload=300):
    return f"Subject: {label}\r\nFrom: {EXTERNAL}\r\n\r\n".encode() + b"x" * payload + b"\r\n"


def check_imap(test):
    raw = imap_message()
    size = len(raw)
    mailbox = test.provision("imap", quota=size - 1)
    with test.imap(mailbox) as imap:
        assert_imap(imap.append("INBOX", None, None, raw), "NO", b"[OVERQUOTA]")
        assert test.bytes(mailbox) == 0
        test.provision("imap", quota=2 * size)
        assert_imap(imap.append("INBOX", "(\\Flagged)", None, raw), response=b"APPENDUID")
        assert_imap(imap.append("INBOX", None, None, raw), response=b"APPENDUID")
        assert test.bytes(mailbox) == 2 * size
        assert_imap(imap.append("INBOX", None, None, raw), "NO", b"[OVERQUOTA]")
        assert_imap(imap.create("QuotaCopies"))
        assert_imap(imap.select("INBOX"))
        test.provision("imap", quota=4 * size - 1)
        assert_imap(imap.copy("1:2", "QuotaCopies"), "NO", b"[OVERQUOTA]")
        assert test.bytes(mailbox) == 2 * size, "COPY partially published before rejecting"
        test.provision("imap", quota=4 * size)
        uids = assert_imap(imap.uid("SEARCH", None, "ALL"))[0].replace(b" ", b",").decode()
        assert_imap(imap.uid("COPY", uids, "QuotaCopies"))
        assert test.bytes(mailbox) == 4 * size
        assert_imap(imap.copy("1", "QuotaCopies"), "NO", b"[OVERQUOTA]")
        assert_imap(imap.select("QuotaCopies"))
        flags = assert_imap(imap.fetch("1:2", "FLAGS"))
        assert any(b"\\Flagged" in line for line in flags), flags

        # A folder called tmp can be a flat legacy folder created by COPY.
        assert_imap(imap.rename("QuotaCopies", "Renamed"))
        assert test.bytes(mailbox) == 4 * size
        assert_imap(imap.select("INBOX"))
        assert_imap(imap.copy("1", "tmp"), "NO", b"[OVERQUOTA]")
        assert_imap(imap.store("1", "+FLAGS", r"(\Deleted)"))
        assert_imap(imap.expunge())
        assert_imap(imap.copy("1", "tmp"))
        folder = test.directory / "mail" / mailbox / "tmp"
        assert folder.is_dir() and not folder.is_symlink()
        assert test.bytes(mailbox) == 4 * size
        assert_imap(imap.append("tmp", None, None, raw), "NO", b"[OVERQUOTA]")

        # Accept the literal handshake before changing the account. The final
        # tagged result must use the new state and leave the stream in sync.
        imap.send(f"QUOTA APPEND INBOX {{{size}}}\r\n".encode())
        assert imap.readline().startswith(b"+")
        test.provision("imap", quota=5 * size, enabled=False)
        imap.send(raw + b"\r\n")
        reply = imap.readline()
        assert reply.startswith(b"QUOTA NO [NOPERM]"), reply
        assert_imap(imap.copy("1", "Renamed"), "NO", b"[NOPERM]")
        assert_imap(imap.noop())
        assert test.bytes(mailbox) == 4 * size

    # A single byte budget covers IMAP APPEND and EWS SaveOnly concurrently.
    race = test.provision("imap-race", quota=1100)
    raw = imap_message("Race", payload=800)
    barrier = Barrier(2)

    def append():
        with test.imap(race) as imap:
            barrier.wait(timeout=10)
            return imap.append("INBOX", None, None, raw)[0]

    def save_draft():
        barrier.wait(timeout=10)
        return ews_codes(test.ews(race, create_ews_item("SaveOnly", body="c" * 600)))[0]

    with ThreadPoolExecutor(max_workers=2) as workers:
        one, two = workers.submit(append), workers.submit(save_draft)
        assert (one.result(), two.result()) in (("OK", "ErrorQuotaExceeded"), ("NO", "NoError"))
    assert 0 < test.bytes(race) <= 1100


def check_implicit_tls(test, sink):
    raw = imap_message("Implicit TLS")
    full = test.provision("implicit-imap", quota=len(raw))
    with imaplib.IMAP4_SSL("127.0.0.1", test.imaps_port, ssl_context=test.tls_context, timeout=10) as imap:
        assert_imap(imap.login(full, test.password))
        assert_imap(imap.append("INBOX", None, None, raw), response=b"APPENDUID")
        assert_imap(imap.append("INBOX", None, None, raw), "NO", b"[OVERQUOTA]")
    assert test.bytes(full) == len(raw)

    sender = test.provision("implicit-smtp", daily=1)
    with smtplib.SMTP_SSL("127.0.0.1", test.smtps_port, local_hostname="client.example.test",
                         context=test.tls_context, timeout=10) as smtp:
        smtp.login(sender, test.password)
        expect_smtp(smtp_message(smtp, sender, [full]), 452, "4.2.2")
        assert test.count(sender) == 0
        expect_smtp(smtp_message(smtp, sender, [sink]), 250)
        expect_smtp(smtp_message(smtp, sender, [sink]), 452, "4.7.0")
    assert test.count(sender) == 1 and test.bytes(full) == len(raw)
    print("Verified IMAPS exact-fit APPEND and SMTPS storage refusal and allowance exhaustion.")


def create_ews_item(disposition, *, to=(), cc=(), bcc=(), subject="EWS quota", body="EWS body"):
    fields = [
        f"<t:Subject>{escape(subject)}</t:Subject>",
        f'<t:Body BodyType="Text">{escape(body)}</t:Body>',
    ]
    for field, addresses in (("ToRecipients", to), ("CcRecipients", cc), ("BccRecipients", bcc)):
        if addresses:
            mailboxes = "".join(f"<t:Mailbox><t:EmailAddress>{escape(address)}</t:EmailAddress></t:Mailbox>"
                                for address in addresses)
            fields.append(f"<t:{field}>{mailboxes}</t:{field}>")
    return (f'<m:CreateItem MessageDisposition={quoteattr(disposition)}><m:Items>'
            f'<t:Message>{"".join(fields)}</t:Message></m:Items></m:CreateItem>')


def send_ews_items(*ids, save=True):
    items = "".join(f"<t:ItemId Id={quoteattr(item)} />" for item in ids)
    return f'<m:SendItem SaveItemToFolder="{str(save).lower()}"><m:ItemIds>{items}</m:ItemIds></m:SendItem>'


def ews_codes(response):
    status, _, raw = response
    assert status == 200, (status, raw)
    return [code.text for code in ET.fromstring(raw).findall(".//{*}ResponseCode")]


def ews_draft(test, sender, recipient, **options):
    response = test.ews(sender, create_ews_item("SaveOnly", to=[recipient], **options))
    assert ews_codes(response) == ["NoError"], response
    return ET.fromstring(response[2]).find(".//{*}ItemId").attrib["Id"]


def check_ews(test, sink):
    sender = test.provision("ews", daily=2)
    blind = test.provision("blind")
    request = create_ews_item("SendAndSaveCopy", to=[sink], cc=[sink.upper()], bcc=[blind], subject="Private EWS copy")
    assert ews_codes(test.ews(sender, request)) == ["NoError"]
    assert test.count(sender) == 2
    assert len(list((test.directory / "mail" / sender / "Sent").glob("*.eml*"))) == 1
    assert not (test.directory / "mail" / "ews").exists()
    for user in (sink, blind):
        messages = [path.read_bytes() for path in (test.directory / "mail" / user / "new").glob("*.eml*")]
        received = [msg for msg in messages if b"Subject: Private EWS copy" in msg]
        assert len(received) == 1 and b"Bcc:" not in received[0], received

    draft = ews_draft(test, sender, sink, bcc=[blind])
    draft_file, = (test.directory / "mail" / sender / "Drafts").glob(draft.split(":", 1)[1] + "*")
    draft_bytes = draft_file.stat().st_size
    before = (test.bytes(sender), test.bytes(sink), test.bytes(blind))
    assert ews_codes(test.ews(sender, send_ews_items(draft))) == ["ErrorSubmissionQuotaExceeded"]
    assert ews_codes(test.ews(sender, request, fragmented=True)) == ["ErrorSubmissionQuotaExceeded"]
    expect_smtp(test.deliver(sink, identity=sender), 452, "4.7.0")
    code, result = test.api(test.login(sender), "compose", {"to": [sink], "text": "EWS used the allowance"})
    assert code == 429 and result["error"] == "sending_limit", (code, result)
    assert before == (test.bytes(sender), test.bytes(sink), test.bytes(blind))

    # Sending a saved draft counts Bcc, including when Sent filing is disabled.
    test.provision("ews", daily=3)
    assert ews_codes(test.ews(sender, send_ews_items(draft, save=False))) == ["ErrorSubmissionQuotaExceeded"]
    test.provision("ews", daily=4)
    assert ews_codes(test.ews(sender, send_ews_items(draft, save=False))) == ["NoError"]
    assert test.count(sender) == 4 and test.bytes(sender) == before[0] - draft_bytes
    assert not draft_file.exists()
    assert ews_codes(test.ews(sender, send_ews_items(draft, save=False))) == ["NoError"]
    assert ews_codes(test.ews(sender, send_ews_items(draft))) == ["ErrorInvalidSendItemSaveSettings"]
    quota_draft = ews_draft(test, sender, sink, bcc=[blind])
    test.provision("ews", quota=test.bytes(sender), daily=6)
    other_before = (test.bytes(sink), test.bytes(blind))
    assert ews_codes(test.ews(sender, send_ews_items(quota_draft))) == ["ErrorQuotaExceeded"]
    assert test.count(sender) == 4 and other_before == (test.bytes(sink), test.bytes(blind))

    # A quota refusal for the requested Sent copy must not deliver or spend
    # the allowance. SendOnly can still use the allowance in a full mailbox.
    tiny = test.provision("ews-tiny", daily=1, quota=1)
    before = test.bytes(sink)
    assert ews_codes(test.ews(tiny, create_ews_item("SaveOnly", to=[sink]))) == ["ErrorQuotaExceeded"]
    assert ews_codes(test.ews(tiny, create_ews_item("SendAndSaveCopy", to=[sink]))) == ["ErrorQuotaExceeded"]
    assert test.count(tiny) == 0 and test.bytes(tiny) == 0 and test.bytes(sink) == before
    assert ews_codes(test.ews(tiny, create_ews_item("SendOnly", to=[sink]))) == ["NoError"]
    assert test.count(tiny) == 1 and test.bytes(sink) > before
    test.provision("ews-tiny", quota=1, daily=2)
    assert ews_codes(test.ews(tiny, create_ews_item("SendOnly", to=[tiny]))) == ["ErrorQuotaExceeded"]
    assert test.bytes(tiny) == 0 and test.count(tiny) == 2

    batch = test.provision("ews-batch", daily=1)
    one = ews_draft(test, batch, sink, subject="First EWS batch item")
    two = ews_draft(test, batch, blind, subject="Second EWS batch item")
    before = test.bytes(blind)
    result = ews_codes(test.ews(batch, send_ews_items(one, two)))
    assert result == ["NoError", "ErrorSubmissionQuotaExceeded"], result
    assert test.count(batch) == 1 and test.bytes(blind) == before
    test.provision("ews-batch", daily=2)
    blocked = ews_draft(test, batch, tiny, subject="Recipient has no storage")
    assert ews_codes(test.ews(batch, send_ews_items(blocked, save=False))) == ["ErrorQuotaExceeded"]
    assert test.count(batch) == 2 and test.bytes(tiny) == 0
    retained, = (test.directory / "mail" / batch / "Drafts").glob(blocked.split(":", 1)[1] + "*")
    assert retained.is_file()
    test.provision("ews-batch", daily=4)
    partial = ews_draft(test, batch, sink, cc=[tiny], subject="Partial EWS draft")
    assert ews_codes(test.ews(batch, send_ews_items(partial))) == ["ErrorMessageSubmissionBlocked"]
    assert ews_codes(test.ews(batch, send_ews_items(partial))) == ["ErrorMessageSubmissionBlocked"]
    assert len(list((test.directory / "mail" / batch / "Drafts").glob(partial.split(":", 1)[1] + "*"))) == 1
    assert test.count(batch) == 4

    race = test.provision("ews-race", daily=1)
    session = test.login(race)
    before = len(list((test.directory / "mail" / sink / "new").glob("*.eml*")))
    barrier = Barrier(3)

    def via_ews():
        barrier.wait(timeout=10)
        code = ews_codes(test.ews(race, create_ews_item("SendOnly", to=[sink])))[0]
        assert code in ("NoError", "ErrorSubmissionQuotaExceeded"), code
        return code == "NoError"

    def via_smtp():
        barrier.wait(timeout=10)
        code = test.deliver(sink, identity=race)[0]
        assert code in (250, 452), code
        return code == 250

    def via_webmail():
        barrier.wait(timeout=10)
        code = test.api(session, "compose", {"to": [sink], "text": "Race with EWS"})[0]
        assert code in (200, 429), code
        return code == 200

    with ThreadPoolExecutor(max_workers=3) as workers:
        results = [workers.submit(method) for method in (via_ews, via_smtp, via_webmail)]
        assert sum(result.result() for result in results) == 1
    assert test.count(race) == 1
    assert len(list((test.directory / "mail" / sink / "new").glob("*.eml*"))) == before + 1

    test.provision("ews", daily=4, enabled=False)
    assert test.ews(sender, request)[0] == 401
    assert test.count(sender) == 4
    test.provision("ews", daily=4)
    return sender


def mb_uint(value):
    result = [value & 0x7f]
    value >>= 7
    while value:
        result.append((value & 0x7f) | 0x80)
        value >>= 7
    return bytes(reversed(result))


COMPOSE_TAGS = {"SendMail": 0x45, "SmartForward": 0x46, "SmartReply": 0x47}


def eas_send(mime, client_id="first", *, save=False, command="SendMail", source=None, replace=False, occurrence=None):
    source_xml = b""
    if source:
        folder, item = source
        source_xml = (b"\x4b" + (b"\x4c\x03" + folder.encode() + b"\x00\x01" if folder else b"")
                      + b"\x4d\x03" + item.encode() + b"\x00\x01"
                      + (b"\x4f\x03" + occurrence.encode() + b"\x00\x01" if occurrence else b"") + b"\x01")
    return (b"\x03\x01\x6a\x00\x00\x15" + bytes([COMPOSE_TAGS[command]])
            + b"\x51\x03" + client_id.encode() + b"\x00\x01"
            + (b"\x08" if save else b"") + (b"\x09" if replace else b"") + source_xml
            + b"\x50\xc3" + mb_uint(len(mime)) + mime + b"\x01\x01")


def eas_result(response, command="SendMail"):
    status, _, data = response
    if status != 200:
        return status
    if not data:
        return 0
    prefix = b"\x03\x01\x6a\x00\x00\x15" + bytes([COMPOSE_TAGS[command]]) + b"\x52\x03"
    assert data.startswith(prefix) and data.endswith(b"\x00\x01\x01"), response
    return int(data[len(prefix):-3])


def eas_mime(sender, to, *, extra=b"", subject="ActiveSync quotas", payload=b"Message body"):
    return (f"From: {sender}\r\nTo: {to}\r\n".encode() + extra
            + f"Subject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\n".encode()
            + payload + b"\r\n")


def eas_sync(key, folder="3"):
    return (b"\x03\x01\x6a\x00\x45\x5c\x4f\x4b\x03" + str(key).encode()
            + b"\x00\x01\x52\x03" + folder.encode() + b"\x00\x01\x01\x01\x01")


def eas_sync_key(data):
    match = re.search(rb"\x4b\x03([^\x00]{1,64})\x00\x01", data)
    assert match, data[:160]
    return match[1].decode()


def check_eas(test, sink):
    blind = test.provision("eas-blind")
    active = f"eas@{DOMAIN}"
    extra = f"Cc: {sink.upper()}\r\nBcc:\r\n {blind}\r\n".encode()
    private = eas_mime(active, f'"Doe, Jane" <{sink}>', extra=extra)
    wire = eas_mime(EXTERNAL, f'"Doe, Jane" <{sink}>', extra=extra)
    size = len(private)
    test.provision("eas", quota=size - 1, daily=2)
    request = eas_send(wire, save=True)
    before_sink = test.bytes(sink)

    assert eas_result(test.eas(active, request[:-1])) == 103, "truncated WBXML was accepted"
    assert eas_result(test.eas(active, eas_send(wire, "a" * 41))) == 103
    invalid = eas_send(eas_mime(active, "bad address"), save=True)
    assert eas_result(test.eas(active, invalid)) == 116
    assert eas_result(test.eas(active, eas_send(b"Subject: Empty\r\n\r\nbody"))) == 119
    assert eas_result(test.eas(active, request)) == 113, "one byte over storage was accepted"
    assert test.bytes(sink) == before_sink and test.bytes(blind) == 0
    assert test.count(active) == 0 and test.bytes(active) == 0

    test.provision("eas", quota=size, daily=2)
    assert eas_result(test.eas(active, request)) == 0, "exact byte and recipient allowance was refused"
    assert test.bytes(active) == size and test.count(active) == 2
    sent = list((test.directory / "mail" / active / "Sent").glob("*.eml*"))
    assert len(sent) == 1 and sent[0].read_bytes() == private, sent
    assert not (test.directory / "mail" / "eas").exists(), "hosted Sent copy used the short username"
    for target in (sink, blind):
        received = [path.read_bytes() for path in (test.directory / "mail" / target / "new").glob("*.eml*")]
        messages = [raw for raw in received if b"Subject: ActiveSync quotas" in raw]
        assert len(messages) == 1, messages
        assert messages[0].startswith(f"From: {active}\r\n".encode())
        assert b"Bcc:" not in messages[0] and b"\r\n\r\nMessage body\r\n" in messages[0]
    assert eas_result(test.eas(active, request, encoded=True)) == 118
    assert test.count(active) == 2
    assert eas_result(test.eas(active, eas_send(wire, "over"))) == 115
    expect_smtp(test.deliver(sink, identity=active), 452, "4.7.0")
    assert test.api(test.login(active), "compose", {"to": [sink], "text": "ActiveSync charged both"})[0] == 429
    ews = create_ews_item("SendOnly", to=[sink])
    assert ews_codes(test.ews(active, ews)) == ["ErrorSubmissionQuotaExceeded"]

    # Sent sync follows the canonical Maildir, including the flat folder
    # layout used by SMTP, IMAP, webmail, and hosted EWS.
    status, _, bootstrap = test.eas(active, eas_sync(0), command="Sync")
    assert status == 200 and eas_sync_key(bootstrap) != "0", bootstrap
    status, _, changes = test.eas(active, eas_sync(eas_sync_key(bootstrap)), command="Sync", encoded=True)
    assert status == 200 and b"ActiveSync quotas" in changes, changes
    attempted_add = eas_sync(eas_sync_key(changes))[:-3] + b"\x56\x47\x01\x01\x01\x01\x01"
    status, _, denied = test.eas(active, attempted_add, command="Sync")
    assert status == 200 and b"\x4e\x03" + b"6\x00\x01" in denied, denied
    assert test.bytes(active) == size

    test.provision("eas", quota=size, daily=4)
    single = eas_mime(active, sink, subject="Send without a stored copy")
    assert eas_result(test.eas(active, eas_send(single, "withoutcopy", save=True))) == 113
    assert test.count(active) == 2
    assert eas_result(test.eas(active, eas_send(single, "withoutcopy"))) == 0
    assert eas_result(test.eas(active, single, legacy=True, save=True, encoded=True)) == 507
    assert test.count(active) == 3
    assert eas_result(test.eas(active, single, legacy=True)) == 0
    assert eas_result(test.eas(active, single, legacy=True)) == 503
    assert test.count(active) == 4 and test.bytes(active) == size

    # A full hosted recipient is also checked through the local Inbox writer.
    race = test.provision("eas-race", daily=2)
    assert eas_result(test.eas(race, eas_send(eas_mime(race, active)))) == 113
    assert test.count(race) == 1 and test.bytes(active) == size
    session = test.login(race)
    barrier = Barrier(5)
    recipient_count = len(list((test.directory / "mail" / sink / "new").glob("*.eml*")))

    def via_eas():
        barrier.wait(timeout=10)
        code = eas_result(test.eas(race, eas_send(eas_mime(race, sink), "race")))
        assert code in (0, 115, 118), code
        return code == 0

    def via_smtp():
        barrier.wait(timeout=10)
        code = test.deliver(sink, identity=race)[0]
        assert code in (250, 452), code
        return code == 250

    def via_webmail():
        barrier.wait(timeout=10)
        code = test.api(session, "compose", {"to": [sink], "text": "ActiveSync race"})[0]
        assert code in (200, 429), code
        return code == 200

    def via_ews():
        barrier.wait(timeout=10)
        code = ews_codes(test.ews(race, create_ews_item("SendOnly", to=[sink])))[0]
        assert code in ("NoError", "ErrorSubmissionQuotaExceeded"), code
        return code == "NoError"

    with ThreadPoolExecutor(max_workers=5) as workers:
        results = [workers.submit(method) for method in (via_eas, via_eas, via_smtp, via_webmail, via_ews)]
        assert sum(result.result() for result in results) == 1
    assert len(list((test.directory / "mail" / sink / "new").glob("*.eml*"))) == recipient_count + 1
    assert test.count(race) == 2
    assert eas_result(test.eas(active, request, command="SmartReply"), "SmartReply") == 103

    test.provision("eas", quota=size, daily=4, enabled=False)
    assert test.eas(active, request)[0] == 401
    test.provision("eas", quota=size, daily=4)
    return active, request


def synced_mail_item(test, mailbox, device, folder="1"):
    status, _, bootstrap = test.eas(mailbox, eas_sync(0, folder), command="Sync", device=device)
    assert status == 200, bootstrap
    status, _, body = test.eas(mailbox, eas_sync(eas_sync_key(bootstrap), folder), command="Sync", device=device)
    item = re.search(rb"\x4d\x03(" + folder.encode() + rb":[0-9]+(?::[0-9a-f]{32})?)\x00", body)
    assert status == 200 and item, body
    return folder, item.group(1).decode()


def check_smart_mail(test, sink):
    device = "SmartDevice"
    reply, forward = "SmartReply", "SmartForward"
    blind = test.provision("smart-bcc")
    owner = test.provision("smart-sender", daily=2)
    source_mime = (
        f"From: {EXTERNAL}\r\nTo: {owner}\r\nBcc: {blind}\r\nSubject: Original\r\n".encode()
        + b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="fixture"\r\n\r\n'
        + b"--fixture\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nOriginal quoted text\r\n"
        + b"--fixture\r\nContent-Type: application/octet-stream\r\n"
        + b'Content-Disposition: attachment; filename="original.dat"\r\n'
        + b"Content-Transfer-Encoding: base64\r\n\r\nYWJjAA==\r\n--fixture--\r\n"
    )
    with test.smtp() as client:
        expect_smtp(client.mail(EXTERNAL), 250)
        expect_smtp(client.rcpt(owner), 250)
        expect_smtp(client.data(source_mime), 250)
    source = synced_mail_item(test, owner, device)
    baseline = test.bytes(owner)
    assert baseline > 0

    def send(command, raw, client_id, *, save=False, replace=False, refer=source, encoded=False):
        body = eas_send(raw, client_id, save=save, command=command, source=refer, replace=replace)
        return eas_result(test.eas(owner, body, command=command, device=device, encoded=encoded), command)

    def received(mailbox, subject):
        return [raw for path in (test.directory / "mail" / mailbox / "new").glob("*.eml*")
                if f"Subject: {subject}\r\n".encode() in (raw := path.read_bytes())]

    def parsed(raw):
        return BytesParser(policy=policy.default).parsebytes(raw)

    edited = eas_mime(owner, sink, extra=f"Cc: {sink.upper()}\r\nBcc: {blind}\r\n".encode(),
                      subject="Smart reply edited", payload=b"Edited reply only")
    assert send(reply, edited, "missing", refer=None) == 106
    assert send(forward, edited, "mismatch", refer=("4", source[1])) == 105
    assert send(reply, edited, "calendar", refer=("5", "5:1")) == 147
    assert send(forward, edited, "stale", refer=("1", "1:999999")) == 150
    assert test.count(owner) == 0 and test.bytes(owner) == baseline

    # ReplaceMime uses the edited client content. The exact stored size
    # includes the original mailbox contents and the private Bcc header.
    exact = baseline + len(edited)
    test.provision("smart-sender", quota=exact - 1, daily=2)
    assert send(reply, edited, "edited", save=True, replace=True) == 113
    assert not received(sink, "Smart reply edited") and test.count(owner) == 0
    test.provision("smart-sender", quota=exact, daily=2)
    assert send(reply, edited, "edited", save=True, replace=True, refer=(None, source[1]), encoded=True) == 0
    assert test.bytes(owner) == exact and test.count(owner) == 2
    assert send(reply, edited, "edited", save=True, replace=True) == 118
    assert send(forward, edited, "edited", replace=True) == 118, "ClientId must be shared across compose commands"
    for recipient in (sink, blind):
        mail, = received(recipient, "Smart reply edited")
        assert b"Edited reply only" in mail and b"Original quoted text" not in mail
        assert b"Bcc:" not in mail
    assert send(forward, edited, "full") == 115
    expect_smtp(test.deliver(sink, identity=owner), 452, "4.7.0")

    # Forward composes the server's original MIME, including its attachment,
    # and charges for the resulting file, not just the client payload.
    draft = eas_mime(owner, sink, subject="Smart forward expanded", payload=b"Forward note")
    test.provision("smart-sender", daily=10)
    assert send(forward, draft, "measure", save=True) == 0
    sent = test.directory / "mail" / owner / "Sent"
    stored, = [path.read_bytes() for path in sent.glob("*.eml*") if b"Subject: Smart forward expanded" in path.read_bytes()]
    expanded_size = len(stored)
    assert expanded_size > len(draft)
    message = parsed(stored)
    assert b"Original quoted text" in stored and b"Bcc:" not in stored
    assert any(part.get_filename() == "original.dat" and part.get_payload(decode=True) == b"abc\x00"
               for part in message.walk())
    assert not received(blind, "Smart forward expanded"), "inherited Bcc became a recipient"

    session = test.login(owner)
    test.expunge(session, "Sent")
    test.expunge(session, "Trash")
    assert test.bytes(owner) == baseline
    test.provision("smart-sender", quota=baseline + expanded_size - 1, daily=10)
    assert send(forward, draft, "expanded", save=True) == 113
    assert len(received(sink, "Smart forward expanded")) == 1 and test.count(owner) == 3
    test.provision("smart-sender", quota=baseline + expanded_size, daily=10)
    assert send(forward, draft, "expanded", save=True) == 0
    assert send(forward, draft, "expanded", save=True) == 118
    assert test.bytes(owner) == baseline + expanded_size and test.count(owner) == 4

    # Replying with no Sent copy still works at full storage and quotes only
    # the original body. Legacy requests use the same allowance.
    quote = eas_mime(owner, sink, subject="Smart reply quoted", payload=b"Reply note")
    assert send(reply, quote, "quote") == 0
    mail, = received(sink, "Smart reply quoted")
    assert b"Original quoted text" in mail and b"original.dat" not in mail
    old = eas_mime(owner, sink, subject="Legacy smart forward")
    assert eas_result(test.eas(owner, old, command=forward, legacy=True, encoded=True, source=source, save=True), forward) == 507
    assert eas_result(test.eas(owner, old, command=forward, legacy=True, version="2.5", source=source), forward) == 0
    mail, = received(sink, "Legacy smart forward")
    attachment, = [part for part in parsed(mail).walk() if part.get_content_type() == "message/rfc822"]
    nested, = attachment.get_payload()
    assert nested["Bcc"] is None and nested["Subject"] == "Original"
    assert any(part.get_filename() == "original.dat" for part in nested.walk())
    assert test.count(owner) == 6

    intruder = test.provision("smart-other", daily=1)
    assert eas_result(test.eas(intruder, eas_send(quote, command=reply, source=source),
                               command=reply, device="OtherDevice"), reply) == 150
    assert test.count(intruder) == 0

    # SmartReply, SmartForward, and SMTP contend for the same last recipient.
    test.provision("smart-sender", quota=baseline + expanded_size, daily=7)
    barrier = Barrier(3)

    def smart_race(command):
        barrier.wait(timeout=10)
        return send(command, quote, "race-" + command, replace=True)

    def smtp_race():
        barrier.wait(timeout=10)
        return test.deliver(sink, identity=owner)[0]

    with ThreadPoolExecutor(max_workers=3) as workers:
        reply_job = workers.submit(smart_race, reply)
        forward_job = workers.submit(smart_race, forward)
        smtp_job = workers.submit(smtp_race)
        results = reply_job.result(), forward_job.result(), smtp_job.result()
        assert results in ((0, 115, 452), (115, 0, 452), (115, 115, 250)), results
    assert test.count(owner) == 7

    test.provision("smart-sender", daily=7, enabled=False)
    assert test.eas(owner, eas_send(quote, command=forward, source=source), command=forward)[0] == 401
    test.provision("smart-sender", daily=7)
    test.expunge(test.login(owner), "INBOX")
    test.expunge(test.login(owner), "Trash")
    replay = eas_send(draft, "expanded", save=True, command=forward, source=source)
    assert eas_result(test.eas(owner, replay, command=forward, device=device), forward) == 118
    return owner, replay, device


def check_eas_tls(binary):
    with tempfile.TemporaryDirectory(prefix="mail-eas-tls-") as directory:
        test = Fixture(binary, Path(directory), tls=True)
        with test.daemon():
            sink = test.provision("tls-receiver")
            sender = f"tls-sender@{DOMAIN}"
            raw = eas_mime(sender, sink, payload=(b"TLS record boundary\r\n" * 1800))
            test.provision("tls-sender", quota=len(raw), daily=1)
            status, headers, _ = request(test.eas_url, method="OPTIONS", context=test.tls_context)
            assert status == 200 and "SendMail" in headers["MS-ASProtocolCommands"].split(",")
            assert {"SmartReply", "SmartForward"} <= set(headers["MS-ASProtocolCommands"].split(","))
            assert eas_result(test.eas(sender, eas_send(raw, save=True))) == 0
            assert test.bytes(sender) == len(raw) == test.bytes(sink)
            assert eas_result(test.eas(sender, eas_send(raw, "next", save=True))) == 115
            assert test.count(sender) == 1

            device = "SmartTLS"
            source = synced_mail_item(test, sender, device, "3")
            command = "SmartReply"
            replace = eas_send(raw, "large-reply", command=command, source=source, replace=True)
            assert eas_result(test.eas(sender, replace, command=command, device=device), command) == 115
            test.provision("tls-sender", quota=len(raw), daily=2)
            assert eas_result(test.eas(sender, replace, command=command, device=device), command) == 0
            assert test.bytes(sender) == len(raw) and test.bytes(sink) == 2 * len(raw)
            assert test.count(sender) == 2

            test.provision("tls-sender", quota=len(raw), daily=3)
            command = "SmartForward"
            forward = eas_send(eas_mime(sender, sink, subject="TLS smart forward"),
                               "tls-forward", command=command, source=source)
            assert eas_result(test.eas(sender, forward, command=command, device=device), command) == 0
            assert test.bytes(sender) == len(raw) and test.count(sender) == 3
            forwards = [data for path in (test.directory / "mail" / sink / "new").glob("*.eml*")
                        if b"Subject: TLS smart forward" in (data := path.read_bytes())]
            forwarded, = forwards
            assert b"TLS record boundary" in forwarded


def stage_suspended_retry(test):
    sender = test.provision("retry")
    test.provision("retry", enabled=False)
    # Seed a persisted delivery from a previously accepted submission. Mail
    # must hold this record on startup without attempting remote delivery.
    now = int(time.time())
    with sqlite3.connect(test.directory / "smtp.db") as db:
        db.execute(
            """INSERT INTO message_queue
            (id, from_addr, to_addr, message_data, status, attempts, next_retry, created_at, updated_at, hosted_user_id)
            SELECT 'hosted-retry-fixture', ?, 'nobody@external.invalid', 'test', 'retry', 2, ?, ?, ?, id
            FROM users WHERE username=?""", (sender, now, now, now, sender),
        )
    return now


def check_suspended_retry(test, previous_retry):
    with sqlite3.connect(test.directory / "smtp.db") as db:
        for _ in range(80):
            status, attempts, next_retry = db.execute(
                "SELECT status, attempts, next_retry FROM message_queue WHERE id='hosted-retry-fixture'"
            ).fetchone()
            if next_retry > previous_retry:
                assert (status, attempts) == ("retry", 2)
                return
            time.sleep(0.125)
    raise AssertionError("SMTP retry worker did not hold the suspended sender's delivery")


def check_previous_day_usage(test, sender, sink):
    # Model a daemon carrying yesterday's exhausted allowance into today.
    today = int(time.time()) // 86400
    with sqlite3.connect(test.directory / "smtp.db") as db:
        changed = db.execute(
            "UPDATE hosted_sending_usage SET utc_day=? WHERE user_id=(SELECT id FROM users WHERE username=?)",
            (today - 1, sender),
        )
        assert changed.rowcount == 1

    expect_smtp(test.deliver(sink, identity=sender), 250)
    assert test.count(sender) == 1
    assert ews_codes(test.ews(sender, create_ews_item("SendOnly", to=[sink]))) == ["NoError"]
    assert test.count(sender) == 2
    with sqlite3.connect(test.directory / "smtp.db") as db:
        row = db.execute(
            "SELECT utc_day FROM hosted_sending_usage JOIN users ON users.id=user_id WHERE username=?", (sender,),
        ).fetchone()
        assert row == (today,)

    status, result = test.api(test.login(sender), "compose", {"to": [sink], "text": "Over the new allowance"})
    assert status == 429 and result["error"] == "sending_limit", (status, result)
    print("Verified prior UTC day usage resets and SMTP, EWS, and webmail share today's allowance.")


def check_shared_mailbox(test, sink):
    name = "shared-limits"
    mailbox = test.provision(name, daily=4)
    session = test.login(mailbox)
    raw = imap_message("Shared mailbox APPEND")
    draft = {"subject": "Shared mailbox draft", "text": "Stored by webmail", "saveToken": "shared-draft"}
    ews_draft = create_ews_item("SaveOnly", subject="Shared mailbox EWS draft")
    ews_send = create_ews_item("SendOnly", to=[sink])

    expect_smtp(test.deliver(mailbox), 250)
    inbox_bytes = test.bytes(mailbox)
    assert inbox_bytes > 0
    assert test.api(session, "drafts", draft)[0] == 200
    draft_bytes = test.bytes(mailbox)
    assert draft_bytes > inbox_bytes

    with test.imap(mailbox) as imap:
        assert_imap(imap.append("INBOX", None, None, raw), response=b"APPENDUID")
        assert test.bytes(mailbox) == draft_bytes + len(raw)

        expect_smtp(test.deliver(sink, identity=mailbox), 250)
        assert test.count(mailbox) == 1
        web_send = {"to": [sink], "text": "Shared allowance via webmail"}
        assert test.api(session, "compose", web_send)[0] == 200
        assert test.count(mailbox) == 2
        assert ews_codes(test.ews(mailbox, create_ews_item("SendAndSaveCopy", to=[sink]))) == ["NoError"]
        assert test.count(mailbox) == 3

        mime = eas_mime(mailbox, sink, subject="Shared mailbox final send")
        request = eas_send(mime, "shared-final", save=True)
        before, received = test.bytes(mailbox), test.bytes(sink)
        exact_quota = before + len(mime)
        test.provision(name, quota=exact_quota - 1, daily=4)
        assert eas_result(test.eas(mailbox, request)) == 113
        assert (test.bytes(mailbox), test.bytes(sink), test.count(mailbox)) == (before, received, 3)

        test.provision(name, quota=exact_quota, daily=4)
        assert eas_result(test.eas(mailbox, request)) == 0
        assert (test.bytes(mailbox), test.bytes(sink), test.count(mailbox)) == (exact_quota, received + len(mime), 4)

        expect_smtp(test.deliver(mailbox), 452, "4.2.2")
        status, error = test.api(session, "drafts", dict(draft, saveToken="shared-extra"))
        assert status == 507 and error["error"] == "mailbox_full", (status, error)
        assert_imap(imap.append("INBOX", None, None, raw), "NO", b"[OVERQUOTA]")
        assert ews_codes(test.ews(mailbox, ews_draft)) == ["ErrorQuotaExceeded"]

        expect_smtp(test.deliver(sink, identity=mailbox), 452, "4.7.0")
        status, error = test.api(session, "compose", web_send)
        assert status == 429 and error["error"] == "sending_limit", (status, error)
        assert ews_codes(test.ews(mailbox, ews_send)) == ["ErrorSubmissionQuotaExceeded"]
        assert eas_result(test.eas(mailbox, eas_send(mime, "shared-extra"))) == 115
        assert eas_result(test.eas(mailbox, request)) == 118
        assert (test.bytes(mailbox), test.bytes(sink), test.count(mailbox)) == (exact_quota, received + len(mime), 4)

    print("Verified that one mailbox shares storage across all five protocols and one allowance across all four senders.")


def check_shared_storage_race(test):
    # Each payload alone fits. Even the two smallest payloads exceed the quota
    # before adding headers, so exactly one protocol can publish a message.
    quota = 7 * 1024
    body = "\r\n".join(["x" * 240] * 17)
    mailbox = test.provision("storage-race", quota=quota, daily=1)
    sink = test.provision("storage-race-sink")
    session = test.login(mailbox)
    barrier = Barrier(5)
    subjects = {protocol: f"Final storage via {protocol}" for protocol in ("SMTP", "webmail", "IMAP", "EWS", "ActiveSync")}
    mime = eas_mime(mailbox, sink, subject=subjects["ActiveSync"], payload=body.encode())
    send = eas_send(mime, "storage-race", save=True)

    def via_smtp():
        with test.smtp() as client:
            barrier.wait(timeout=10)
            result = smtp_message(client, EXTERNAL, [mailbox], subject=subjects["SMTP"], body=body)
        if result[0] != 250:
            expect_smtp(result, 452, "4.2.2")
        return result[0] == 250

    def via_webmail():
        barrier.wait(timeout=10)
        status, result = test.api(session, "drafts", {
            "subject": subjects["webmail"], "text": body, "saveToken": "storage-race",
        })
        if status != 200:
            assert status == 507 and result["error"] == "mailbox_full", (status, result)
        return status == 200

    def via_imap():
        raw = f"Subject: {subjects['IMAP']}\r\nFrom: {EXTERNAL}\r\n\r\n{body}\r\n".encode()
        with test.imap(mailbox) as client:
            barrier.wait(timeout=10)
            result = client.append("INBOX", None, None, raw)
        if result[0] != "OK":
            assert_imap(result, "NO", b"[OVERQUOTA]")
        return result[0] == "OK"

    def via_ews():
        barrier.wait(timeout=10)
        codes = ews_codes(test.ews(mailbox, create_ews_item("SaveOnly", subject=subjects["EWS"], body=body)))
        assert codes in (["NoError"], ["ErrorQuotaExceeded"]), codes
        return codes == ["NoError"]

    def via_eas():
        barrier.wait(timeout=10)
        code = eas_result(test.eas(mailbox, send))
        assert code in (0, 113), code
        return code == 0

    protocols = {"SMTP": via_smtp, "webmail": via_webmail, "IMAP": via_imap, "EWS": via_ews, "ActiveSync": via_eas}
    with ThreadPoolExecutor(max_workers=len(protocols)) as workers:
        operations = {protocol: workers.submit(write) for protocol, write in protocols.items()}
        winners = [protocol for protocol, result in operations.items() if result.result()]
    assert len(winners) == 1, winners
    messages = list((test.directory / "mail" / mailbox).rglob("*.eml*"))
    assert len(messages) == 1 and 0 < test.bytes(mailbox) <= quota, messages
    stored = BytesParser(policy=policy.default).parsebytes(messages[0].read_bytes(), headersonly=True)
    assert stored["Subject"] == subjects[winners[0]], (winners, stored["Subject"])
    eas_won = winners[0] == "ActiveSync"
    assert test.count(mailbox) == int(eas_won)
    assert test.bytes(sink) == (len(mime) if eas_won else 0)
    assert eas_result(test.eas(mailbox, send)) == (118 if eas_won else 113)
    assert test.count(mailbox) == int(eas_won)
    assert test.bytes(sink) == (len(mime) if eas_won else 0)
    print(f"Verified one winner for the final storage across five simultaneous writers ({winners[0]}).")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--staging", action="store_true",
                        help="Use the staging profile, STARTTLS, implicit TLS, and HTTPS with a temporary certificate.")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-hosted-limits-") as directory:
        test = Fixture(args.binary.resolve(), Path(directory), staging=args.staging)
        with test.daemon():
            if args.staging:
                test.check_staging_smtp()
                print("Staging profile with certificate-verified TLS on SMTP, webmail, IMAP, EWS, and ActiveSync.")
            sink = test.provision("sink")
            if args.staging:
                check_implicit_tls(test, sink)
            sender = test.provision("storage-sender")
            check_storage(test, sink, test.login(sender))
            print("Verified exact byte quota, one byte over, DATA, BDAT, concurrent storage, Trash and draft replacement.")
            sender = check_sending(test, sink)
            check_outbox(test, sink)
            check_imap(test)
            print("Verified IMAP APPEND, COPY and UID COPY byte boundaries, suspension, and an IMAP/EWS storage race.")
            ews_sender = check_ews(test, sink)
            print("Verified both EWS send operations, Bcc, Sent and draft storage, batch refusal, and the shared sending race.")
            eas_sender, eas_request = check_eas(test, sink)
            print("Verified ActiveSync boundaries and retry receipts, and a race across all four send protocols for the final recipient.")
            smart_sender, smart_request, smart_device = check_smart_mail(test, sink)
            print("Verified SmartReply and SmartForward source lookup, MIME, quota boundaries, and cross-protocol races.")
            check_shared_mailbox(test, sink)
            check_shared_storage_race(test)
            previous_retry = stage_suspended_retry(test)
            print("Verified the shared recipient allowance, duplicate recipients, concurrent dispatch, suspension and Sent copy failure.")
        with test.daemon():
            check_suspended_retry(test, previous_retry)
            expect_smtp(test.deliver(sink, identity=sender), 452, "4.7.0")
            status, result = test.api(test.login(sender), "compose", {"to": [sink], "text": "After restart"})
            assert status == 429 and result["error"] == "sending_limit", (status, result)
            assert test.count(sender) == 2
            assert ews_codes(test.ews(ews_sender, create_ews_item("SendOnly", to=[sink]))) == ["ErrorSubmissionQuotaExceeded"]
            assert eas_result(test.eas(eas_sender, eas_request)) == 118
            assert eas_result(test.eas(eas_sender, eas_send(eas_mime(eas_sender, sink), "afterrestart"))) == 115
            assert test.count(eas_sender) == 4
            assert eas_result(test.eas(smart_sender, smart_request, command="SmartForward", device=smart_device), "SmartForward") == 118
            assert test.count(smart_sender) == 7
            print("Verified allowance persistence, the ActiveSync receipt and suspension of a persisted SMTP retry after daemon restart.")
            if args.staging:
                check_previous_day_usage(test, sender, sink)
    check_eas_tls(args.binary.resolve())
    print("Verified SendMail and SmartReply across TLS records, and SmartForward and shared quotas over HTTPS.")


if __name__ == "__main__":
    main()
