#!/usr/bin/env python3
"""Verify hosted limits through a staging server's TLS protocols and private provisioning API."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from email.parser import BytesParser
import http.client
import imaplib
import ipaddress
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import signal
import smtplib
import ssl
from tempfile import TemporaryDirectory
from threading import Barrier
import time
import urllib.error
import urllib.parse
import urllib.request

suite = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
MailClient, Fixture = suite["MailClient"], suite["Fixture"]
assert_imap, expect_smtp = suite["assert_imap"], suite["expect_smtp"]
create_ews_item, ews_codes = suite["create_ews_item"], suite["ews_codes"]
ews_draft, send_ews_items = suite["ews_draft"], suite["send_ews_items"]
eas_mime, eas_send, eas_result = suite["eas_mime"], suite["eas_send"], suite["eas_result"]
imap_message, synced_mail_item = suite["imap_message"], suite["synced_mail_item"]
LARGE = suite["LARGE"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def mail_domain(value):
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
    ):
        raise argparse.ArgumentTypeError("expected a lowercase DNS hostname")
    return value


def loopback_origin(value):
    try:
        url = urllib.parse.urlsplit(value)
        host = ipaddress.ip_address(url.hostname or "")
        port = url.port
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a literal loopback origin") from error
    if (url.scheme != "http" or not host.is_loopback or not port or url.username or url.password
            or url.path not in ("", "/") or url.query or url.fragment):
        raise argparse.ArgumentTypeError("expected http://127.0.0.1:PORT or http://[::1]:PORT")
    return urllib.parse.urlunsplit((url.scheme, url.netloc, "", "", ""))


def port_number(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def imap_folders(client):
    for line in assert_imap(client.list()):
        if line is None:
            continue
        match = re.fullmatch(rb'(\([^)]*\)) (?:NIL|"[^"]*") (.+)', line)
        assert match, line
        flags, name = match.groups()
        if b"\\noselect" in flags.lower():
            continue
        if name.startswith(b'"'):
            name = re.sub(rb'\\(["\\])', rb'\1', name[1:-1])
        yield name.decode("ascii")


def imap_folder_arg(folder):
    return '"' + folder.replace("\\", "\\\\").replace('"', '\\"') + '"'


def clear_imap_folder(client, folder):
    name = imap_folder_arg(folder)
    count = int(assert_imap(client.select(name))[0])
    if count:
        assert_imap(client.store("1:*", "+FLAGS", r"(\Deleted)"))
        assert_imap(client.expunge())
        assert int(assert_imap(client.select(name, readonly=True))[0]) == 0, folder


class StagingClient(MailClient):
    staging = True

    def __init__(self, *, host, domain, private, token, tls_context, ports):
        if domain in ("stacksjs.com", "hq.training") or host in ("mail.stacksjs.com", "mail.hq.training"):
            raise ValueError("Use a dedicated staging mailbox domain and hostname")
        if host != "127.0.0.1" and not host.endswith("." + domain):
            raise ValueError("The staging hostname must be in the staging mailbox domain")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", token):
            raise ValueError("Set MAIL_STAGING_PROVISIONING_TOKEN to the staging token")
        self.hostname, self.domain, self.private = host, domain, loopback_origin(private)
        self.smtp_port, self.submission_port, self.smtps_port, self.imap_port, self.imaps_port, web, dav = ports
        self.webmail = f"https://{host}:{web}"
        self.ews_url = f"https://{host}:{dav}/EWS/Exchange.asmx"
        self.eas_url = f"https://{host}:{dav}/Microsoft-Server-ActiveSync"
        self.tls_context = tls_context
        self.password = secrets.token_hex(24)
        self.auth = {"Authorization": f"Bearer {token}"}
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=tls_context),
        )
        self.prefix = "qa-" + secrets.token_hex(5)
        self.actors = {}
        self.sessions = {}

    def http(self, url, payload=None, headers=None, method=None, context=None, timeout=10):
        headers = dict(headers or {})
        if payload is not None and not isinstance(payload, bytes):
            payload = json.dumps(payload).encode()
            headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=timeout) as res:
                return res.status, res.headers, res.read()
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.headers, error.read()

    def verify_domain(self):
        assert self.http(self.private + "/provisioning/v1/status")[0] == 401
        status, _, body = self.http(self.private + "/provisioning/v1/status", headers=self.auth)
        if status != 200 or json.loads(body) != {"version": 1, "domain": self.domain}:
            raise AssertionError("Private listener does not serve the selected staging domain")
        self.check_staging_smtp()
        status, _, _ = self.http(self.eas_url, method="OPTIONS")
        assert status == 200, status

    def state(self, address):
        query = urllib.parse.urlencode({"mailbox": address, "actor": self.actors[address]})
        status, _, body = self.http(self.private + "/provisioning/v1/mailbox?" + query, headers=self.auth)
        if status == 404:
            return None
        assert status == 200, (status, body)
        return json.loads(body)

    def provision(self, name, *, quota=LARGE, daily=20, enabled=True):
        address = f"{self.prefix}-{name}@{self.domain}"
        if address not in self.actors:
            self.actors[address] = secrets.token_hex(16)
        current = self.state(address)
        revision = current["revision"] + 1 if current else 1
        change = {
            "mailbox": address, "actor": self.actors[address], "operation_id": secrets.token_hex(16),
            "revision": revision, "quota_bytes": quota, "send_recipients_per_day": daily, "enabled": enabled,
        }
        if revision == 1:
            change.update(initial_password=self.password, initial_recovery=f"{self.prefix}@recovery.example.test")
        for attempt in range(3):
            try:
                status, _, body = self.http(self.private + "/provisioning/v1/mailbox", change, self.auth)
            except (OSError, http.client.HTTPException):
                if attempt == 2:
                    raise
                continue
            if status != 503 or attempt == 2:
                break
        assert status == 200, (status, body)
        assert json.loads(body) == {key: change[key] for key in (
            "mailbox", "revision", "quota_bytes", "send_recipients_per_day", "enabled",
        )}
        if current and current["enabled"] != enabled:
            self.sessions.pop(address, None)
        return address

    def login(self, mailbox):
        if mailbox not in self.sessions:
            self.sessions[mailbox] = super().login(mailbox)
        return self.sessions[mailbox]

    def messages(self, address, folder="INBOX"):
        with self.imap(address) as client:
            if folder not in set(imap_folders(client)):
                return []
            count = int(assert_imap(client.select(imap_folder_arg(folder), readonly=True))[0])
            if not count:
                return []
            items = assert_imap(client.fetch("1:*", "(RFC822.SIZE BODY.PEEK[HEADER.FIELDS (SUBJECT)])"))
            messages = []
            for item in items:
                if isinstance(item, tuple):
                    size = int(re.search(rb"RFC822.SIZE (\d+)", item[0])[1])
                    messages.append((size, BytesParser().parsebytes(item[1], headersonly=True)["Subject"]))
            assert len(messages) == count, (folder, count, messages)
            return messages

    def stored_bytes(self, address, *folders):
        return sum(size for folder in folders for size, _ in self.messages(address, folder))

    def empty_folder(self, address, folder):
        with self.imap(address) as client:
            clear_imap_folder(client, folder)

    def clean_up(self):
        failures = []
        for address in self.actors:
            name = address.split("@", 1)[0].removeprefix(self.prefix + "-")
            try:
                state = self.state(address)
                if state is None:
                    continue
                try:
                    if not state["enabled"]:
                        self.provision(name, quota=state["quota_bytes"], daily=state["send_recipients_per_day"])
                    with self.imap(address) as client:
                        for folder in imap_folders(client):
                            clear_imap_folder(client, folder)
                finally:
                    self.provision(name, quota=1, daily=0, enabled=False)
            except (AssertionError, OSError, http.client.HTTPException, imaplib.IMAP4.error, ValueError):
                failures.append(address)
        if failures:
            raise AssertionError("Could not fully clear and suspend: " + ", ".join(failures))
        print(f"Cleared and suspended the {self.prefix} synthetic mailboxes.")


def rejected_webmail(test, session, path, payload, status, reason):
    code, reply = test.api(session, path, payload)
    assert code == status and reply["error"] == reason, (code, reply)


def check_storage(test, sender):
    receiver = test.provision("storage")
    sender_session = test.login(sender)
    # Measure both SMTP forms because their stored trace headers can differ.
    expect_smtp(test.deliver(receiver, identity=sender), 250)
    size = test.stored_bytes(receiver, "INBOX")
    assert size > 0
    expect_smtp(test.deliver(receiver, identity=sender, chunked=True), 250)
    exact = test.stored_bytes(receiver, "INBOX")
    assert exact > size
    test.empty_folder(receiver, "INBOX")
    expect_smtp(test.deliver(receiver, identity=sender), 250)
    assert test.stored_bytes(receiver, "INBOX") == size
    test.provision("storage", quota=exact - 1)
    expect_smtp(test.deliver(receiver, identity=sender, chunked=True), 452, "4.2.2")
    assert test.stored_bytes(receiver, "INBOX") == size
    test.provision("storage", quota=exact)
    expect_smtp(test.deliver(receiver, identity=sender, chunked=True), 250)
    assert test.stored_bytes(receiver, "INBOX") == exact
    rejected_webmail(test, sender_session, "compose", {"to": [receiver], "text": "Over storage"},
                     507, "mailbox_full")

    session = test.login(receiver)
    test.expunge(session, "INBOX")
    assert not test.messages(receiver)
    assert test.stored_bytes(receiver, "Trash") == exact
    expect_smtp(test.deliver(receiver, identity=sender), 452, "4.2.2")
    test.expunge(session, "Trash")
    assert test.stored_bytes(receiver, "INBOX", "Trash") == 0
    with smtplib.SMTP_SSL(test.hostname, test.smtps_port, local_hostname="client.example.test",
                          context=test.tls_context, timeout=10) as smtp:
        smtp.login(sender, test.password)
        expect_smtp(suite["smtp_message"](smtp, sender, [receiver], subject="Implicit TLS"), 250)
    print("SMTP DATA, BDAT and SMTPS respected storage shared with webmail and Trash.")


def check_imap_ews(test):
    raw = imap_message("Staging IMAP APPEND and COPY")
    size = len(raw)
    address = test.provision("imap", quota=size - 1)
    with imaplib.IMAP4_SSL(test.hostname, test.imaps_port, ssl_context=test.tls_context, timeout=10) as client:
        assert_imap(client.login(address, test.password))
        assert_imap(client.append("INBOX", None, None, raw), "NO", b"[OVERQUOTA]")
        test.provision("imap", quota=2 * size)
        assert_imap(client.append("INBOX", None, None, raw), response=b"APPENDUID")
        assert_imap(client.append("INBOX", None, None, raw), response=b"APPENDUID")
        assert_imap(client.create("QuotaCopies"))
        assert_imap(client.select("INBOX"))
        test.provision("imap", quota=4 * size - 1)
        assert_imap(client.copy("1:2", "QuotaCopies"), "NO", b"[OVERQUOTA]")
        assert not test.messages(address, "QuotaCopies")
        test.provision("imap", quota=4 * size)
        uids = assert_imap(client.uid("SEARCH", None, "ALL"))[0].replace(b" ", b",").decode()
        assert_imap(client.uid("COPY", uids, "QuotaCopies"))
        copied = test.messages(address, "QuotaCopies")
        assert len(copied) == 2 and all(length == size for length, _ in copied), (size, copied)
        assert test.stored_bytes(address, "INBOX", "QuotaCopies") == 4 * size
        assert_imap(client.append("INBOX", None, None, raw), "NO", b"[OVERQUOTA]")
        assert ews_codes(test.ews(address, create_ews_item("SaveOnly"))) == ["ErrorQuotaExceeded"]

    drafts = test.provision("drafts")
    draft = create_ews_item("SaveOnly", subject="Staging EWS storage")
    assert ews_codes(test.ews(drafts, draft)) == ["NoError"]
    size = test.stored_bytes(drafts, "Drafts")
    assert size > 0
    test.provision("drafts", quota=2 * size - 1)
    assert ews_codes(test.ews(drafts, draft)) == ["ErrorQuotaExceeded"]
    assert test.stored_bytes(drafts, "Drafts") == size
    test.provision("drafts", quota=2 * size)
    assert ews_codes(test.ews(drafts, draft)) == ["NoError"]
    assert test.stored_bytes(drafts, "Drafts") == 2 * size
    print("IMAPS APPEND, COPY, UID COPY and EWS draft storage passed exact-fit and one-byte-over checks.")


def check_allowance(test, sink):
    sender = test.provision("allowance", daily=4)
    session = test.login(sender)
    before = len(test.messages(sink))
    expect_smtp(test.deliver([sink, sink], identity=sender, subject="Staging SMTP allowance"), 250)
    web = {"to": [sink], "bcc": [sink.upper()], "text": "Staging webmail allowance"}
    status, result = test.api(session, "compose", web)
    assert status == 200 and result["delivered"] == 1, (status, result)
    item = ews_draft(test, sender, sink, subject="Staging EWS allowance")
    assert ews_codes(test.ews(sender, send_ews_items(item))) == ["NoError"]

    mime = eas_mime(sender, sink, subject="Staging ActiveSync allowance")
    send = eas_send(mime, "allowance", save=True)
    stored = test.stored_bytes(sender, "INBOX", "Drafts", "Sent", "Trash")
    exact = stored + len(mime)
    test.provision("allowance", quota=exact - 1, daily=4)
    assert eas_result(test.eas(sender, send)) == 113
    assert len(test.messages(sink)) == before + 3
    test.provision("allowance", quota=exact, daily=4)
    assert eas_result(test.eas(sender, send)) == 0
    assert test.stored_bytes(sender, "INBOX", "Drafts", "Sent", "Trash") == exact
    assert eas_result(test.eas(sender, send)) == 118
    expect_smtp(test.deliver(sink, identity=sender), 452, "4.7.0")
    rejected_webmail(test, session, "compose", web, 429, "sending_limit")
    assert ews_codes(test.ews(sender, create_ews_item("SendOnly", to=[sink]))) == ["ErrorSubmissionQuotaExceeded"]
    assert eas_result(test.eas(sender, eas_send(mime, "over-allowance"))) == 115
    assert len(test.messages(sink)) == before + 4
    print("SMTP, webmail, EWS SendItem and ActiveSync shared one four-recipient allowance.")


def check_smart_mail(test, sender, sink):
    mailbox = test.provision("smart", daily=3)
    expect_smtp(test.deliver(mailbox, identity=sender, subject="Original staging message", body="Quoted source"), 250)
    source = synced_mail_item(test, mailbox, "StagingSmart")
    stored = test.stored_bytes(mailbox, "INBOX")

    def send(command, raw, request_id, *, replace=False):
        request = eas_send(raw, request_id, save=True, command=command, source=source, replace=replace)
        return eas_result(test.eas(mailbox, request, command=command, device="StagingSmart"), command)

    def deliveries(subject):
        return sum(subject == received for _, received in test.messages(sink))

    reply = eas_mime(mailbox, sink, subject="Staging SmartReply")
    test.provision("smart", quota=stored + len(reply) - 1, daily=3)
    assert send("SmartReply", reply, "reply", replace=True) == 113
    assert deliveries("Staging SmartReply") == 0
    test.provision("smart", quota=stored + len(reply), daily=3)
    assert send("SmartReply", reply, "reply", replace=True) == 0
    assert send("SmartReply", reply, "reply", replace=True) == 118
    assert test.stored_bytes(mailbox, "Sent") == len(reply)

    test.provision("smart", daily=3)
    test.empty_folder(mailbox, "Sent")
    forward = eas_mime(mailbox, sink, subject="Staging SmartForward")
    assert send("SmartForward", forward, "measure") == 0
    expanded = test.stored_bytes(mailbox, "Sent")
    assert expanded > len(forward)
    test.empty_folder(mailbox, "Sent")
    test.provision("smart", quota=stored + expanded - 1, daily=3)
    assert send("SmartForward", forward, "forward") == 113
    assert deliveries("Staging SmartForward") == 1
    test.provision("smart", quota=stored + expanded, daily=3)
    assert send("SmartForward", forward, "forward") == 0
    assert send("SmartForward", forward, "forward") == 118
    assert test.stored_bytes(mailbox, "Sent") == expanded
    assert deliveries("Staging SmartReply") == 1 and deliveries("Staging SmartForward") == 2
    expect_smtp(test.deliver(sink, identity=mailbox), 452, "4.7.0")
    print("SmartReply and expanded SmartForward enforced exact Sent sizes and replayed without redelivery.")


def race(operations):
    gate = Barrier(len(operations))

    def run(operation):
        gate.wait(timeout=10)
        return operation()

    with ThreadPoolExecutor(max_workers=len(operations)) as workers:
        tracked = [workers.submit(run, operation) for operation in operations]
        return [result.result() for result in tracked]


def check_races(test, sender, sink):
    contender = test.provision("last-slot", daily=1)
    session = test.login(contender)
    before = len(test.messages(sink))
    mime = eas_mime(contender, sink, subject="ActiveSync final slot")
    results = race([
        lambda: test.deliver(sink, identity=contender, subject="SMTP final slot")[0],
        lambda: test.api(session, "compose", {"to": [sink], "text": "Webmail final slot"})[0],
        lambda: ews_codes(test.ews(contender, create_ews_item("SendOnly", to=[sink])))[0],
        lambda: eas_result(test.eas(contender, eas_send(mime, "last-slot"))),
    ])
    accepted = [250, 200, "NoError", 0]
    refused = [452, 429, "ErrorSubmissionQuotaExceeded", 115]
    assert all(result in (yes, no) for result, yes, no in zip(results, accepted, refused)), results
    assert sum(result == yes for result, yes in zip(results, accepted)) == 1, results
    assert len(test.messages(sink)) == before + 1

    quota = 7 * 1024
    body = "\r\n".join(["x" * 240] * 17)
    mailbox = test.provision("last-bytes", quota=quota)
    session = test.login(mailbox)
    rfc822 = eas_mime(mailbox, sink, subject="Final bytes via ActiveSync", payload=body.encode())
    raw = f"Subject: Final bytes via IMAP\r\nFrom: {sender}\r\n\r\n{body}\r\n".encode()

    def append():
        with test.imap(mailbox) as client:
            result = client.append("INBOX", None, None, raw)
            if result[0] != "OK":
                assert_imap(result, "NO", b"[OVERQUOTA]")
            return result[0]

    results = race([
        lambda: test.deliver(mailbox, identity=sender, subject="Final bytes via SMTP", body=body)[0],
        lambda: test.api(session, "drafts", {"subject": "Final bytes via webmail", "text": body})[0],
        append,
        lambda: ews_codes(test.ews(mailbox, create_ews_item("SaveOnly", subject="Final bytes via EWS", body=body)))[0],
        lambda: eas_result(test.eas(mailbox, eas_send(rfc822, "last-bytes", save=True))),
    ])
    accepted = [250, 200, "OK", "NoError", 0]
    refused = [452, 507, "NO", "ErrorQuotaExceeded", 113]
    assert all(result in (yes, no) for result, yes, no in zip(results, accepted, refused)), results
    winner, = [index for index, result in enumerate(results) if result == accepted[index]]
    saved, = [message for folder in ("INBOX", "Drafts", "Sent") for message in test.messages(mailbox, folder)]
    assert 0 < saved[0] <= quota
    assert saved[1] == f"Final bytes via {('SMTP', 'webmail', 'IMAP', 'EWS', 'ActiveSync')[winner]}", saved
    print("Exactly one protocol won each of the last-recipient and last-storage races.")


def check_suspension(test, sender, sink):
    mailbox = test.provision("paused", daily=1)
    session = test.login(mailbox)
    before = len(test.messages(sink))
    send_id = secrets.token_hex(16)
    status, item = test.api(session, "compose", {
        "to": [sink], "text": "Suspend before enqueue dispatch", "sendId": send_id, "delaySeconds": 3,
    })
    assert status == 200 and item["state"] == "pending", (status, item)
    with test.smtp(sender) as smtp:
        expect_smtp(smtp.mail(sender), 250)
        expect_smtp(smtp.rcpt(mailbox), 250)
        test.provision("paused", daily=1, enabled=False)
        expect_smtp(smtp.data(b"Subject: Suspended during SMTP\r\n\r\nbody\r\n"), 550, "5.2.1")
    expect_smtp(test.deliver(mailbox, identity=sender), 550, "5.2.1")
    assert test.api(session, "folders")[0] == 401
    time.sleep(5)
    test.provision("paused", daily=1)
    status, item = test.api(test.login(mailbox), f"outbox/{send_id}")
    assert status == 200 and item["state"] == "failed" and "disabled" in item["error"], (status, item)
    assert not test.messages(mailbox)
    assert len(test.messages(sink)) == before
    print("A provisioning suspension beat accepted SMTP RCPT and a pending webmail send.")


def verify(test):
    test.verify_domain()
    print(f"Using certificate-verified staging endpoints and synthetic mailbox prefix {test.prefix}.")
    try:
        sender = test.provision("sender", daily=20)
        sink = test.provision("sink")
        check_storage(test, sender)
        check_imap_ews(test)
        check_allowance(test, sink)
        check_smart_mail(test, sender, sink)
        check_races(test, sender, sink)
        check_suspension(test, sender, sink)
    finally:
        test.clean_up()


def main():
    if not __debug__:
        raise RuntimeError("Run the staging verifier with assertions enabled")

    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", type=mail_domain, help="Dedicated staging Mail hostname")
    target.add_argument("--fixture", type=Path, help="Run the same client against a disposable local Mail binary")
    parser.add_argument("--domain", type=mail_domain, help="Staging mailbox domain")
    parser.add_argument("--provisioning-url", type=loopback_origin, default="http://127.0.0.1:8099")
    parser.add_argument("--ca-file", help="Optional CA file for a staging private trust root")
    for name, default in (("smtp", 25), ("submission", 587), ("smtps", 465), ("imap", 143),
                          ("imaps", 993), ("webmail", 8443), ("dav", 443)):
        parser.add_argument(f"--{name}-port", type=port_number, default=default)
    args = parser.parse_args()
    if args.fixture:
        print("Disposable loopback fixture with a temporary TLS certificate.")
        with TemporaryDirectory(prefix="mail-staging-protocols-") as directory:
            fixture = Fixture(args.fixture.resolve(strict=True), Path(directory), staging=True)
            ports = (fixture.smtp_port, fixture.submission_port, fixture.smtps_port, fixture.imap_port,
                     fixture.imaps_port, urllib.parse.urlsplit(fixture.webmail).port,
                     urllib.parse.urlsplit(fixture.ews_url).port)
            with fixture.daemon():
                verify(StagingClient(host="127.0.0.1", domain=suite["DOMAIN"], private=fixture.private,
                                     token=fixture.auth["Authorization"].removeprefix("Bearer "),
                                     tls_context=fixture.tls_context, ports=ports))
    else:
        if not args.domain:
            parser.error("--domain is required with --host")
        ports = (args.smtp_port, args.submission_port, args.smtps_port, args.imap_port,
                 args.imaps_port, args.webmail_port, args.dav_port)
        try:
            test = StagingClient(host=args.host, domain=args.domain, private=args.provisioning_url,
                                 token=os.environ.get("MAIL_STAGING_PROVISIONING_TOKEN", ""),
                                 tls_context=ssl.create_default_context(cafile=args.ca_file), ports=ports)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        print(f"Connecting to {args.host} for {args.domain}.")
        verify(test)


if __name__ == "__main__":
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    main()
