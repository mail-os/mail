#!/usr/bin/env python3
"""Rehearse an MX cutover and rollback with disposable staging Mail servers."""

import argparse
from collections import Counter
from contextlib import contextmanager
from email import policy
from email.parser import BytesHeaderParser
from pathlib import Path
import runpy
import socket
from socketserver import BaseRequestHandler, ThreadingUDPServer
import struct
import tempfile
from threading import Thread


HERE = Path(__file__).resolve().parent
support = runpy.run_path(str(HERE / "test-mail-import.py"))
Fixture, append, messages, run = (support[name] for name in ("Fixture", "append", "messages", "run"))
paid_mailbox = runpy.run_path(str(HERE / "test-webmail-team-invitations.py"))["paid_mailbox"]
DOMAIN, OTHER = "cutover.example.test", "other.example.test"
OLD_MX, NEW_MX = "legacy.example.test", "candidate.example.test"
TTL = 180
HEADER = struct.Struct("!6H")
RECORD = struct.Struct("!HHIH")
PREFERENCE = struct.Struct("!H")


def dns_name(name):
    labels = name.encode("ascii").split(b".")
    return b"".join(bytes((len(label),)) + label for label in labels) + b"\0"


QUESTION = dns_name(DOMAIN) + struct.pack("!HH", 15, 1)


class MXAnswer(BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        if query[HEADER.size:] != QUESTION:
            return
        transaction = HEADER.unpack_from(query)[0]
        header = HEADER.pack(transaction, 0x8400, 1, 1, 0, 0)
        data = PREFERENCE.pack(10) + dns_name(self.server.exchange)
        answer = b"\xc0\x0c" + RECORD.pack(15, 1, TTL, len(data)) + data
        sock.sendto(header + QUESTION + answer, self.client_address)


@contextmanager
def mx_zone():
    with ThreadingUDPServer(("127.0.0.1", 0), MXAnswer) as zone:
        zone.exchange = OLD_MX
        worker = Thread(target=zone.serve_forever, daemon=True)
        worker.start()
        try:
            yield zone
        finally:
            zone.shutdown()
            worker.join()


def resolve_mx(zone):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        client.connect(zone.server_address)
        client.send(HEADER.pack(0x3141, 0, 1, 0, 0, 0) + QUESTION)
        reply = client.recv(512)
    assert HEADER.unpack_from(reply) == (0x3141, 0x8400, 1, 1, 0, 0)
    offset = HEADER.size + len(QUESTION)
    assert reply[HEADER.size:offset] == QUESTION and reply[offset:offset + 2] == b"\xc0\x0c"
    offset += 2
    kind, record_class, ttl, length = RECORD.unpack_from(reply, offset)
    data = reply[offset + RECORD.size:]
    assert (kind, record_class, ttl, length) == (15, 1, TTL, len(data))
    assert PREFERENCE.unpack_from(data) == (10,)
    exchanges = {dns_name(name): name for name in (OLD_MX, NEW_MX)}
    return exchanges[data[PREFERENCE.size:]]


def subject(row):
    return str(BytesHeaderParser(policy=policy.default).parsebytes(row[3])["Subject"])


def contents(rows):
    return Counter((date, frozenset(flags), raw) for _, date, flags, raw in rows)


def inbox(server, mailbox):
    return messages(server, mailbox, "INBOX")


def deliver(servers, exchange, mailbox, label, expected=250):
    code, response = servers[exchange].deliver(mailbox, subject=label)
    assert code == expected, (mailbox, label, code, response)


def transfer(source, destination, mailbox, checkpoint, mapping, count):
    result = run(source, mailbox, destination, mailbox, checkpoint, mapping, "--apply")
    imported = [row for row in result if row["event"] == "imported"]
    assert len(imported) == count, result
    return {row["destination_uid"] for row in imported if row["destination"] == "INBOX"}


def stage_recovery(candidate, mailbox, recovery, excluded):
    rows = [row for row in inbox(candidate, mailbox) if row[0] not in excluded]
    identifiers = ",".join(str(row[0]) for row in rows)
    with candidate.imap(mailbox) as imap:
        assert imap.select("INBOX")[0] == "OK"
        assert imap.uid("COPY", identifiers, recovery)[0] == "OK"
    return rows


def verify(legacy, candidate, zone, scratch):
    servers = {OLD_MX: legacy, NEW_MX: candidate}
    mailbox = paid_mailbox(legacy, "desk", DOMAIN)
    assert paid_mailbox(candidate, "desk", DOMAIN) == mailbox
    foreign = paid_mailbox(candidate, "desk", OTHER)
    assert resolve_mx(zone) == OLD_MX
    cached_legacy = resolve_mx(zone)
    deliver(servers, cached_legacy, mailbox, "Before cutover")
    deliver(servers, NEW_MX, foreign, "Other domain")
    deliver(servers, NEW_MX, f"missing@{DOMAIN}", "Unprovisioned address", expected=550)
    assert inbox(candidate, mailbox) == []

    with legacy.imap(mailbox) as imap:
        assert imap.create("Archive")[0] == "OK"
    archived = support["mime_message"](mailbox, "Historical attachment")
    append(legacy, mailbox, "Archive", archived)
    mapping = [("INBOX", "INBOX"), ("Archive", "Archive")]
    checkpoint = scratch / "forward.sqlite"
    preview = run(legacy, mailbox, candidate, mailbox, checkpoint, mapping)
    assert [(row["destination"], row["messages"]) for row in preview] == [("INBOX", 1), ("Archive", 1)]
    assert not checkpoint.exists() and inbox(candidate, mailbox) == []
    copied_uids = transfer(legacy, candidate, mailbox, checkpoint, mapping, 2)
    deliver(servers, resolve_mx(zone), mailbox, "Final delta")
    copied_uids.update(transfer(legacy, candidate, mailbox, checkpoint, mapping, 1))

    zone.exchange = NEW_MX
    cached_candidate = resolve_mx(zone)
    assert cached_candidate == NEW_MX
    deliver(servers, cached_candidate, mailbox, "New route")
    deliver(servers, cached_legacy, mailbox, "Cached old route")
    copied_uids.update(transfer(legacy, candidate, mailbox, checkpoint, mapping, 1))
    transfer(legacy, candidate, mailbox, checkpoint, mapping, 0)
    left, right = inbox(legacy, mailbox), inbox(candidate, mailbox)
    assert [subject(row) for row in left] == ["Before cutover", "Final delta", "Cached old route"]
    assert [subject(row) for row in right] == ["Before cutover", "Final delta", "New route", "Cached old route"]
    assert contents(left) == contents(row for row in right if row[0] in copied_uids)
    assert contents(messages(legacy, mailbox, "Archive")) == contents(messages(candidate, mailbox, "Archive"))
    assert [subject(row) for row in inbox(candidate, foreign)] == ["Other domain"]

    zone.exchange = OLD_MX
    assert resolve_mx(zone) == OLD_MX
    deliver(servers, resolve_mx(zone), mailbox, "Restored route")
    existing = inbox(legacy, mailbox)
    recovery = "Cutover-recovery"
    with candidate.imap(mailbox) as imap:
        assert imap.create(recovery)[0] == "OK"
    rollback = scratch / "rollback.sqlite"
    reverse_mapping = [(recovery, "INBOX")]
    first = stage_recovery(candidate, mailbox, recovery, copied_uids)
    assert [subject(row) for row in first] == ["New route"]
    transfer(candidate, legacy, mailbox, rollback, reverse_mapping, 1)

    deliver(servers, cached_candidate, mailbox, "Cached new route")
    right = inbox(candidate, mailbox)
    # Later recovery passes exclude both forward receipts and UIDs already staged.
    staged_uids = {row[0] for row in first}
    late = stage_recovery(candidate, mailbox, recovery, copied_uids | staged_uids)
    assert [subject(row) for row in late] == ["Cached new route"]
    assert contents(messages(candidate, mailbox, recovery)) == contents(first + late)
    transfer(candidate, legacy, mailbox, rollback, reverse_mapping, 1)
    transfer(candidate, legacy, mailbox, rollback, reverse_mapping, 0)
    restored = inbox(legacy, mailbox)
    assert restored[:len(existing)] == existing
    assert [subject(row) for row in restored] == [
        "Before cutover", "Final delta", "Cached old route", "Restored route", "New route", "Cached new route",
    ]
    assert contents(restored[-2:]) == contents(first + late)
    assert inbox(candidate, mailbox) == right
    assert contents(messages(legacy, mailbox, "Archive")) == contents(messages(candidate, mailbox, "Archive"))
    for server, expected in ((legacy, restored), (candidate, right)):
        status, data = server.api(server.login(mailbox), "messages?folder=INBOX")
        assert status == 200 and Counter(item["subject"] for item in data["items"]) == Counter(map(subject, expected))
    print("Both MX changes routed new SMTP deliveries correctly. Cached routes drained into the active mailbox.")
    print(f"Rollback kept {len(restored)} messages on the legacy server and {len(right)} on the candidate.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="mail-cutover-") as directory:
        scratch = Path(directory)
        legacy_path, candidate_path = scratch / "legacy", scratch / "candidate"
        legacy_path.mkdir()
        candidate_path.mkdir()
        legacy = Fixture(binary, legacy_path, staging=True)
        candidate = Fixture(binary, candidate_path, staging=True)
        for server in (legacy, candidate):
            server.env["SMTP_LOCAL_DOMAINS"] += f",{DOMAIN},{OTHER}"
            server.env.update(SMTP_EXACT_MAILBOX_DOMAINS=f"{DOMAIN},{OTHER}",
                              SMTP_PROVISIONING_ADDITIONAL_DOMAINS=f"{DOMAIN},{OTHER}")
        with legacy.daemon(), candidate.daemon(), mx_zone() as zone:
            verify(legacy, candidate, zone, scratch)


if __name__ == "__main__":
    main()
