#!/usr/bin/env python3
"""Verify operator import against two independent, disposable TLS Mail servers."""

import argparse
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
import fcntl
from imaplib import Time2Internaldate
import json
from pathlib import Path
import re
import runpy
import sqlite3
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
IMPORT = HERE / "mail-import.py"
Fixture = runpy.run_path(str(HERE / "test-hosted-limits.py"))["Fixture"]
command = runpy.run_path(str(HERE / "test-webmail-teams.py"))["command"]
HISTORICAL = datetime(1969, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
SOURCE_ARCHIVE = "Résumé historique"
TARGET_ARCHIVE = "Old project archive"
FLAGS = r"(\Flagged \Answered ProjectReviewed)"


def mime_message(owner, subject):
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = owner
    message["To"] = owner
    message["Subject"] = subject
    message["Message-ID"] = "<intentionally-duplicated@import.example.test>"
    message.set_content("A message with an attachment.")
    message.add_attachment(b"original bytes\x00\xff\r\n", maintype="application", subtype="octet-stream", filename="receipt.bin")
    return message.as_bytes()


def append(fixture, account, folder, raw, when=HISTORICAL, flags=FLAGS):
    with fixture.imap(account) as imap:
        mailbox = f'"{folder}"'.encode()
        status, response = imap.append(mailbox, flags, Time2Internaldate(when), raw)
        assert status == "OK", response
        _, receipt = imap.response("APPENDUID")
        return int(receipt[0].split()[1])


def messages(fixture, account, folder):
    with fixture.imap(account) as imap:
        status, [count] = imap.select(f'"{folder}"'.encode(), readonly=True)
        assert status == "OK", (folder, status)
        if count == b"0":
            return []
        status, response = imap.fetch("1:*", "(UID FLAGS INTERNALDATE BODY.PEEK[])")
        assert status == "OK"
        result = []
        for row in response:
            if isinstance(row, tuple):
                meta, raw = row
                uid = int(re.search(rb"\bUID ([0-9]+)", meta)[1])
                flags = set(re.search(rb"\bFLAGS \(([^)]*)\)", meta)[1].split()) - {b"\\Recent"}
                date = re.search(rb'\bINTERNALDATE "([^"]+)"', meta)[1]
                result.append((uid, datetime.strptime(date.decode(), "%d-%b-%Y %H:%M:%S %z"), flags, raw))
        assert len(result) == int(count)
        return result


def run(source, origin, destination, target, state, folders, *options, expected=0, disconnect=None):
    cmd = ["python3", str(IMPORT)]
    if disconnect:
        # Interrupt after the durable local checkpoint, either before sending
        # APPEND or after the server has accepted it.
        code = """import os, runpy, sys
module = runpy.run_path(sys.argv.pop(1))
stage = sys.argv.pop(1)
original = module['Session'].append_message
def disconnect(self, *args):
    if stage == 'after':
        result = original(self, *args)
        assert result[0] == 'OK', result
    os._exit(73)
module['Session'].append_message = disconnect
sys.exit(module['main']())
"""
        cmd = ["python3", "-c", code, str(IMPORT), disconnect]
    for role, fixture, user in (("source", source, origin), ("destination", destination, target)):
        cmd.extend([f"--{role}-host", "127.0.0.1", f"--{role}-port", str(fixture.imaps_port),
                    f"--{role}-user", user, f"--{role}-ca", fixture.env["SMTP_TLS_CERT"]])
    cmd.extend(["--password-stdin", "--state", str(state)])
    for origin_folder, target_folder in folders:
        cmd.extend(["--folder", origin_folder, target_folder])
    result = subprocess.run(
        cmd + list(options), input=f"{source.password}\n{destination.password}\n",
        text=True, capture_output=True, timeout=45,
    )
    assert source.password not in result.stdout + result.stderr
    assert destination.password not in result.stdout + result.stderr
    assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
    return [json.loads(line) for line in result.stdout.splitlines()]


def verify_transfer(source, origin, destination, target, root):
    with source.imap(origin) as imap:
        assert imap.create(f'"{SOURCE_ARCHIVE}"'.encode())[0] == "OK"
        assert imap.create('"Empty source folder"')[0] == "OK"
    raw = mime_message(origin, "Identical messages are separate source UIDs")
    archive_raw = mime_message(origin, "Old folder attachment")
    first_uid = append(source, origin, "INBOX", raw)
    second_uid = append(source, origin, "INBOX", raw)
    assert second_uid != first_uid
    append(source, origin, SOURCE_ARCHIVE, archive_raw, when=EPOCH, flags=r"(\Seen \Draft \Deleted)")
    before = messages(source, origin, "INBOX")

    state = root / "transfer.sqlite"
    mapping = [("INBOX", "INBOX"), (SOURCE_ARCHIVE, TARGET_ARCHIVE), ("Empty source folder", "Empty destination folder")]
    discovered = run(source, origin, destination, target, state, [])
    assert any(row["source"] == SOURCE_ARCHIVE and row["messages"] == 1 for row in discovered), discovered
    preview = run(source, origin, destination, target, state, mapping)
    assert [(row["destination"], row["messages"], row["create"]) for row in preview] == [
        ("INBOX", 2, False), (TARGET_ARCHIVE, 1, True), ("Empty destination folder", 0, True),
    ], preview
    assert not state.exists() and messages(destination, target, "INBOX") == []

    # Simulate a verified TLS destination with room for exactly one copy.
    destination.provision(target.split("@")[0], quota=len(raw))
    partial = run(source, origin, destination, target, state, mapping, "--apply", expected=1)
    assert [row["uid"] for row in partial if row["event"] == "imported"] == [first_uid], partial
    assert sum(row["event"] == "error" and not row["resolution_required"] for row in partial) == 2, partial
    assert state.stat().st_mode & 0o777 == 0o600
    assert source.password.encode() not in state.read_bytes() and destination.password.encode() not in state.read_bytes()
    with (root / "transfer.sqlite.lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        concurrent = run(source, origin, destination, target, state, mapping, "--apply", expected=1)
        assert "Another process holds" in concurrent[-1]["reason"]

    destination.provision(target.split("@")[0])
    resumed = run(source, origin, destination, target, state, mapping, "--apply")
    assert [row["uid"] for row in resumed if row["event"] == "imported" and row["source"] == "INBOX"] == [second_uid]
    flags = {b"\\Flagged", b"\\Answered", b"ProjectReviewed"}
    imported = messages(destination, target, "INBOX")
    assert [message[1:] for message in imported] == [(HISTORICAL, flags, raw)] * 2
    assert messages(destination, target, TARGET_ARCHIVE)[0][1:] == (EPOCH, {b"\\Seen", b"\\Draft", b"\\Deleted"}, archive_raw)
    assert messages(destination, target, "Empty destination folder") == []
    assert messages(source, origin, "INBOX") == before, "Reading from the source mutated it"

    arriving = mime_message(origin, "Only the final delta")
    delta_uid = append(source, origin, "INBOX", arriving, when=EPOCH, flags=r"(\Seen)")
    delta = run(source, origin, destination, target, state, mapping, "--apply")
    assert [row["uid"] for row in delta if row["event"] == "imported"] == [delta_uid]
    assert messages(destination, target, "INBOX")[-1][1:] == (EPOCH, {b"\\Seen"}, arriving)
    replay = run(source, origin, destination, target, state, mapping, "--apply")
    assert not any(row["event"] == "imported" for row in replay)

    foreign = destination.provision("other-organization")
    wrong = run(source, origin, destination, foreign, state, mapping, "--apply", expected=1)
    assert "different account pair" in wrong[-1]["reason"]
    assert messages(destination, foreign, "INBOX") == []

    teammate = source.provision("former-teammate")
    command(source, "team", "create", "migration", "Migration", origin)
    command(source, "team", "member", "migration", teammate, "member")
    command(source, "team", "grant", "migration", origin, teammate, "mailbox")
    team_session = source.login(teammate)
    assert source.api(team_session, "shared-inboxes")[1]
    command(source, "team", "revoke", "migration", origin, teammate, "mailbox")
    assert source.api(team_session, "shared-inboxes") == (200, [])
    revoked = run(source, teammate, destination, target, root / "revoked.sqlite",
                  [(SOURCE_ARCHIVE, "Unauthorized folder")], "--apply", expected=1)
    assert "source folder does not exist" in revoked[0]["reason"]
    return state, mapping


def verify_interruption(source, origin, destination, target, root):
    with source.imap(origin) as imap:
        assert imap.create('"Interrupted source"')[0] == "OK"
    state = root / "interrupted.sqlite"
    mapping = [("Interrupted source", "Interrupted import")]
    raw = mime_message(origin, "Accepted before the client stopped")
    source_uid = append(source, origin, "Interrupted source", raw)
    remaining = mime_message(origin, "Still needs importing")
    remaining_uid = append(source, origin, "Interrupted source", remaining)
    run(source, origin, destination, target, state, mapping, "--apply", expected=73, disconnect="after")
    pending = run(source, origin, destination, target, state, mapping, "--apply", expected=1)
    assert pending[-1]["unresolved"] == 1
    committed, = messages(destination, target, "Interrupted import")
    assert committed[3] == raw
    wrong_uid = append(destination, target, "Interrupted import", mime_message(origin, "A different local copy"))
    wrong = run(source, origin, destination, target, state, mapping, "--resolve", "Interrupted source",
                str(source_uid), str(wrong_uid), expected=1)
    assert wrong[-1]["unresolved"] == 1
    unsafe_retry = run(source, origin, destination, target, state, mapping, "--resolve", "Interrupted source",
                       str(source_uid), "uncommitted", expected=1)
    assert "UIDNEXT changed" in unsafe_retry[0]["reason"]
    resolved = run(source, origin, destination, target, state, mapping, "--resolve", "Interrupted source",
                   str(source_uid), str(committed[0]))
    assert resolved[0]["event"] == "resolved"
    replay = run(source, origin, destination, target, state, mapping, "--apply")
    assert [row["uid"] for row in replay if row["event"] == "imported"] == [remaining_uid]
    copies = messages(destination, target, "Interrupted import")
    assert len(copies) == 3 and copies[-1][3] == remaining
    final = mime_message(origin, "Interrupted before sending APPEND")
    final_uid = append(source, origin, "Interrupted source", final)
    run(source, origin, destination, target, state, mapping, "--apply", expected=73, disconnect="before")
    assert len(messages(destination, target, "Interrupted import")) == 3
    released = run(source, origin, destination, target, state, mapping, "--resolve", "Interrupted source",
                   str(final_uid), "uncommitted")
    assert released[0]["event"] == "resolved_uncommitted"
    completed = run(source, origin, destination, target, state, mapping, "--apply")
    assert [row["uid"] for row in completed if row["event"] == "imported"] == [final_uid]
    assert messages(destination, target, "Interrupted import")[-1][3] == final


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="mail-import-") as directory:
        root = Path(directory)
        (root / "source").mkdir()
        (root / "destination").mkdir()
        source = Fixture(binary, root / "source", staging=True)
        destination = Fixture(binary, root / "destination", staging=True)
        with source.daemon(), destination.daemon():
            origin = source.provision("existing-mail")
            target = destination.provision("new-mail")
            bad_ca = run(source, origin, destination, target, root / "wrong-ca.sqlite", [("INBOX", "INBOX")],
                         "--source-ca", destination.env["SMTP_TLS_CERT"], "--apply", expected=1)
            assert bad_ca[0]["reason"] == "IMAP certificate verification failed"
            state, mapping = verify_transfer(source, origin, destination, target, root)
            verify_interruption(source, origin, destination, target, root)
            with sqlite3.connect(source.directory / "smtp.db") as db:
                db.execute("UPDATE imap_mailboxes SET uidvalidity = uidvalidity + 1 WHERE username = ? AND mailbox = 'INBOX'",
                           (origin,))
            mismatch = run(source, origin, destination, target, state, mapping, "--apply", expected=1)
            assert any("UIDVALIDITY changed" in row.get("reason", "") for row in mismatch), mismatch
            with sqlite3.connect(source.directory / "smtp.db") as db:
                db.execute("UPDATE imap_mailboxes SET uidvalidity = uidvalidity - 1 WHERE username = ? AND mailbox = 'INBOX'",
                           (origin,))
            with sqlite3.connect(destination.directory / "smtp.db") as db:
                db.execute("UPDATE imap_mailboxes SET uidvalidity = uidvalidity + 1 WHERE username = ? AND mailbox = 'INBOX'",
                           (target,))
            mismatch = run(source, origin, destination, target, state, mapping, "--apply", expected=1)
            assert any("UIDVALIDITY changed" in row.get("reason", "") for row in mismatch), mismatch
            old_count = len(messages(destination, target, "INBOX"))
            source.provision(origin.split("@")[0], enabled=False)
            run(source, origin, destination, target, state, mapping, "--apply", expected=1)
            assert len(messages(destination, target, "INBOX")) == old_count
    print("Verified certificate-checked preview, folder mapping, exact MIME, flags, dates, quota resume, interrupted APPEND reconciliation, final delta, and account isolation.")


if __name__ == "__main__":
    main()
