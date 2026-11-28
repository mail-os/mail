#!/usr/bin/env python3
"""Kill the active native Mail daemon on both sides of Sent publication."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
import sys
import tempfile
import time


FIXTURE = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture = FIXTURE["Fixture"]


def start_standby(binary, workspace, writer):
    workspace.mkdir()
    (workspace / "mail").symlink_to(writer.directory / "mail", target_is_directory=True)
    standby = Fixture(binary, workspace, staging=True)
    standby.env.update({key: writer.env[key] for key in ("SMTP_DB_PATH", "CALDAV_DB_PATH")})
    standby.password = writer.password
    standby.specs = writer.specs
    return standby


def stop_writer_at(writer, hook, sender, boundary):
    writer.env.update({
        "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD": str(hook),
        "MAIL_TEST_SENT_DIRECTORY": f"/mail/{sender}/Sent",
        "MAIL_TEST_SENT_BOUNDARY": boundary,
    })


def check_fence(standby):
    blocked = subprocess.run(standby.daemon_command(), cwd=standby.directory, env=standby.env,
                             capture_output=True, text=True, timeout=8)
    log = blocked.stdout + blocked.stderr
    assert blocked.returncode != 0 and "MaildirWriterActive" in log, log


def wait_for_stop(process, request):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        pid, status = os.waitpid(process.pid, os.WNOHANG | os.WUNTRACED)
        if pid and os.WIFSTOPPED(status):
            return
        assert not pid and not request.done(), "Mail exited or answered before reaching the Sent boundary"
        time.sleep(0.02)
    raise AssertionError("Mail did not reach the Sent boundary")


def terminate_writer(process, request):
    process.kill()
    process.wait(timeout=5)
    if request is not None:
        try:
            request.result(timeout=6)
        except (OSError, EOFError):
            return
        raise AssertionError("Killed daemon returned a protocol response")


def sent_files(sent):
    return list(sent.glob("[!.]*.eml*"))


def query(root, sql):
    with closing(sqlite3.connect(root / "smtp.db")) as db:
        return db.execute(sql).fetchall()


def submission(writer, protocol, sender, recipient, blind):
    subject = f"Sent recovery {protocol}"
    if protocol.startswith("eas"):
        command = {"eas": "SendMail", "eas-reply": "SmartReply", "eas-forward": "SmartForward"}[protocol]
        source = None
        if command != "SendMail":
            FIXTURE["expect_smtp"](writer.deliver(sender, subject="Original for crash recovery"), 250)
            source = FIXTURE["synced_mail_item"](writer, sender, "QuotaDevice")
        mime = FIXTURE["eas_mime"](sender, recipient, extra=f"Bcc: {blind}\r\n".encode(), subject=subject)
        request = FIXTURE["eas_send"](mime, "sent-crash", save=True, command=command, source=source)

        def send(server):
            return FIXTURE["eas_result"](server.eas(sender, request, command=command), command)

        return send, 0, 118

    if protocol == "ews-create":
        request = FIXTURE["create_ews_item"]("SendAndSaveCopy", to=[recipient], bcc=[blind], subject=subject)
        repeat = ["ErrorSubmissionQuotaExceeded"]
    else:
        draft = FIXTURE["ews_draft"](writer, sender, recipient, bcc=[blind], subject=subject)
        request = FIXTURE["send_ews_items"](draft)
        repeat = ["NoError"]

    def send(server):
        return FIXTURE["ews_codes"](server.ews(sender, request))

    return send, ["NoError"], repeat


def check_recovery(binary, hook, protocol, boundary):
    with tempfile.TemporaryDirectory(prefix="mail-native-sent-") as directory:
        root = Path(directory)
        writer = Fixture(binary, root, staging=True)
        sender = f"crash-sender@{FIXTURE['DOMAIN']}"
        sent = root / "mail" / sender / "Sent"
        if boundary != "rollback":
            stop_writer_at(writer, hook, sender, boundary)

        with writer.daemon() as process, ThreadPoolExecutor(1) as executor:
            assert writer.provision("crash-sender", daily=2) == sender
            recipient = writer.provision("crash-recipient")
            blind = writer.provision("crash-blind")
            standby = start_standby(binary, root / "standby", writer)
            send, success, repeat = submission(writer, protocol, sender, recipient, blind)
            accepted_before = len(query(root, "SELECT id FROM accepted_mail"))
            assert not sent_files(sent)
            if boundary == "rollback":
                query(root, """
                    CREATE TRIGGER refuse_acceptance BEFORE INSERT ON accepted_mail
                    BEGIN SELECT RAISE(ABORT, 'injected acceptance failure'); END
                """)
                assert send(writer) != success
                assert not sent_files(sent) and writer.count(sender) == 0
                assert len(query(root, "SELECT id FROM accepted_mail")) == accepted_before
                assert query(root, "SELECT username FROM eas_accepted_submissions") == []
                assert query(root, "SELECT delivery_id FROM mail_ews_draft_sends") == []
                check_fence(standby)
                terminate_writer(process, None)
                query(root, "DROP TRIGGER refuse_acceptance")
            else:
                request = executor.submit(send, writer)
                try:
                    wait_for_stop(process, request)
                    assert len(sent_files(sent)) == int(boundary == "after-link")
                    charged = writer.count(sender)
                    assert charged == 2, charged
                    assert len(query(root, "SELECT id FROM accepted_mail")) == accepted_before + 1
                    (archive_bytes, reserved, archive, outcome), = query(root, """
                        SELECT length(reply_mime),queued_bytes,reply_mime,outcome
                        FROM accepted_mail_targets WHERE is_primary=0
                    """)
                    assert outcome == "pending" and archive_bytes == reserved > 0 and b"Bcc:" in archive
                    if protocol.startswith("eas"):
                        assert len(query(root, "SELECT username FROM eas_accepted_submissions")) == 1
                    if protocol == "ews-draft":
                        assert len(query(root, "SELECT delivery_id FROM mail_ews_draft_sends")) == 1
                    check_fence(standby)
                finally:
                    terminate_writer(process, request)

        standby.directory = root
        with standby.daemon():
            if boundary == "rollback":
                assert not sent_files(sent) and standby.count(sender) == 0
                assert len(query(root, "SELECT id FROM accepted_mail")) == accepted_before
                assert send(standby) == success
            sent_copy, = sent_files(sent)
            assert sent_copy.name.endswith(":2,S") and b"Bcc:" in sent_copy.read_bytes()
            assert not list(sent.glob(".pending-*"))
            assert query(root, "SELECT outcome,queued_bytes,reply_mime FROM accepted_mail_targets WHERE is_primary=0") == [
                ("filed", 0, None),
            ]
            for mailbox in (recipient, blind):
                received, = (root / "mail" / mailbox / "new").glob("[!.]*.eml*")
                assert b"Bcc:" not in received.read_bytes()
            assert send(standby) == repeat
            assert standby.count(sender) == 2 and sent_files(sent) == [sent_copy]
            assert len(query(root, "SELECT id FROM accepted_mail")) == accepted_before + 1
            if protocol == "ews-draft":
                assert not list((root / "mail" / sender / "Drafts").glob("[!.]*.eml*"))
    print(f"Verified {protocol} {boundary} with a fenced standby and exact recovery.", flush=True)


def check_remote_refusal_recovery(binary, hook):
    with tempfile.TemporaryDirectory(prefix="mail-native-sent-refusal-") as directory:
        root = Path(directory)
        writer = Fixture(binary, root, staging=True)
        sender = f"crash-sender@{FIXTURE['DOMAIN']}"
        sent = root / "mail" / sender / "Sent"
        aws = root / "aws"
        aws.write_text("#!/bin/sh\ntouch remote-refused\nexit 1\n")
        aws.chmod(0o700)
        writer.env.update(SMTP_DELIVERY_METHOD="ses", PATH=str(root) + os.pathsep + writer.env["PATH"])
        stop_writer_at(writer, hook, sender, "after-discard")
        with writer.daemon() as process, ThreadPoolExecutor(1) as executor:
            assert writer.provision("crash-sender", daily=1) == sender
            standby = start_standby(binary, root / "standby", writer)
            mime = FIXTURE["eas_mime"](sender, "refused@remote.example.test")
            payload = FIXTURE["eas_send"](mime, "remote-refusal", save=True)
            request = executor.submit(writer.eas, sender, payload)
            try:
                wait_for_stop(process, request)
                assert not sent_files(sent)
                assert query(root, "SELECT outcome,queued_bytes FROM accepted_mail_targets ORDER BY ordinal") == [
                    ("remote_failed", 0), ("sent_discard", 0),
                ]
                check_fence(standby)
            finally:
                terminate_writer(process, request)

        standby.directory = root
        with standby.daemon():
            assert not sent_files(sent)
            assert query(root, "SELECT outcome FROM accepted_mail_targets") == [("remote_failed",)]
            assert FIXTURE["eas_result"](standby.eas(sender, payload)) == 118
            assert standby.count(sender) == 1
    print("Verified journaled Sent removal after a simulated remote refusal and takeover.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mail", type=Path)
    binary = parser.parse_args().mail.resolve()
    with tempfile.TemporaryDirectory(prefix="mail-sent-hook-") as directory:
        hook = Path(directory) / "crash-hook.so"
        source = Path(__file__).with_name("fixtures") / "native-sent-crash.c"
        flags = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC", "-ldl"]
        subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(source), *flags, "-o", str(hook)],
                       check=True)
        for protocol in ("eas", "eas-reply", "eas-forward", "ews-create", "ews-draft"):
            for boundary in ("rollback", "before-link", "after-link"):
                check_recovery(binary, hook, protocol, boundary)
        check_remote_refusal_recovery(binary, hook)


if __name__ == "__main__":
    main()
