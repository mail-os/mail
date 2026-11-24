#!/usr/bin/env python3
"""Verify hosted service and export deadlines with native TLS clients."""

import base64
import imaplib
import json
from pathlib import Path
import runpy
import secrets
import sys
import tempfile
import time


suite = runpy.run_path(Path(__file__).with_name("test-hosted-limits.py"))
Fixture, request = suite["Fixture"], suite["request"]
domain = suite["DOMAIN"]
external = suite["EXTERNAL"]


def verify(fixture):
    mailbox = fixture.provision("paid-access")
    receiver = fixture.provision("paid-receiver")
    revision = 1

    def set_window(window, enabled=True):
        nonlocal revision
        revision += 1
        policy = {
            "mailbox": mailbox,
            "actor": fixture.specs[mailbox]["actor"],
            "operation_id": secrets.token_hex(16),
            "revision": revision,
            "quota_bytes": suite["LARGE"],
            "send_recipients_per_day": 20,
            "enabled": enabled,
        }
        if window is not None:
            policy["access_window"] = window
        status, _, raw = request(fixture.private + "/provisioning/v1/mailbox", policy, fixture.auth)
        assert status == 200, (status, raw)
        return policy, json.loads(raw)

    def renew_window(window):
        nonlocal revision
        revision += 1
        renewal = {
            "mailbox": mailbox,
            "actor": fixture.specs[mailbox]["actor"],
            "operation_id": secrets.token_hex(16),
            "revision": revision,
            "access_window": window,
        }
        url = fixture.private + "/provisioning/v1/mailbox/access"
        status, _, raw = request(url, renewal, fixture.auth)
        assert status == 200, (status, raw)
        state = json.loads(raw)
        replay_status, _, replay = request(url, renewal, fixture.auth)
        assert replay_status == 200 and json.loads(replay) == state, (replay_status, replay)
        return state

    now = int(time.time())
    open_window = {"service_until": now + 1800, "read_until": now + 3600}
    policy, state = set_window(open_window)
    assert state["access"] == "full" and state["access_window"] == open_window, state
    changed_replay = {**policy, "access_window": {**open_window, "read_until": now + 4000}}
    assert request(fixture.private + "/provisioning/v1/mailbox", changed_replay, fixture.auth)[0] == 409
    forbidden = {**changed_replay, "access_window": {"service_until": now + 3600, "read_until": now + 1800}}
    assert request(fixture.private + "/provisioning/v1/mailbox", forbidden, fixture.auth)[0] == 400

    assert fixture.deliver(mailbox, subject="Available for export")[0] == 250
    assert fixture.deliver(receiver, identity=mailbox)[0] == 250
    session = fixture.login(mailbox)
    with imaplib.IMAP4_SSL(fixture.hostname, fixture.imaps_port, ssl_context=fixture.tls_context, timeout=10) as inbox:
        assert inbox.login(mailbox, fixture.password)[0] == "OK"
        assert inbox.select("INBOX")[0] == "OK"

        with fixture.smtp() as smtp:
            assert smtp.mail(external)[0] == 250
            assert smtp.rcpt(mailbox)[0] == 250
            export_window = {"service_until": now - 30, "read_until": now + 1800}
            _, state = set_window(export_window)
            assert state["access"] == "read_only", state
            assert smtp.data(b"Subject: In flight at the boundary\r\n\r\nDeferred.\r\n")[0] == 450

        _, state = set_window(None)
        assert state["access_window"] == export_window and state["access"] == "read_only", state
        with fixture.smtp() as smtp:
            assert smtp.mail(external)[0] == 250
            code, reply = smtp.rcpt(mailbox)
            assert code == 450 and b"read-only" in reply, (code, reply)
        assert fixture.deliver(receiver, identity=mailbox)[0] == 550

        code, listing = fixture.api(session, "messages?folder=INBOX")
        assert code == 200 and [entry["subject"] for entry in listing["items"]] == ["Available for export"], (code, listing)
        status, _ = fixture.api(session, "messages/1?folder=INBOX", method="DELETE")
        assert status == 403, status
        assert inbox.store("1", "+FLAGS", "(\\Seen)")[0] == "NO"
        assert inbox.select("INBOX", readonly=True)[0] == "OK"
        assert inbox.uid("COPY", "1", "Drafts")[0] == "NO"
        assert inbox.append("INBOX", None, None, b"Subject: Denied\r\n\r\nRead only\r\n")[0] == "NO"
        status, content = inbox.fetch("1", "(BODY[] FLAGS)")
        assert status == "OK" and b"Available for export" in content[0][1], (status, content)
        status, flags = inbox.fetch("1", "FLAGS")
        assert status == "OK" and b"\\Seen" not in flags[0], (status, flags)

        assert fixture.ews(mailbox, "<m:FindFolder/>")[0] == 200
        assert fixture.ews(mailbox, "<m:CreateItem/>")[0] == 403
        folder_sync = bytes.fromhex("03016a00000756520330000101")
        assert fixture.eas(mailbox, folder_sync, command="FolderSync")[0] == 200
        assert fixture.eas(mailbox, folder_sync, command="FolderCreate")[0] == 403
        auth = base64.b64encode(f"{mailbox}:{fixture.password}".encode()).decode()
        dav = fixture.ews_url.split("/EWS/", 1)[0]
        status, _, _ = request(dav + "/calendars/" + mailbox + "/readonly-check.ics", b"", {"Authorization": f"Basic {auth}"},
                               method="PUT", context=fixture.tls_context)
        assert status == 403, status

        _, state = set_window({"service_until": now - 60, "read_until": now - 30})
        assert state["access"] == "expired", state
        with fixture.smtp() as smtp:
            assert smtp.mail(external)[0] == 250
            code, reply = smtp.rcpt(mailbox)
            assert code == 550 and b"service ended" in reply, (code, reply)
        assert fixture.api(session, "folders")[0] == 401
        assert fixture.ews(mailbox, "<m:FindFolder/>")[0] == 401
        assert fixture.eas(mailbox, folder_sync, command="FolderSync")[0] == 401
        try:
            inbox.noop()
        except imaplib.IMAP4.abort:
            pass
        else:
            raise AssertionError("The open IMAP session was still usable after expiry")

    _, state = set_window(open_window, enabled=False)
    assert state["access"] == "disabled", state
    renewed = {"service_until": now + 3600, "read_until": now + 7200}
    state = renew_window(renewed)
    assert not state["enabled"] and state["access"] == "disabled" and state["access_window"] == renewed, state
    assert state["quota_bytes"] == suite["LARGE"] and state["send_recipients_per_day"] == 20, state
    _, state = set_window(None)
    assert state["access"] == "full", state
    assert fixture.deliver(mailbox)[0] == 250
    assert fixture.api(fixture.login(mailbox), "messages?folder=INBOX")[0] == 200
    return mailbox


if __name__ == "__main__":
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="mail-hosted-access-") as directory:
        fixture = Fixture(binary, Path(directory), staging=True)
        with fixture.daemon():
            mailbox = verify(fixture)
        with fixture.daemon():
            assert fixture.deliver(mailbox)[0] == 250
            assert fixture.api(fixture.login(mailbox), "folders")[0] == 200
    print("Verified hosted service, export and expiry over native SMTP, webmail, IMAPS, EWS, ActiveSync and DAV.")
