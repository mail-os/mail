#!/usr/bin/env python3
"""Rehearse the native archive and Restic restore using local HTTPS mailboxes."""

import argparse
from contextlib import closing
import os
from pathlib import Path
import runpy
import secrets
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlencode


SCRIPTS = Path(__file__).resolve().parent
fixture_module = runpy.run_path(str(SCRIPTS / "test-hosted-limits.py"))
Fixture = fixture_module["Fixture"]
DavClient = runpy.run_path(str(SCRIPTS / "test-dav-https.py"))["DavClient"]
team_command = runpy.run_path(str(SCRIPTS / "test-webmail-teams.py"))["command"]


def response(result, expected=200):
    status, body = result
    assert status == expected, (status, body)
    return body


def mailbox_identity(fixture, username, uid):
    with fixture.imap(username) as imap:
        assert imap.select("INBOX")[0] == "OK"
        validity = imap.response("UIDVALIDITY")[1]
        status, items = imap.uid("FETCH", str(uid), "(UID FLAGS BODY.PEEK[])")
        assert status == "OK", items
        content, = [pair for pair in items if isinstance(pair, tuple)]
        return validity, content


def pending_message(fixture, session):
    held, = response(fixture.api(session, "sender-review?view=pending"))["items"]
    assert held["verified"] and held["subject"] == "Sender Review backup marker", held
    return held


def archive_and_restore(binary, root, live):
    archive_dir, restic_dir, downloaded, restored, altered = (root / name for name in (
        "archives", "repository", "downloaded", "restored", "altered",
    ))
    config = root / "mail.env"
    config.write_text("SMTP_HOSTNAME=mail.hosted.example.test\n")
    env = dict(os.environ, MAIL_DIR=str(live), BACKUP_DIR=str(archive_dir),
               MAIL_BACKUP_BIN=str(binary), MAIL_BACKUP_ENV_FILE=str(config))
    subprocess.run(["bash", str(SCRIPTS / "mail-backup.sh")], env=env, check=True)
    archive, = archive_dir.glob("mail-backup-*.tgz")
    env_archive = archive.with_suffix(".env.tar")
    key = root / "restic-password"
    key.touch(mode=0o600)
    key.write_text(secrets.token_hex(32) + "\n")
    restic = ["restic", "--repo", str(restic_dir), "--password-file", str(key)]
    subprocess.run([*restic, "init"], check=True)
    subprocess.run([*restic, "backup", "--tag", "mail", str(archive), str(env_archive)], check=True)
    subprocess.run([*restic, "check", "--read-data"], check=True)
    subprocess.run([*restic, "restore", "latest", "--tag", "mail", "--target", str(downloaded)], check=True)

    restored_archive, = downloaded.rglob(archive.name)
    restored_env, = downloaded.rglob(env_archive.name)
    with tarfile.open(restored_env) as contents:
        assert contents.extractfile("mail.env").read() == config.read_bytes()
    for destination in (restored, altered):
        destination.mkdir()
        with tarfile.open(restored_archive) as contents:
            assert all(not any(part.startswith("._") for part in Path(member.name).parts)
                       for member in contents.getmembers() if member.name.startswith("mail/"))
            contents.extractall(destination, filter="data")
    return restored, altered


def verify_worker_rollback(server, previous, owner, sender, endpoint):
    candidate = server.binary
    send_id = secrets.token_hex(16)
    subject = "Scheduled by the newer binary"
    with server.daemon():
        session = server.login(owner)
        response(server.api(session, "compose", {
            "sendId": send_id, "subject": subject, "to": [sender],
            "text": "Dispatch this after swapping binaries.", "scheduleAt": int(time.time()) + 8,
        }))
        server.outbox(session, send_id, "pending")

    incoming = "SMTP during binary rollback"
    server.binary = previous
    with server.daemon():
        session = server.login(owner)
        original = response(server.api(session, endpoint))
        assert server.deliver(owner, identity=sender, subject=incoming)[0] == 250
        sent = server.outbox(session, send_id, "sent")
        assert sent["scheduled"]

    server.binary = candidate
    with server.daemon():
        session = server.login(owner)
        assert response(server.api(session, endpoint))["reference"] == original["reference"]
        assert server.outbox(session, send_id, "sent")["dueAt"] == sent["dueAt"]
        for account, expected in ((owner, incoming), (sender, subject)):
            query = urlencode({"folder": "INBOX", "q": expected})
            message, = response(server.api(server.login(account), "messages?" + query))["items"]
            assert message["subject"] == expected
    print("The previous worker dispatched the newer binary's scheduled send while accepting SMTP. The upgraded worker retained the send result and exactly one recipient copy.")


def verify(binary, root, previous=None):
    live = root / "live"
    live.mkdir()
    source = Fixture(binary, live, staging=True)
    subject = "Back up this message"
    text = "Original mail body kept through backup and restore."
    with source.daemon():
        owner = source.provision("backup-owner")
        sender = source.provision("backup-sender")
        reviewer = source.provision("backup-review-sender")
        team = "restored-team"
        team_command(source, "team", "create", team, "Restored team", sender)
        team_command(source, "team", "member", team, owner, "member")
        team_command(source, "team", "grant", team, owner, sender, "mailbox")
        session = source.login(owner)
        response(source.api(session, "sender-review", {"setting": "disable"}, "PUT"))
        assert source.deliver(owner, identity=sender, subject=subject, body=text)[0] == 250
        query = urlencode({"folder": "INBOX", "q": subject})
        mail, = response(source.api(session, "messages?" + query))["items"]
        endpoint = "messages/ref/" + mail["reference"]
        original = response(source.api(session, endpoint))
        with closing(sqlite3.connect(live / "smtp.db")) as db:
            owner_id, = db.execute("SELECT id FROM users WHERE username=?", (owner,)).fetchone()
        shared_path = f"shared-inboxes/{team}/{owner_id}/messages/{mail['reference']}"
        assert response(source.api(source.login(sender), shared_path))["reference"] == mail["reference"]
        original_uid = mailbox_identity(source, owner, mail["uid"])
        calendar = response(source.api(session, "calendars", {"name": "Backup Calendar"}), 201)
        fields = dict(session, **{"X-Webmail-Source-Message": mail["reference"]})
        event = response(source.api(fields, "calendar-events", {
            "summary": "Restored planning session", "calendarId": calendar["id"],
            "time": {"start": 1795708800, "end": 1795712400},
        }), 201)
        event_path = f"calendar-events/{event['id']}?source=1"
        resource = f"/calendars/{owner}/Backup%20Calendar/{event['uid']}.ics"
        dav = DavClient(source, owner).request("GET", resource)
        assert dav[0] == 200, dav

        draft_id, send_id = secrets.token_hex(16), secrets.token_hex(16)
        draft = response(source.api(session, "drafts", {
            "draftId": draft_id, "saveToken": secrets.token_hex(16), "subject": "Recovered draft", "text": "Draft before archive",
        }))
        response(source.api(session, "compose", {
            "sendId": send_id, "subject": "Recovered scheduled send", "to": [sender], "text": "Scheduled before archive",
            "scheduleAt": int(time.time()) + 3600,
        }))
        scheduled = source.outbox(session, send_id, "pending")

        response(source.api(session, "sender-review", {"setting": "enable"}, "PUT"))
        assert source.deliver(owner, identity=reviewer, subject="Sender Review backup marker", body="Unchanged screening content")[0] == 250
        held = pending_message(source, session)
        if sys.platform == "darwin":
            stored, = [file for file in (live / "mail" / owner).rglob("*.eml*")
                       if b"Subject: Back up this message" in file.read_bytes()]
            subprocess.run(["xattr", "-w", "com.example.mail-test", "portable-backup", str(stored)], check=True)
        previous_projects = live / "mail" / owner / ".PreviousProjects"
        for slot in ("cur", "new", "tmp"):
            (previous_projects / slot).mkdir(parents=True)
        archive_message = b"Subject: Maildir++ archive marker\r\n\r\nArchived folder body.\r\n"
        archived_path = previous_projects / "cur" / "archive.eml:2,S"
        archived_path.write_bytes(archive_message)
        previous_projects.with_name("PreviousProjects").symlink_to(".PreviousProjects/cur", target_is_directory=True)
        archived, = response(source.api(session, "messages?folder=PreviousProjects"))["items"]
        assert archived["subject"] == "Maildir++ archive marker"
        (live / "forwards.json").write_text("{}\n")
        restored, altered = archive_and_restore(binary, root, live)
        assert (restored / archived_path.relative_to(live)).read_bytes() == archive_message
        offboard = ("team", "offboard-owner", team, sender, owner, "restore-fixture-" + secrets.token_hex(8))
        team_command(source, *offboard)
        response(source.api(source.login(sender), shared_path), 404)
        session = source.login(owner)
        assert response(source.api(session, endpoint))["reference"] == mail["reference"]
        assert source.deliver(owner, identity=sender, subject="Mail sent after the backup")[0] == 250

    def stamps(directory):
        with closing(sqlite3.connect(directory / "smtp.db")) as db:
            return (
                db.execute("SELECT reference,file_stamp FROM mailbox_message_refs ORDER BY reference").fetchall(),
                db.execute("SELECT user_id,folder,basename,file_stamp FROM sender_review_messages ORDER BY user_id,folder,basename").fetchall(),
            )

    before = stamps(altered)
    with closing(sqlite3.connect(altered / "smtp.db")) as db:
        folder, basename = db.execute("SELECT folder,basename FROM mailbox_message_refs WHERE user_id=? AND reference=?",
                                      (owner_id, held["reference"])).fetchone()
    screened, = (altered / "mail" / owner / folder).glob(basename + "*")
    content = screened.read_bytes()
    assert b"Unchanged screening content" in content
    screened.write_bytes(content.replace(b"Unchanged screening content", b"Modified screening content!"))
    refused = subprocess.run([str(binary), "backup", "rebind-local", str(altered / "smtp.db"), str(altered / "mail")],
                             capture_output=True, text=True)
    assert refused.returncode != 0 and "BackupFileMismatch" in refused.stderr, (refused.returncode, refused.stdout, refused.stderr)
    assert stamps(altered) == before, "A failed archive check partially changed message identities"

    subprocess.run([str(binary), "backup", "rebind-local", str(restored / "smtp.db"), str(restored / "mail")], check=True)
    assert (restored / "forwards.json").read_text() == (live / "forwards.json").read_text()
    restored_server = Fixture(binary, restored, staging=True)
    restored_server.password = source.password
    with closing(sqlite3.connect(restored / "smtp.db")) as db:
        assert db.execute("SELECT COUNT(*) FROM mail_team_owner_handoffs WHERE operation_id=?", (offboard[-1],)).fetchone()[0] == 0
    team_command(restored_server, *offboard)
    team_command(restored_server, *offboard)
    with restored_server.daemon():
        response(restored_server.api(restored_server.login(sender), shared_path), 404)
        session = restored_server.login(owner)
        assert response(restored_server.api(session, f"teams/{team}"))["team"]["role"] == "owner"
        archived, = response(restored_server.api(session, "messages?folder=PreviousProjects"))["items"]
        assert archived["subject"] == "Maildir++ archive marker"
        recovered = response(restored_server.api(session, endpoint))
        assert recovered["reference"] == original["reference"] and recovered["placement"]["verified_author"] == sender
        assert text in recovered["text"]
        restored_uid = mailbox_identity(restored_server, owner, mail["uid"])
        assert restored_uid == original_uid, (restored_uid[0], original_uid[0], restored_uid[1][0], original_uid[1][0])
        assert response(restored_server.api(session, event_path))["source_message"] == mail["reference"]
        reopened = DavClient(restored_server, owner).request("GET", resource)
        assert reopened[0] == 200 and reopened[1]["ETag"] == dav[1]["ETag"] and reopened[2] == dav[2], reopened
        assert response(restored_server.api(session, f"drafts?uid={draft['uid']}"))["message"]["text"] == "Draft before archive"
        assert restored_server.outbox(session, send_id, "pending")["dueAt"] == scheduled["dueAt"]
        recovered_hold = pending_message(restored_server, session)
        assert recovered_hold["reference"] == held["reference"]
        assert response(restored_server.api(session, "messages?" + urlencode({
            "folder": "INBOX", "q": "Mail sent after the backup",
        })))["total"] == 0
        response(restored_server.api(session, "sender-review", {"setting": "disable"}, "PUT"))
        assert restored_server.deliver(owner, identity=sender, subject="Mail sent to the restored server")[0] == 250
        assert response(restored_server.api(session, "messages?" + urlencode({
            "folder": "INBOX", "q": "Mail sent to the restored server",
        })))["total"] == 1
    print("Verified the local Restic round trip, IMAP identity, verified mail links, Calendar source and ETag, drafts, scheduled sends, and Sender Review. Replayed a post-backup owner offboarding before opening the restored listeners. Tampering failed atomically.")
    if previous is not None:
        verify_worker_rollback(restored_server, previous, owner, sender, endpoint)

    old_domain = owner.rsplit("@", 1)[1]
    new_domain = "renamed.example.test"
    renamed = owner.rsplit("@", 1)[0] + "@" + new_domain
    command = [str(binary), "domain", "migrate", old_domain, new_domain]
    plan = subprocess.run(command, cwd=restored, env=restored_server.env, check=True, capture_output=True, text=True)
    assert "Nothing changed" in plan.stderr and (restored / "mail" / owner).is_dir(), plan.stderr
    migration = subprocess.run([*command, "--yes"], cwd=restored, env=restored_server.env, check=True,
                               capture_output=True, text=True)
    assert "Migrated 3 mailbox(es)." in migration.stderr and "WARNING" not in migration.stderr, migration.stderr
    assert (restored / "mail" / renamed).is_dir() and not (restored / "mail" / owner).exists()
    restored_server.env["SMTP_LOCAL_DOMAINS"] += "," + new_domain
    with restored_server.daemon():
        assert restored_server.api(session, endpoint)[0] == 401
        session = restored_server.login(renamed)
        assert response(restored_server.api(session, endpoint))["reference"] == mail["reference"]
        assert mailbox_identity(restored_server, renamed, mail["uid"]) == original_uid
        assert response(restored_server.api(session, event_path))["source_message"] == mail["reference"]
        client = DavClient(restored_server, renamed)
        assert client.request("GET", resource)[0] == 404
        moved = client.request("GET", resource.replace(f"/{owner}/", f"/{renamed}/", 1))
        assert moved[0] == 200 and moved[1]["ETag"] == dav[1]["ETag"] and moved[2] == dav[2], moved
    print("The offline domain migration preserved the restored IMAP identifiers, webmail links, and CalDAV resource under the new address.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--previous", type=Path, help="Previous binary for the SMTP and scheduled worker rollback rehearsal")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-backup-restore-") as tmp:
        previous = args.previous.resolve(strict=True) if args.previous else None
        verify(args.binary.resolve(strict=True), Path(tmp), previous)
