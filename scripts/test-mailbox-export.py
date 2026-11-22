#!/usr/bin/env python3
"""Export a disabled mailbox and transfer the archive to a fresh Mail instance."""

import argparse
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from imaplib import Time2Internaldate
import json
import mailbox
from pathlib import Path
import runpy
import stat
import subprocess
import tarfile
import tempfile

SCRIPTS = Path(__file__).resolve().parent
tools = runpy.run_path(str(SCRIPTS / "test-webmail-teams.py"))
Fixture, command = tools["Fixture"], tools["command"]
DavClient = runpy.run_path(str(SCRIPTS / "test-dav-https.py"))["DavClient"]
ATTACHMENT = b"Portable attachment content \x00\xff"
FILE_TIME = 1741212345
USTAR_MTIME_LIMIT = (1 << 33) - 1
LONG_FOLDER = "Historical mail " + "x" * 150
TIMESTAMP_CASES = [
    ("INBOX", "One second before the epoch", -1),
    ("INBOX", "The Unix epoch", 0),
    (LONG_FOLDER, "Historical message in a long folder", -205891200),
    ("INBOX", "At the USTAR timestamp limit", USTAR_MTIME_LIMIT),
    ("INBOX", "After the USTAR timestamp limit", USTAR_MTIME_LIMIT + 1),
]
EVENT = (
    b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail Export Fixture//EN\r\n"
    b"BEGIN:VEVENT\r\nUID:portable-event\r\nDTSTAMP:20260317T100000Z\r\n"
    b"DTSTART:20260317T110000Z\r\nDTEND:20260317T120000Z\r\n"
    b"SUMMARY:Portable calendar event\r\nRRULE:FREQ=WEEKLY;COUNT=3\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
)
CARD = (
    b"BEGIN:VCARD\r\nVERSION:3.0\r\nUID:portable-contact\r\n"
    b"FN:Casey Portable\r\nEMAIL:casey@example.test\r\nEND:VCARD\r\n"
)


def put_dav(client, path, content_type, body):
    result = client.request("PUT", path, body, {"Content-Type": content_type})
    assert result[0] == 201, result


def internaldate(response):
    value = response.split(b'INTERNALDATE "', 1)[1].split(b'"', 1)[0]
    return datetime.strptime(value.decode(), "%d-%b-%Y %H:%M:%S %z").timestamp()


def seed(source):
    owner = source.provision("portable")
    foreign = source.provision("foreign")
    teammate = source.provision("former-teammate")
    assert source.deliver(owner, subject="Portable inbox")[0] == 250
    assert source.deliver(foreign, subject="Foreign private inbox")[0] == 250

    item = EmailMessage(policy=policy.SMTP)
    item["From"] = owner
    item["To"] = owner
    item["Subject"] = "Portable project attachment"
    item.set_content("Original MIME content.")
    item.add_attachment(ATTACHMENT, maintype="application", subtype="octet-stream", filename="fixture.bin")
    raw = item.as_bytes()
    with source.imap(owner) as imap:
        for invalid in ('"Empty folder" extra', '"Unterminated folder'):
            try:
                # Bypass imaplib's quoting here to send malformed protocol input.
                imap._simple_command("CREATE", invalid)
            except imap.error as error:
                assert "CREATE requires one mailbox name" in str(error), error
            else:
                raise AssertionError(f"CREATE accepted invalid mailbox arguments {invalid}")
        for folder in ["Projects", "Empty folder", LONG_FOLDER]:
            assert imap.create('"' + folder + '"')[0] == "OK"
        assert imap.create('"Temporary folder"')[0] == "OK"
        assert imap.delete('"Temporary folder"')[0] == "OK"
        assert imap.append("Projects", r"(\Seen \Flagged)", FILE_TIME, raw)[0] == "OK"
        assert imap.append("Sent", r"(\Seen \Answered)", None, raw)[0] == "OK"
        for folder, subject, received_at in TIMESTAMP_CASES:
            message = EmailMessage(policy=policy.SMTP)
            message["From"] = message["To"] = owner
            message["Subject"] = subject
            message.set_content("Verify the archive preserves the original received time.")
            assert imap.append(f'"{folder}"', None, Time2Internaldate(received_at), message.as_bytes())[0] == "OK"

    owner_dir = source.directory / "mail" / owner
    # Imported or upgraded installations may have both the old flat directory
    # and the current Maildir++ directory. Include both without duplicating an alias.
    (owner_dir / "Projects").unlink()
    (owner_dir / "Projects").mkdir()
    (owner_dir / "Projects" / "legacy.eml:2,D").write_bytes(raw.replace(b"Portable project attachment", b"Legacy project copy"))
    foreign_mail, = (source.directory / "mail" / foreign / "new").glob("*.eml")
    (owner_dir / "new" / "foreign-link.eml").symlink_to(foreign_mail)
    (owner_dir / "ForeignFolder").symlink_to(foreign_mail.parent, target_is_directory=True)
    (owner_dir / "tmp").mkdir(exist_ok=True)
    (owner_dir / "tmp" / "uncommitted.eml").write_bytes(b"Uncommitted staging bytes")

    dav = DavClient(source, owner)
    put_dav(dav, f"/calendars/{owner}/Design/export.ics", "text/calendar", EVENT)
    put_dav(dav, f"/addressbooks/{owner}/Friends/export.vcf", "text/vcard", CARD)
    other_dav = DavClient(source, foreign)
    put_dav(other_dav, f"/calendars/{foreign}/Private/private.ics", "text/calendar",
            EVENT.replace(b"Portable calendar event", b"Foreign calendar"))
    put_dav(other_dav, f"/addressbooks/{foreign}/Private/private.vcf", "text/vcard",
            CARD.replace(b"Casey Portable", b"Foreign contact"))

    command(source, "team", "create", "archive", "Archive", owner)
    command(source, "team", "member", "archive", teammate, "member")
    command(source, "team", "grant", "archive", owner, teammate, "mailbox")
    assert source.api(source.login(teammate), "shared-inboxes")[1]
    command(source, "team", "revoke", "archive", owner, teammate, "mailbox")
    assert source.api(source.login(teammate), "shared-inboxes") == (200, [])
    owner_session = source.login(owner)
    command(source, "user:local", "disable", owner)
    assert source.api(owner_session, "folders")[0] == 401
    return owner, raw


def inspect(source, owner, archive, extracted, original):
    command(source, "user:local", "export", owner, str(archive))
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    with tarfile.open(archive) as data:
        assert len(set(data.getnames())) == len(data.getnames())
        assert all(member.isfile() or member.isdir() for member in data.getmembers())
        members_by_subject = {}
        for member in data.getmembers():
            if member.isfile() and ".eml" in member.name:
                with data.extractfile(member) as content:
                    message = BytesParser(policy=policy.default).parse(content)
                members_by_subject[message["Subject"]] = member
        for folder, subject, received_at in TIMESTAMP_CASES:
            member = members_by_subject[subject]
            assert member.mtime == received_at, (subject, member.mtime, received_at)
            expected_pax_mtime = str(received_at) if not 0 <= received_at <= USTAR_MTIME_LIMIT else None
            assert member.pax_headers.get("mtime") == expected_pax_mtime
            if folder == LONG_FOLDER:
                assert member.pax_headers.get("path") == member.name
        assert "mtime" not in members_by_subject["Legacy project copy"].pax_headers
    subprocess.run(["tar", "-xf", str(archive), "-C", str(extracted)], check=True)

    manifest = json.loads((extracted / "manifest.json").read_bytes())
    assert manifest["version"] == 1 and manifest["mailbox"] == owner
    folders = {item["name"]: extracted / item["path"] for item in manifest["folders"]}
    assert set(folders) == {"INBOX", "Projects", "Empty folder", "Sent", LONG_FOLDER}, folders
    assert {item["name"] for item in manifest["calendars"]} == {"Design"}
    assert {item["name"] for item in manifest["addressBooks"]} == {"Friends"}
    assert not list(folders["INBOX"].joinpath("tmp").iterdir())
    assert not list(folders["Empty folder"].joinpath("cur").iterdir())
    projects = sorted(folders["Projects"].joinpath("cur").iterdir())
    assert len(projects) == 2
    flagged, = [path for path in projects if path.name.endswith(":2,FS")]
    assert flagged.stat().st_mtime == FILE_TIME and flagged.read_bytes() == original

    # Read the extract with an independent Maildir implementation.
    portable = mailbox.Maildir(str(folders["INBOX"]), create=False)
    assert {item["Subject"] for item in portable} == {
        "Portable inbox", *(subject for folder, subject, _ in TIMESTAMP_CASES if folder == "INBOX"),
    }
    for folder, subject, received_at in TIMESTAMP_CASES:
        maildir = portable if folder == "INBOX" else portable.get_folder(folder)
        item, = [message for message in maildir if message["Subject"] == subject]
        assert item.get_date() == received_at, (subject, item.get_date(), received_at)
    project_box = portable.get_folder("Projects")
    assert {item["Subject"]: item.get_flags() for item in project_box} == {
        "Portable project attachment": "FS", "Legacy project copy": "D",
    }
    assert len(portable.get_folder("Empty folder")) == 0
    assert {item["Subject"]: item.get_flags() for item in portable.get_folder("Sent")} == {
        "Portable project attachment": "RS",
    }

    # The archive is published only on success and never overwrites a file.
    original_archive = archive.read_bytes()
    command(source, "user:local", "export", owner, str(archive), error="PathAlreadyExists")
    assert archive.read_bytes() == original_archive
    missing = archive.parent / "missing.tar"
    command(source, "user:local", "export", "missing@hosted.example.test", str(missing), error="NotFound")
    assert not missing.exists()
    return manifest


def transfer(destination, extracted, manifest):
    owner = destination.provision("restored")
    flag_map = {"D": r"\Draft", "F": r"\Flagged", "R": r"\Answered", "S": r"\Seen", "T": r"\Deleted"}
    with destination.imap(owner) as imap:
        for folder in manifest["folders"]:
            name = folder["name"]
            quoted = '"' + name + '"'
            if name != "INBOX":
                assert imap.create(quoted)[0] == "OK"
            path = extracted / folder["path"]
            for slot in ("new", "cur"):
                for file in (path / slot).iterdir():
                    flags = file.name.partition(":2,")[2]
                    encoded = "(" + " ".join(flag_map[flag] for flag in flags) + ")"
                    date_arg = Time2Internaldate(file.stat().st_mtime)
                    assert imap.append(quoted, encoded, date_arg, file.read_bytes())[0] == "OK"
        assert imap.select('"Projects"') == ("OK", [b"2"])
        result, rows = imap.search(None, "FLAGGED")
        assert result == "OK" and len(rows[0].split()) == 1
        result, rows = imap.fetch(rows[0], "(BODY.PEEK[] INTERNALDATE)")
        message = BytesParser(policy=policy.default).parsebytes(rows[0][1])
        assert result == "OK" and message["Subject"] == "Portable project attachment"
        assert internaldate(rows[0][0]) == FILE_TIME
        part, = message.iter_attachments()
        assert part.get_filename() == "fixture.bin" and part.get_payload(decode=True) == ATTACHMENT
        assert imap.select('"Empty folder"') == ("OK", [b"0"])
        for folder, subject, received_at in TIMESTAMP_CASES:
            assert imap.select(f'"{folder}"')[0] == "OK"
            result, rows = imap.search(None, "SUBJECT", f'"{subject}"')
            assert result == "OK" and len(rows[0].split()) == 1, (subject, rows)
            result, rows = imap.fetch(rows[0], "(INTERNALDATE)")
            assert result == "OK"
            assert internaldate(rows[0]) == received_at

    client = DavClient(destination, owner)
    calendar, = manifest["calendars"]
    calendar_path = f"/calendars/{owner}/Restored/export.ics"
    put_dav(client, calendar_path, "text/calendar", (extracted / calendar["path"]).read_bytes())
    status, _, body = client.request("GET", calendar_path)
    assert status == 200 and b"UID:portable-event" in body and b"RRULE:FREQ=WEEKLY;COUNT=3" in body
    book, = manifest["addressBooks"]
    card, = (extracted / book["path"]).glob("*.vcf")
    contact_path = f"/addressbooks/{owner}/Restored/export.vcf"
    put_dav(client, contact_path, "text/vcard", card.read_bytes())
    assert client.request("GET", contact_path)[2] == CARD


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--archive", type=Path, help="Keep a copy of the disposable test archive")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-export-") as scratch:
        root = Path(scratch)
        for name in ("source", "destination", "extracted"):
            (root / name).mkdir()
        binary = args.binary.resolve(strict=True)
        source = Fixture(binary, root / "source", staging=True)
        with source.daemon():
            owner, raw = seed(source)
        archive = args.archive.resolve() if args.archive else root / "mailbox.tar"
        manifest = inspect(source, owner, archive, root / "extracted", raw)
        destination = Fixture(binary, root / "destination", staging=True)
        with destination.daemon():
            transfer(destination, root / "extracted", manifest)
    print("Verified private portable export and transfer of messages, received times, flags, folders, calendar, and contacts.")


if __name__ == "__main__":
    main()
