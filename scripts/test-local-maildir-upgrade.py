#!/usr/bin/env python3
"""Exercise local short-name Maildir recovery and cross-client folder identity."""

import argparse
import base64
from contextlib import contextmanager
from functools import partial
from pathlib import Path
import runpy
import subprocess
import tempfile
from threading import Thread
from xml.etree import ElementTree as ET
from xml.sax.saxutils import quoteattr


suite = runpy.run_path(str(Path(__file__).with_name("test-eas-folder-hierarchy.py")))
index_suite = runpy.run_path(str(Path(__file__).with_name("test-imap-move-index.py")))
Fixture, hierarchy, create, snapshot, ids, move, visible_folders = (
    suite[name] for name in ("Fixture", "hierarchy", "create", "snapshot", "ids", "move", "visible_folders")
)
DOMAIN = suite["hosted"]["DOMAIN"]
message = suite["hosted"]["imap_message"]
ews_draft = suite["hosted"]["ews_draft"]
ews_codes = suite["hosted"]["ews_codes"]


@contextmanager
def search_index():
    with index_suite["SearchIndex"]() as index:
        thread = Thread(target=index.serve_forever, daemon=True)
        thread.start()
        try:
            yield index
        finally:
            index.shutdown()
            thread.join()


def local(test, name):
    mailbox = name if "@" in name else f"{name}@{DOMAIN}"
    subprocess.run([str(test.binary), "user:local", "create", mailbox, "--password-stdin"],
                   input=test.password + "\n", text=True, cwd=test.directory, env=test.env,
                   capture_output=True, check=True)
    return mailbox


def file(root, path, raw):
    destination = root / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    return destination


def uid_snapshot(test, mailbox, folder):
    with test.imap(mailbox) as client:
        code, count = client.select(f'"{folder}"')
        assert code == "OK", (folder, count)
        validity = client.response("UIDVALIDITY")[1][0]
        assert validity
        code, found = client.uid("SEARCH", None, "ALL")
        assert code == "OK"
        return validity, set(found[0].split())


def unique_message(test, owner, folder, field):
    status, listing = test.api(test.login(owner), f"messages?folder={folder}&conversations=false")
    assert status == 200, listing
    result, = [item for item in listing["items"] if item["subject"] == field]
    return result["uid"]


def ews_draft_content(test, owner, item):
    operation = f"<m:GetItem><m:ItemIds><t:ItemId Id={quoteattr(item)}/></m:ItemIds></m:GetItem>"
    response = test.ews(owner, operation)
    assert ews_codes(response) == ["NoError"], response
    tree = ET.fromstring(response[2])
    assert tree.find(".//{*}ItemId").attrib["Id"] == item
    return base64.b64decode(tree.findtext(".//{*}MimeContent"), validate=True)


def verify(candidate, previous):
    with tempfile.TemporaryDirectory(prefix="mail-local-root-") as directory, search_index() as index:
        test = Fixture(previous or candidate, Path(directory), staging=True)
        test.env.update(TYPESENSE_API_KEY="disposable-search-index", TYPESENSE_HOST="127.0.0.1",
                        TYPESENSE_PORT=str(index.server_port))
        mail = test.directory / "mail"
        owner = local(test, "local-owner")
        only = local(test, "short-only")
        canonical_only = local(test, "canonical-only")
        collision = local(test, "collision")
        peers = [local(test, f"ambiguous@{domain}") for domain in (DOMAIN, "other.example.test")]
        legacy, canonical = mail / "local-owner", mail / owner
        shared = "Projects"
        old_message = message("Legacy project")
        canonical_message = message("Canonical project")
        file(legacy, "new/legacy-inbox.eml", message("Legacy inbox"))
        file(canonical, "cur/canonical-inbox.eml:2,S", message("Canonical inbox"))
        file(legacy, f"{shared}/new/legacy-project.eml:2,Sa", old_message)
        file(legacy, f"{shared}/dovecot-keywords", b"0 $Legacy\n")
        file(canonical, f".{shared}/cur/canonical-project.eml:2,S", canonical_message)
        pending_map = file(canonical, f".{shared}/.pending-dovecot-keywords", b"unfinished")
        (canonical / shared).symlink_to(f".{shared}/cur")
        file(legacy, "Device Archive/cur/archive.eml:2,S", message("Legacy archive"))
        file(legacy, ".Waiting/new/waiting.eml", message("Imported folder with pending mail"))
        legacy_archive_inode = (legacy / "Device Archive").stat().st_ino
        file(mail / "short-only", "new/only.eml", message("Short-only inbox"))
        old_suffix = message("Short-only message with historical suffix")
        file(mail / "short-only", "new/older.eml:1,S", old_suffix)
        canonical_tree = mail / canonical_only
        file(canonical_tree, "Editorial/visible.eml:2,S", message("Existing canonical message"))
        file(canonical_tree, "Editorial/new/pending.eml", message("Nested canonical message"))
        file(canonical_tree, ".Reports/cur/visible.eml:2,S", message("Existing Maildir++ message"))
        file(canonical_tree, ".Reports/new/pending.eml", message("Nested Maildir++ message"))
        (canonical_tree / "Reports").symlink_to(".Reports/cur")

        legacy_collision = file(mail / "collision", "new/duplicate.eml:2,S", message("Legacy duplicate"))
        legacy_extra = file(mail / "collision", "cur/other.eml:2,S", message("Legacy untouched"))
        canonical_collision = file(mail / collision, "cur/duplicate.eml:2,F", message("Canonical duplicate"))
        ambiguous = file(mail / "ambiguous", "new/private.eml", message("Unclaimed old mailbox"))
        old_key = previous_snapshot = old_message_id = old_canonical = None
        draft = None
        old_canonical_folders = {}

        if previous:
            # Operators can point the whole mail spool at a mounted volume.
            spool = mail.with_name("spool")
            mail.rename(spool)
            mail.symlink_to(spool.name, target_is_directory=True)
            with test.daemon():
                old_canonical = uid_snapshot(test, owner, shared)
                for folder in ("Editorial", "Reports"):
                    old_canonical_folders[folder] = uid_snapshot(test, canonical_only, folder)
                old_key, old_folders = hierarchy(test, owner)
                previous_snapshot = {label: ident for _, ident, _, label, _ in old_folders}
                _, data = snapshot(test, owner, previous_snapshot[shared])
                old_message_id, = ids(data)
                assert b"Legacy project" in data and b"Canonical project" not in data
                draft = ews_draft(test, owner, only, subject="EWS draft before upgrade")
                raw_draft = ews_draft_content(test, owner, draft)
            test.binary = candidate

        with test.daemon():
            assert not legacy.exists() and not (mail / "short-only").exists()
            assert not pending_map.exists()
            assert (canonical / "Device Archive").stat().st_ino == legacy_archive_inode
            assert legacy_collision.is_file() and legacy_extra.is_file() and canonical_collision.is_file()
            assert ambiguous.is_file()
            with test.imap(owner) as client:
                code, listed = client.list()
                assert code == "OK" and any(b"Device Archive" in line for line in listed), listed
            assert visible_folders(test, owner)[shared] == 2
            assert visible_folders(test, owner)["Device Archive"] == 1
            assert visible_folders(test, only)["INBOX"] == 2
            assert (mail / only / "new/older.eml:1,S").read_bytes() == old_suffix
            assert visible_folders(test, collision)["INBOX"] == 1
            assert all(visible_folders(test, peer)["INBOX"] == 0 for peer in peers)
            _, canonical_folders = hierarchy(test, canonical_only)
            canonical_folders = {label: ident for _, ident, _, label, _ in canonical_folders}
            for folder, subject in (("Editorial", "Nested canonical message"), ("Reports", "Nested Maildir++ message")):
                assert visible_folders(test, canonical_only)[folder] == 2
                validity, uids = uid_snapshot(test, canonical_only, folder)
                assert len(uids) == 2
                if previous:
                    assert validity == old_canonical_folders[folder][0] and old_canonical_folders[folder][1] <= uids
                _, listing = snapshot(test, canonical_only, canonical_folders[folder])
                assert subject.encode() in listing and len(ids(listing)) == 2
            assert visible_folders(test, owner)["Waiting"] == 1
            if draft:
                assert ews_draft_content(test, owner, draft) == raw_draft
                assert visible_folders(test, owner)["Drafts"] == 1
                assert uid_snapshot(test, owner, "Drafts")[1]
            actual_validity, current_uids = uid_snapshot(test, owner, shared)
            if old_canonical:
                assert actual_validity == old_canonical[0] and old_canonical[1] <= current_uids
                upgraded_key, changes = hierarchy(test, owner, old_key)
                assert upgraded_key != old_key
                assert [(command, label) for command, _, _, label, _ in changes] == [(0x4f, "Waiting")]

            key, folders = hierarchy(test, owner)
            folders = {label: ident for _, ident, _, label, _ in folders}
            if previous_snapshot:
                for folder in (shared, "Device Archive"):
                    assert folders[folder] == previous_snapshot[folder]
            _, listing = snapshot(test, owner, folders[shared])
            assert b"Legacy project" in listing and b"Canonical project" in listing
            index_suite["wait_for"](lambda: any(
                row["username"] == owner and row["mailbox"] == shared and row["subject"] == "Legacy project"
                for row in index.documents
            ), "The migrated message should be indexed from its canonical folder")
            legacy_uid = unique_message(test, owner, shared, "Legacy project")
            legacy_id, = [item for item in ids(listing) if int(item.split(":")[1]) == legacy_uid]
            if old_message_id:
                assert legacy_id == old_message_id
            with test.imap(owner) as client:
                assert client.select(shared)[0] == "OK"
                code, data = client.uid("FETCH", str(legacy_uid), "(FLAGS BODY.PEEK[])")
                assert code == "OK" and b"$Legacy" in data[0][0] and data[0][1] == old_message, data

            key, destination = create(test, owner, key, "Created from device")
            with test.imap(owner) as client:
                code, names = client.list()
                assert code == "OK" and any(b"Created from device" in name for name in names), names
            (status, moved), = move(test, owner, (legacy_id, folders[shared], destination))
            assert status == 3 and ids(snapshot(test, owner, destination)[1]) == [moved]
            assert visible_folders(test, owner)["Created from device"] == 1
            with test.imap(owner) as client:
                assert client.select('"Created from device"') == ("OK", [b"1"])
                code, data = client.fetch("1", "(FLAGS BODY.PEEK[])")
                assert code == "OK" and b"$Legacy" in data[0][0] and data[0][1] == old_message
                assert client.create('"Created from IMAP"')[0] == "OK"
            key, changes = hierarchy(test, owner, key)
            assert any(label == "Created from IMAP" for _, _, _, label, _ in changes)

            test.eas = partial(test.eas, full_login=True)
            for peer in peers:
                peer_key, _ = hierarchy(test, peer)
                create(test, peer, peer_key, "Isolated device folder")
                _, data = snapshot(test, peer, "1")
                assert not ids(data)
                with test.imap(peer) as client:
                    assert client.select('"Isolated device folder"') == ("OK", [b"0"])

        with test.daemon():
            assert hierarchy(test, owner, key) == (key, [])
            assert ids(snapshot(test, owner, destination)[1]) == [moved]
            assert visible_folders(test, owner)[shared] == 1
            assert visible_folders(test, owner)["Created from device"] == 1
            assert visible_folders(test, canonical_only)["Editorial"] == 2
            assert visible_folders(test, canonical_only)["Reports"] == 2
            assert legacy_collision.is_file() and legacy_extra.is_file() and ambiguous.is_file()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--upgrade-from", type=Path)
    args = parser.parse_args()
    verify(args.binary.resolve(strict=True), args.upgrade_from.resolve(strict=True) if args.upgrade_from else None)
    print("Verified local Maildir migration, cross-client folders and moves, conflicts, and restart.")
