#!/usr/bin/env python3
"""Verify account-local webmail organization against native TLS and IMAP."""

import argparse
from contextlib import closing
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path
import runpy
import sqlite3
import tempfile
from urllib.parse import urlencode


fixtures = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture = fixtures["Fixture"]
NOTE = "Private workspace note for the studio's renewal."
CLIP = "This sentence is from the original message."
LABEL = "Personal studio label"
GROUP_PATH = "private/group"
UNDO_PATH = "private/undo-group"
COLLECTIONS = "private/collections"


def seed(imap, owner, subject, message_id=None, reply=None, folder="INBOX", flags=None):
    mail = EmailMessage()
    mail["Subject"], mail["To"], mail["From"] = subject, owner, "Morgan <morgan@example.test>"
    if message_id:
        mail["Message-ID"] = f"<{message_id}@example.test>"
    if reply:
        mail["References"] = mail["In-Reply-To"] = f"<{reply}@example.test>"
    mail.set_content(f"Studio notes.\n{CLIP}\n")
    assert imap.append(folder, flags, None, mail.as_bytes(policy=SMTP))[0] == "OK"


def run(binary, previous):
    with tempfile.TemporaryDirectory(prefix="mail-workspace-") as tmp:
        directory = Path(tmp)
        test = Fixture(previous or binary, directory, staging=True)

        def call(session, path, payload=None, *, method=None, status=200, etag=None):
            headers = dict(session)
            if etag is not None:
                headers["If-Match"] = etag
            code, data = test.api(headers, path, payload, method)
            assert code == status, (path, code, data)
            return data

        def listing(session, **params):
            return call(session, "messages?" + urlencode(params))

        def get_tools(session, row, status=200):
            return call(session, "private/message?" + urlencode({"reference": row["reference"]}), status=status)

        def change(session, row, action, *, status=200, **params):
            return call(session, "private/message", {"reference": row["reference"], "action": action, **params},
                        method="POST", status=status, etag=row["revision"])

        def group(session, *rows, status=200):
            payload = {"messages": [{key: row[key] for key in ("reference", "revision")} for row in rows]}
            return call(session, GROUP_PATH, payload, method="POST", status=status)

        def undo(session, receipt, status=200):
            return call(session, UNDO_PATH, {"id": receipt["undoId"]}, method="POST", status=status)

        def partitions(session):
            view = listing(session, folder="*", conversations="true", personal="true")
            return {frozenset(row["subject"] for row in thread["members"]) for thread in view["threads"]}

        with test.daemon():
            alice = test.provision("alice")
            bob = test.provision("bob")
            with test.imap(alice) as imap:
                assert imap.create("Archive")[0] == "OK"
                assert imap.create("Drafts")[0] == "OK"
                seed(imap, alice, "Studio terms", "root")
                seed(imap, alice, "Re: Studio terms", "reply", "root")
                seed(imap, alice, "Studio follow through", "follow", "reply")
                seed(imap, alice, "Vendor sheet")  # No wire identity. The reference is the anchor.
                seed(imap, alice, "Signed agreement", "agreement")
            with test.imap(bob) as imap:
                seed(imap, bob, "Bob's message", "root")  # Same wire ID belongs to a different account.
        test.binary = binary

        with test.daemon():
            owner, foreign = test.login(alice), test.login(bob)
            rows = {item["subject"]: item for item in listing(owner)["items"]}
            root, reply, follow, vendor, agreement = (rows[name] for name in
                                                     ("Studio terms", "Re: Studio terms", "Studio follow through",
                                                      "Vendor sheet", "Signed agreement"))
            outsider = listing(foreign)["items"][0]
            assert get_tools(owner, root)["entries"] == []
            get_tools(foreign, root, 404)
            change(foreign, root, "note", body="Forbidden", status=404)
            change({**owner, "Origin": "https://elsewhere.example.test"}, root, "note", body="Forbidden", status=403)
            call(owner, "private/message", {"reference": root["reference"], "action": "note", "body": NOTE},
                 method="POST", status=428)
            group(owner, root, outsider, status=404)
            group(owner, root, {**vendor, "revision": '"stale"'}, status=412)
            assert len(partitions(owner)) == 3

            tools = change(owner, root, "note", body=NOTE)
            note = tools["entries"][0]
            assert note["kind"] == "note" and note["body"] == NOTE
            assert get_tools(owner, reply)["entries"][0]["id"] == note["id"]
            assert get_tools(owner, follow)["entries"][0]["id"] == note["id"]
            change(owner, vendor, "edit", entry=note["id"], revision=note["revision"], body="Wrong conversation", status=412)
            changed = change(owner, reply, "edit", entry=note["id"], revision=note["revision"], body=NOTE + " Updated.")
            assert changed["entries"][0]["revision"] == note["revision"] + 1
            change(owner, root, "edit", entry=note["id"], revision=note["revision"], body="Stale", status=412)
            change(owner, root, "clip", body="This sentence does not appear in the message.", status=400)
            clipped = change(owner, root, "clip", body=CLIP)
            assert clipped["entries"][0]["kind"] == "clip" and clipped["entries"][0]["source_subject"] == "Studio terms"
            clip = clipped["entries"][0]
            change(owner, root, "edit", entry=clip["id"], revision=clip["revision"], body="Altered clip", status=412)
            labelled = change(owner, root, "label", body=LABEL, label_revision="")
            assert labelled["label"]["value"] == LABEL
            change(owner, reply, "label", body="Stale label", label_revision="", status=412)
            assert get_tools(owner, reply)["label"]["value"] == LABEL
            original = call(owner, "messages/ref/" + root["reference"])
            assert original["subject"] == "Studio terms" and "personal_subject" not in original
            mail_items = listing(owner, personal="true")["items"]
            assert {row["subject"] for row in mail_items if row.get("personal_subject") == LABEL} == {
                "Studio terms", "Re: Studio terms", "Studio follow through"
            }
            assert not any("personal_subject" in row for row in listing(owner)["items"])
            assert get_tools(foreign, outsider)["entries"] == [] and get_tools(foreign, outsider)["label"]["value"] == ""

            collections = call(owner, COLLECTIONS, {"action": "create", "name": "Studio"}, method="POST")["items"]
            collection = collections[0]
            call(owner, COLLECTIONS, {"action": "create", "name": "studio"}, method="POST", status=409)
            call(foreign, COLLECTIONS, {"action": "rename", "id": collection["id"], "revision": collection["revision"], "name": "No"},
                 method="POST", status=409)
            assert call(foreign, COLLECTIONS)["items"] == []
            call(foreign, "messages?" + urlencode({"collection": collection["id"]}), status=404)
            renamed = call(owner, COLLECTIONS, {"action": "rename", "id": collection["id"], "revision": collection["revision"],
                                               "name": "Studio renewal"}, method="POST")["items"][0]
            assert renamed["name"] == "Studio renewal" and renamed["revision"] == collection["revision"] + 1
            change(owner, root, "collection", collection=collection["id"], included=True)
            with test.imap(alice) as imap:
                seed(imap, alice, "Unsent reply", "draft", "root", "Drafts", r"(\Draft)")
            draft = listing(owner, folder="Drafts", personal="true")["items"][0]
            assert "personal_subject" not in draft
            get_tools(owner, draft, 404)
            scoped = listing(owner, collection=collection["id"], per_page=1)
            assert scoped["total"] == 3 and len(scoped["items"]) == 1
            assert get_tools(owner, reply)["collections"][0]["included"] is True
            with test.imap(alice) as imap:
                assert imap.select("Drafts")[0] == "OK"
                assert imap.store("1:*", "+FLAGS", r"(\Deleted)")[0] == "OK"
                assert imap.expunge()[0] == "OK"

            first = group(owner, root, vendor)
            second = group(owner, vendor, agreement)
            assert partitions(owner) == {frozenset(rows)}
            undo(foreign, first, 404)
            undo(owner, first)
            assert partitions(owner) == {frozenset(("Studio terms", "Re: Studio terms", "Studio follow through")),
                                         frozenset(("Vendor sheet", "Signed agreement"))}
            assert get_tools(owner, vendor)["entries"] == []
            undo(owner, first, 404)
            undo(owner, second)
            assert len(partitions(owner)) == 3
            lasting = group(owner, root, vendor)
            assert listing(owner, collection=collection["id"], conversations="true")["total"] == 1
            assert len(get_tools(owner, vendor)["entries"]) == 2
            with closing(sqlite3.connect(directory / "smtp.db")) as sql:
                sql.execute("UPDATE mail_private_groups SET undo_until=unixepoch()-1 WHERE id=?", (lasting["undoId"],))
                sql.commit()
            undo(owner, lasting, 404)

            with test.imap(alice) as imap:
                assert imap.select("INBOX")[0] == "OK"
                status, parts = imap.uid("FETCH", str(root["uid"]), "(BODY.PEEK[])")
                assert status == "OK"
                wire = parts[0][1]
                assert b"Subject: Studio terms" in wire and CLIP.encode() in wire
                assert NOTE.encode() not in wire and LABEL.encode() not in wire and b"Studio renewal" not in wire
                assert imap.uid("MOVE", str(root["uid"]), "Archive")[0] == "OK"
            archived = listing(owner, folder="Archive", personal="true")["items"][0]
            assert archived["reference"] == root["reference"] and archived["personal_subject"] == LABEL
            assert len(get_tools(owner, archived)["entries"]) == 2
            change(owner, root, "note", body="Old revision", status=412)
            with test.imap(alice) as imap:
                assert imap.select("Archive")[0] == "OK"
                assert imap.uid("STORE", str(archived["uid"]), "+FLAGS", r"(\Deleted)")[0] == "OK"
                assert imap.expunge()[0] == "OK"
            get_tools(owner, archived, 404)
            assert len(get_tools(owner, reply)["entries"]) == 2
            assert len(get_tools(owner, vendor)["entries"]) == 2
            with test.imap(alice) as imap:
                assert imap.select("INBOX")[0] == "OK"
                assert imap.uid("STORE", str(reply["uid"]), "+FLAGS", r"(\Deleted)")[0] == "OK"
                assert imap.expunge()[0] == "OK"
            get_tools(owner, reply, 404)
            assert len(get_tools(owner, follow)["entries"]) == 2
            assert listing(owner, collection=collection["id"])["total"] == 2
            print("Verified notes, clips, labels, collection filters, scoped revisions, grouping Undo, and unchanged IMAP headers.")

        with test.daemon():
            owner = test.login(alice)
            assert get_tools(owner, follow)["label"]["value"] == LABEL
            result = get_tools(owner, vendor)
            assert {entry["body"] for entry in result["entries"]} == {CLIP, NOTE + " Updated."}
            assert result["collections"][0]["included"]
            assert listing(owner, collection=collection["id"], per_page=1, page=2)["total"] == 2
            change(owner, vendor, "collection", collection=collection["id"], included=False)
            assert listing(owner, collection=collection["id"])["total"] == 0
            change(owner, follow, "label", body="", label_revision=get_tools(owner, follow)["label"]["revision"])
            assert get_tools(owner, follow)["label"]["value"] == ""
            for entry in result["entries"]:
                change(owner, vendor, "remove", entry=entry["id"], revision=entry["revision"])
            assert get_tools(owner, follow)["entries"] == []
            call(owner, COLLECTIONS, {"action": "delete", "id": collection["id"], "revision": renamed["revision"]}, method="POST")
            call(owner, "messages?" + urlencode({"collection": collection["id"]}), status=404)
            assert listing(owner, folder="*")["total"] == 3
            print("Verified private organization survives restart, move and partial deletion, then supports clean removal.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--previous", type=Path)
    args = parser.parse_args()
    run(args.binary.resolve(), args.previous.resolve() if args.previous else None)
