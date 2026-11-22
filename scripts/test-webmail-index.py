#!/usr/bin/env python3
"""Verify indexed search and attachment downloads over native HTTPS and IMAP."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path
import runpy
import sqlite3
import tempfile
from urllib.parse import urlencode


fixtures = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture = fixtures["Fixture"]
request = fixtures["request"]
PAYLOAD = b"actual indexed attachment bytes\x00\xff\n"


def message(owner, index, *, subject=None, body=None, files=(), cc=None):
    mail = EmailMessage()
    mail["From"], mail["To"] = "Morgan Lee <morgan@example.test>", owner
    mail["Subject"] = subject or f"Research note {index:02}"
    mail["Message-ID"] = f"<index-{index}@example.test>"
    mail["Date"] = datetime(2025, 3, index + 1, 12, tzinfo=timezone.utc)
    if cc:
        mail["Cc"] = cc
    mail.set_content(body or "Studio planning.")
    for name in files:
        mail.add_attachment(PAYLOAD, maintype="application", subtype="octet-stream", filename=name)
    return mail


def run(binary, previous):
    with tempfile.TemporaryDirectory(prefix="mail-web-fts-") as tmp:
        directory = Path(tmp)
        test = Fixture(previous or binary, directory, staging=True)

        def list_api(session, path="messages", **params):
            return test.api(session, path + "?" + urlencode(params))

        def items(session, path="messages", **params):
            status, result = list_api(session, path, **params)
            assert status == 200, (path, params, status, result)
            return result

        def download(session, item, expected=200, *, version="content_revision"):
            row = item["message"]
            params = {"reference": row["reference"], version: row[version], "index": item["index"]}
            status, response, data = request(test.webmail + "/webmail/api/attachment?" + urlencode(params),
                                             headers=session, context=test.tls_context)
            assert status == expected, (status, data)
            return response, data

        with test.daemon():
            owner = test.provision("alice")
            foreign = test.provision("bob")
            with test.imap(owner) as imap:
                assert imap.create("Research")[0] == "OK"
                assert imap.create("Trash")[0] == "OK"
                for index in range(12):
                    memo = message(owner, index, body="Needle point for March analysis." if index in (2, 8) else None,
                                   files=("survey.csv", "notes.txt") if index == 2 else ("survey-old.csv",) if index == 8 else (),
                                   cc="Reviewer <reviewer@example.test>" if index in (2, 8) else None)
                    assert imap.append("INBOX", None, None, memo.as_bytes(policy=SMTP))[0] == "OK"
                custom = message(owner, 12, body='Quoted term "field notes" and an asterisk *')
                custom.set_content("<p>Quoted term &quot;field notes&quot; and an asterisk *</p>", subtype="html")
                custom.add_attachment(PAYLOAD, maintype="application", subtype="octet-stream", filename="résumé.txt")
                assert imap.append("Research", None, None, custom.as_bytes(policy=SMTP))[0] == "OK"
            with test.imap(foreign) as imap:
                secret = message(foreign, 1, subject="Bob private research", body="Needle point for March analysis.", files=("bob-private.csv",))
                assert imap.append("INBOX", None, None, secret.as_bytes(policy=SMTP))[0] == "OK"
        test.binary = binary

        with test.daemon():
            alice, bob = test.login(owner), test.login(foreign)
            first = items(alice, folder="INBOX", q="needle point", index_budget=2)
            assert first["index"] == {"total": 12, "indexed": 2, "pending": True}, first
            assert first["total"] == 0 and not first["items"]
            for count in (4, 6, 8, 10, 12):
                result = items(alice, folder="INBOX", q="needle point", index_budget=2)
                assert result["index"] == {"total": 12, "indexed": count, "pending": count != 12}, result
            assert result["total"] == 2
            # The older of two matching messages is beyond the unfiltered
            # first page. Combined filters and grouping must run first.
            before = int(datetime(2025, 3, 5, tzinfo=timezone.utc).timestamp())
            params = dict(q="Needle Point", folder="*", to="reviewer@example.test", filename="SURVEY",
                          attachments="true", before=before, per_page=1, page=1)
            filtered = items(alice, **params)
            assert filtered["total"] == 1 and filtered["items"][0]["subject"] == "Research note 02", filtered
            oldest = filtered["items"][0]
            assert items(alice, **dict(params, conversations="true"))["threads"][0]["matching"] == 1
            assert items(alice, q='"field notes"', folder="Research")["total"] == 1
            direct = items(alice, "search", q='"field notes"', folder="Research")
            assert direct["total"] == 1 and isinstance(direct["items"][0]["date"], int), direct
            unicode_file = items(alice, "attachments", folder="Research", filename="résumé")["items"][0]
            assert unicode_file["filename"] == "résumé.txt" and download(alice, unicode_file)[1] == PAYLOAD
            assert items(alice, q="* OR *", folder="*")["total"] == 0
            assert items(alice, q="Bob private", folder="*")["total"] == 0
            assert items(bob, q="Needle Point", folder="*")["total"] == 1
            assert items(alice, q="Needle Point", folder="Research")["total"] == 0

            first_files = items(alice, "attachments", folder="INBOX", filename="survey", per_page=1)
            second_files = items(alice, "attachments", folder="INBOX", filename="survey", per_page=1, page=2)
            assert first_files["total"] == second_files["total"] == 2
            target = second_files["items"][0]
            assert target["filename"] == "survey.csv" and target["size"] == len(PAYLOAD), target
            assert target["message"]["reference"] == oldest["reference"]
            assert first_files["items"][0]["filename"] == "survey-old.csv"
            assert items(alice, "attachments", folder="*", filename="bob-private")["total"] == 0
            other = items(bob, "attachments", folder="*", filename="bob-private")["items"][0]
            assert download(bob, other)[1] == PAYLOAD
            assert test.api(alice, "messages/ref/" + other["message"]["reference"])[0] == 404
            assert test.api(bob, "messages/ref/" + oldest["reference"])[0] == 404
            download(bob, target, 404)
            download(alice, other, 404)
            assert download(alice, target)[1] == PAYLOAD
            assert download(alice, target, version="revision")[1] == PAYLOAD

            with test.imap(owner) as imap:
                assert imap.select("INBOX")[0] == "OK"
                assert imap.uid("STORE", str(oldest["uid"]), "+FLAGS", r"(\Flagged \Seen)")[0] == "OK"
            assert items(alice, **dict(params, unread="true"))["total"] == 0
            updated = items(alice, **dict(params, flagged="true"))["items"][0]
            assert items(alice, **dict(params, status="read"))["items"][0]["reference"] == oldest["reference"]
            assert items(alice, **dict(params, status="answered"))["total"] == 0
            assert updated["reference"] == oldest["reference"] and updated["revision"] != oldest["revision"]
            detail = "messages/ref/" + oldest["reference"]
            assert test.api(dict(alice, **{"If-Match": oldest["revision"]}), detail)[0] == 412
            assert test.api(dict(alice, **{"If-Match": updated["revision"]}), detail)[0] == 200
            assert updated["content_revision"] == oldest["content_revision"]
            assert download(alice, target)[1] == PAYLOAD
            download(alice, target, 412, version="revision")

            with test.imap(owner) as imap:
                assert imap.select("INBOX")[0] == "OK"
                assert imap.uid("MOVE", str(oldest["uid"]), "Research")[0] == "OK"
            assert items(alice, "attachments", folder="INBOX", filename="survey.csv")["total"] == 0
            moved = items(alice, "attachments", folder="Research", filename="survey.csv")["items"][0]
            assert moved["message"]["reference"] == oldest["reference"]
            assert download(alice, moved)[1] == PAYLOAD
            assert download(alice, target)[1] == PAYLOAD
            download(alice, target, 412, version="revision")
            print("Verified bounded index progress, query and attachment filters, pagination, cross-account ACLs, IMAP flags and moves.")

        with test.daemon():
            alice = test.login(owner)
            ready = items(alice, "attachments", folder="Research", index_budget=1)
            assert ready["index"] == {"indexed": 2, "total": 2, "pending": False}, ready
            doc_path = next(path for path in (directory / "mail" / owner / "Research").iterdir()
                            if b"<index-2@example.test>" in path.read_bytes())
            replacement = message(owner, 2, subject="Updated local file", body="Revised spreadsheet",
                                  files=("replacement.txt",))
            doc_path.write_bytes(replacement.as_bytes(policy=SMTP))
            assert items(alice, "attachments", folder="Research", filename="survey.csv")["total"] == 0
            fresh = items(alice, "attachments", folder="Research", filename="replacement.txt")["items"][0]
            assert fresh["message"]["reference"] == moved["message"]["reference"]
            assert fresh["message"]["content_revision"] != moved["message"]["content_revision"]
            assert download(alice, fresh)[1] == PAYLOAD
            download(alice, moved, 412)
            doc_path.unlink()
            assert items(alice, "attachments", folder="Research", filename="replacement.txt")["total"] == 0
            download(alice, fresh, 404)
            with closing(sqlite3.connect(directory / "smtp.db")) as sql:
                assert sql.execute(
                    "SELECT count(*) FROM webmail_search_docs d JOIN users u ON u.id=d.user_id "
                    "WHERE u.username=? AND d.message_id=?", (owner, "<index-2@example.test>"),
                ).fetchone() == (0,)
            with test.imap(owner) as imap:
                assert imap.select("Research")[0] == "OK"
                assert imap.store("1:*", "+FLAGS", r"(\Deleted)")[0] == "OK"
                assert imap.expunge()[0] == "OK"
                assert imap.select("INBOX")[0] == "OK"
                assert imap.delete("Research")[0] == "OK"
            assert items(alice, "attachments", folder="*", filename="résumé")["total"] == 0
            with closing(sqlite3.connect(directory / "smtp.db")) as sql:
                assert sql.execute("SELECT count(*) FROM webmail_search_docs WHERE folder='Research'").fetchone() == (0,)
            last_download = first_files["items"][0]
            assert download(alice, last_download)[1] == PAYLOAD
            test.provision("alice", enabled=False)
            download(alice, last_download, 401)
            print("Verified index persistence, in-place Maildir changes, pruning, and revocation of stale downloads.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--previous", type=Path)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.previous.resolve() if arguments.previous else None)
