#!/usr/bin/env python3
"""Exercise EWS attachment discovery, retrieval, and draft edits over HTTPS."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
from pathlib import Path
import runpy
import secrets
import sqlite3
import subprocess
import tempfile
from types import SimpleNamespace
from urllib.parse import urlencode
from xml.sax.saxutils import quoteattr


HERE = Path(__file__).resolve().parent
ews = SimpleNamespace(**runpy.run_path(str(HERE / "test-ews-clamav.py")))
INVALID = "ErrorInvalidAttachmentId"
CONFLICT = "ErrorIrresolvableConflict"


def operation(name, *ids, change_key=None):
    root = f" RootItemChangeKey={quoteattr(change_key)}" if change_key else ""
    elements = "".join(f"<t:AttachmentId Id={quoteattr(attachment)}{root}/>" for attachment in ids)
    return f"<m:{name}><m:AttachmentIds>{elements}</m:AttachmentIds></m:{name}>"


def list_files(test, owner, item):
    request = f'<m:GetItem><m:ItemIds><t:ItemId Id={quoteattr(item["Id"])}/></m:ItemIds></m:GetItem>'
    tree = ews.check(test, owner, request, "NoError")
    files = [(entry.findtext("{*}Name"), entry.find("{*}AttachmentId").attrib["Id"])
             for entry in tree.findall(".//{*}FileAttachment")]
    raw = base64.b64decode(tree.findtext(".//{*}MimeContent"), validate=True)
    return ews.item_id(tree), files, raw


def retrieve(test, owner, attachment, expected, *, inline=False, content_id=None):
    tree = ews.check(test, owner, operation("GetAttachment", attachment), "NoError")
    part = tree.find(".//{*}FileAttachment")
    assert part.find("{*}AttachmentId").attrib["Id"] == attachment
    assert part.findtext("{*}IsInline") == ("true" if inline else "false")
    assert part.findtext("{*}ContentId") == content_id
    assert int(part.findtext("{*}Size")) == len(expected)
    assert base64.b64decode(part.findtext("{*}Content"), validate=True) == expected


def verify_draft(test, owner, other):
    first_data = bytes(range(256))
    second_data = b"keep the other attachment\x00\xff"
    first_file = ews.file_xml(first_data, "first & clean.bin")
    second_file = ews.file_xml(second_data, "second.bin")
    first_item = ews.item_id(ews.check(test, owner, ews.create("SaveOnly", ews.message(other, first_file)), "NoError"))
    item, ((filename, first),), _ = list_files(test, owner, first_item)
    assert item == first_item and filename == "first & clean.bin"
    created = ews.check(test, owner, ews.attach(item, second_file), "NoError").find(".//{*}AttachmentId").attrib
    item, files, raw = list_files(test, owner, item)
    second = created["Id"]
    assert files == [(filename, first), ("second.bin", second)]
    assert item["ChangeKey"] == created["RootItemChangeKey"]
    retrieve(test, owner, first, first_data)
    retrieve(test, owner, second, second_data)
    ews.check(test, other, operation("GetAttachment", first), INVALID)
    ews.check(test, other, operation("DeleteAttachment", first), INVALID)
    other_scope = ews.item_id(ews.check(test, other, ews.create("SaveOnly", ews.message(owner, first_file)), "NoError"))
    other_id = list_files(test, other, other_scope)[1][0][1]
    forged = other_id.split(":", 1)[0] + ":" + first.split(":", 1)[1]
    ews.check(test, other, operation("GetAttachment", forged), INVALID)
    ews.check(test, owner, operation("GetAttachment", "unknown", first), INVALID, "NoError")
    ews.check(test, owner, operation("DeleteAttachment", first, change_key=first_item["ChangeKey"]), CONFLICT)
    assert list_files(test, owner, item) == (item, files, raw)

    used = test.bytes(owner)
    deletion = ews.check(test, owner, operation("DeleteAttachment", "unknown", first, change_key=item["ChangeKey"]),
                         INVALID, "NoError").find(".//{*}RootItemId").attrib
    current, remaining, updated = list_files(test, owner, item)
    assert deletion == {"RootItemId": item["Id"], "RootItemChangeKey": current["ChangeKey"]}
    assert current["ChangeKey"] != item["ChangeKey"]
    assert remaining == [("second.bin", second)]
    assert used - test.bytes(owner) == len(raw) - len(updated) > 0
    ews.check(test, owner, operation("GetAttachment", first), INVALID)
    retrieve(test, owner, second, second_data)
    mime, parts = ews.attachments_of(updated)
    assert mime.get_body().get_content().strip() == "Original EWS body"
    assert parts == [("second.bin", second_data)]

    def remove():
        return ews.hosted.ews_codes(test.ews(owner, operation("DeleteAttachment", second, change_key=current["ChangeKey"])))[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in (pool.submit(remove), pool.submit(remove))]
    assert results.count("NoError") == 1 and set(results).issubset({"NoError", CONFLICT, INVALID}), results
    assert list_files(test, owner, current)[1] == []


def verify_legacy_mime(test, owner, other):
    twin = (b"Content-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename*=UTF-8''same%20file.bin\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n\r\nA=00B=FF")
    raw = (f"From: {owner}\r\nTo: {other}\r\nSubject: Existing MIME\r\n"
           "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n").encode()
    raw += (b"preamble\r\n--outer\r\nContent-Type: text/plain\r\n\r\nOriginal raw body\r\n"
            b"--outer\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n--inner\r\n"
            + twin + b"\r\n--inner\r\n" + twin + b"\r\n--inner--\r\n\r\n--outer--\r\nepilogue")
    item = ews.item_id(ews.check(test, owner, ews.create("SaveOnly", ews.mime_message(raw)), "NoError"))
    _, files, _ = list_files(test, owner, item)
    assert [name for name, _ in files] == ["same file.bin", "same file.bin"]
    first, second = [attachment for _, attachment in files]
    assert first != second
    retrieve(test, owner, second, b"A\x00B\xff")
    ews.check(test, owner, operation("DeleteAttachment", first), "NoError")
    _, remaining, updated = list_files(test, owner, item)
    assert remaining == [("same file.bin", second)]
    assert b"Original raw body\r\n" in updated and updated.endswith(b"--outer--\r\nepilogue")
    retrieve(test, owner, second, b"A\x00B\xff")
    ews.check(test, owner, operation("DeleteAttachment", second), "NoError")
    assert list_files(test, owner, item)[1] == []

    # A single-part 8-bit attachment may contain bytes illegal in SOAP text.
    single = (f"From: {owner}\r\nTo: {other}\r\nSubject: Single file\r\n"
              "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: 8bit\r\n"
              "Content-Disposition: attachment; filename=root.bin\r\n\r\n").encode()
    data = b"\x00\xff\x80\xef\xbf\xbf\r\n"
    item = ews.item_id(ews.check(test, owner, ews.create("SaveOnly", ews.mime_message(single + data)), "NoError"))
    _, ((name, root),), _ = list_files(test, owner, item)
    assert name == "root.bin"
    retrieve(test, owner, root, data)
    ews.check(test, owner, operation("DeleteAttachment", root), "NoError")
    _, files, raw = list_files(test, owner, item)
    assert files == [] and b"Subject: Single file\r\n" in raw


def verify_shared_draft(test, owner, other):
    session = test.login(owner)
    upload_id = secrets.token_hex(16)
    first_data = b"webmail file\x00\xff"
    second_data = b"EWS inline file\xff\x00"
    request = urlencode({"uploadId": upload_id, "filename": "webmail.bin", "contentType": "application/octet-stream"})
    status, _, raw = ews.hosted.request(test.webmail + "/webmail/api/uploads?" + request, first_data, session, context=test.tls_context)
    assert status == 200, raw
    folder = test.directory / "mail" / owner / "Drafts"
    files_before = set(folder.glob("*.eml*"))
    payload = {"draftId": secrets.token_hex(16), "saveToken": secrets.token_hex(16), "to": [other],
               "subject": "Shared draft and frozen Outbox", "text": "Original webmail body",
               "recipientInputs": {"cc": "still typing"}, "attachments": [{"uploadId": upload_id}]}
    status, saved = test.api(session, "drafts", payload)
    assert status == 200, saved
    draft, = set(folder.glob("*.eml*")) - files_before
    lookup = f"drafts?uid={saved['uid']}"

    def load():
        status, row = test.api(session, lookup)
        assert status == 200, row
        return row

    def attachment_bytes(index):
        passing = f"/webmail/api/attachment?folder=Drafts&uid={saved['uid']}&index={index}"
        status, _, content = ews.hosted.request(test.webmail + passing, headers=session, context=test.tls_context)
        assert status == 200, content
        return content

    item, ((_, first),), original_wire = list_files(test, owner, {"Id": "drafts:" + draft.name.split(":2,", 1)[0]})
    second_file = ews.file_xml(second_data, "inline.bin").replace(
        "<t:Content>", "<t:IsInline>true</t:IsInline><t:ContentId>inline@example.test</t:ContentId><t:Content>",
    )
    original_quota = test.specs[owner]["quota_bytes"]
    test.provision(owner.split("@")[0], quota=test.bytes(owner))
    ews.check(test, owner, ews.attach(item, second_file), "ErrorQuotaExceeded")
    assert draft.read_bytes() == original_wire and load()["revision"] == saved["revision"]
    test.provision(owner.split("@")[0], quota=original_quota)

    second = ews.check(test, owner, ews.attach(item, second_file), "NoError").find(".//{*}AttachmentId").attrib["Id"]
    edited = load()
    assert edited["revision"] == saved["revision"] + 1
    assert edited["message"]["recipientInputs"]["cc"] == "still typing"
    assert edited["message"]["text"] == "Original webmail body"
    assert edited["message"]["attachments"][1]["filename"] == "inline.bin"
    assert [attachment_bytes(index) for index in range(2)] == [first_data, second_data]
    retrieve(test, owner, second, second_data, inline=True, content_id="inline@example.test")
    status, conflict = test.api(session, "drafts", {**payload, "draftRevision": saved["revision"]})
    assert status == 409, conflict

    latest_payload = {**edited["message"], "draftRevision": edited["revision"], "saveToken": secrets.token_hex(16),
                      "recipientInputs": {"cc": ""}, "text": "Webmail edit after EWS"}
    status, saved_again = test.api(session, "drafts", latest_payload)
    assert status == 200, saved_again
    current, listed, queued_wire = list_files(test, owner, item)
    assert listed == [("webmail.bin", first), ("inline.bin", second)]
    retrieve(test, owner, second, second_data, inline=True, content_id="inline@example.test")

    send_id = secrets.token_hex(16)
    send = {**latest_payload, "draftRevision": saved_again["revision"], "sendId": send_id, "delaySeconds": 30}
    status, frozen = test.api(session, "compose", send)
    assert status == 200 and frozen["state"] == "pending", frozen
    ews.check(test, owner, operation("DeleteAttachment", first), CONFLICT)
    ews.check(test, owner, ews.attach(current, second_file), CONFLICT)
    assert draft.read_bytes() == queued_wire
    status, latest = test.api(session, f"outbox/{send_id}")
    assert status == 200 and latest["message"] == frozen["message"]
    status, cancelled = test.api(session, f"outbox/{send_id}", method="DELETE")
    assert status == 200 and cancelled["state"] == "cancelled", cancelled

    before = load()
    ews.check(test, owner, operation("DeleteAttachment", first), "NoError")
    final = load()
    assert final["revision"] == before["revision"] + 1
    assert attachment_bytes(0) == second_data
    assert len(final["message"]["attachments"]) == 1
    assert list_files(test, owner, item)[1] == [("inline.bin", second)]
    new_send = secrets.token_hex(16)
    send = {**final["message"], "draftRevision": final["revision"], "sendId": new_send, "delaySeconds": 0}
    sent_before = test.count(owner)
    status, queued = test.api(session, "compose", send)
    assert status == 200, queued
    test.outbox(session, new_send, "sent")
    assert test.count(owner) == sent_before + 1
    delivered = [ews.attachments_of(raw.read_bytes()) for raw in (test.directory / "mail" / other / "new").glob("*.eml*")]
    mime, attachments = next(pair for pair in delivered if pair[0]["Subject"] == send["subject"])
    assert mime.get_body().get_content().strip() == "Webmail edit after EWS"
    inline, = mime.iter_attachments()
    assert inline["Content-ID"] == "<inline@example.test>"
    assert attachments == [("inline.bin", second_data)]


def prepare_recovery(test, owner, other):
    """Capture real before/after records to replay both sides of the rename."""
    session = test.login(owner)
    draft_id = secrets.token_hex(16)
    status, saved = test.api(session, "drafts", {"draftId": draft_id, "to": [other], "subject": "Interrupted EWS edit"})
    assert status == 200, saved

    def record():
        with closing(sqlite3.connect(test.directory / "smtp.db")) as db:
            return db.execute("SELECT payload,revision FROM webmail_records WHERE kind='draft' AND id=?", (draft_id,)).fetchone()

    with closing(sqlite3.connect(test.directory / "smtp.db")) as db:
        filename, = db.execute("SELECT filename FROM imap_uids WHERE username=? AND mailbox='Drafts' AND uid=?",
                               (owner, saved["uid"])).fetchone()
    path, = (test.directory / "mail" / owner / "Drafts").glob(filename.split(":2,", 1)[0] + "*")
    item, _, old_raw = list_files(test, owner, {"Id": "drafts:" + path.name.split(":2,", 1)[0]})
    before = record()
    ews.check(test, owner, ews.attach(item, ews.file_xml(b"Recovered attachment", "recovery.bin")), "NoError")
    return path, draft_id, saved["uid"], before, record(), old_raw, path.read_bytes()


def verify_recovery(test, owner, recovery):
    path, draft_id, uid, before, after, old_raw, new_raw = recovery
    for renamed in (False, True):
        path.write_bytes(new_raw if renamed else old_raw)
        with closing(sqlite3.connect(test.directory / "smtp.db")) as db, db:
            db.execute("UPDATE webmail_records SET payload=?,revision=? WHERE kind='draft' AND id=?", (*before, draft_id))
            db.execute("INSERT INTO webmail_records(username,kind,id,payload,state,revision,due_at) VALUES(?,?,?,?,?,?,?)",
                       (owner, "draft-edit", draft_id, after[0], hashlib.sha256(new_raw).hexdigest(), 1, before[1]))
        with test.daemon():
            status, saved = test.api(test.login(owner), f"drafts?uid={uid}")
            assert status == 200 and saved["revision"] == (after if renamed else before)[1], saved
            assert len(saved["message"]["attachments"]) == int(renamed)
            assert path.read_bytes() == (new_raw if renamed else old_raw)
            with closing(sqlite3.connect(test.directory / "smtp.db")) as db:
                assert db.execute("SELECT 1 FROM webmail_records WHERE kind='draft-edit' AND id=?", (draft_id,)).fetchone() is None


def verify_self_hosted_draft(test):
    owner = "ews-self-hosted@example.test"
    subprocess.run([str(test.binary), "user:local", "create", owner, test.password, owner],
                   cwd=test.directory, env=test.env, check=True, stdout=subprocess.DEVNULL)
    session = test.login(owner)
    status, saved = test.api(session, "drafts", {"draftId": secrets.token_hex(16), "subject": "Self-hosted draft"})
    assert status == 200, saved
    path, = (test.directory / "mail" / owner / "Drafts").glob("*.eml*")
    item, _, _ = list_files(test, owner, {"Id": "drafts:" + path.name.split(":2,", 1)[0]})
    content = b"Self-hosted attachment"
    added = ews.check(test, owner, ews.attach(item, ews.file_xml(content)), "NoError").find(".//{*}AttachmentId").attrib
    retrieve(test, owner, added["Id"], content)
    status, loaded = test.api(session, f"drafts?uid={saved['uid']}")
    assert status == 200 and loaded["revision"] == saved["revision"] + 1, loaded
    assert loaded["message"]["attachments"][0]["size"] == len(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-ews-files-", dir="/tmp") as directory:
        test = ews.hosted.Fixture(args.binary.resolve(strict=True), Path(directory), staging=True)
        with test.daemon():
            owner = test.provision("ews-files-owner")
            other = test.provision("ews-files-other")
            verify_draft(test, owner, other)
            verify_legacy_mime(test, owner, other)
            verify_shared_draft(test, owner, other)
            verify_self_hosted_draft(test)
            recovery = prepare_recovery(test, owner, other)
        verify_recovery(test, owner, recovery)
    print("Verified EWS attachment IDs, byte retrieval, deletion, concurrency, hosted storage, webmail revisions, Outbox, and interrupted-edit recovery over HTTPS.")


if __name__ == "__main__":
    main()
