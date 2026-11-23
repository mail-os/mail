#!/usr/bin/env python3
"""Exercise identity-bound conversation shares on native HTTPS."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
import os
from pathlib import Path
import runpy
import secrets
import sys
import tempfile
import time
from xml.sax.saxutils import escape, quoteattr


SCRIPTS = Path(__file__).resolve().parent
teams = runpy.run_path(str(SCRIPTS / "test-webmail-teams.py"))
Fixture, command, expect = teams["Fixture"], teams["command"], teams["expect"]
hosted = runpy.run_path(str(SCRIPTS / "test-hosted-limits.py"))
request = hosted["request"]
SHARES = "thread-shares"
FILE = b"An explicitly shared file.\x00\xff"


def append(imap, mailbox, subject, body, *, attachment=False, folder="INBOX"):
    msg = EmailMessage()
    msg["From"], msg["To"] = "Sender <sender@example.test>", mailbox
    msg["Bcc"] = "hidden-recipient@example.test"
    msg["Subject"] = subject
    msg.set_content(body)
    if attachment:
        msg.add_attachment(FILE, maintype="application", subtype="octet-stream", filename="design.bin")
        hidden = EmailMessage()
        hidden["Bcc"] = "nested-hidden@example.test"
        hidden.set_content("A nested message stays private.")
        msg.add_attachment(hidden, filename="nested.eml")
    assert imap.append(folder, None, None, msg.as_bytes())[0] == "OK"


def send(fixture, mailbox, author, key, *, verified=True, parent=None, references=None, automatic=False, attachment=False):
    msg = EmailMessage()
    msg["From"], msg["To"] = author, mailbox
    msg["Subject"] = f"Follow fixture {key}"
    msg["Message-ID"] = f"<{key}@threads.example.test>"
    if parent:
        msg["In-Reply-To"] = f"<{parent}@threads.example.test>"
    if references:
        msg["References"] = " ".join(f"<{ref}@threads.example.test>" for ref in references)
    if automatic:
        msg["Auto-Submitted"] = "auto-replied"
    msg.set_content(f"Reply content for {key}.")
    if attachment:
        msg.add_attachment(FILE, maintype="application", subtype="octet-stream", filename="future.bin")
    identity = author if verified else None
    with fixture.smtp(identity) as connection:
        assert connection.send_message(msg, from_addr=identity or "unverified@example.test", to_addrs=[mailbox]) == {}


def verify_collection(fixture, call, download, owner, peer, witness, outsider, own, other, third, foreign, rows, root):
    collections = "private/collections"
    collection, = call(own, collections, {"action": "create", "name": "Design collection"}, "POST")["items"]
    collection_id = collection["id"]
    settings = {"collectionId": collection_id, "downloads": True}

    def change(row, included, *, confirm=False, status=200):
        return call({**own, "If-Match": row["revision"]}, "private/message", {
            "reference": row["reference"], "action": "collection", "collection": collection_id,
            "included": included, "shareCollectionMessage": confirm,
        }, "POST", status)

    def preview(session=own, **changes):
        return call(session, SHARES + "/preview", {**settings, **changes}, "POST")

    def issue(review, **changes):
        return {**settings, "digest": review["digest"], "team": "studio", "grantee": peer, **changes}

    first = call(own, "messages/ref/" + rows["Design review"]["reference"])
    change(first, True)
    change(root, True)
    send(fixture, owner, witness, "collection-unapproved", parent="root", verified=False)
    private = call(own, "messages?collection=" + collection_id)
    assert "Follow fixture collection-unapproved" in {msg["subject"] for msg in private["items"]}
    review = preview()
    assert {msg["subject"] for msg in review["messages"]} == {"Follow fixture root", "Design review"}
    assert review["collection"]["name"] == collection["name"]
    call(other, SHARES + "/preview", settings, "POST", 404)
    call(own, SHARES + "/preview", {**settings, "followReplies": True}, "POST", 400)
    call(own, SHARES, issue(review, grantee=outsider), "POST", 409)
    call(own, SHARES, issue(review, downloads=False), "POST", 409)
    renamed, = call(own, collections, {
        "action": "rename", "id": collection_id, "revision": collection["revision"], "name": "Studio notes",
    }, "POST")["items"]
    call(own, SHARES, issue(review), "POST", 409)
    review = preview()
    grant = call(own, SHARES, issue(review), "POST", 201)
    path = f"{SHARES}/{grant['id']}"
    attachment = f"{path}/attachments/{first['reference']}/0"
    assert grant["collectionId"] == collection_id and grant["subject"] == "Studio notes"
    assert call(own, SHARES, issue(review), "POST", 409)["error"] == "collection_already_shared"
    assert call(other, SHARES)["grants"] == [grant]
    for denied in (third, foreign):
        call(denied, path + "?q=cobalt", status=404)
        call(denied, path + "/comments", {"text": "Private"}, "POST", 404)
        download(denied, attachment, 404)
    detail = call(other, path)
    assert len(detail["messages"]) == 2
    assert all(value not in str(detail) for value in ("hidden-recipient", "owner-only", "nested.eml", "collection-unapproved"))
    assert call(other, path + "?q=COBALT")["messages"][0]["reference"] == first["reference"]
    assert call(other, path + "?q=owner-only")["messages"] == []
    assert download(other, attachment) == FILE
    call(other, path + "/comments", {"text": "Published review"}, "POST", 201)
    assert call(own, path)["comments"][0]["author"] == peer

    later, = call(own, "messages?conversations=false&q=collection-unapproved")["items"]
    change(later, True, status=409)
    assert call(other, path + "?q=collection-unapproved")["messages"] == []
    member = change(later, True, confirm=True)["collections"][0]
    assert member["explicit"] and member["shared"]
    change(root, False, confirm=True)
    live = call(other, path)["messages"]
    assert {msg["subject"] for msg in live} == {later["subject"], first["subject"]}
    change(first, False, confirm=True)
    download(other, attachment, 404)
    change(first, True, confirm=True)

    with fixture.imap(owner) as imap:
        for index in range(21):
            append(imap, owner, f"Collection page item {index:02d}", "Owner-curated addition.")
    added = call(own, "messages?conversations=false&per_page=60&q=Collection+page+item")["items"]
    for item in added:
        change(item, True, confirm=True)
    first_page = call(other, path)
    assert len(first_page["messages"]) == 20 and first_page["next"]
    last_page = call(other, path + f"?before={first_page['next']}")
    assert last_page["next"] is None
    references = {msg["reference"] for msg in first_page["messages"] + last_page["messages"]}
    assert references == {first["reference"], later["reference"], *(item["reference"] for item in added)}
    call(other, path + "?before=bad", status=400)

    renamed_again, = call(own, collections, {
        "action": "rename", "id": collection_id, "revision": renamed["revision"], "name": "Studio handoff",
    }, "POST")["items"]
    assert call(other, path)["grant"]["subject"] == "Studio handoff"
    call(other, path, method="DELETE", status=404)
    command(fixture, "team", "member", "studio", peer, "remove")
    call(other, path, status=401)
    other = fixture.login(peer)
    call(other, path, status=404)
    command(fixture, "team", "member", "studio", peer, "member")
    call(other, path, status=404)
    renewed = call(own, SHARES, issue(preview()), "POST", 201)
    renewed_path = f"{SHARES}/{renewed['id']}"
    assert call(other, renewed_path)["comments"] == []
    call(own, collections, {"action": "delete", "id": collection_id, "revision": renamed_again["revision"]}, "POST")
    assert call(other, SHARES) == {"grants": []}
    call(other, renewed_path, status=404)
    download(other, f"{renewed_path}/attachments/{first['reference']}/0", 404)


def verify_sent_replies(fixture, call, download, claim, owner, peer, witness, outsider, own, other, third, foreign, root):
    parent = "<root@threads.example.test>"
    selection = {"references": [root["reference"]], "downloads": True, "followReplies": True}
    sent_selection = {**selection, "followSentReplies": True}
    reviewed = call(own, SHARES + "/preview", selection, "POST")
    sent_reviewed = call(own, SHARES + "/preview", sent_selection, "POST")
    assert sent_reviewed["followingSentReplies"] and sent_reviewed["digest"] != reviewed["digest"]
    call(own, SHARES + "/preview", {**sent_selection, "followReplies": False}, "POST", 400)
    audience = {"team": "studio", "grantee": peer}
    call(own, SHARES, {**sent_selection, **audience, "digest": reviewed["digest"]}, "POST", 409)

    def share(selected, preview, grantee=peer):
        grant = call(own, SHARES, {**selected, **audience, "grantee": grantee, "digest": preview["digest"]}, "POST", 201)
        return f"{SHARES}/{grant['id']}"

    incoming_only = share(selection, reviewed)
    outgoing = share(sent_selection, sent_reviewed)
    direct_recipient_share = share(sent_selection, sent_reviewed, witness)

    def compose(subject, **changes):
        return call(own, "compose", {
            "to": [witness], "subject": subject, "text": subject + " preview text", "inReplyTo": parent,
            "replyContext": {key: root[key] for key in ("uid", "folder", "reference")}, **changes,
        }, "POST")

    def published(path, subject):
        return call(other, path + "?q=" + subject.replace(" ", "+"))["messages"]

    scheduled = secrets.token_hex(16)
    compose("Future outgoing hold", sendId=scheduled, scheduleAt=int(time.time()) + 600)
    assert published(outgoing, "Future outgoing hold") == []
    call(own, "drafts", {"subject": "Unsent reply draft", "text": "Private draft text", "to": [witness], "inReplyTo": parent}, "POST")
    assert published(outgoing, "Unsent reply draft") == []
    with fixture.imap(owner) as imap:
        imap.create("Sent")
        imported = EmailMessage()
        imported["From"], imported["To"] = owner, witness
        imported["Subject"], imported["In-Reply-To"] = "Imported Sent reply", parent
        imported["Message-ID"] = "<imported-reply@example.test>"
        imported.set_content("This mail only exists in an imported Sent copy.")
        assert imap.append("Sent", None, None, imported.as_bytes())[0] == "OK"
        imported.replace_header("Subject", "Unshared duplicate wire ID")
        imported.replace_header("Message-ID", parent)
        assert imap.append("INBOX", None, None, imported.as_bytes())[0] == "OK"
    assert published(outgoing, "Imported Sent reply") == []
    collision, = call(own, "messages?conversations=false&q=Unshared+duplicate+wire+ID")["items"]

    for subject, changes in (
        ("Unapproved CC reply", {"cc": [outsider]}),
        ("Blind copy reply", {"bcc": [witness]}),
        ("Wrong parent reply", {"inReplyTo": "<unrelated@example.test>", "references": parent}),
        ("Header-only reply", {"replyContext": None}),
        ("Duplicate wire ID reply", {"replyContext": {key: collision[key] for key in ("uid", "folder", "reference")}}),
    ):
        assert compose(subject, **changes)["sent_saved"]
        assert published(outgoing, subject) == []
    assert claim(other) == 0

    direct = compose("Approved outgoing reply")
    assert direct["ok"] and direct["sent_saved"]
    automatic, = published(outgoing, "Approved outgoing reply")
    assert automatic["sentReply"] and not automatic["verifiedReply"] and automatic["attachments"] == []
    assert published(incoming_only, "Approved outgoing reply") == []
    assert call(other, outgoing)["grant"]["followingSentReplies"]
    call(foreign, outgoing + "?q=Approved", status=404)
    download(other, f"{outgoing}/attachments/{automatic['reference']}/0", 404)
    assert claim(other) == 1 and claim(other) == 0
    assert claim(third) == 0
    assert any(message["sentReply"] for message in call(third, direct_recipient_share)["messages"])

    # The follow-up uses the original filed Message-ID, including the host.
    continuation = EmailMessage()
    continuation["From"], continuation["To"] = witness, owner
    continuation["Subject"] = "Verified continuation to owner reply"
    continuation["Message-ID"] = "<reply-to-owner-sent@threads.example.test>"
    continuation["In-Reply-To"] = direct["message_id"]
    continuation.set_content("Continuation to a shared owner reply.")
    with fixture.smtp(witness) as connection:
        assert connection.send_message(continuation) == {}
    continuation_row, = published(outgoing, "Verified continuation")
    assert continuation_row["verifiedReply"] and published(incoming_only, "Verified continuation") == []
    assert claim(other) == 1
    call(own, incoming_only, method="DELETE")

    queued_id = secrets.token_hex(16)
    compose("Outbox sent reply", sendId=queued_id, delaySeconds=0)
    assert fixture.outbox(own, queued_id, "sent")["result"]["sent_saved"]
    assert published(outgoing, "Outbox sent reply")[0]["sentReply"]
    for start in range(0, 37, 10):
        with fixture.smtp(witness) as connection:
            for index in range(start, min(start + 10, 37)):
                extra = EmailMessage()
                extra["From"], extra["To"] = witness, owner
                extra["Subject"], extra["In-Reply-To"] = f"Reply limit fixture {index}", parent
                extra["Message-ID"] = f"<reply-limit-{index}@threads.example.test>"
                extra.set_content("A verified incoming reply.")
                assert connection.send_message(extra) == {}
    at_limit = call(other, outgoing)
    assert len(at_limit["messages"]) == 41 and at_limit["grant"]["replyLimitReached"]
    assert compose("Sent past the reply limit")["sent_saved"]
    assert published(outgoing, "Sent past the reply limit") == []
    call(own, outgoing, method="DELETE")
    assert claim(other) == 0
    assert compose("Reply after revoke")["sent_saved"]
    call(other, outgoing + "?q=Reply", status=404)
    call(own, direct_recipient_share, method="DELETE")


def smart_reply_parent(fixture, owner, teammate, author):
    own, peer = (fixture.login(address) for address in (owner, teammate))
    command(fixture, "team", "create", "native", "Native", owner)
    command(fixture, "team", "member", "native", teammate, "member")
    expect(fixture.api(own, "sender-review", {"setting": "disable"}, "PUT"))
    expect(fixture.api(peer, "notifications", {"enabled": True}, "PUT"))
    send(fixture, owner, author, "native-parent")
    root, = expect(fixture.api(own, "messages?conversations=false&q=native-parent"))["items"]
    return own, peer, root


def share_smart_reply(fixture, own, teammate, root, follow_sent):
    selection = {"references": [root["reference"]], "downloads": True, "followReplies": True, "followSentReplies": follow_sent}
    preview = expect(fixture.api(own, SHARES + "/preview", selection))
    grant = expect(fixture.api(own, SHARES, {**selection, "team": "native", "grantee": teammate, "digest": preview["digest"]}), 201)
    return f"{SHARES}/{grant['id']}"


def verify_ews_reply(fixture):
    ews = runpy.run_path(str(SCRIPTS / "test-ews-clamav.py"))
    with ExitStack() as servers:
        servers.enter_context(fixture.daemon())
        owner, teammate, author, outsider = (
            fixture.provision(name) for name in ("ews-owner", "ews-peer", "ews-author", "ews-outsider"))
        own, peer, root = smart_reply_parent(fixture, owner, teammate, author)
        sync = ('<m:SyncFolderItems><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>'
                '<m:SyncFolderId><t:DistinguishedFolderId Id="inbox"/></m:SyncFolderId>'
                '<m:MaxChangesReturned>10</m:MaxChangesReturned></m:SyncFolderItems>')
        source = ews["item_id"](ews["check"](fixture, owner, sync, "NoError"))
        source, _ = ews["get_mime"](fixture, owner, source)

        def create(kind, disposition, note, *codes, identity=owner, original=source, cc=(), bcc=(), subject=None):
            fields = "".join(
                f"<t:{field}Recipients>" + "".join(
                    f"<t:Mailbox><t:EmailAddress>{escape(address)}</t:EmailAddress></t:Mailbox>" for address in recipients
                ) + f"</t:{field}Recipients>" for field, recipients in (("Cc", cc), ("Bcc", bcc)) if recipients
            )
            if subject is not None:
                fields = f"<t:Subject>{escape(subject)}</t:Subject>" + fields
            item = (f"<t:{kind}>{fields}<t:ReferenceItemId Id={quoteattr(original['Id'])} "
                    f"ChangeKey={quoteattr(original['ChangeKey'])}/>"
                    f"<t:NewBodyContent BodyType='HTML'>&lt;p&gt;{escape(note)}&lt;/p&gt;</t:NewBodyContent></t:{kind}>")
            return ews["check"](fixture, identity, ews["create"](disposition, item), *(codes or ("NoError",)))

        def send_draft(item, code="NoError"):
            request = (f"<m:SendItem SaveItemToFolder='true'><m:ItemIds>"
                       f"<t:ItemId ChangeKey={quoteattr(item['ChangeKey'])} Id={quoteattr(item['Id'])}/>"
                       "</m:ItemIds></m:SendItem>")
            ews["check"](fixture, owner, request, code)

        # The draft starts before the grant. Its server-owned source survives
        # the normal attachment edit and a later grant against the same parent.
        draft = ews["item_id"](create("ReplyToItem", "SaveOnly", "Saved EWS reply", subject="Draft with EWS file"))
        outgoing = share_smart_reply(fixture, own, teammate, root, True)
        inbound_only = share_smart_reply(fixture, own, teammate, root, False)
        foreign = fixture.login(outsider)

        def visible(path=outgoing):
            return expect(fixture.api(peer, path))["messages"]

        create("ReplyToItem", "SendOnly", "EWS without Sent")
        create("ReplyAllToItem", "SendAndSaveCopy", "Blind EWS reply", bcc=[author])
        create("ReplyAllToItem", "SendAndSaveCopy", "Outside EWS audience", cc=[outsider])
        create("ReplyToItem", "SendAndSaveCopy", "Cross-owner source", "ErrorItemNotFound", identity=outsider)
        create("ReplyToItem", "SendAndSaveCopy", "Stale source", "ErrorIrresolvableConflict",
               original={**source, "ChangeKey": "stale"})
        with fixture.imap(owner) as mailbox:
            duplicate = hosted["eas_mime"](author, owner, subject="Different local item with the same ID",
                                           extra=f"Message-ID: {root['message_id']}\r\n".encode())
            assert mailbox.append("Sent", None, None, duplicate)[0] == "OK"
        sent_sync = ews["check"](fixture, owner, sync.replace('Id="inbox"', 'Id="sentitems"'), "NoError")
        for candidate in sent_sync.findall(".//{*}ItemId"):
            copied, raw = ews["get_mime"](fixture, owner, candidate.attrib)
            if BytesParser(policy=policy.default).parsebytes(raw)["Subject"] == "Different local item with the same ID":
                break
        else:
            raise AssertionError("EWS did not return the imported duplicate")
        create("ReplyToItem", "SendAndSaveCopy", "Different item reply", original=copied)
        forged = EmailMessage()
        forged["From"], forged["To"], forged["Subject"] = owner, author, "Ordinary EWS MIME with a reply header"
        forged["Message-ID"], forged["In-Reply-To"] = "<forged-ews@threads.example.test>", root["message_id"]
        forged.set_content("MIME headers alone do not authenticate the source.")
        unproven = ews["item_id"](ews["check"](fixture, owner, ews["create"]("SaveOnly", ews["mime_message"](forged.as_bytes())), "NoError"))
        send_draft(unproven)
        assert [message["reference"] for message in visible()] == [root["reference"]]
        expect(fixture.api(foreign, outgoing), 404)

        direct = ews["item_id"](create("ReplyAllToItem", "SendAndSaveCopy", "Direct EWS reply"))
        _, direct_raw = ews["get_mime"](fixture, owner, direct)
        message = BytesParser(policy=policy.default).parsebytes(direct_raw)
        assert message["To"] == author and message["In-Reply-To"] == root["message_id"]
        assert message["Subject"] == "Re: Follow fixture native-parent"
        rendered = message.get_body(preferencelist=("html",)).get_content()
        assert "<p>Direct EWS reply</p>" in rendered
        assert "<blockquote><pre>Reply content for native-parent." in rendered

        attached = ews["check"](fixture, owner, ews["attach"](draft, ews["file_xml"](FILE, "ews-reply.bin")), "NoError")
        change = attached.find(".//{*}AttachmentId").attrib["RootItemChangeKey"]
        edited = {**draft, "ChangeKey": change}
        servers.close()
        servers.enter_context(fixture.daemon())
        send_draft(draft, "ErrorIrresolvableConflict")
        _, draft_raw = ews["get_mime"](fixture, owner, edited)
        baseline, count = fixture.bytes(owner), fixture.count(owner)
        fixture.provision("ews-owner", quota=baseline + len(draft_raw) - 1)
        send_draft(edited, "ErrorQuotaExceeded")
        assert fixture.bytes(owner) == baseline and fixture.count(owner) == count and len(visible()) == 2
        fixture.provision("ews-owner", quota=baseline + len(draft_raw))
        send_draft(edited)
        assert fixture.bytes(owner) == baseline + len(draft_raw) and fixture.count(owner) == count + 1
        _, first, second = visible()
        assert first["sentReply"] and second["sentReply"] and second["subject"] == "Draft with EWS file"
        assert "Saved EWS reply" in second["text"] and second["attachments"] == []
        expect(fixture.api(peer, f"{outgoing}/attachments/{second['reference']}/0"), 404)
        saved = expect(fixture.api(own, "messages/ref/" + second["reference"]))
        assert saved["in_reply_to"] == root["message_id"] and saved["attachments"][0]["filename"] == "ews-reply.bin"
        assert not any(message["sentReply"] for message in visible(inbound_only))
        assert expect(fixture.api(peer, "notifications/claim", method="POST"))["teamReplies"] == 2

        fixture.provision("ews-owner")
        send_draft(edited)
        assert [message["reference"] for message in visible()] == [root["reference"], first["reference"], second["reference"]]
        assert expect(fixture.api(peer, "notifications/claim", method="POST")).get("teamReplies", 0) == 0
        continuation = ews["item_id"](create("ReplyToItem", "SendAndSaveCopy", "EWS reply to a saved sent reply",
                                             original=direct, subject="EWS conversation continuation"))
        _, continuation_raw = ews["get_mime"](fixture, owner, continuation)
        parsed = BytesParser(policy=policy.default).parsebytes(continuation_raw)
        assert parsed["To"] == author and parsed["In-Reply-To"] == message["Message-ID"]
        assert root["message_id"] in parsed["References"] and message["Message-ID"] in parsed["References"]
        assert visible()[-1]["sentReply"]
        expect(fixture.api(own, outgoing, method="DELETE"))
        create("ReplyToItem", "SendAndSaveCopy", "EWS after revocation")
        expect(fixture.api(peer, outgoing), 404)
        print("Verified EWS reply and reply-all, exact owner and source, Sent quota, edited drafts, blind copies, and revoked grants.")


def verify_smart_reply(fixture, outsider):
    owner, teammate, author = (fixture.provision(name) for name in ("smart-owner", "smart-teammate", "smart-author"))
    own, peer, root = smart_reply_parent(fixture, owner, teammate, author)
    foreign = fixture.login(outsider)
    outgoing = share_smart_reply(fixture, own, teammate, root, True)
    inbound_only = share_smart_reply(fixture, own, teammate, root, False)
    source = hosted["synced_mail_item"](fixture, owner, "NativeReplyDevice")
    assert source == ("1", f"1:{root['uid']}")

    def send_on_device(raw, client_id, *, save=True, op="SmartReply", refer=source, replace=True):
        body = hosted["eas_send"](raw, client_id, command=op, save=save, source=refer, replace=replace)
        return hosted["eas_result"](fixture.eas(owner, body, command=op, device="NativeReplyDevice"), op)

    def visible(path=outgoing):
        return expect(fixture.api(peer, path))["messages"]

    def notices():
        return expect(fixture.api(peer, "notifications/claim", method="POST")).get("teamReplies", 0)

    mime = hosted["eas_mime"]
    with fixture.imap(owner) as imap:
        imap.create("Sent")
        duplicate = mime(author, owner, subject="Imported identical wire ID",
                         extra=f"Message-ID: {root['message_id']}\r\n".encode())
        assert imap.append("Sent", None, None, duplicate)[0] == "OK"
    unrelated = hosted["synced_mail_item"](fixture, owner, "NativeReplyDevice", folder="3")

    assert send_on_device(mime(owner, author, subject="Reply without Sent"), "no-copy", save=False) == 0
    assert send_on_device(mime(owner, author, subject="Forwarded parent"), "forward", op="SmartForward") == 0
    assert send_on_device(mime(owner, author, extra=f"Bcc: {author}\r\n".encode(), subject="Blind SmartReply"), "bcc") == 0
    assert send_on_device(mime(owner, outsider, subject="Unapproved SmartReply recipient"), "out-of-scope") == 0
    assert send_on_device(mime(owner, author, subject="Conflicting parent",
                               extra=b"In-Reply-To: <elsewhere@threads.example.test>\r\n"), "other-parent") == 0
    assert send_on_device(mime(owner, author, subject="Duplicate ID reply"), "duplicate", refer=unrelated) == 0
    assert [msg["reference"] for msg in visible()] == [root["reference"]]
    assert notices() == 0
    expect(fixture.api(foreign, outgoing), 404)

    complete = mime(owner, author, subject="Followed quota reply", extra=(
        f"Message-ID: <native-quota-reply@threads.example.test>\r\nIn-Reply-To: {root['message_id']}\r\n"
    ).encode())
    baseline, charged = fixture.bytes(owner), fixture.count(owner)
    fixture.provision("smart-owner", quota=baseline + len(complete) - 1)
    assert send_on_device(complete, "quota") == 113
    assert fixture.bytes(owner) == baseline and fixture.count(owner) == charged and len(visible()) == 1
    fixture.provision("smart-owner", quota=baseline + len(complete))
    assert send_on_device(complete, "quota") == 0
    assert fixture.bytes(owner) == baseline + len(complete) and fixture.count(owner) == charged + 1
    assert send_on_device(complete, "quota") == 118
    assert len(visible()) == 2 and notices() == 1 and notices() == 0
    fixture.provision("smart-owner")

    generated = mime(owner, author, subject="Followed native reply", payload=b"Approved SmartReply body")
    assert send_on_device(generated, "thread", replace=False) == 0
    _, explicit, appended = visible()
    assert explicit["sentReply"] and appended["sentReply"]
    assert "Approved SmartReply body" in appended["text"] and not appended["attachments"]
    assert not any(msg["sentReply"] for msg in visible(inbound_only))
    saved = expect(fixture.api(own, "messages/ref/" + appended["reference"]))
    assert saved["in_reply_to"] == root["message_id"] and saved["message_id"].startswith("<")
    continuation = EmailMessage()
    continuation["From"], continuation["To"] = author, owner
    continuation["Subject"], continuation["Message-ID"] = "Reply to generated native ID", "<native-continuation@threads.example.test>"
    continuation["In-Reply-To"] = saved["message_id"]
    continuation.set_content("The generated identifier links the next verified reply.")
    with fixture.smtp(author) as connection:
        assert connection.send_message(continuation) == {}
    assert visible()[-1]["verifiedReply"] and len(visible(inbound_only)) == 1

    expect(fixture.api(own, outgoing, method="DELETE"))
    assert notices() == 0
    assert send_on_device(mime(owner, author, subject="After revocation"), "revoked") == 0
    expect(fixture.api(peer, outgoing), 404)


def verify_remote_smart_reply(fixture):
    directory = fixture.directory
    local_domains = fixture.env["SMTP_LOCAL_DOMAINS"]
    author = "partner@remote.example.test"
    fixture.env["SMTP_LOCAL_DOMAINS"] += ",remote.example.test"
    command(fixture, "user:local", "create", author, fixture.password, author)
    with fixture.daemon():
        owner, teammate = (fixture.provision(name) for name in ("remote-reply-owner", "remote-reply-viewer"))
        own, _, root = smart_reply_parent(fixture, owner, teammate, author)
        share = share_smart_reply(fixture, own, teammate, root, True)

    aws = directory / "aws"
    aws.write_text(f'''#!{sys.executable}
import base64
import json
from pathlib import Path
import sys
import time

assert sys.argv[1:3] == ["ses", "send-raw-email"]
payload = json.loads(Path(sys.argv[-1].removeprefix("file://")).read_text())
assert payload["Destinations"] == ["{author}"]
mime = base64.b64decode(payload["RawMessage"]["Data"])
if b"Subject: Remote refused" in mime:
    sys.exit(1)
assert b"Subject: Remote confirmed" in mime, mime
Path("remote-pending").touch()
for _ in range(160):
    if Path("remote-confirm").exists():
        sys.exit(0)
    time.sleep(.05)
sys.exit(2)
''')
    aws.chmod(0o700)
    fixture.env.update(SMTP_LOCAL_DOMAINS=local_domains, SMTP_DELIVERY_METHOD="ses",
                       PATH=str(directory) + os.pathsep + fixture.env["PATH"])

    with fixture.daemon():
        own, peer = fixture.login(owner), fixture.login(teammate)
        device = "NativeRemote"
        source = hosted["synced_mail_item"](fixture, owner, device)

        def send_on_device(subject, client_id):
            mime = hosted["eas_mime"](owner, author, subject=subject)
            payload = hosted["eas_send"](mime, client_id, command="SmartReply", source=source, save=True, replace=True)
            return hosted["eas_result"](fixture.eas(owner, payload, command="SmartReply", device=device), "SmartReply")

        def sent(subject):
            query = subject.replace(" ", "+")
            return expect(fixture.api(own, "messages?folder=Sent&q=" + query))["items"]

        with ThreadPoolExecutor(max_workers=1) as pool:
            confirming = pool.submit(send_on_device, "Remote confirmed", "confirm")
            try:
                deadline = time.monotonic() + 7
                while not (directory / "remote-pending").exists() and time.monotonic() < deadline:
                    time.sleep(.05)
                assert (directory / "remote-pending").exists()
                assert len(sent("Remote confirmed")) == 1
                assert len(expect(fixture.api(peer, share))["messages"]) == 1
                assert expect(fixture.api(peer, "notifications/claim", method="POST")).get("teamReplies", 0) == 0
            finally:
                (directory / "remote-confirm").touch()
            assert confirming.result(timeout=10) == 0
        published, = [msg for msg in expect(fixture.api(peer, share))["messages"] if msg["sentReply"]]
        assert published["reference"] == sent("Remote confirmed")[0]["reference"]
        assert expect(fixture.api(peer, "notifications/claim", method="POST"))["teamReplies"] == 1
        assert send_on_device("Remote confirmed", "confirm") == 118
        assert send_on_device("Remote refused", "refuse") == 120
        assert sent("Remote refused") == []

    with fixture.daemon():
        peer = fixture.login(teammate)
        restored = expect(fixture.api(peer, share))["messages"]
        assert {msg["subject"] for msg in restored} == {"Follow fixture native-parent", "Remote confirmed"}
        assert expect(fixture.api(peer, "notifications/claim", method="POST")).get("teamReplies", 0) == 0
    print("Verified that remote SmartReply follows confirmation, rejects failed delivery, and preserves one preview across replay and restart.")


def verify(fixture):
    def call(session, path, payload=None, method=None, status=200):
        return expect(fixture.api(session, path, payload, method), status)

    def download(session, path, status=200):
        actual, headers, content = request(fixture.webmail + "/webmail/api/" + path,
                                           headers=session, context=fixture.tls_context)
        assert actual == status, (actual, content)
        if status == 200:
            assert headers["Cache-Control"] == "no-store"
            assert headers["Content-Disposition"].startswith("attachment")
        return content

    with fixture.daemon():
        owner, peer, witness, outsider = (fixture.provision(name, daily=100) for name in (
            "thread-owner", "thread-peer", "thread-witness", "thread-outsider",
        ))
        own, other, third, foreign = (fixture.login(address) for address in (owner, peer, witness, outsider))
        command(fixture, "team", "create", "studio", "Studio", owner)
        command(fixture, "team", "create", "independent", "Independent", outsider)
        command(fixture, "team", "member", "studio", peer, "member")
        command(fixture, "team", "member", "studio", witness, "member")
        assert call(own, "config")["teamThreadsAvailable"]
        with fixture.imap(owner) as imap:
            assert imap.create("Drafts")[0] == "OK"
            append(imap, owner, "Design review", "Review the cobalt palette.", attachment=True)
            append(imap, owner, "Re: Design review", "The turquoise option is ready.")
            append(imap, owner, "Personal mail", "Unselected confidential mail.", attachment=True)
            append(imap, owner, "Draft title", "Private draft body.", folder="Drafts")

        rows = {row["subject"]: row for row in call(own, "messages?conversations=false")["items"]}
        chosen = [rows[subject]["reference"] for subject in ("Design review", "Re: Design review")]
        outside = rows["Personal mail"]["reference"]
        call({**own, "If-Match": rows["Design review"]["revision"]}, "private/message",
             {"reference": chosen[0], "action": "note", "body": "An owner-only note."}, "POST")
        draft, = call(own, "messages?folder=Drafts")["items"]
        selection = {"references": chosen, "downloads": False}
        call({}, SHARES, status=401)
        call(own, SHARES + "/preview", {"references": [draft["reference"]]}, "POST", 404)
        call(other, SHARES + "/preview", selection, "POST", 404)
        text_only = call(own, SHARES + "/preview", selection, "POST")
        assert all(not message["attachments"] for message in text_only["messages"])
        draft_grant = {**selection, "team": "studio", "grantee": peer, "digest": text_only["digest"]}
        call(own, SHARES, {**draft_grant, "grantee": outsider}, "POST", 409)
        call(own, SHARES, {**draft_grant, "downloads": True}, "POST", 409)
        call({**own, "Origin": "https://foreign.example.test"}, SHARES, draft_grant, "POST", 403)
        plain = call(own, SHARES, draft_grant, "POST", 201)
        plain_path = f"{SHARES}/{plain['id']}"
        download(other, f"{plain_path}/attachments/{chosen[0]}/0", 404)
        call(own, plain_path, method="DELETE")
        call(own, SHARES + "/preview", {**selection, "followReplies": True}, "POST", 409)

        preview = call(own, SHARES + "/preview", {**selection, "downloads": True}, "POST")
        part, = preview["messages"][0]["attachments"]
        assert part["filename"] == "design.bin"
        grant = call(own, SHARES, {**draft_grant, "downloads": True, "digest": preview["digest"]}, "POST", 201)
        path = f"{SHARES}/{grant['id']}"
        attachment = f"{path}/attachments/{chosen[0]}/{part['index']}"
        assert call(other, SHARES) == {"grants": [grant]}
        detail = call(other, path)
        assert [item["reference"] for item in detail["messages"]] == chosen
        assert all(value not in str(detail) for value in (
            "hidden-recipient", "nested-hidden", "nested.eml", "Personal mail", "Private draft", "Unselected confidential", "owner-only",
        ))
        assert [item["reference"] for item in call(other, path + "?q=TURQUOISE")["messages"]] == [chosen[1]]
        assert call(other, path + "?q=confidential")["messages"] == []
        assert download(other, attachment) == FILE
        download(other, f"{path}/attachments/{outside}/0", 404)
        for session in (third, foreign):
            assert call(session, SHARES) == {"grants": []}
            call(session, path, status=404)
            call(session, path + "?q=cobalt", status=404)
            call(session, path + "/comments", {"text": "Not part of this share"}, "POST", 404)
            download(session, attachment, 404)
        call(other, path, method="DELETE", status=404)
        call(other, path + "/comments", {"text": "Looks good to me."}, "POST", 201)
        comments = call(own, path)["comments"]
        assert len(comments) == 1 and comments[0]["author"] == peer and comments[0]["text"] == "Looks good to me."

        def move(folder):
            current = call(own, f"messages/ref/{chosen[0]}")
            target = {field: current[field] for field in ("uid", "folder", "reference", "revision")}
            result = call(own, "bulk", {"action": "move", "folder": folder, "messages": [target]}, "POST")
            assert result["ok"], result

        move("Archive")
        assert download(other, attachment) == FILE

        call(own, "sender-review", {"setting": "disable"}, "PUT")
        send(fixture, owner, witness, "root")
        send(fixture, owner, witness, "before-grant", parent="root")
        root, = call(own, "messages?conversations=false&q=Follow+fixture+root")["items"]
        follow = {"references": [root["reference"]], "downloads": True, "followReplies": True}
        reviewed = call(own, SHARES + "/preview", follow, "POST")
        assert reviewed["followingAuthors"] == [witness]
        followed = call(own, SHARES, {**follow, "digest": reviewed["digest"], "team": "studio", "grantee": peer}, "POST", 201)
        followed_path = f"{SHARES}/{followed['id']}"
        assert [item["reference"] for item in call(other, followed_path)["messages"]] == [root["reference"]]
        for session in (other, third, foreign):
            call(session, "notifications", {"enabled": True}, "PUT")
        send(fixture, owner, witness, "visible-reply", parent="root", attachment=True)
        send(fixture, owner, witness, "visible-continuation", references=["root", "visible-reply"])
        send(fixture, owner, witness, "spoofed", parent="root", verified=False)
        send(fixture, owner, outsider, "different-sender", parent="root")
        send(fixture, owner, witness, "reference-only-ancestor", references=["root", "unrelated-parent"])
        send(fixture, owner, witness, "unrelated-direct-parent", parent="unrelated-parent", references=["root"])
        send(fixture, owner, witness, "automatic", parent="root", automatic=True)
        send(fixture, owner, witness, "visible-reply", parent="root")
        data = call(other, followed_path)
        assert data["grant"]["followingAuthors"] == [witness]
        assert [row["subject"] for row in data["messages"]] == [
            "Follow fixture root", "Follow fixture visible-reply", "Follow fixture visible-continuation",
        ]
        reply = data["messages"][1]
        assert reply["verifiedReply"] and reply["attachments"] == []
        assert call(other, followed_path + "?q=visible-continuation")["messages"] == data["messages"][2:]
        assert call(other, followed_path + "?q=before-grant")["messages"] == []
        download(other, f"{followed_path}/attachments/{reply['reference']}/0", 404)
        call(third, followed_path, status=404)
        call(foreign, followed_path, status=404)

        def claim(session):
            batch = call(session, "notifications/claim", method="POST")
            assert set(batch) <= {"ids", "teamReplies"}
            return batch.get("teamReplies", 0)

        assert claim(third) == claim(foreign) == 0
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sum(pool.map(claim, [other, other])) == 2
        assert claim(other) == 0
        send(fixture, owner, witness, "disabled-notice", parent="visible-continuation")
        call(other, "notifications", {"enabled": False}, "PUT")
        call(other, "notifications", {"enabled": True}, "PUT")
        assert claim(other) == 0
        send(fixture, owner, witness, "pending-notice", parent="visible-continuation")
        assert len(call(other, followed_path + "?q=pending-notice")["messages"]) == 1
        call(own, followed_path, method="DELETE")
        assert claim(other) == 0
        send(fixture, owner, witness, "after-revoke", parent="visible-continuation")
        call(other, followed_path, status=404)
        move("Trash")
        assert call(other, path + "?q=cobalt")["messages"] == []
        download(other, attachment, 404)
        move("Archive")
        assert download(other, attachment) == FILE

        command(fixture, "team", "member", "studio", peer, "remove")
        call(other, SHARES, status=401)
        other = fixture.login(peer)
        assert call(other, SHARES) == {"grants": []}
        call(other, path + "?q=cobalt", status=404)
        download(other, attachment, 404)
        command(fixture, "team", "member", "studio", peer, "member")
        call(other, path, status=404)
        fresh = call(own, SHARES, {**draft_grant, "downloads": True, "digest": preview["digest"]}, "POST", 201)
        assert fresh["id"] != grant["id"]
        fresh_path = f"{SHARES}/{fresh['id']}"
        assert call(other, fresh_path)["comments"] == []
        call(own, fresh_path, method="DELETE")
        call(other, fresh_path, status=404)
        root = call(own, "messages/ref/" + root["reference"])
        verify_sent_replies(fixture, call, download, claim, owner, peer, witness, outsider, own, other, third, foreign, root)
        root = call(own, "messages/ref/" + root["reference"])
        verify_collection(fixture, call, download, owner, peer, witness, outsider, own, other, third, foreign, rows, root)
        verify_smart_reply(fixture, outsider)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-team-threads-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    with tempfile.TemporaryDirectory(prefix="mail-team-smart-remote-") as directory:
        verify_remote_smart_reply(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    with tempfile.TemporaryDirectory(prefix="mail-team-ews-reply-") as directory:
        verify_ews_reply(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Verified team conversations, followed incoming, webmail, ActiveSync, and EWS replies, live collections, previews, search, downloads, comments, notices, and revocation.")


if __name__ == "__main__":
    main()
