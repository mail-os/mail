#!/usr/bin/env python3
"""Exercise identity-bound conversation shares on native HTTPS."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from pathlib import Path
import runpy
import secrets
import tempfile
import time


SCRIPTS = Path(__file__).resolve().parent
teams = runpy.run_path(str(SCRIPTS / "test-webmail-teams.py"))
Fixture, command, expect = teams["Fixture"], teams["command"], teams["expect"]
request = runpy.run_path(str(SCRIPTS / "test-hosted-limits.py"))["request"]
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-team-threads-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Verified team conversations, followed incoming and sent replies, live collections, previews, searching, attachments, comments, notifications, and revocation.")


if __name__ == "__main__":
    main()
