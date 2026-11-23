#!/usr/bin/env python3
"""Exercise identity-bound conversation shares on native HTTPS."""

import argparse
from email.message import EmailMessage
from pathlib import Path
import runpy
import tempfile


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
        owner, peer, witness, outsider = (fixture.provision(name) for name in (
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-team-threads-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Verified team conversation previews, identity, searching, attachments, comments, and revocation.")


if __name__ == "__main__":
    main()
