#!/usr/bin/env python3
"""Test recipient-owned shared Mail retention through the native TLS API."""

import argparse
import base64
from hashlib import sha256
from contextlib import closing
from email.message import EmailMessage
import json
import os
from pathlib import Path
import runpy
import sqlite3
from stat import S_IMODE
import subprocess
import tarfile
import time
from tempfile import TemporaryDirectory

scripts = Path(__file__).resolve().parent
dav = runpy.run_path(str(scripts / "test-hosted-erasure-dav.py"))
portable = runpy.run_path(str(scripts / "test-mailbox-export.py"))
Fixture, cli, prepare, success = (dav[name] for name in ("Fixture", "cli", "prepare", "success"))
command = portable["command"]
PUBLIC_BYTES = b"Approved bytes\x00\xff\r\n"
PRIVATE_BYTES = b"Never retain this attachment"


def browser_journey(test, peer, mode, output):
    env = dict(os.environ, MAIL_THREAD_TEST_URL=test.webmail, MAIL_THREAD_TEST_CERT=test.env["SMTP_TLS_CERT"],
               MAIL_THREAD_TEST_PEER=peer, MAIL_THREAD_TEST_PASSWORD=test.password,
               MAIL_THREAD_TEST_ATTACHMENT=base64.b64encode(PUBLIC_BYTES).decode("ascii"))
    subprocess.run(["node", str(scripts / "webmail-team-threads-browser.mjs"), mode, str(output / mode)],
                   env=env, check=True, timeout=110)


def verify(test, *, screenshots=None):
    db_path = test.directory / "smtp.db"
    review, decision = (test.directory / name for name in ("review.json", "decision.json"))
    team = "retained-mail-fixture"

    def api(session, path, data=None, *, method=None, status=200):
        actual, value = test.api(session, path, data, method)
        assert actual == status, (path, actual, value)
        return value

    def download(session, path, status=200):
        actual, headers, raw = test.http(test.webmail + "/webmail/api/" + path, headers=session,
                                         context=test.tls_context)
        assert actual == status, (path, actual, raw)
        if status == 200:
            assert headers["Cache-Control"] == "no-store"
            assert headers["Content-Disposition"].startswith("attachment")
        return raw

    def step(name, *args):
        return cli(test, name, str(review), str(start), *map(str, args))

    def refuse(result, cause=None):
        assert result.returncode and not result.stdout and (cause is None or cause in result.stderr), result

    def state(db):
        return db.execute("SELECT count(*) FROM mail_retained_thread_archives").fetchone()[0]

    def approve(plan, archive_items):
        decision.write_text(json.dumps({
            "version": 1, "scope_sha256": plan["scope_sha256"],
            "disposition": "release_source_with_thread_archives",
            "approval_reference": "fixture-archive-approval", "retained_thread_archives": archive_items,
        }))
        decision.chmod(0o600)
        return step("hosted-erasure-shared-release", "maildir", decision)

    def ordinary_export(mailbox, archive_path):
        result = cli(test, "export", mailbox, str(archive_path))
        assert result.returncode == 0, result.stderr
        return archive_path

    def exported(archive_path, mailbox, expected):
        assert S_IMODE(archive_path.stat().st_mode) == 0o600
        with tarfile.open(archive_path) as bundle:
            manifest = json.load(bundle.extractfile("manifest.json"))
            assert manifest["mailbox"] == mailbox and manifest["version"] == 1
            if not expected:
                assert "retainedMail" not in manifest
                assert not any(name.startswith("RetainedMail/") for name in bundle.getnames())
                return {}
            retained = manifest["retainedMail"]
            assert retained["version"] == 1
            copies = retained["copies"]
            assert {item["id"] for item in copies} == expected and len(copies) == len(expected)
            docs = {}
            for copy in copies:
                member = bundle.getmember(copy["path"])
                assert member.name == f"RetainedMail/{copy['id']}.json" and member.mode == 0o600
                docs[copy["id"]] = json.load(bundle.extractfile(member))
            return docs

    with test.daemon():
        owner, peer, outsider = (test.provision(name, daily=100) for name in (
            "retained-source", "retained-peer", "retained-outsider",
        ))
        command(test, "team", "create", team, "Retention fixture", owner)
        command(test, "team", "member", team, peer, "member")
        command(test, "team", "member", team, outsider, "member")
        own, other, foreign = (test.login(mailbox) for mailbox in (owner, peer, outsider))

        def send(subject, body, *, reply=False, attachments=False):
            msg = EmailMessage()
            msg["From"], msg["To"], msg["Subject"] = peer, owner, subject
            if subject == "Approved source":
                msg["Message-ID"] = "<approved-source@hosted.example.test>"
            if reply:
                msg["In-Reply-To"] = "<approved-source@hosted.example.test>"
                msg["References"] = "<approved-source@hosted.example.test>"
            msg.set_content(body)
            if attachments:
                msg.add_attachment(PUBLIC_BYTES, maintype="application", subtype="octet-stream", filename="allowed.bin")
                msg.add_attachment(PRIVATE_BYTES, maintype="application", subtype="octet-stream", filename="blocked.eml")
            with test.smtp(peer) as smtp:
                assert smtp.send_message(msg) == {}

        def share(selection):
            preview = api(own, "thread-shares/preview", selection)
            grant = api(own, "thread-shares", {
                **selection, "team": team, "grantee": peer, "digest": preview["digest"],
            }, status=201)
            return grant["id"]

        send("Approved source", "Approved original body", attachments=True)
        send("Private sibling", "Mailbox private sibling text")
        for page in range(20):
            send(f"Collection member {page:02}", f"Approved collection body {page:02}")
        messages = {row["subject"]: row["reference"] for row in api(own, "messages?conversations=false&per_page=100")["items"]}
        original, unrelated = (messages.pop(name) for name in ("Approved source", "Private sibling"))
        thread = share({"references": [original], "downloads": True, "followReplies": True})
        hidden = share({"references": [unrelated], "downloads": False})
        thread_path, hidden_path = (f"thread-shares/{grant}" for grant in (thread, hidden))
        send("Verified reply", "Verified reply excerpt", reply=True, attachments=True)
        discussion = "Approved teammate discussion"
        api(other, thread_path + "/comments", {"text": discussion}, status=201)
        before_thread = api(other, thread_path)
        assert [(row["subject"], row["verifiedReply"]) for row in before_thread["messages"]] == [
            ("Approved source", False), ("Verified reply", True),
        ], before_thread["messages"]
        assert before_thread["messages"][1]["attachments"] == []
        allowed, = before_thread["messages"][0]["attachments"]
        allowed_path = f"{thread_path}/attachments/{original}/{allowed['index']}"
        assert download(other, allowed_path) == PUBLIC_BYTES
        download(other, f"{thread_path}/attachments/{original}/1", status=404)

        collection, = api(own, "private/collections", {"action": "create", "name": "Approved collection"})["items"]
        for reference in [original, *messages.values()]:
            message = api(own, f"messages/ref/{reference}")
            api({**own, "If-Match": message["revision"]}, "private/message", {
                "reference": reference, "action": "collection", "collection": collection["id"], "included": True,
            })
        collection_share = share({"collectionId": collection["id"], "downloads": False})
        collection_path = f"thread-shares/{collection_share}"
        # Use the native permission API to preserve the original search restriction.
        api(own, f"teams/{team}/grants", {
            "source": owner, "grantee": peer, "scope": "search", "resource": collection_share, "allowed": False,
        }, method="PUT")
        before_collection = api(other, collection_path)
        assert before_collection["next"] and len(before_collection["messages"]) == 20
        last_page = api(other, f"{collection_path}?before={before_collection['next']}")
        assert len(last_page["messages"]) == 1 and last_page["next"] is None
        if screenshots:
            browser_journey(test, peer, "live", screenshots)
        with closing(sqlite3.connect(db_path)) as db:
            peer_id, outsider_id = (
                db.execute("SELECT id FROM users WHERE username=?", (mailbox,)).fetchone()[0]
                for mailbox in (peer, outsider)
            )
        _, _, start = prepare(test, "retained-source", review)
        plan = success(step("hosted-erasure-shared-release", "maildir"))
        selections = [{"source_share_id": share_id, "peer_user_id": peer_id}
                      for share_id in (thread, collection_share)]
        refuse(approve(plan, [{**selections[0], "peer_user_id": outsider_id}]),
               "ErasureThreadArchiveNotAuthorized")
        refuse(approve(plan, [selections[0], selections[0]]), "InvalidErasureSharedDecision")
        approved = success(approve(plan, selections))
        refuse(step("hosted-erasure-retain-threads"), "MaildirWriterActive")
        api(other, thread_path, status=404)

    maildir = test.directory / "mail" / owner
    refuse(step("hosted-erasure-maildir"), "ErasureThreadArchivePending")
    assert maildir.is_dir()
    with closing(sqlite3.connect(db_path)) as db:
        with db:
            db.execute(f"""CREATE TRIGGER abort_second_archive BEFORE INSERT ON mail_retained_thread_archives
                           WHEN NEW.share_id='{collection_share}'
                           BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END""")
        refuse(step("hosted-erasure-retain-threads"))
        assert state(db) == 0 and maildir.is_dir()
        with db:
            db.execute("DROP TRIGGER abort_second_archive")
            db.execute("UPDATE users SET enabled=0 WHERE id=?", (peer_id,))
        refuse(step("hosted-erasure-retain-threads"), "ErasureThreadArchivePeerUnavailable")
        assert state(db) == 0
        with db:
            db.execute("UPDATE users SET enabled=1 WHERE id=?", (peer_id,))
            db.execute("UPDATE mail_team_thread_comments SET text='Changed since approval' WHERE share_id=?", (thread,))
        refuse(step("hosted-erasure-retain-threads"), "ErasureSharedReleaseRequired")
        with db:
            db.execute("UPDATE mail_team_thread_comments SET text=? WHERE share_id=?", (discussion, thread))

        receipt = success(step("hosted-erasure-retain-threads"))
        assert receipt["approval_audit_id"] == approved["audit_id"]
        assert {entry["share_id"] for entry in receipt["archives"]} == {thread, collection_share}
        assert state(db) == 2 and maildir.is_dir()
        assert success(step("hosted-erasure-retain-threads")) == receipt
        docs = db.execute("SELECT share_id,document FROM mail_retained_thread_archives").fetchall()
        assert all("Mailbox private sibling text" not in value and "blocked.eml" not in value for _, value in docs)
        # The native command verifies each stored payload against the audit.
        document, = [value for key, value in docs if key == thread]
        with db:
            db.execute("UPDATE mail_retained_thread_archives SET document=json_set(document,'$.grant.subject','altered') WHERE share_id=?", (thread,))
        refuse(step("hosted-erasure-maildir"), "ErasureThreadArchiveInvalid")
        assert maildir.is_dir()
        with db:
            db.execute("UPDATE mail_retained_thread_archives SET document=? WHERE share_id=?", (document, thread))

    staged_export = ordinary_export(peer, test.directory / "staged.tar")
    exported(staged_export, peer, set())
    with test.daemon():
        api(other, thread_path, status=404)
        assert api(other, "thread-shares") == {"grants": []}

    erased = success(step("hosted-erasure-maildir"))
    assert not maildir.exists() and success(step("hosted-erasure-maildir")) == erased
    assert success(step("hosted-erasure-retain-threads")) == receipt
    plan = success(step("hosted-erasure-shared-sqlite"))["plan"]
    assert {entry["share_id"] for entry in plan["shared_edges"]} == {thread, collection_share, hidden}
    assert plan["releases"]["maildir"] == approved["audit_id"]
    assert plan["removed"]["threads"] == 3 and plan["removed"]["collections"] == 1
    decision.write_text(json.dumps({"version": 1, "scope_sha256": plan["scope_sha256"],
                                    "approval_reference": "fixture-live-shared-release"}))
    removed = success(step("hosted-erasure-shared-sqlite", decision))
    assert removed["receipt"]["maildir_release_audit_id"] == approved["audit_id"]
    assert success(step("hosted-erasure-shared-sqlite", decision)) == removed
    assert success(step("hosted-erasure-retain-threads")) == receipt
    with closing(sqlite3.connect(db_path)) as db:
        assert db.execute("SELECT count(*) FROM mail_team_thread_shares").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM mail_private_members").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM mail_team_members WHERE team_id=?", (team,)).fetchone()[0] == 3
        with db:
            db.execute("UPDATE mail_retained_thread_archives SET document=json_set(document,'$.grant.subject','altered') WHERE share_id=?", (thread,))
        corrupt = test.directory / "corrupt.tar"
        refuse(cli(test, "export", peer, str(corrupt)), "ErasureThreadArchiveInvalid")
        assert not corrupt.exists()
        with db:
            db.execute("UPDATE mail_retained_thread_archives SET document=? WHERE share_id=?", (document, thread))

    personal = exported(ordinary_export(peer, test.directory / "personal.tar"), peer, {thread, collection_share})
    exported(ordinary_export(outsider, test.directory / "outsider.tar"), outsider, set())
    retained_thread, retained_collection = personal[thread], personal[collection_share]
    assert retained_thread["comments"] == before_thread["comments"]
    assert retained_thread["pages"][0]["messages"] == before_thread["messages"]
    assert [page["messages"] for page in retained_collection["pages"]] == [
        before_collection["messages"], last_page["messages"],
    ]
    attachment, = retained_thread["parts"]
    assert attachment["filename"] == allowed["filename"] and base64.b64decode(attachment["encoded"]) == PUBLIC_BYTES
    assert retained_collection["parts"] == []

    with test.daemon():
        other, foreign = (test.login(mailbox) for mailbox in (peer, outsider))
        grants = api(other, "thread-shares")["grants"]
        assert {grant["id"] for grant in grants} == {thread, collection_share}
        assert all(grant["retained"] and not grant["commentsAllowed"] for grant in grants)
        after = api(other, thread_path)
        for key in ("messages", "comments"):
            assert after[key] == before_thread[key]
        assert after["comments"][0]["text"] == discussion
        assert len(api(other, thread_path + "?q=verified")["messages"]) == 1
        api(other, thread_path + "/comments", {"text": "No new comments"}, status=404)
        api(other, thread_path, method="DELETE", status=404)
        assert download(other, allowed_path) == PUBLIC_BYTES
        download(other, f"{thread_path}/attachments/{original}/1", status=404)
        download(other, f"{collection_path}/attachments/{original}/0", status=404)
        assert api(other, collection_path)["messages"] == before_collection["messages"]
        assert api(other, f"{collection_path}?before={before_collection['next']}")["messages"] == last_page["messages"]
        api(other, collection_path + "?q=collection", status=403)
        api(other, hidden_path, status=404)
        api(foreign, thread_path, status=404)
        download(foreign, allowed_path, status=404)
        assert api(foreign, "thread-shares") == {"grants": []}
        api(own, thread_path, status=401)
        if screenshots:
            browser_journey(test, peer, "retained", screenshots)
        export_review, hosted_export = (test.directory / name for name in ("export-review.json", "hosted.tar"))
        actor = test.specs[peer]["actor"]
        case = "retained-peer-portable-export"
        test.provision("retained-peer", enabled=False)
        identity = success(cli(test, "hosted-erasure-preflight", peer, actor, case))["observation"]["identity"]
        handoff = {
            "version": 1, "mailbox": peer, "assignment_actor": actor, "case_reference": case,
            "recipient_verification_reference": "fixture-verified-recipient", "recipient": "retained-recipient@example.test",
        }
        export_review.write_text(json.dumps(dict(handoff, identity=identity, expires_at=int(time.time()) + 3600)))
        export_review.chmod(0o600)
        args = ("hosted-erasure-export", str(export_review), str(hosted_export))
        prepared = success(cli(test, *args))
        content = hosted_export.read_bytes()
        assert prepared["prepared"]["archive_sha256"] == sha256(content).hexdigest()
        assert exported(hosted_export, peer, {thread, collection_share}) == personal
        refuse(cli(test, *args), "PathAlreadyExists")
        assert hosted_export.read_bytes() == content
        handoff_review, delivered = (test.directory / name for name in ("handoff.json", "delivered.tar"))
        handoff_review.write_text(json.dumps(dict(handoff, export_audit_id=prepared["audit_id"])))
        handoff_review.chmod(0o600)
        handoff_args = ("hosted-erasure-handoff", str(handoff_review), str(hosted_export), str(delivered))
        ready = success(cli(test, *handoff_args))
        assert ready["prepared"] == prepared["prepared"]
        assert success(cli(test, *handoff_args)) == ready
        assert delivered.read_bytes() == content
        assert exported(delivered, peer, {thread, collection_share}) == personal
        _, _, start = prepare(test, "retained-peer", review)

    success(step("hosted-erasure-maildir"))
    private = success(step("hosted-erasure-sqlite"))
    assert success(step("hosted-erasure-sqlite")) == private
    with closing(sqlite3.connect(db_path)) as db:
        assert state(db) == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--screenshots", type=Path, help="Run the Chromium journey and save screenshots")
    args = parser.parse_args()
    with TemporaryDirectory(prefix="mail-retained-threads-") as directory:
        verify(Fixture(args.binary.resolve(), Path(directory), staging=True), screenshots=args.screenshots)
    print("Verified authorized peer-owned Mail archives, pagination, reply and file scope, audited portable export, rollback, and retry.")
