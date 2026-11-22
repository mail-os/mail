#!/usr/bin/env python3
"""Verify account-owned writing tools and composed text over native HTTPS."""

import argparse
from email import policy
from email.parser import BytesParser
from pathlib import Path
import runpy
import tempfile
import time


helpers = runpy.run_path(str(Path(__file__).with_name("test-webmail-scheduled-send.py")))
Fixture, expect, new_id, save, draft = (
    helpers[name] for name in ("Fixture", "expect", "new_id", "save", "draft")
)
path = "compose-library"
empty = {"revision": 0, "snippets": [], "signatures": [], "defaultSignatureId": None}


def verify_library(test, session, other_session):
    def put(payload, status=200, headers=session):
        return expect(test.api(headers, path, payload, method="PUT"), status)

    expect(test.api({}, path), 401)
    assert expect(test.api(session, path)) == empty
    snippet = {"id": new_id(), "name": "Next steps", "text": "Here’s the résumè.\nI’ll follow up on Thursday."}
    signature = {"id": new_id(), "name": "Studio", "text": "Mélanie\nStudio équipe"}
    proposed = dict(empty, snippets=[snippet], signatures=[signature], defaultSignatureId=signature["id"])
    put(proposed, 403, dict(session, Origin="https://foreign.example.test"))
    for invalid in (
        dict(proposed, snippets=[snippet, snippet]),
        dict(proposed, defaultSignatureId=snippet["id"]),
        dict(proposed, snippets=[dict(snippet, id=new_id()) for _ in range(33)]),
        dict(proposed, snippets=[dict(snippet, text="é" * 4097)]),
        dict(proposed, signatures=[dict(signature, text="s" * 4097)]),
        dict(proposed, snippets=[dict(snippet, id=new_id(), text="s" * 8192) for _ in range(17)]),
    ):
        assert put(invalid, 400)["error"] == "invalid_compose_library"
    assert expect(test.api(session, path)) == empty
    library = put(proposed)
    assert library == dict(proposed, revision=1)
    assert put(proposed, 409)["error"] == "compose_library_changed"
    assert expect(test.api(session, path)) == library
    assert expect(test.api(other_session, path)) == empty
    signatures = [signature, dict(signature, id=new_id(), text="s" * 4096)]
    snippets = [dict(snippet, text="s" * 8192)]
    other_library = dict(empty, signatures=signatures, snippets=snippets, defaultSignatureId=signature["id"])
    assert put(other_library, headers=other_session) == dict(other_library, revision=1)
    return library


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-writing-tools-", dir="/tmp") as directory:
        test = Fixture(args.binary.resolve(strict=True), Path(directory), staging=True)
        with test.daemon():
            owner, other = test.provision("writer"), test.provision("recipient")
            session = test.login(owner)
            library = verify_library(test, session, test.login(other))
            text = library["snippets"][0]["text"] + "\n\n-- \n" + library["signatures"][0]["text"]
            saved = save(test, session, other, "Writing tools draft", text=text)
            queued = dict(saved, sendId=new_id(), scheduleAt=int(time.time()) + 3600)
            assert expect(test.api(session, "compose", queued))["scheduled"]
        with test.daemon():
            session = test.login(owner)
            assert expect(test.api(session, path)) == library
            cleared = expect(test.api(session, path, dict(empty, revision=library["revision"]), method="PUT"))
            assert cleared == dict(empty, revision=library["revision"] + 1)
            assert expect(test.api(test.login(other), path))["signatures"][0] == library["signatures"][0]
            outbox = "outbox/" + queued["sendId"]
            assert expect(test.api(session, outbox))["message"]["text"] == text
            assert expect(test.api(session, outbox, method="DELETE"))["state"] == "cancelled"
            thawed = draft(test, session, saved)
            assert thawed["state"] == "saved" and thawed["message"]["text"] == text
            delivery = dict(saved, draftRevision=thawed["revision"], sendId=new_id(), delaySeconds=0)
            expect(test.api(session, "compose", delivery))
            test.outbox(session, delivery["sendId"], "sent")
            inbox, = (test.directory / "mail" / other / "new").glob("*.eml*")
            message = BytesParser(policy=policy.default).parsebytes(inbox.read_bytes())
            assert message.get_body().get_content().rstrip("\r\n").replace("\r\n", "\n") == text
    print("Verified writing-tool ownership, validation, revision conflicts, restart persistence, and unchanged scheduled and delivered text over HTTPS.")


if __name__ == "__main__":
    main()
