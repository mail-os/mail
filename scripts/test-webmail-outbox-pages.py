#!/usr/bin/env python3
"""Verify bounded, account-scoped Outbox navigation over native HTTPS."""

import argparse
from contextlib import closing
from pathlib import Path
import runpy
import secrets
import sqlite3
import tempfile
import time
from urllib.parse import urlencode


Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]


def expect(response, status=200):
    assert response[0] == status, response
    return response[1]


def page(test, session, view="upcoming", **parameters):
    return test.api(session, "outbox?" + urlencode({"view": view, **parameters}))


def send(test, session, recipient, subject, **options):
    payload = {
        "sendId": secrets.token_hex(16), "subject": subject, "to": [recipient],
        "text": "Private body only available from the message detail.",
        **options,
    }
    return expect(test.api(session, "compose", payload))


def seed_queue(test, session, recipient, count=125):
    """Queue the earliest message first, then vary insertion order and tie times."""
    now = int(time.time())
    queued = [
        send(test, session, recipient, f"Scheduled handoff {index + 1:03}", scheduleAt=now + 1200 + ((index + 1) // 2) * 30)
        for index in (0, *reversed(range(1, count)))
    ]
    return sorted(queued, key=lambda row: (row["dueAt"], row["id"]))


def ids(items):
    return [item["id"] for item in items]


def verify(test):
    owner = test.provision("owner")
    other = test.provision("other")
    full = test.provision("full", quota=8)
    session = test.login(owner)
    other_session = test.login(other)
    expected = seed_queue(test, session, other)
    assert test.count(owner) == 0
    first = expect(page(test, session))
    assert first["counts"] == {"upcoming": len(expected), "review": 0, "history": 0}
    assert ids(first["items"]) == ids(expected[:20])
    legacy = expect(test.api(session, "outbox"))
    assert len(legacy) == 100 and expected[0]["id"] not in ids(legacy)
    assert first["nextCursor"] == expected[19]["id"]
    assert first["serverTime"] <= int(time.time()) + 1
    assert first["tracked"] is None
    assert all(item["scheduled"] and set(item["message"]) == {"subject", "to"} for item in first["items"])
    detail = expect(test.api(session, f"outbox/{expected[0]['id']}"))
    assert detail["message"]["text"] == "Private body only available from the message detail."

    # The cursor binds to its owner, regardless of a known public send time.
    wrong_scope = expect(page(test, other_session, after=first["nextCursor"]), 404)
    assert wrong_scope["error"] == "outbox_cursor_expired"
    assert expect(page(test, other_session, "overview", track=expected[0]["id"]))["tracked"] is None
    expect(page(test, session, "overview", after=first["nextCursor"]), 400)
    expect(page(test, session, "upcoming", after="invalid!"), 400)
    expect(page(test, session, "unsupported"), 400)
    expect(test.api(other_session, f"outbox/{expected[0]['id']}", method="DELETE"), 404)

    # New earlier sends, terminal receipts, and failures arrive during paging.
    # They must not shift the later pages or change the selected cursor.
    earlier = send(test, session, other, "New earliest", scheduleAt=int(time.time()) + 300)
    sent = send(test, session, other, "Recent delivery", delaySeconds=0)
    test.outbox(session, sent["id"], "sent")
    failure = send(test, session, full, "Needs attention", delaySeconds=0)
    test.outbox(session, failure["id"], "failed")
    usage = test.count(owner)
    review = expect(page(test, session, "review"))
    assert ids(review["items"]) == [failure["id"]] and review["items"][0]["error"]
    assert ids(expect(page(test, session, "history"))["items"]) == [sent["id"]]
    assert expect(page(test, session))["items"][0]["id"] == earlier["id"]

    walked = ids(first["items"])
    cursor = first["nextCursor"]
    while cursor:
        window = expect(page(test, session, after=cursor, track=expected[0]["id"]))
        assert 0 < len(window["items"]) <= 20
        assert window["tracked"]["id"] == expected[0]["id"]
        assert window["counts"] == {"upcoming": len(expected) + 1, "review": 1, "history": 1}
        walked += ids(window["items"])
        cursor = window["nextCursor"]
    assert walked == ids(expected) and len(set(walked)) == len(expected)

    # A cursor that moves to History still refers to the same deadline.
    anchor = first["nextCursor"]
    cancelled = expect(test.api(session, f"outbox/{anchor}", method="DELETE"))
    assert cancelled["state"] == "cancelled"
    after_cancel = expect(page(test, session, after=anchor, track=anchor))
    assert ids(after_cancel["items"]) == ids(expected[20:40])
    assert after_cancel["tracked"]["state"] == "cancelled"
    overview = expect(page(test, session, "overview", track=anchor))
    assert overview["items"] == [] and overview["nextCursor"] is None
    assert overview["counts"] == {"upcoming": len(expected), "review": 1, "history": 2}

    # Simulate expiry of the cancelled receipt, which also removes its anchor.
    with closing(sqlite3.connect(test.directory / "smtp.db")) as db, db:
        db.execute("DELETE FROM webmail_records WHERE username=? AND kind='outbox' AND state='cancelled' AND id=?", (owner, anchor))
    expired = expect(page(test, session, after=anchor), 404)
    assert expired == wrong_scope
    assert expect(page(test, session, track=anchor))["tracked"] is None

    last_id = expected[-1]["id"]
    assert expect(test.api(session, f"outbox/{last_id}", method="DELETE"))["state"] == "cancelled"
    assert expect(page(test, session, "overview"))["counts"] == {"upcoming": len(expected) - 1, "review": 1, "history": 2}
    assert test.count(owner) == usage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-outbox-pages-", dir="/tmp") as directory:
        test = Fixture(args.binary.resolve(strict=True), Path(directory), staging=True)
        with test.daemon():
            verify(test)
    print("Verified bounded Outbox summaries, all 125 schedules and stable cursors, counts, new deliveries, cancellation, expiry, and account isolation over HTTPS.")


if __name__ == "__main__":
    main()
