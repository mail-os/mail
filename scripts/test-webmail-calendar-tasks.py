#!/usr/bin/env python3
"""Verify personal calendar tasks over the native HTTPS API."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import runpy
import sqlite3
import tempfile


Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]
ENDPOINT = "calendar-tasks"


def tasks(fixture, session, status=200):
    actual, result = fixture.api(session, ENDPOINT)
    assert actual == status, (actual, result)
    return result


def save(fixture, session, title, day=None, completed=False, revision=0, task_id=None, status=None):
    payload = {"title": title, "day": day, "completed": completed, "revision": revision}
    if task_id is None:
        actual, result = fixture.api(session, ENDPOINT, payload, method="POST")
    else:
        actual, result = fixture.api(session, f"{ENDPOINT}/{task_id}", payload, method="PUT")
    assert actual == (status if status is not None else 201 if task_id is None else 200), (actual, result)
    return result


def remove(fixture, session, task_id, revision, status=200):
    actual, result = fixture.api(session, f"{ENDPOINT}/{task_id}", {"revision": revision}, method="DELETE")
    assert actual == status, (actual, result)
    return result


def verify(fixture):
    with fixture.daemon():
        owner = fixture.provision("task-owner")
        peer = fixture.provision("task-peer")
        session, other = fixture.login(owner), fixture.login(peer)
        tasks(fixture, {}, status=401)
        assert tasks(fixture, session) == {"tasks": []}
        assert save(fixture, dict(session, Origin="https://foreign.example.test"), "Cross origin", status=403)["error"] == "forbidden"
        save(fixture, dict(other, **{"X-Webmail-Account": owner}), "Cross mailbox", status=409)
        for title, date in (("", None), ("   ", None), ("Two\nlines", None), ("Null\x00byte", None), ("🧭" * 121, None),
                            ("Non-leap day", "2027-02-29"), ("Date and time", "2028-02-29T00:00:00Z")):
            assert save(fixture, session, title, date, status=400)["error"] == "invalid_calendar_task"
        save(fixture, session, "Wrong starting revision", revision=1, status=400)

        first = save(fixture, session, "  Schedule the review  ")
        second = save(fixture, session, "🧭" * 120, "2028-02-29")
        assert first == {"id": first["id"], "title": "Schedule the review", "day": None, "completed": False, "revision": 1}
        assert tasks(fixture, session) == {"tasks": [second, first]}
        assert tasks(fixture, other) == {"tasks": []}
        save(fixture, other, "Other mailbox", revision=1, task_id=first["id"], status=409)
        remove(fixture, other, first["id"], 1, status=409)
        remove(fixture, dict(session, Origin="https://foreign.example.test"), first["id"], 1, status=403)

        def edit(day):
            return fixture.api(session, f"{ENDPOINT}/{first['id']}",
                               {"title": first["title"], "day": day, "completed": True, "revision": 1}, method="PUT")

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(edit, ("2028-03-12", "2028-11-05")))
        assert sorted(status for status, _ in results) == [200, 409], results
        completed = next(result for status, result in results if status == 200)
        assert completed["revision"] == 2 and completed["completed"] and completed["day"]
        remove(fixture, session, first["id"], 1, status=409)

    with fixture.daemon():
        session = fixture.login(owner)
        assert tasks(fixture, session) == {"tasks": [second, completed]}
        reopened = save(fixture, session, "Review", revision=2, task_id=first["id"])
        assert reopened == {"id": first["id"], "title": "Review", "day": None, "completed": False, "revision": 3}
        assert remove(fixture, session, first["id"], 3) == {"removed": True}
        save(fixture, session, "Stale edit", revision=3, task_id=first["id"], status=409)

    # Seed the list at the boundary. The remaining writes all go through HTTPS.
    with sqlite3.connect(fixture.directory / "smtp.db") as db:
        db.execute("""
            WITH RECURSIVE copies(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM copies WHERE n<498)
            INSERT INTO mail_calendar_tasks(user_id,title,completed,revision)
            SELECT users.id, 'Fixture task ' || copies.n, 1, 1 FROM copies,users WHERE users.username=?
        """, (owner,))

    with fixture.daemon():
        session = fixture.login(owner)
        assert len(tasks(fixture, session)["tasks"]) == 499
        last = save(fixture, session, "At capacity")
        assert last["id"] != first["id"]
        assert save(fixture, session, "Over capacity", status=409)["error"] == "calendar_task_limit"
        assert len(tasks(fixture, session)["tasks"]) == 500
        remove(fixture, session, last["id"], 1)
        save(fixture, session, "Space reclaimed")
        assert len(tasks(fixture, session)["tasks"]) == 500
        assert tasks(fixture, fixture.login(peer)) == {"tasks": []}
        fixture.provision("task-owner", enabled=False)
        tasks(fixture, session, status=401)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-calendar-tasks-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Calendar task API verification passed.")


if __name__ == "__main__":
    main()
