#!/usr/bin/env python3
"""Verify private calendar day labels over the native HTTPS API."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import runpy
import tempfile


Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]
path = "calendar-day-labels"
date = "2028-02-29"


def get(fixture, session, start=date, end=date, status=200):
    actual, result = fixture.api(session, f"{path}?start={start}&end={end}")
    assert actual == status, (actual, result)
    return result


def put(fixture, session, label, revision, day=date, status=200):
    actual, result = fixture.api(session, f"{path}/{day}", {"label": label, "revision": revision}, method="PUT")
    assert actual == status, (actual, result)
    return result


def verify(fixture):
    with fixture.daemon():
        owner = fixture.provision("calendar-owner")
        other = fixture.provision("calendar-peer")
        session, peer = fixture.login(owner), fixture.login(other)
        get(fixture, {}, status=401)
        assert get(fixture, session) == {"labels": []}
        assert get(fixture, session, "2028-01-01", "2028-12-31") == {"labels": []}
        for start, end in (("2028-01-01", "2029-01-01"), ("2028-03-01", date), ("2027-02-29", date)):
            assert get(fixture, session, start, end, 400)["error"] == "invalid_day_label_range"
        put(fixture, dict(session, Origin="https://foreign.example.test"), "Travel", 0, status=403)
        put(fixture, dict(peer, **{"X-Webmail-Account": owner}), "Travel", 0, status=409)
        for invalid in ("", "  ", "Two\nlines", "🧭" * 81, "Null\x00byte"):
            assert put(fixture, session, invalid, 0, status=400)["error"] == "invalid_day_label"
        put(fixture, session, "Travel", 0, day="2027-02-29", status=400)
        longest = "🧭" * 80
        assert put(fixture, session, " " + longest + " ", 0) == {"day": date, "label": longest, "revision": 1}
        assert get(fixture, peer) == {"labels": []}
        assert get(fixture, session, "2028-03-01", "2028-03-01") == {"labels": []}
        assert put(fixture, peer, "Personal day", 0)["revision"] == 1

        def edit(label):
            return fixture.api(session, f"{path}/{date}", {"label": label, "revision": 1}, method="PUT")

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(edit, ("Remote work", "Field visit")))
        assert sorted(status for status, _ in results) == [200, 409], results
        edited = next(result for status, result in results if status == 200)
        assert edited["revision"] == 2 and get(fixture, session) == {"labels": [edited]}
        assert put(fixture, session, None, 2) == {"day": date, "label": None, "revision": 3}
        assert put(fixture, session, "Stale edit", 2, status=409)["error"] == "day_label_changed"
        assert put(fixture, session, "Stale create", 0, status=409)["error"] == "day_label_changed"

    with fixture.daemon():
        session, peer = fixture.login(owner), fixture.login(other)
        assert get(fixture, session) == {"labels": [{"day": date, "label": None, "revision": 3}]}
        assert get(fixture, peer) == {"labels": [{"day": date, "label": "Personal day", "revision": 1}]}
        assert put(fixture, session, "Travel day", 3)["revision"] == 4

    with fixture.daemon():
        assert get(fixture, fixture.login(owner)) == {"labels": [{"day": date, "label": "Travel day", "revision": 4}]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-day-labels-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Calendar day label API verification passed.")


if __name__ == "__main__":
    main()
