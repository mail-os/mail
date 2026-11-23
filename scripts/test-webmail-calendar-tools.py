#!/usr/bin/env python3
"""Verify opt-in personal Calendar tools over native HTTPS."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import runpy
import tempfile


Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]
ENDPOINT = "calendar-tools"
EMPTY = {"version": 1, "enabled": False, "appearance": "standard", "habits": [], "countdowns": [], "journal": [], "time": []}
DAY = "2028-02-29"


def get(fixture, session, *, display=False, status=200):
    actual, result = fixture.api(session, ENDPOINT + ("?display=1" if display else ""))
    assert actual == status, (actual, result)
    return result


def put(fixture, session, tools, revision, status=200):
    actual, result = fixture.api(session, ENDPOINT, {"tools": tools, "revision": revision}, method="PUT")
    assert actual == status, (actual, result)
    return result


def verify(fixture):
    with fixture.daemon():
        owner, other = fixture.provision("tools-owner"), fixture.provision("tools-peer")
        session, peer = fixture.login(owner), fixture.login(other)
        get(fixture, {}, status=401)
        assert get(fixture, session) == {"revision": 0, "tools": EMPTY}
        assert get(fixture, session, display=True) == {"compact": False}
        portable = {
            "version": 1, "enabled": True, "appearance": "compact",
            "habits": [{"id": "a" * 32, "title": "Practice piano", "days": [DAY, "2028-03-01"]}],
            "countdowns": [{"id": "b" * 32, "title": "Trip", "day": DAY}],
            "journal": [{"day": DAY, "text": "First line\nPrivate second line"}],
            "time": [{"id": "c" * 32, "title": "Piano lesson", "day": DAY, "minutes": 30}],
        }
        put(fixture, dict(session, Origin="https://foreign.example.test"), portable, 0, 403)
        put(fixture, dict(peer, **{"X-Webmail-Account": owner}), portable, 0, 409)
        for key, value in (("version", 2), ("appearance", "unsupported"), ("enabled", 1)):
            invalid = dict(portable, **{key: value})
            assert put(fixture, session, invalid, 0, 400)["error"] == "invalid_personal_tools"
        for key, field, value in (
            ("habits", "days", [DAY, DAY]), ("habits", "days", ["2028-03-01", DAY]),
            ("countdowns", "day", "2027-02-29"), ("countdowns", "title", "🧭" * 101),
            ("journal", "text", "\x00hidden"), ("journal", "text", "x" * 2001),
            ("time", "minutes", 0), ("time", "minutes", 1441), ("time", "id", "A" * 32),
        ):
            invalid = deepcopy(portable)
            invalid[key][0][field] = value
            assert put(fixture, session, invalid, 0, 400)["error"] == "invalid_personal_tools"
        duplicate = deepcopy(portable)
        duplicate["journal"] *= 2
        put(fixture, session, duplicate, 0, 400)
        partial = dict(portable)
        del partial["journal"]
        put(fixture, session, partial, 0, 400)
        oversized = dict(portable, journal=[{"day": DAY, "text": "x" * (512 * 1024)}])
        assert put(fixture, session, oversized, 0, 413)["error"] == "personal_tools_too_large"
        assert put(fixture, session, portable, 0) == {"revision": 1, "tools": portable}
        assert get(fixture, peer) == {"revision": 0, "tools": EMPTY}
        assert get(fixture, session, display=True) == {"compact": True}

        def edit(amount):
            update = deepcopy(portable)
            update["time"][0]["minutes"] = amount
            return fixture.api(session, ENDPOINT, {"revision": 1, "tools": update}, method="PUT")

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(edit, (45, 90)))
        assert sorted(status for status, _ in results) == [200, 409], results
        saved = next(result for status, result in results if status == 200)
        assert saved["revision"] == 2 and saved["tools"]["time"][0]["minutes"] in (45, 90)
        assert get(fixture, session) == saved

    with fixture.daemon():
        session, peer = fixture.login(owner), fixture.login(other)
        assert get(fixture, session) == saved
        exported = get(fixture, session)["tools"]
        disabled = dict(exported, enabled=False)
        assert put(fixture, session, disabled, 2) == {"revision": 3, "tools": disabled}
        assert get(fixture, session, display=True) == {"compact": False}
        assert put(fixture, peer, exported, 0) == {"revision": 1, "tools": exported}
        assert get(fixture, session) == {"revision": 3, "tools": disabled}
        assert get(fixture, peer, display=True) == {"compact": True}
        fixture.provision("tools-owner", enabled=False)
        get(fixture, session, status=401)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-calendar-tools-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Personal Calendar tools API verification passed.")


if __name__ == "__main__":
    main()
