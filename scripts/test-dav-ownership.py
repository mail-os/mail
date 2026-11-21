#!/usr/bin/env python3
"""Regression checks for offline assignment of legacy DAV collections."""

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

MIGRATOR = Path(__file__).with_name("migrate-dav-ownership.py")


class OwnershipMigrationTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.mail = root / "smtp.db"
        self.dav = root / "dav.db"
        self.assignments = root / "assignments.json"

        with closing(sqlite3.connect(self.mail)) as connection:
            connection.executescript("""
                CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, enabled INTEGER);
                INSERT INTO users VALUES (5, 'one@example.test', 1), (6, 'two@example.test', 1);
            """)
        # Legacy calendars and address books can carry the same unverified
        # number. Each collection must be assigned independently.
        with closing(sqlite3.connect(self.dav)) as connection:
            connection.executescript("""
                CREATE TABLE dav_calendars (id INTEGER PRIMARY KEY, user_id INTEGER);
                CREATE TABLE dav_addressbooks (id INTEGER PRIMARY KEY, user_id INTEGER);
                INSERT INTO dav_calendars VALUES (1, 7), (2, 7);
                INSERT INTO dav_addressbooks VALUES (1, 7);
            """)

    def migrate(self, rows, apply=False):
        self.assignments.write_text(json.dumps(rows))
        command = [
            sys.executable, str(MIGRATOR),
            "--mail-db", str(self.mail), "--dav-db", str(self.dav),
            "--assignments", str(self.assignments),
        ]
        if apply:
            command.append("--apply")
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def test_dry_run_and_repeatable_selective_assignment(self):
        known = [
            {"kind": "calendar", "id": 1, "mailbox": "one@example.test"},
            {"kind": "address_book", "id": 1, "mailbox": "two@example.test"},
        ]
        before = self.dav.read_bytes()
        result = self.migrate(known)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.dav.read_bytes(), before)
        result = self.migrate(known, apply=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        with closing(sqlite3.connect(self.dav)) as connection:
            self.assertEqual(connection.execute("SELECT * FROM dav_calendars ORDER BY id").fetchall(), [(1, 8), (2, 7)])
            self.assertEqual(connection.execute("SELECT * FROM dav_addressbooks").fetchall(), [(1, 9)])
            self.assertEqual(connection.execute("SELECT mailbox_id FROM dav_users ORDER BY id").fetchall(), [(5,), (6,)])
        after = self.dav.read_bytes()
        result = self.migrate(known, apply=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.dav.read_bytes(), after)

    def test_conflict_does_not_assign_an_earlier_valid_collection(self):
        known = [{"kind": "calendar", "id": 1, "mailbox": "one@example.test"}]
        result = self.migrate(known, apply=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        before = self.dav.read_bytes()
        conflict = [
            {"kind": "calendar", "id": 2, "mailbox": "two@example.test"},
            {"kind": "calendar", "id": 1, "mailbox": "two@example.test"},
        ]
        result = self.migrate(conflict, apply=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("already has a different registered owner", result.stderr)
        self.assertEqual(self.dav.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
