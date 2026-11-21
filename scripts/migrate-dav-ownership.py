#!/usr/bin/env python3
"""Assign individually verified legacy DAV collections to real Mail accounts."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys


TABLES = {
    "calendar": "dav_calendars",
    "address_book": "dav_addressbooks",
}


def read_assignments(path):
    rows = json.loads(path.read_text())
    if not isinstance(rows, list):
        raise ValueError("The assignment file must be a JSON array.")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"kind", "id", "mailbox"}:
            raise ValueError("Each assignment must contain kind, id, and mailbox.")
        kind, collection_id, mailbox = row["kind"], row["id"], row["mailbox"]
        if not isinstance(kind, str) or kind not in TABLES:
            raise ValueError("Collection kind must be calendar or address_book.")
        if type(collection_id) is not int or not 0 < collection_id <= 2**63 - 1:
            raise ValueError("Collection IDs must be positive SQLite integers.")
        if not isinstance(mailbox, str) or not mailbox or mailbox != mailbox.strip():
            raise ValueError("Every assignment requires an exact mailbox username.")
        key = (kind, collection_id)
        if key in seen:
            raise ValueError(f"Duplicate assignment for {kind} {collection_id}.")
        seen.add(key)
    return rows


def prepare(mail, dav, assignments):
    has_registry = dav.execute(
        "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'dav_users'"
    ).fetchone() is not None
    pending = []
    for row in assignments:
        kind, collection_id, mailbox = row["kind"], row["id"], row["mailbox"]
        account = mail.execute(
            "SELECT id FROM users WHERE username = ? AND enabled != 0",
            (mailbox,),
        ).fetchone()
        if account is None:
            raise ValueError(f"{kind} {collection_id} names a missing or disabled mailbox.")
        mailbox_id = account[0]
        if has_registry:
            query = f"""SELECT dav_users.id, dav_users.mailbox_id
                        FROM {TABLES[kind]} AS collection
                        LEFT JOIN dav_users ON dav_users.id = collection.user_id
                        WHERE collection.id = ?"""
        else:
            query = f"SELECT NULL, NULL FROM {TABLES[kind]} WHERE id = ?"
        collection = dav.execute(query, (collection_id,)).fetchone()
        if collection is None:
            raise ValueError(f"{kind} {collection_id} does not exist.")
        existing_owner, existing_mailbox = collection
        if existing_owner is not None:
            if existing_mailbox != mailbox_id:
                raise ValueError(f"{kind} {collection_id} already has a different registered owner.")
            continue
        pending.append((kind, collection_id, mailbox, mailbox_id))
    return pending


def apply(dav, pending):
    dav.execute(
        """CREATE TABLE IF NOT EXISTS dav_users (
               id INTEGER PRIMARY KEY, username TEXT NOT NULL, mailbox_id INTEGER UNIQUE
           )"""
    )
    dav.execute(
        """CREATE UNIQUE INDEX IF NOT EXISTS idx_dav_users_local_name
           ON dav_users(username) WHERE mailbox_id IS NULL"""
    )
    next_owner = dav.execute(
        """SELECT coalesce(max(id), 0) + 1
           FROM (
               SELECT id FROM dav_users
               UNION ALL SELECT user_id FROM dav_calendars
               UNION ALL SELECT user_id FROM dav_addressbooks
           )"""
    ).fetchone()[0]
    for kind, collection_id, mailbox, mailbox_id in pending:
        owner = dav.execute(
            "SELECT id FROM dav_users WHERE mailbox_id = ?", (mailbox_id,)
        ).fetchone()
        if owner is None:
            owner_id = next_owner
            if type(owner_id) is not int or owner_id > 2**63 - 1:
                raise ValueError("DAV owner IDs are exhausted.")
            next_owner += 1
            dav.execute(
                "INSERT INTO dav_users (id, username, mailbox_id) VALUES (?, ?, ?)",
                (owner_id, mailbox, mailbox_id),
            )
        else:
            owner_id = owner[0]
        dav.execute(
            f"UPDATE {TABLES[kind]} SET user_id = ? WHERE id = ?",
            (owner_id, collection_id),
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mail-db", type=Path, required=True)
    parser.add_argument("--dav-db", type=Path, required=True)
    parser.add_argument("--assignments", type=Path, required=True)
    parser.add_argument("--apply", action="store_true",
                        help="Write assignments during an offline maintenance window.")
    args = parser.parse_args()
    try:
        assignments = read_assignments(args.assignments)
        mail_uri = f"{args.mail_db.resolve().as_uri()}?mode=ro"
        mode = "rw" if args.apply else "ro"
        dav_uri = f"{args.dav_db.resolve().as_uri()}?mode={mode}"
        with closing(sqlite3.connect(mail_uri, uri=True)) as mail, closing(sqlite3.connect(dav_uri, uri=True)) as dav:
            mail.execute("BEGIN")
            dav.execute("BEGIN IMMEDIATE" if args.apply else "BEGIN")
            pending = prepare(mail, dav, assignments)
            if args.apply:
                apply(dav, pending)
                dav.commit()
                print(f"Assigned {len(pending)} legacy DAV collection(s).")
            else:
                print(f"Validated {len(pending)} pending and {len(assignments) - len(pending)} existing assignment(s).")
    except (OSError, ValueError, sqlite3.Error) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
