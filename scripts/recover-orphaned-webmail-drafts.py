#!/usr/bin/env python3
"""Report orphaned hosted drafts. Stop all Maildir writers before using --apply."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import stat


MAX_HEADERS = 128 * 1024
DRAFT_ID = re.compile(r"[A-Za-z0-9-]{16,64}\Z")
DRAFT_MARKER = re.compile(rb"<draft\.([A-Za-z0-9-]{16,64})@")


def candidates(db, mailbox):
    rows = db.execute(
        """SELECT d.id, d.payload, d.revision FROM webmail_records d
           WHERE d.username=? AND d.kind='draft' AND d.state='saved'
             AND NOT EXISTS (SELECT 1 FROM webmail_records p
                             WHERE p.username=d.username AND p.id=d.id
                               AND p.kind IN ('draft-edit','draft-expunge'))
             AND NOT EXISTS (SELECT 1 FROM webmail_records o
                             WHERE o.username=d.username AND o.kind='outbox'
                               AND o.state IN ('pending','sending','unknown')
                               AND json_extract(CASE WHEN json_valid(o.payload) THEN o.payload END,
                                                '$.message.draftId')=d.id)""", (mailbox,),
    )
    for draft_id, payload, revision in rows:
        try:
            draft = json.loads(payload)
        except (ValueError, TypeError):
            continue
        if not isinstance(draft, dict) or not DRAFT_ID.fullmatch(draft_id):
            continue
        message, uid, folder = (draft.get(key) for key in ("message", "uid", "folder"))
        if (not isinstance(message, dict) or message.get("draftId") != draft_id
                or type(uid) is not int or uid < 1 or not isinstance(folder, str) or not folder):
            continue
        assigned = db.execute("SELECT filename FROM imap_uids WHERE username=? AND mailbox=? AND uid=?",
                              (mailbox, folder, uid)).fetchone()
        yield draft_id, payload, revision, assigned[0] if assigned else None


def header(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("A message path is not a regular file")
        data = stream.read(MAX_HEADERS + 1)
    stops = [end for separator in (b"\r\n\r\n", b"\n\n") if (end := data.find(separator)) >= 0]
    if stops:
        return data[:min(stops)]
    if len(data) > MAX_HEADERS:
        raise ValueError("Cannot verify a message with an incomplete header")
    return data


def live_identities(roots):
    names, markers = set(), set()

    def unavailable(error):
        raise error

    for root in roots:
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise ValueError("The full-address Maildir must be present as an account directory")
        for directory, _, files in os.walk(root, followlinks=False, onerror=unavailable):
            for filename in files:
                basename = filename.split(":2,", 1)[0]
                if not basename.endswith(".eml"):
                    continue
                names.add(basename)
                markers.update(match.decode("ascii") for match in DRAFT_MARKER.findall(
                    header(Path(directory) / filename),
                ))
    return names, markers


def recover(db, root, mailbox, apply):
    if not db.execute("SELECT 1 FROM provisioned_mailboxes p JOIN users u ON u.id=p.user_id "
                      "WHERE p.mailbox=? AND u.username=?", (mailbox, mailbox)).fetchone():
        raise ValueError("Mailbox is not a managed account")
    drafts = list(candidates(db, mailbox))
    if not drafts:
        return []
    roots = [root / mailbox]
    # Older native layouts can retain a moved copy under a local-part root.
    alternate = root / mailbox.split("@", 1)[0]
    if alternate.exists() or alternate.is_symlink():
        roots.append(alternate)
    names, markers = live_identities(roots)
    orphaned = []
    for draft_id, payload, revision, basename in drafts:
        # An older IMAP session may already have pruned the UID inventory.
        # An empty account provides independent evidence of absence. With
        # remaining files and no mapping, keep the ambiguous record.
        if draft_id in markers or basename in names or (basename is None and names):
            continue
        orphaned.append(draft_id)
        if apply:
            result = db.execute("DELETE FROM webmail_records "
                                "WHERE username=? AND kind='draft' AND id=? AND revision=? AND payload=?",
                                (mailbox, draft_id, revision, payload))
            if result.rowcount != 1:
                raise ValueError("Draft changed during recovery")
    return orphaned


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--mail-root", type=Path, required=True)
    parser.add_argument("--mailbox", required=True)
    parser.add_argument("--apply", action="store_true", help="Remove verified stale records while Mail is stopped")
    args = parser.parse_args()
    if not re.fullmatch(r"[^/@\\\s]+@[^/@\\\s]+", args.mailbox):
        parser.error("--mailbox must be a full address")
    try:
        database = args.database.resolve(strict=True)
        root = args.mail_root.resolve(strict=True)
        mode = "rw" if args.apply else "ro"
        with closing(sqlite3.connect(database.as_uri() + f"?mode={mode}", uri=True)) as db, db:
            db.execute("BEGIN IMMEDIATE" if args.apply else "BEGIN")
            verified = recover(db, root, args.mailbox, args.apply)
    except (OSError, ValueError, sqlite3.Error) as error:
        parser.exit(1, f"Draft recovery failed: {error}\n")
    print(json.dumps({"mode": "applied" if args.apply else "report", "draftIds": verified}))


if __name__ == "__main__":
    main()
