#!/usr/bin/env python3
"""Import selected IMAP folders into Mail using two mailbox-scoped logins."""

import argparse
import base64
from contextlib import contextmanager, suppress
from datetime import datetime
import fcntl
import getpass
import hashlib
import imaplib
import json
import locale
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import sys


MAX_MESSAGE_BYTES = 50 * 1024 * 1024
UID_WINDOW = 20_000
MAX_UID = (1 << 32) - 1
SYSTEM_FLAGS = {flag.lower(): flag for flag in (
    b"\\Seen", b"\\Answered", b"\\Flagged", b"\\Deleted", b"\\Draft",
)}
LIST_ROW = re.compile(rb'^\(([^)]*)\) (?:NIL|"(?:[^"\\]|\\.)*") (.+)$', re.IGNORECASE)
INTERNAL_DATE = re.compile(rb'\bINTERNALDATE ("[^"]+")', re.IGNORECASE)
UID = re.compile(rb'\bUID ([0-9]+)', re.IGNORECASE)
SIZE = re.compile(rb'\bRFC822\.SIZE ([0-9]+)', re.IGNORECASE)
LITERAL = re.compile(rb"\bBODY\[\] \{([0-9]+)\}$", re.IGNORECASE)


class TransferError(Exception):
    """An operation failed without exposing credentials or a server response."""


class Session(imaplib.IMAP4_SSL):
    def read(self, size):
        if size > MAX_MESSAGE_BYTES:
            raise self.abort("IMAP literal exceeds the import limit")
        return super().read(size)

    def append_message(self, folder, flags, date, raw):
        # imaplib.append() rewrites line endings. Forward the source literal verbatim.
        self.literal = raw
        return self._simple_command("APPEND", quoted(folder), flags, date)


def report(event, **fields):
    print(json.dumps({"event": event, **fields}, ensure_ascii=True), flush=True)


def quoted(value):
    if not value or any(byte in value for byte in (b"\r", b"\n", b"\x00")):
        raise TransferError("Invalid IMAP mailbox name")
    return b'"' + value.replace(b"\\", b"\\\\").replace(b'"', b'\\"') + b'"'


def decode_folder(value):
    # IMAP4rev1 convention uses modified UTF-7. Some servers send UTF-8 directly.
    if not value.isascii():
        return value.decode("utf-8")

    def decode(match):
        encoded = match[1].replace(b",", b"/")
        if not encoded:
            return b"&"
        raw = base64.b64decode(encoded + b"=" * (-len(encoded) % 4), validate=True)
        return raw.decode("utf-16-be").encode("utf-8")

    return re.sub(rb"&([A-Za-z0-9+,]*)-", decode, value).decode("utf-8")


def list_folders(client, *, decode_names):
    status, rows = client.list()
    if status != "OK":
        raise TransferError("Could not list IMAP folders")
    folders = {}
    for row in rows:
        if row is None or row == b"":
            continue
        literal = isinstance(row, tuple)
        info = LIST_ROW.fullmatch(row[0] if literal else row)
        if info is None:
            raise TransferError("Invalid IMAP LIST response")
        attributes = info[1].lower().split()
        if b"\\noselect" in attributes or b"\\nonexistent" in attributes:
            continue
        if literal:
            wire_name = row[1]
        elif info[2].startswith(b'"') and info[2].endswith(b'"'):
            wire_name = re.sub(rb'\\(["\\])', rb'\1', info[2][1:-1])
        else:
            wire_name = info[2]
        try:
            name = decode_folder(wire_name) if decode_names else wire_name.decode("utf-8")
        except ValueError as error:
            raise TransferError("Invalid IMAP folder encoding") from error
        if name.upper() == "INBOX":
            name = "INBOX"
        if name in folders and wire_name != folders[name]:
            raise TransferError("Ambiguous IMAP folder names")
        folders[name] = wire_name
    return folders


def selected(client, folder):
    status, rows = client.select(quoted(folder), readonly=True)
    if status != "OK":
        raise TransferError("Could not open IMAP folder read-only")
    _, validity = client.response("UIDVALIDITY")
    _, next_uid = client.response("UIDNEXT")
    try:
        count = int(rows[0])
        generation = int(validity[0])
        next_value = int(next_uid[0]) if next_uid[0] else None
    except (IndexError, TypeError, ValueError) as error:
        raise TransferError("Invalid IMAP folder identity") from error
    if count < 0 or not 0 < generation <= MAX_UID or (next_value is not None and not 0 < next_value <= MAX_UID):
        raise TransferError("Invalid IMAP folder identity")
    return count, generation, next_value


def source_uids(client, count, next_uid):
    if not count:
        return
    if next_uid is None or count <= UID_WINDOW:
        # Small mailboxes can still have widely scattered UIDs after deletions.
        ranges = [(1, next_uid - 1 if next_uid is not None else MAX_UID, "ALL")]
    else:
        bounds = ((start, min(start + UID_WINDOW - 1, next_uid - 1)) for start in range(1, next_uid, UID_WINDOW))
        ranges = ((start, end, f"UID {start}:{end}") for start, end in bounds)
    for start, end, criterion in ranges:
        status, values = client.uid("SEARCH", None, criterion)
        if status != "OK":
            raise TransferError("UID search failed")
        try:
            results = {int(value) for value in (values[0] or b"").split()}
        except (IndexError, TypeError, ValueError) as error:
            raise TransferError("Invalid UID search response") from error
        yield from sorted(uid for uid in results if start <= uid <= end)


def message_info(prefix, uid):
    match = UID.search(prefix)
    if match is None or int(match[1]) != uid:
        return None
    date = INTERNAL_DATE.search(prefix)
    size = SIZE.search(prefix)
    flags = imaplib.ParseFlags(prefix)
    if date is None or size is None or re.search(rb"\bFLAGS \(", prefix, re.IGNORECASE) is None:
        raise TransferError("Message did not include size, flags, and received time")
    try:
        instant = int(datetime.strptime(date[1][1:-1].decode("ascii"), "%d-%b-%Y %H:%M:%S %z").timestamp())
    except ValueError as error:
        raise TransferError("Invalid IMAP received time") from error
    return int(size[1]), date[1], instant, flags


def fetch_message(client, uid):
    # Check the size first so an oversized item can be reported without
    # downloading it or losing the connection for the rest of the folder.
    status, rows = client.uid("FETCH", str(uid), "(UID FLAGS INTERNALDATE RFC822.SIZE)")
    metadata = [info for row in rows if isinstance(row, bytes) and (info := message_info(row, uid))]
    if status != "OK" or len(metadata) != 1:
        raise TransferError("Message disappeared or its metadata could not be read")
    size, date, instant, flags = metadata[0]
    if size <= 0 or size > MAX_MESSAGE_BYTES:
        raise TransferError("Message size is outside the supported range")

    status, rows = client.uid("FETCH", str(uid), "(UID BODY.PEEK[])")
    literals = [index for index, row in enumerate(rows) if isinstance(row, tuple) and LITERAL.search(row[0])]
    if status != "OK" or len(literals) != 1:
        raise TransferError("Could not read one complete message")
    index = literals[0]
    prefix, raw = rows[index]
    # FETCH item order is server-defined. imaplib emits atoms following the
    # body literal as a separate bytes entry.
    after = b""
    if index + 1 < len(rows) and isinstance(rows[index + 1], bytes) and rows[index + 1].startswith((b" ", b")")):
        after = rows[index + 1]
    identity = UID.search(prefix + b" " + after)
    if identity is None or int(identity[1]) != uid or size != len(raw) or int(LITERAL.search(prefix)[1]) != size:
        raise TransferError("IMAP returned different message bytes or size")
    return raw, date, instant, flags


def append_flags(flags, keywords_supported):
    supported = []
    omitted = []
    for flag in flags:
        lower = flag.lower()
        if lower in SYSTEM_FLAGS:
            supported.append(SYSTEM_FLAGS[lower])
        elif lower != b"\\recent":
            valid = 0 < len(flag) <= 255 and all(32 < byte < 127 and byte not in b'(){}%*"\\]' for byte in flag)
            if keywords_supported and valid:
                supported.append(flag)
            else:
                omitted.append(flag.decode("utf-8", errors="replace"))
    return b"(" + b" ".join(supported) + b")", omitted


@contextmanager
def private_file(path):
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags, 0o600)
    try:
        file = os.fstat(fd)
        if not stat.S_ISREG(file.st_mode) or file.st_uid != os.getuid() or file.st_mode & 0o077 or file.st_nlink != 1:
            raise TransferError("The checkpoint must be a private regular file owned by this user")
        yield fd
    finally:
        os.close(fd)


@contextmanager
def journal(path, identity):
    # Use a separate file so the operator lock does not conflict with SQLite's
    # own locking on macOS. Keep both files in an operator-owned directory.
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise TransferError("Keep the checkpoint in a directory owned and writable only by this user")
    with private_file(path.with_name(path.name + ".lock")) as lock, private_file(path):
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise TransferError("Another process holds this checkpoint") from error
        db = sqlite3.connect(path)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS job (id INTEGER PRIMARY KEY CHECK (id = 1), identity TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS folders (
                    name TEXT PRIMARY KEY, source_validity INTEGER NOT NULL, destination_validity INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages (
                    folder TEXT NOT NULL, uid INTEGER NOT NULL, status TEXT NOT NULL,
                    digest TEXT, received INTEGER, destination_floor INTEGER, destination_uid INTEGER,
                    PRIMARY KEY (folder, uid)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS message_destination_uid
                    ON messages(folder, destination_uid) WHERE destination_uid IS NOT NULL;
            """)
            with db:
                db.execute("INSERT OR IGNORE INTO job VALUES (1, ?)", (identity,))
                if db.execute("SELECT identity FROM job WHERE id = 1").fetchone()[0] != identity:
                    raise TransferError("This checkpoint belongs to a different account pair or folder map")
            yield db
        finally:
            db.close()


def open_destination(client, folder, *, create):
    if create:
        client.create(quoted(folder))
    state = selected(client, folder)
    if state[2] is None:
        raise TransferError("Destination did not provide UIDNEXT")
    return state


def resume_folder(db, name, source_validity, destination_validity):
    with db:
        db.execute("INSERT OR IGNORE INTO folders VALUES (?, ?, ?)", (name, source_validity, destination_validity))
        saved = db.execute("SELECT source_validity, destination_validity FROM folders WHERE name = ?", (name,)).fetchone()
        if saved != (source_validity, destination_validity):
            raise TransferError("UIDVALIDITY changed since the previous import")


def resolve_message(db, destination, name, source_uid, result, destination_next):
    row = db.execute(
        "SELECT status, digest, received, destination_floor FROM messages WHERE folder = ? AND uid = ?",
        (name, source_uid),
    ).fetchone()
    if row is None or row[0] != "uncertain":
        raise TransferError("The source UID does not have an uncertain APPEND")
    if result == "uncommitted":
        if destination_next != row[3]:
            raise TransferError("Destination UIDNEXT changed. Identify the accepted copy before resuming")
        with db:
            db.execute("DELETE FROM messages WHERE folder = ? AND uid = ?", (name, source_uid))
        report("resolved_uncommitted", source=name, uid=source_uid)
        return

    destination_uid = int(result)
    if destination_uid < row[3]:
        raise TransferError("The destination UID predates this attempt")
    if db.execute("SELECT 1 FROM messages WHERE folder = ? AND destination_uid = ?", (name, destination_uid)).fetchone():
        raise TransferError("This destination UID is already attributed to another source message")
    raw, _, instant, _ = fetch_message(destination, destination_uid)
    if instant != row[2] or hashlib.sha256(raw).hexdigest() != row[1]:
        raise TransferError("The destination UID does not match the attempted message bytes and received time")
    with db:
        db.execute("UPDATE messages SET status = 'done', destination_uid = ? WHERE folder = ? AND uid = ?",
                   (destination_uid, name, source_uid))
    report("resolved", source=name, uid=source_uid, destination_uid=destination_uid)


def import_folder(db, source, destination, source_name, destination_name, wire_target, source_state, destination_state,
                  keywords_supported):
    pending = db.execute("SELECT uid, destination_floor FROM messages WHERE folder = ? AND status = 'uncertain'",
                         (source_name,)).fetchone()
    if pending:
        report("error", source=source_name, uid=pending[0], destination=destination_name, destination_floor=pending[1],
               reason="Resolve the uncertain APPEND before continuing this folder", resolution_required=True)
        return 1
    bytes_moved = imported = skipped = errors = 0
    destination_validity, destination_floor = destination_state[1:]
    for uid in source_uids(source, source_state[0], source_state[2]):
        previous = db.execute("SELECT status FROM messages WHERE folder = ? AND uid = ?", (source_name, uid)).fetchone()
        if previous == ("done",):
            skipped += 1
            continue
        try:
            raw, date, instant, source_flags = fetch_message(source, uid)
            flags, omitted = append_flags(source_flags, keywords_supported)
        except TransferError as error:
            errors += 1
            report("error", source=source_name, uid=uid, reason=str(error))
            continue

        # Commit before sending APPEND. An aborted connection or process leaves
        # this record for explicit reconciliation, never an automatic retry.
        with db:
            db.execute("INSERT OR REPLACE INTO messages VALUES (?, ?, 'uncertain', ?, ?, ?, NULL)",
                       (source_name, uid, hashlib.sha256(raw).hexdigest(), instant, destination_floor))
        try:
            status, values = destination.append_message(wire_target, flags, date, raw)
        except (imaplib.IMAP4.error, OSError):
            report("error", source=source_name, uid=uid, destination=destination_name, destination_floor=destination_floor,
                   reason="Append outcome is unknown", resolution_required=True)
            raise
        if status != "OK":
            # These are definitive pre-write rejections from Mail. Other
            # outcomes stay uncertain because publication may have begun.
            reply = values[0] or b""
            rejected = reply.upper().startswith((b"[OVERQUOTA]", b"[TOOBIG]", b"[NOPERM]", b"[LIMIT]"))
            if rejected:
                with db:
                    db.execute("DELETE FROM messages WHERE folder = ? AND uid = ?", (source_name, uid))
            errors += 1
            report("error", source=source_name, uid=uid, reason="Destination refused APPEND",
                   resolution_required=not rejected)
            if not rejected:
                break
            continue

        _, receipt = destination.response("APPENDUID")
        try:
            generation, destination_uid = map(int, receipt[0].split())
        except (AttributeError, IndexError, TypeError, ValueError) as error:
            raise TransferError("Destination did not confirm APPENDUID. Verify the last attempt before resuming") from error
        if generation != destination_validity or not destination_floor <= destination_uid <= MAX_UID:
            raise TransferError("Destination did not confirm a UID in the planned mailbox")
        destination_floor = destination_uid + 1
        with db:
            db.execute("UPDATE messages SET status = 'done', destination_uid = ? WHERE folder = ? AND uid = ?",
                       (destination_uid, source_name, uid))
        imported += 1
        bytes_moved += len(raw)
        report("imported", source=source_name, uid=uid, destination=destination_name, destination_uid=destination_uid,
               omitted_flags=omitted)
    report("folder_complete", source=source_name, destination=destination_name, imported=imported,
           skipped=skipped, errors=errors, bytes=bytes_moved)
    return errors


def read_password(name, use_stdin):
    if use_stdin:
        value = sys.stdin.readline(8193)
        if not value.endswith("\n") or len(value) > 8192:
            raise TransferError("Expected one password line per mailbox")
        value = value[:-1]
    else:
        if not sys.stdin.isatty():
            raise TransferError("Use a terminal or supply two password lines on stdin")
        value = getpass.getpass(f"{name} IMAP password: ")
    if not value or "\r" in value or "\n" in value or "\x00" in value:
        raise TransferError("Invalid IMAP password")
    return value


@contextmanager
def connect(args, role):
    host, port, user, cafile = (getattr(args, f"{role}_{field}") for field in ("host", "port", "user", "ca"))
    password = read_password(role.capitalize(), args.password_stdin)
    client = Session(host, port, ssl_context=ssl.create_default_context(cafile=cafile), timeout=30)
    try:
        client.login(user, password)
        del password
        yield client
    finally:
        with suppress(OSError, imaplib.IMAP4.error):
            client.shutdown()


def validate_mapping(folders):
    mapping = {}
    for source, destination in folders:
        source = "INBOX" if source.upper() == "INBOX" else source
        destination = "INBOX" if destination.upper() == "INBOX" else destination
        if (not destination.strip() or destination.startswith(".") or ".." in destination
                or any(char in '/\\"' or ord(char) < 32 or ord(char) == 127 for char in destination)
                or len(destination.encode("utf-8")) > 255
                or destination.casefold() in {"all", "all mail", "starred", "important"}):
            raise TransferError("Map to a real Mail folder with a single safe name")
        if source in mapping or destination.casefold() in (name.casefold() for name in mapping.values()):
            raise TransferError("Each source and destination folder may appear only once")
        mapping[source] = destination
    return mapping


def valid_uid(value):
    return re.fullmatch(r"[0-9]{1,10}", value) is not None and 0 < int(value) <= MAX_UID


def execute(args, mapping, source, destination, db=None, *, keywords_supported=False):
    source_folders = list_folders(source, decode_names=True)
    destination_folders = list_folders(destination, decode_names=False)
    if not mapping:
        for name, wire_name in sorted(source_folders.items()):
            count, generation, _ = selected(source, wire_name)
            report("source_folder", source=name, messages=count, uidvalidity=generation)
        return 0

    if set(mapping) - set(source_folders):
        raise TransferError("A mapped source folder does not exist or is not selectable")
    errors = 0
    for name, target in mapping.items():
        if args.resolve and name != args.resolve[0]:
            continue
        try:
            # Select afresh before each snapshot. BODY.PEEK and EXAMINE leave
            # source flags untouched, including when the job is only a preview.
            source_state = selected(source, source_folders[name])
            wire_target = destination_folders.get(target, target.encode("utf-8"))
            if db is None:
                report("preview", source=name, destination=target, messages=source_state[0],
                       uidvalidity=source_state[1], create=target not in destination_folders)
                continue
            saved = db.execute("SELECT 1 FROM folders WHERE name = ?", (name,)).fetchone()
            if args.resolve and not saved:
                raise TransferError("No import attempts are recorded for this folder")
            if saved and target not in destination_folders:
                raise TransferError("Checkpoint destination folder no longer exists")
            destination_state = open_destination(destination, wire_target, create=target not in destination_folders)
            resume_folder(db, name, source_state[1], destination_state[1])
            if args.resolve:
                _, source_uid, result = args.resolve
                resolve_message(db, destination, name, int(source_uid), result, destination_state[2])
            else:
                errors += import_folder(db, source, destination, name, target, wire_target, source_state,
                                        destination_state, keywords_supported)
        except TransferError as error:
            report("error", source=name, destination=target, reason=str(error))
            errors += 1
    if db is not None:
        pending = db.execute("SELECT count(*) FROM messages WHERE status = 'uncertain'").fetchone()[0]
        report("complete", errors=errors, unresolved=pending)
        return bool(errors or pending)
    return bool(errors)


def main():
    locale.setlocale(locale.LC_TIME, "C")  # IMAP date-times use English month names.
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ("source", "destination"):
        parser.add_argument(f"--{role}-host", required=True)
        parser.add_argument(f"--{role}-port", type=int, default=993)
        parser.add_argument(f"--{role}-user", required=True)
        parser.add_argument(f"--{role}-ca", type=Path)
    parser.add_argument("--folder", action="append", nargs=2, metavar=("SOURCE", "DESTINATION"), default=[])
    parser.add_argument("--state", type=Path, help="Private checkpoint, required for import and resolution")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--apply", action="store_true", help="Create mapped folders and import missing messages")
    modes.add_argument("--resolve", nargs=3, metavar=("SOURCE_FOLDER", "SOURCE_UID", "DESTINATION_UID_OR_UNCOMMITTED"),
                       help="Reconcile an uncertain APPEND before resuming that folder")
    parser.add_argument("--password-stdin", action="store_true", help="Read source and destination passwords in order")
    args = parser.parse_args()
    try:
        mapping = validate_mapping(args.folder)
        source = [args.source_host.lower(), args.source_port, args.source_user]
        destination = [args.destination_host.lower(), args.destination_port, args.destination_user]
        if source[:2] == destination[:2] and source[2].casefold() == destination[2].casefold():
            raise TransferError("Source and destination must be different mailboxes")
        for _, port, user in (source, destination):
            if not 0 < port <= 65535 or not re.fullmatch(r'[^\s(){}%*"\\\x00-\x1f\x7f]+', user, re.ASCII) or not user.isascii():
                raise TransferError("Invalid IMAP account name or port")
        writing = args.apply or args.resolve is not None
        if writing and (not args.state or not mapping):
            raise TransferError("Import and resolution require an explicit folder map and checkpoint")
        if args.resolve:
            name, source_uid, result = args.resolve
            if (name not in mapping or not valid_uid(source_uid)
                    or (result != "uncommitted" and not valid_uid(result))):
                raise TransferError("Resolution requires a mapped folder, a source UID, and a destination UID or 'uncommitted'")
            if not args.state.is_file():
                raise TransferError("The checkpoint for this resolution does not exist")
        with connect(args, "source") as origin, connect(args, "destination") as target:
            if origin.sock.getpeername()[:2] == target.sock.getpeername()[:2] and source[2].casefold() == destination[2].casefold():
                raise TransferError("Source and destination resolve to the same mailbox")
            if not writing:
                return execute(args, mapping, origin, target)
            status, response = target.capability()
            capabilities = {feature for value in response if value for feature in value.upper().split()}
            if status != "OK" or b"UIDPLUS" not in capabilities:
                raise TransferError("The destination must support UIDPLUS to confirm copied messages")
            identity = json.dumps([1, source, destination, sorted(mapping.items())])
            with journal(args.state, identity) as db:
                return execute(args, mapping, origin, target, db, keywords_supported=b"XMAILDIR-KEYWORDS" in capabilities)
    except TransferError as error:
        report("error", reason=str(error))
    except ssl.SSLCertVerificationError:
        report("error", reason="IMAP certificate verification failed")
    except (imaplib.IMAP4.error, OSError, sqlite3.Error, UnicodeError) as error:
        report("error", reason="An IMAP or checkpoint operation did not complete", error_type=type(error).__name__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
