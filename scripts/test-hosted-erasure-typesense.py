#!/usr/bin/env python3
"""Reconcile one reserved mailbox against a disposable real Typesense server."""

import argparse
from contextlib import closing, contextmanager
from hashlib import sha256
import json
from pathlib import Path
import runpy
import secrets
import socket
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

fixtures = runpy.run_path(str(Path(__file__).with_name("test-hosted-operator.py")))
Fixture, cli, expect_smtp = (fixtures[key] for key in ("Fixture", "cli", "expect_smtp"))
COLLECTIONS = ("messages", "messages_v2", "messages_v3")
HOST = "127.0.0.1"


def available_port():
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


class Typesense:
    def __init__(self, binary, directory):
        self.binary = binary
        self.directory = directory
        self.port = available_port()
        self.key = secrets.token_hex(18)

    def request(self, path, method="GET", data=None):
        body = None if data is None else json.dumps(data).encode()
        request = Request(f"http://{HOST}:{self.port}{path}", data=body, method=method, headers={
            "X-TYPESENSE-API-KEY": self.key, "Content-Type": "application/json",
        })
        with urlopen(request, timeout=5) as response:
            return response.read()

    @contextmanager
    def running(self):
        self.directory.mkdir()
        peer_port = available_port()
        with (self.directory.parent / "typesense.log").open("wb") as log:
            process = subprocess.Popen([
                str(self.binary), f"--data-dir={self.directory}", f"--api-key={self.key}",
                f"--api-address={HOST}", f"--api-port={self.port}",
                f"--peering-address={HOST}", f"--peering-port={peer_port}",
            ], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    try:
                        if json.loads(self.request("/health"))["ok"]:
                            break
                    except OSError:
                        if process.poll() is not None:
                            raise RuntimeError(f"Typesense exited with {process.returncode}") from None
                    time.sleep(.15)
                else:
                    raise RuntimeError("Disposable Typesense did not become healthy")
                yield self
            finally:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    def create_collection(self, name):
        self.request("/collections", "POST", {"name": name, "fields": [
            {"name": "username", "type": "string", "facet": True},
            {"name": "mailbox", "type": "string", "facet": True},
            {"name": "filename", "type": "string"},
            {"name": "subject", "type": "string"},
        ]})

    def put(self, collection, owner, filename, *, document_id=None):
        identity = "\0".join((owner, "INBOX", filename)).encode()
        item = {"id": document_id or sha256(identity).hexdigest()[:32], "username": owner,
                "mailbox": "INBOX", "filename": filename, "subject": "Disposable search fixture"}
        self.request(f"/collections/{collection}/documents", "POST", item)
        return item

    def documents(self, collection):
        return {item["id"]: item for item in map(json.loads, self.request(
            f"/collections/{collection}/documents/export").splitlines())}


def success(result):
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def verify(test, engine):
    test.env.update(TYPESENSE_API_KEY=engine.key, TYPESENSE_HOST=HOST, TYPESENSE_PORT=str(engine.port))
    database = test.directory / "smtp.db"
    path = test.directory / "review.json"
    with test.daemon():
        target = test.provision("erase.search")
        peer = test.provision("erase-search")
        expect_smtp(test.deliver(target, subject="Erasure Typesense target"), 250)
        expect_smtp(test.deliver(peer, subject="Erasure Typesense peer"), 250)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                if {item["username"] for item in engine.documents("messages_v3").values()} == {target, peer}:
                    break
            except HTTPError as error:
                if error.code != 404:
                    raise
            time.sleep(.15)
        else:
            raise AssertionError("Mail did not index both SMTP-delivered messages")

        for collection in COLLECTIONS[:2]:
            engine.create_collection(collection)
            engine.put(collection, target, "target.eml")
            engine.put(collection, peer, "peer.eml")
            engine.put(collection, target.upper(), "case-only.eml")
        for number in range(65):
            engine.put("messages_v2", target, f"batch-{number}.eml")

        test.provision("erase.search", enabled=False)
        actor = test.specs[target]["actor"]
        case = "typesense-erasure-test"
        inventory = success(cli(test, "hosted-erasure-inventory", target, actor, case))
        review = {
            "version": 1, "request_id": "typesense-erasure-request", "mailbox": target, "assignment_actor": actor,
            "case_reference": case, "inventory_audit_id": inventory["audit_id"],
            "retention_disposition": "cleared", "export_disposition": "not_requested",
            "evidence": dict.fromkeys(("authorization_reference", "retention_reference", "backup_reference",
                                       "billing_reference", "search_reference", "export_resolution_reference"), "fixture-case"),
        }
        path.write_text(json.dumps(review))
        path.chmod(0o600)
        approved = success(cli(test, "hosted-erasure-review", str(path)))["audit_id"]
        start = success(cli(test, "hosted-erasure-begin", str(path), str(approved)))["audit_id"]

        def erase(*, port=engine.port, env=None):
            return cli(test, "hosted-erasure-typesense", str(path), str(start), HOST, str(port), env=env)

        def refuse(error, **kwargs):
            result = erase(**kwargs)
            assert result.returncode and not result.stdout and error in result.stderr, result

        refuse("MaildirWriterActive")

    original = {name: engine.documents(name) for name in COLLECTIONS}
    survivors = {name: {key: item for key, item in rows.items() if item["username"] != target}
                 for name, rows in original.items()}
    assert all(len(survivors[name]) == (1 if name == "messages_v3" else 2) for name in COLLECTIONS)

    refuse("ErasureTypesenseEndpointMismatch", port=engine.port + 1 if engine.port < 65535 else engine.port - 1)
    refuse("ErasureMaildirPending")
    success(cli(test, "hosted-erasure-maildir", str(path), str(start)))
    refuse("ErasureLocalSearchPending")
    success(cli(test, "hosted-erasure-search", str(path), str(start)))

    with closing(sqlite3.connect(database)) as db:
        def journal():
            return db.execute("""SELECT completion_audit_id FROM hosted_erasure_typesense_steps
                                 WHERE start_audit_id=?""", (start,)).fetchone()

        def work(table):
            return db.execute(f"SELECT user_id,folder FROM {table} ORDER BY user_id,folder").fetchall()

        ids = dict(db.execute("SELECT username,id FROM users WHERE username IN (?,?)", (target, peer)))
        with db:
            db.executemany("INSERT INTO mail_search_pending(user_id,folder,basename,short_root) VALUES (?,?,?,0)",
                           [(ids[target], "INBOX", "target.eml"), (ids[peer], "Archive", "peer.eml")])
        initial_pending = [(ids[target], "INBOX"), (ids[peer], "Archive")]
        initial_checkpoints = work("mail_search_checkpoints")
        assert all(row in initial_checkpoints for row in initial_pending)

        refuse("ErasureTypesenseUnavailable", env=dict(test.env, TYPESENSE_API_KEY="invalid-key"))
        malformed = engine.put("messages_v2", target, "bad.eml", document_id="unverified-document")
        refuse("ErasureTypesenseDocumentUnverified")
        assert not journal() and work("mail_search_pending") == initial_pending
        assert engine.documents("messages") == original["messages"]
        engine.request(f"/collections/messages_v2/documents/{malformed['id']}", "DELETE")

        with db:
            db.execute("""CREATE TRIGGER interrupt_typesense_audit BEFORE INSERT ON audit_log
                          WHEN NEW.action='hosted.erasure.typesense.removed'
                          BEGIN SELECT RAISE(ABORT,'interrupted before receipt'); END""")
        refuse("StepFailed")
        assert journal() == (None,)
        assert work("mail_search_pending") == initial_pending
        assert work("mail_search_checkpoints") == initial_checkpoints
        assert {name: engine.documents(name) for name in COLLECTIONS} == survivors
        with db:
            db.execute("DROP TRIGGER interrupt_typesense_audit")

        receipt = success(erase())
        assert receipt["state"] == "typesense_removed_other_stores_pending"
        assert receipt["mailbox"] == target and receipt["start_audit_id"] == start
        assert receipt["endpoint"] == f"{HOST}:{engine.port}"
        assert [item["name"] for item in receipt["collections"]] == list(COLLECTIONS)
        assert all(item["created_at"] > 0 for item in receipt["collections"])
        assert journal() == (receipt["audit_id"],)
        assert db.execute("SELECT id FROM audit_log WHERE action='hosted.erasure.typesense.removed'").fetchall() == [journal()]
        assert work("mail_search_pending") == [(ids[peer], "Archive")]
        assert work("mail_search_checkpoints") == [row for row in initial_checkpoints if row[0] == ids[peer]]
        assert success(erase()) == receipt

        # An already completed operation never hides reintroduced search data.
        restored = engine.put("messages", target, "unexpected-restore.eml")
        refuse("ErasureTypesenseDocumentsRemain")
        assert engine.documents("messages")[restored["id"]] == restored
        engine.request(f"/collections/messages/documents/{restored['id']}", "DELETE")
        assert success(erase()) == receipt

    with test.daemon():
        expect_smtp(test.deliver(target, subject="Reserved address"), 550)
        assert test.api(test.login(peer), "messages?folder=INBOX")[0] == 200
    assert {name: engine.documents(name) for name in COLLECTIONS} == survivors

    # These collection changes are confined to the disposable search service.
    engine.request("/collections/messages_v2", "DELETE")
    refuse("ErasureTypesenseCollectionChanged")
    engine.request("/aliases/messages_v2", "PUT", {"collection_name": "messages_v3"})
    refuse("ErasureTypesenseCollectionAlias")
    assert engine.documents("messages_v3") == survivors["messages_v3"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--typesense-server", required=True, type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="mail-erase-typesense-") as directory:
        root = Path(directory)
        with Typesense(args.typesense_server, root / "typesense").running() as engine:
            fixture_root = root / "mail-fixture"
            fixture_root.mkdir()
            verify(Fixture(args.binary.resolve(strict=True), fixture_root, staging=True), engine)
    print("Verified Typesense active and legacy erasure, collision isolation, batch boundaries, and remote/local retry.")
