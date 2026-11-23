#!/usr/bin/env python3
"""Verify expiring file links, download policy, and shared hosted quota over TLS."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
from pathlib import Path
import runpy
import secrets
import sqlite3
import tempfile
import time
from urllib.parse import urlencode, urlsplit


support = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture, request = support["Fixture"], support["request"]
MIB = 1024 * 1024
MAX_FILE = 24 * MIB
API = "/webmail/api/file-links"
PUBLIC = "/webmail/public/file-link"


def verify(fixture):
    def upload(session, payload, *, upload_id=None, filename="Design proofs.bin", lifetime=3600, status=201):
        upload_id = upload_id or secrets.token_hex(16)
        query = urlencode({"filename": filename, "uploadId": upload_id, "lifetime": lifetime})
        actual, _, data = request(fixture.webmail + API + "?" + query, payload,
                                  {**session, "Content-Type": "application/octet-stream"},
                                  context=fixture.tls_context, timeout=60)
        assert actual == status, (actual, data)
        return upload_id, json.loads(data)

    def oversized_header(session, size):
        server = urlsplit(fixture.webmail)
        connection = http.client.HTTPSConnection(server.hostname, server.port, context=fixture.tls_context, timeout=10)
        try:
            connection.request("POST", API, headers={**session, "Content-Length": str(size)})
            response = connection.getresponse()
            assert response.status == 413, (response.status, response.read())
        finally:
            connection.close()

    def public(token, *, download=False, status=200):
        payload = ("token=" + token).encode() if download else {"token": token}
        headers = {"Origin": fixture.webmail}
        if download:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Origin"] = "null"
        actual, headers, data = request(fixture.webmail + PUBLIC + ("/download" if download else ""), payload,
                                        headers, context=fixture.tls_context, timeout=60)
        assert actual == status, (actual, len(data))
        assert headers["Cache-Control"] == "no-store" and "Set-Cookie" not in headers
        return (headers, data) if download and status == 200 else json.loads(data)

    def list_links(session, status=200):
        actual, links = fixture.api(session, "file-links")
        assert actual == status, (actual, links)
        return links

    def revoke(session, upload_id, status=200):
        actual, result = fixture.api(session, "file-links/" + upload_id, method="DELETE")
        assert actual == status, (actual, result)
        return result

    with fixture.daemon():
        owner = fixture.provision("file-owner", quota=128 * MIB)
        peer = fixture.provision("file-peer", quota=MIB)
        session, other = fixture.login(owner), fixture.login(peer)
        list_links({}, 401)
        upload({}, b"secret", status=401)
        upload(dict(other, **{"X-Webmail-Account": owner}), b"secret", status=409)
        upload(dict(session, Origin="https://foreign.example.test"), b"secret", status=403)
        upload(session, b"", status=400)
        upload(session, b"secret", filename="folder/secret", status=400)
        upload(session, b"secret", lifetime=3601, status=400)
        oversized_header(session, MAX_FILE + 1)
        oversized_header(other, MIB + 1)

        actual, limits = fixture.api(session, "config")
        assert actual == 200 and limits["maxFileBytes"] < limits["maxFileLinkBytes"] == MAX_FILE
        contents = bytes(range(256)) * (MAX_FILE // 256)
        upload_id, issued = upload(session, contents, filename="Design proofs — final.bin")
        assert issued["file"]["size"] == len(contents) and len(issued["token"]) == 64
        assert abs(issued["file"]["expires_at"] - time.time() - 3600) < 10
        assert public(issued["token"]) == issued["file"]
        headers, downloaded = public(issued["token"], download=True)
        assert downloaded == contents
        assert headers["Content-Type"] == "application/octet-stream"
        assert headers["Content-Security-Policy"] == "sandbox" and headers["X-Content-Type-Options"] == "nosniff"
        assert headers["Content-Disposition"].startswith("attachment;") and "%E2%80%94" in headers["Content-Disposition"]
        upload(session, b"retry", upload_id=upload_id, status=409)
        assert list_links(session) == {"links": [{"id": upload_id, **issued["file"]}]}
        assert list_links(other) == {"links": []}
        revoke(other, upload_id, 404)
        revoke(dict(session, Origin="https://foreign.example.test"), upload_id, 403)
        assert request(fixture.webmail + "/webmail/public/snapshot", {"token": issued["token"]},
                       context=fixture.tls_context)[0] == 404
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            assert db.execute("SELECT token_hash FROM mail_file_links WHERE id=?", (upload_id,)).fetchone() == (hashlib.sha256(issued["token"].encode()).hexdigest(),)

        full_id, _ = upload(other, b"x" * MIB)
        upload(other, b"x", status=507)
        assert fixture.deliver(peer)[0] >= 400
        with fixture.imap(peer) as imap:
            code, response = imap.append("INBOX", None, None, b"Subject: quota race\r\n\r\nTest\r\n")
            assert code == "NO" and b"OVERQUOTA" in response[0], (code, response)
        assert revoke(other, full_id) == {"revoked": True}
        assert fixture.deliver(peer)[0] == 250
        remaining = MIB - fixture.bytes(peer)

        def compete(_):
            query = urlencode({"filename": "Exact remainder.bin", "uploadId": secrets.token_hex(16), "lifetime": 3600})
            return request(fixture.webmail + API + "?" + query, b"x" * remaining,
                           {**other, "Content-Type": "application/octet-stream"}, context=fixture.tls_context)[0]

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(compete, (0, 1)))
        assert sorted(results) == [201, 507], results

    with fixture.daemon():
        session = fixture.login(owner)
        assert public(issued["token"]) == issued["file"]
        expired_id, expired = upload(session, b"will expire")
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            db.execute("UPDATE mail_file_links SET expires_at=? WHERE id=?", (int(time.time()), expired_id))
        unavailable = public(expired["token"], status=404)
        assert public(expired["token"], download=True, status=404) == unavailable
        assert len(list_links(session)["links"]) == 1
        assert revoke(session, upload_id) == {"revoked": True}
        assert public(issued["token"], download=True, status=404) == unavailable
        assert public("0" * 64, status=404) == unavailable

        # Seed an account one byte below its file-link budget using valid-sized rows.
        with sqlite3.connect(fixture.directory / "smtp.db") as db:
            db.executemany("""
                INSERT INTO mail_file_links(user_id,id,token_hash,filename,data,size,expires_at)
                SELECT id, ?, ?, 'Fixture.bin', zeroblob(?), ?, ? FROM users WHERE username=?
            """, [(secrets.token_hex(16), secrets.token_hex(32), size, size, int(time.time()) + 3600, owner)
                  for size in (MAX_FILE, MAX_FILE, MAX_FILE, MAX_FILE - 1)])
        _, at_limit = upload(session, b"x")
        _, full = upload(session, b"x", status=507)
        assert full["error"] == "file_link_storage_full"
        fixture.provision("file-owner", quota=128 * MIB, enabled=False)
        assert public(at_limit["token"], status=404) == unavailable
        list_links(session, 401)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-file-links-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("File-link HTTPS verification passed.")


if __name__ == "__main__":
    main()
