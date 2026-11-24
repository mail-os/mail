#!/usr/bin/env python3
"""Exercise the private proof issuer and the public browser exchange over HTTPS."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from hashlib import sha256
import http.client
import json
from pathlib import Path
import runpy
import sqlite3
import tempfile
import time
from urllib.parse import urlsplit


Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]
origin = "https://app.example.test"
issue_path = "/provisioning/v1/webmail/sign-in"
exchange_path = "/webmail/auth/hosted"


def verify(mail):
    mail.env["SMTP_HOSTED_SIGN_IN_ORIGIN"] = origin
    host = urlsplit(mail.webmail)

    def issue(mailbox, actor=None, authorization=True, expected=201):
        actor = actor or mail.specs[mailbox]["actor"]
        status, headers, raw = mail.http(mail.private + issue_path, {"mailbox": mailbox, "actor": actor},
                                         mail.auth if authorization else {})
        assert status == expected, (status, raw)
        assert headers["Cache-Control"] == "no-store"
        if status == 201:
            result = json.loads(raw)
            assert result["expires_at"] in range(int(time.time()) + 117, int(time.time()) + 121)
            return result["proof"]

    def exchange(proof, source=origin, cookie=None, path=exchange_path):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if source is not None:
            headers["Origin"] = source
        if cookie:
            headers["Cookie"] = cookie
        with closing(http.client.HTTPSConnection(host.hostname, host.port, timeout=10, context=mail.tls_context)) as client:
            client.request("POST", path, f"proof={proof}", headers)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read()

    def me(cookie, status=200):
        code, _, raw = mail.http(mail.webmail + "/webmail/auth/me", headers={"Cookie": cookie}, context=mail.tls_context)
        assert code == status, (code, raw)
        return json.loads(raw)

    def checked_cookie(result):
        status, headers, raw = result
        assert (status, headers.get("Location"), headers.get("Cache-Control"), raw) == (303, "/", "no-store", b"")
        cookie, *attributes = headers["Set-Cookie"].split("; ")
        assert {"HttpOnly", "Secure", "SameSite=Lax", "Path=/"} <= set(attributes)
        assert not any(attribute.startswith("Domain=") for attribute in attributes)
        return cookie

    def proof_hash(proof):
        return sha256(proof.encode()).digest()

    with mail.daemon(), closing(sqlite3.connect(mail.directory / "smtp.db")) as db:
        first = mail.provision("first-hosted")
        second = mail.provision("second-hosted")
        issue(first, authorization=False, expected=401)
        issue(first, actor=mail.specs[second]["actor"], expected=404)
        assert mail.http(mail.webmail + issue_path, {}, context=mail.tls_context)[0] == 404
        proof = issue(first)
        assert len(proof) == 64
        assert db.execute("SELECT digest FROM hosted_sign_in_proofs").fetchall() == [(proof_hash(proof),)]
        for source in (None, "https://example.net", "https://app.example.test.example.net"):
            assert exchange(proof, source)[0] == 403
        assert exchange(proof, path=exchange_path + "?mailbox=other")[0] == 400
        with db:
            db.execute("""CREATE TRIGGER fixture_session_failure BEFORE INSERT ON webmail_sessions
                       BEGIN SELECT RAISE(ABORT, 'fixture session error'); END""")
        assert exchange(proof)[0] == 503
        with db:
            db.execute("DROP TRIGGER fixture_session_failure")
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(exchange, (proof, proof)))
        assert sorted(status for status, _, _ in results) == [303, 401]
        cookie = checked_cookie(next(result for result in results if result[0] == 303))
        assert me(cookie)["user"]["username"] == first
        assert db.execute("SELECT COUNT(*) FROM hosted_sign_in_proofs WHERE digest=?", (proof_hash(proof),)).fetchone() == (0,)

        replacement = checked_cookie(exchange(issue(second), cookie=cookie))
        assert me(replacement)["user"]["username"] == second
        me(cookie, 401)
        headers = {"Cookie": replacement, "Origin": mail.webmail}
        assert mail.http(mail.webmail + "/webmail/auth/logout", b"", headers, context=mail.tls_context)[0] == 200
        me(replacement, 401)

        expired = issue(first)
        with db:
            db.execute("UPDATE hosted_sign_in_proofs SET expires_at=unixepoch() WHERE digest=?", (proof_hash(expired),))
        assert exchange(expired)[0] == 401
        disabled = issue(first)
        with db:
            db.execute("UPDATE users SET enabled=0 WHERE username=?", (first,))
        issue(first, expected=404)
        with db:
            db.execute("UPDATE users SET enabled=1 WHERE username=?", (first,))
        assert exchange(disabled)[0] == 401

        retiring = issue(first)
        with db:
            db.execute("UPDATE provisioned_mailboxes SET service_until=unixepoch()-1, read_until=unixepoch()+120 WHERE mailbox=?", (first,))
        assert me(checked_cookie(exchange(issue(first))))["user"]["username"] == first
        with db:
            db.execute("UPDATE provisioned_mailboxes SET read_until=unixepoch() WHERE mailbox=?", (first,))
        assert exchange(retiring)[0] == 401
        issue(first, expected=404)

        stale = issue(second)
        with db:
            original, = db.execute("SELECT password_hash FROM users WHERE username=?", (second,)).fetchone()
            db.execute("UPDATE users SET password_hash=? WHERE username=?", ("fixture-rotation", second))
            db.execute("UPDATE users SET password_hash=? WHERE username=?", (original, second))
        assert exchange(stale)[0] == 401
        assert me(mail.login(second)["Cookie"])["user"]["username"] == second
        restarting = issue(second)

    with mail.daemon():
        assert exchange(restarting)[0] == 401
        assert me(checked_cookie(exchange(issue(second))))["user"]["username"] == second
        for _ in range(9):
            assert exchange(restarting)[0] == 401
        assert exchange(restarting)[0] == 429


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mail-hosted-sign-in-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print("Verified private hosted proof issuance, atomic HTTPS exchange, switching, sign-out, revocation, and restart.")


if __name__ == "__main__":
    main()
