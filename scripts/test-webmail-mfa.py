#!/usr/bin/env python3
"""Exercise webmail two-step verification against native HTTPS."""
import argparse
from base64 import b32decode
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from hashlib import sha256
import hmac
import http.client
import json
import os
from pathlib import Path
import runpy
import secrets
import smtplib
import sqlite3
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
Fixture = runpy.run_path(str(HERE / "test-hosted-limits.py"))["Fixture"]
ORIGIN = "https://app.example.test"
AUTH = "/webmail/auth"
HOSTED = AUTH + "/hosted"
MFA = AUTH + "/mfa"
LINKS = "/webmail/api/combined/accounts"


def totp(secret, step):
    digest = hmac.digest(b32decode(secret), step.to_bytes(8, "big"), "sha1")
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
    return f"{value % 1_000_000:06d}"


def verify(mail):
    host = urlsplit(mail.webmail)

    def call(path, body=None, *, method="POST", cookie=None, origin=mail.webmail, status=200, error=None):
        with closing(http.client.HTTPSConnection(host.hostname, host.port, timeout=10, context=mail.tls_context)) as client:
            headers = {"Origin": origin}
            if cookie:
                headers["Cookie"] = cookie
            if path == HOSTED:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                body = f"proof={body}"
            elif body is not None:
                headers["Content-Type"] = "application/json"
                body = json.dumps(body)
            client.request(method, path, body, headers)
            response = client.getresponse()
            result = response.read()
            assert response.status == status, (path, response.status, result)
            data = json.loads(result) if result else None
            if error:
                assert data["error"] == error, (path, data)
            return response.headers, data

    def cookies(headers):
        return [value.split(";", 1)[0] for value in headers.get_all("Set-Cookie", [])]

    def login(mailbox, factor=None, **options):
        return call(AUTH + "/login", credentials(mailbox, factor), **options)[0]

    def credentials(mailbox, factor=None):
        data = {"username": mailbox, "password": mail.password}
        if factor is not None:
            data["factor"] = factor
        return data

    def me(cookie, expected):
        _, result = call(AUTH + "/me", method="GET", cookie=cookie, status=200 if expected else 401)
        if expected:
            assert result["user"]["username"] == expected

    def proof(mailbox):
        status, _, body = mail.http(mail.private + "/provisioning/v1/webmail/sign-in",
                                     {"mailbox": mailbox, "actor": mail.specs[mailbox]["actor"]}, mail.auth)
        assert status == 201, (status, body)
        return json.loads(body)["proof"]

    def challenge(mailbox, old=None):
        token = proof(mailbox)
        headers, _ = call(HOSTED, token, cookie=old, origin=ORIGIN, status=303)
        assert headers["Location"] == "/login#hosted-factor"
        cookie, = cookies(headers)
        assert cookie.startswith("__Secure-mail_hosted_factor=")
        assert all(part in headers["Set-Cookie"] for part in ("Path=" + HOSTED + "/verify;", "Secure;", "HttpOnly;", "SameSite=Strict"))
        return token, cookie

    with mail.daemon(), closing(sqlite3.connect(mail.directory / "smtp.db", timeout=10)) as db:
        owner = mail.provision("protected")
        other = mail.provision("second")
        enrollment, = cookies(login(owner))
        older, = cookies(login(owner))
        root, = cookies(login(other))
        _, device = call("/webmail/api/client-passwords", {
            "label": "MFA protocol fixture", "scope": "mail", "current_password": mail.password,
        }, cookie=enrollment, status=201)

        assert call(MFA, method="GET", cookie=enrollment)[1] == {"enabled": False, "available": True}
        call(MFA, {"currentPassword": mail.password}, cookie=enrollment, origin=ORIGIN, status=403)
        call(MFA, {"currentPassword": "incorrect-fixture-password"}, cookie=enrollment, status=400, error="invalid_credentials")
        begin_headers, setup = call(MFA, {"currentPassword": mail.password}, cookie=enrollment)
        assert begin_headers["Cache-Control"] == "no-store"
        secret = setup["secret"]
        assert len(secret) == 32
        start = int(time.time()) // 30
        call(MFA, {"factor": totp(secret, start - 1)}, method="PUT", cookie=older, status=409)
        _, activation = call(MFA, {"factor": totp(secret, start - 1)}, method="PUT", cookie=enrollment)
        codes = activation["recoveryCodes"]
        assert len(set(codes)) == 10 and all(len(code) == 32 for code in codes)
        me(enrollment, owner)
        me(older, None)
        assert call(MFA, method="GET", cookie=enrollment)[1] == {"enabled": True, "available": True}
        assert not cookies(login(owner, status=403, error="factor_required"))
        call(AUTH + "/login", {"username": owner, "password": device["password"]}, status=401, error="invalid_credentials")
        with smtplib.SMTP(mail.hostname, mail.submission_port, timeout=10) as smtp:
            smtp.starttls(context=mail.tls_context)
            assert smtp.login(owner, device["password"])[0] == 235
        code = totp(secret, int(time.time()) // 30)
        signed_in, = cookies(login(owner, code))
        me(signed_in, owner)
        login(owner, code, status=403, error="invalid_factor")

        traffic, pending = challenge(owner, root)
        me(root, other)
        call(HOSTED, traffic, origin=ORIGIN, status=401, error="invalid_proof")
        call(HOSTED + "/verify", {"factor": codes[0]}, cookie=pending, origin=ORIGIN, status=403)
        finished, _ = call(HOSTED + "/verify", {"factor": codes[0]}, cookie=pending)
        issued, cleared = cookies(finished)
        assert cleared == "__Secure-mail_hosted_factor="
        me(issued, owner)
        me(root, None)
        call(HOSTED + "/verify", {"factor": codes[1]}, cookie=pending, status=401, error="invalid_proof")
        root, = cookies(login(other))
        call(LINKS, credentials(owner), cookie=root, status=403, error="factor_required")
        _, result = call(LINKS, credentials(owner, codes[1]), cookie=root)
        assert len(result["accounts"]) == 1
        assert result["accounts"][0]["username"] == owner
        linked = result["accounts"][0]["id"]
        call(MFA + "?linked=" + linked, method="GET", cookie=root, status=403, error="linked_route_unavailable")
        call(LINKS, credentials(owner, codes[2]), cookie=root, status=409, error="account_already_linked")

        _, stale = challenge(owner)
        reset = secrets.token_hex(32)
        with db:
            db.execute("""INSERT INTO mailbox_reset_tokens (token_hash, username, recovery_email, created_at, expires_at)
                       VALUES (?, ?, ?, unixepoch(), unixepoch() + 300)""",
                       (sha256(reset.encode()).hexdigest(), owner, other))
        new_password = secrets.token_hex(16)
        call(AUTH + "/reset", {"token": reset, "password": new_password})
        me(issued, None)
        call(HOSTED + "/verify", {"factor": codes[2]}, cookie=stale, status=401, error="invalid_proof")
        call(AUTH + "/login", {"username": owner, "password": new_password}, status=403, error="factor_required")

    # Restart keeps the factor and consumed codes. Recovery must work even if
    # the authenticator and deployment wrapping key are both unavailable.
    del mail.env["SMTP_WEBMAIL_MFA_KEY"]
    mail.password = new_password
    with mail.daemon():
        login(owner, codes[0], status=403, error="invalid_factor")
        login(owner, codes[1], status=403, error="invalid_factor")
        with ThreadPoolExecutor(max_workers=2) as race:
            def recover():
                try:
                    return cookies(login(owner, codes[2]))[0]
                except AssertionError as problem:
                    assert problem.args[0][1] == 403 and b"invalid_factor" in problem.args[0][2], problem
                    return None
            sessions = [cookie for cookie in race.map(lambda _: recover(), range(2)) if cookie]
        restored, = sessions
        me(restored, owner)
        assert call(MFA, method="GET", cookie=restored)[1] == {"enabled": True, "available": False}
        call(MFA, {"factor": codes[3]}, method="DELETE", cookie=restored)
        me(restored, owner)
        assert call(MFA, method="GET", cookie=restored)[1] == {"enabled": False, "available": False}
        assert cookies(login(owner))


def make_fixture(binary, directory):
    mail = Fixture(binary, directory, staging=True)
    mail.env.update(SMTP_WEBMAIL_MFA_KEY=secrets.token_hex(32), SMTP_HOSTED_SIGN_IN_ORIGIN=ORIGIN)
    return mail


def browser_test(mail, engine, output):
    with mail.daemon():
        owner, other = (mail.provision(name) for name in ("alex", "morgan"))
        env = dict(os.environ, MAIL_MFA_URL=mail.webmail, MAIL_MFA_OWNER=owner, MAIL_MFA_OTHER=other,
                   MAIL_MFA_PASSWORD=mail.password, MAIL_MFA_ORIGIN=ORIGIN, MAIL_MFA_PRIVATE=mail.private,
                   MAIL_MFA_ACTOR=mail.specs[owner]["actor"], MAIL_MFA_TOKEN=mail.auth["Authorization"])
        subprocess.run(["node", str(HERE / "webmail-mfa-browser.mjs"), engine, str(output / engine)],
                       env=env, check=True, timeout=120)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--browser", choices=("chromium", "firefox", "webkit"), action="append")
    parser.add_argument("--screenshots", type=Path, default=Path("webmail-browser-screenshots/mfa"))
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="mail-mfa-") as directory:
        verify(make_fixture(binary, Path(directory)))
    for engine in args.browser or ():
        with tempfile.TemporaryDirectory(prefix="mail-mfa-browser-") as directory:
            browser_test(make_fixture(binary, Path(directory)), engine, args.screenshots.resolve())
    print("Verified MFA across native HTTPS enrollment, login, hosted handoff, account linking, reset, replay, and recovery.")


if __name__ == "__main__":
    main()
