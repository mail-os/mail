#!/usr/bin/env python3
"""Verify app passwords against the disposable native TLS listeners."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import imaplib
import os
from pathlib import Path
import runpy
import smtplib
import sqlite3
import subprocess
import tempfile
import time
from urllib.parse import quote, urlencode


SCRIPTS = Path(__file__).resolve().parent
hosted = runpy.run_path(str(SCRIPTS / "test-hosted-limits.py"))
Fixture = hosted["Fixture"]
path = "client-passwords"
folder_sync = b"\x03\x01\x6a\x00\x00\x07\x56\x52\x030\x00\x01\x01"
calendar_ping = b"\x03\x01\x6a\x00\x00\x0d\x45\x48\x0320\x00\x01\x49\x4a\x4b\x035\x00\x01\x01\x01\x01"


def expect(result, status=200):
    assert result[0] == status, result
    return result[1]


def verify(mail, browser=None, screenshots=None):
    with mail.daemon(), closing(sqlite3.connect(mail.directory / "smtp.db")) as db:
        owner = mail.provision("device-owner", daily=1)
        other = mail.provision("other-owner")
        session = mail.login(owner)
        stranger = mail.login(other)

        def create(label, scope="mail", password=None, status=201, headers=session):
            return expect(mail.api(headers, path, {"label": label, "scope": scope,
                                                   "current_password": password or mail.password}, "POST"), status)

        def revoke(entry, headers=session, status=200):
            return expect(mail.api(headers, f"{path}/{entry['id']}", method="DELETE"), status)

        def smtp(password):
            connection = smtplib.SMTP(mail.hostname, mail.submission_port, timeout=10)
            try:
                connection.starttls(context=mail.tls_context)
                connection.login(owner, password)
                return connection
            except BaseException:
                connection.close()
                raise

        def imap(password, username=owner, starttls=False):
            if starttls:
                client = imaplib.IMAP4(mail.hostname, mail.imap_port, timeout=10)
                client.starttls(mail.tls_context)
            else:
                client = imaplib.IMAP4_SSL(mail.hostname, mail.imaps_port, ssl_context=mail.tls_context, timeout=10)
            try:
                if starttls:
                    assert client.authenticate("PLAIN", lambda _: f"\0{username}\0{password}".encode())[0] == "OK"
                else:
                    assert client.login(username, password)[0] == "OK"
                return client
            except BaseException:
                client.shutdown()
                raise

        def dav(password, kind, *, secure=True):
            tls_port = mail.env["CALDAV_SSL_PORT"]
            origin = f"https://127.0.0.1:{tls_port}" if secure else f"http://127.0.0.1:{mail.env['CALDAV_PORT']}"
            document = "<d:propfind xmlns:d='DAV:'><d:prop><d:resourcetype/></d:prop></d:propfind>"
            headers = {"Depth": "0", "Authorization": "Basic " + base64.b64encode(f"{owner}:{password}".encode()).decode()}
            return mail.http(f"{origin}/{kind}/{quote(owner, safe='')}/", document.encode(), headers, "PROPFIND", context=mail.tls_context)

        def exchange(password, eas, *, ping=False):
            headers = {"Authorization": "Basic " + base64.b64encode(f"{owner}:{password}".encode()).decode()}
            if eas:
                query = urlencode({"Cmd": "Ping" if ping else "FolderSync", "User": owner,
                                   "DeviceId": "AppPasswordWait" if ping else "AppPasswordDevice", "DeviceType": "SmartPhone"})
                headers.update({"MS-ASProtocolVersion": "14.1", "Content-Type": "application/vnd.ms-sync.wbxml"})
                return mail.http(mail.eas_url + "?" + query, calendar_ping if ping else folder_sync,
                                 headers, context=mail.tls_context, timeout=24 if ping else 10)
            headers["Content-Type"] = "text/xml"
            request = b'''<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
                         xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
                         xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
                <s:Body><m:GetFolder><m:FolderShape><t:BaseShape>IdOnly</t:BaseShape></m:FolderShape>
                <m:FolderIds><t:DistinguishedFolderId Id="inbox"/></m:FolderIds></m:GetFolder></s:Body></s:Envelope>'''
            return mail.http(mail.ews_url, request, headers, context=mail.tls_context)

        expect(mail.api({}, path), 401)
        create("Cross-origin", status=403, headers=session | {"Origin": "https://outside.example.test"})
        create("Wrong password", password="wrong-fixture-password", status=403)
        create("\t", status=400)
        with db:
            db.execute("""CREATE TRIGGER fixture_denies_issue BEFORE INSERT ON audit_log
                       WHEN NEW.action='client_password.created' BEGIN SELECT RAISE(ABORT, 'fixture issue'); END""")
        status, _, _ = mail.http(mail.webmail + "/webmail/api/" + path,
                                  {"label": "Audit failure", "scope": "mail", "current_password": mail.password},
                                  session, context=mail.tls_context)
        assert status == 500
        assert expect(mail.api(session, path))["passwords"] == []
        with db:
            db.execute("DROP TRIGGER fixture_denies_issue")

        laptop = create("Laptop mail")
        phone = create("Phone mail")
        office = create("Calendar and contacts", "dav")
        tablet = create("Tablet exchange", "exchange")
        credentials = [laptop, phone, office, tablet]
        listed = expect(mail.api(session, path))["passwords"]
        assert [entry["id"] for entry in listed] == [item["entry"]["id"] for item in reversed(credentials)]
        assert all("password" not in entry and "digest" not in entry for entry in listed)
        assert expect(mail.api(stranger, path))["passwords"] == []
        revoke(laptop["entry"], stranger, 404)
        for item in credentials:
            assert db.execute("SELECT digest FROM mail_client_passwords WHERE id=?", (item["entry"]["id"],)).fetchone() == (
                hashlib.sha256(item["password"].encode()).digest(),)

        assert mail.http(mail.webmail + "/webmail/auth/login", {"username": owner, "password": laptop["password"]},
                         {"Origin": mail.webmail}, context=mail.tls_context)[0] == 401
        create("Cannot reuse app password", password=laptop["password"], status=403)
        assert dav(office["password"], "calendars", secure=False)[0] == 401
        assert dav(laptop["password"], "calendars")[0] == 401
        assert exchange(office["password"], eas=True)[0] == 401
        try:
            imap(laptop["password"], username=other)
        except imaplib.IMAP4.error:
            pass
        else:
            raise AssertionError("A different mailbox accepted this app password")

        for collection in ("calendars", "addressbooks"):
            status, _, data = dav(office["password"], collection)
            assert status == 207, (status, data)
        status, _, data = exchange(tablet["password"], eas=True)
        assert status == 200 and b"Inbox" in data, (status, data)
        status, _, data = exchange(tablet["password"], eas=False)
        assert status == 200 and b"NoError" in data, (status, data)
        with smtplib.SMTP_SSL(mail.hostname, mail.smtps_port, context=mail.tls_context, timeout=10) as implicit_tls:
            assert implicit_tls.login(owner, phone["password"])[0] == 235
            assert implicit_tls.noop()[0] == 250

        with closing(smtp(laptop["password"])) as send:
            assert send.sendmail(owner, [owner], f"From: {owner}\r\nSubject: App-password mail\r\n\r\nAccepted") == {}
            assert send.mail(owner)[0] == 250 and send.rcpt(owner)[0] == 250
            assert send.docmd("DATA")[0] == 354
            client = imap(laptop["password"], starttls=True)
            watcher = imap(laptop["password"])
            try:
                assert client.select("INBOX")[0] == "OK"
                assert watcher.select("INBOX")[0] == "OK"
                watcher.send(b"WATCH IDLE\r\n")
                assert watcher.readline().startswith(b"+")
                payload = b"Subject: Revoked APPEND\r\n\r\nMust not be delivered."
                client.send(b"APPREV APPEND INBOX {" + str(len(payload)).encode() + b"}\r\n")
                assert client.readline().startswith(b"+")
                revoke(laptop["entry"])
                client.send(payload + b"\r\n")
                assert client.readline().startswith(b"* BYE")
                assert watcher.readline().startswith(b"* BYE")
                send.send(b"Subject: Revoked DATA\r\n\r\nMust not be delivered.\r\n.\r\n")
                assert send.getreply()[0] == 421
            finally:
                client.shutdown()
                watcher.shutdown()
                send.close()

        with imap(phone["password"]) as unaffected:
            assert unaffected.select("INBOX")[0] == "OK"
            for subject in ("Revoked APPEND", "Revoked DATA"):
                assert unaffected.search(None, "SUBJECT", f'"{subject}"') == ("OK", [b""])
            assert unaffected.search(None, "SUBJECT", '"App-password mail"')[1][0]
        with closing(smtp(phone["password"])) as untouched:
            assert untouched.noop()[0] == 250
            try:
                untouched.sendmail(owner, [owner], f"From: {owner}\r\nSubject: Over daily quota\r\n\r\nRefused")
            except smtplib.SMTPDataError as error:
                assert error.smtp_code == 452 and b"Daily recipient allowance" in error.smtp_error, error
            else:
                raise AssertionError("A second app password bypassed the mailbox's sending allowance")
        revoke(office["entry"])
        assert dav(office["password"], "addressbooks")[0] == 401
        assert exchange(tablet["password"], eas=True)[0] == 200

        snapshot_path = mail.directory / "snapshot.db"
        with closing(sqlite3.connect(snapshot_path)) as snapshot:
            db.backup(snapshot)
            assert snapshot.execute("SELECT COUNT(*) FROM mail_client_passwords").fetchone() == (2,)
        subprocess.run([str(mail.binary), "backup", "capture-local", str(snapshot_path), str(mail.directory / "mail")],
                       cwd=mail.directory, env=mail.env, check=True, capture_output=True, text=True)
        with closing(sqlite3.connect(snapshot_path)) as snapshot:
            assert snapshot.execute("SELECT COUNT(*) FROM mail_client_passwords").fetchone() == (0,)
        assert db.execute("SELECT COUNT(*) FROM mail_client_passwords").fetchone() == (2,)
        assert db.execute("SELECT COUNT(*) FROM audit_log WHERE target_type='client_password' AND actor=?", (owner,)).fetchone() == (6,)

        temporary = [create(f"Temporary client {index}")["entry"] for index in range(13)]

        def last_slot(index):
            return mail.api(session, path, {"label": f"Concurrent client {index}", "scope": "mail",
                                            "current_password": mail.password}, "POST")

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(last_slot, range(2)))
        assert sorted(status for status, _ in results) == [201, 409]
        temporary.extend(result["entry"] for status, result in results if status == 201)
        assert len(expect(mail.api(session, path))["passwords"]) == 16
        for entry in temporary:
            revoke(entry)
        second_key = create("Other mailbox app", headers=stranger)["entry"]
        with db:
            db.execute("UPDATE users SET enabled=0 WHERE username=?", (other,))
            db.execute("UPDATE users SET enabled=1 WHERE username=?", (other,))
        assert db.execute("SELECT COUNT(*) FROM mail_client_passwords WHERE id=?", (second_key["id"],)).fetchone() == (0,)

        if browser:
            env = dict(os.environ, MAIL_CLIENT_PASSWORD_TEST_URL=mail.webmail, MAIL_CLIENT_PASSWORD_TEST_OWNER=owner,
                       MAIL_CLIENT_PASSWORD_TEST_PASSWORD=mail.password,
                       MAIL_CLIENT_PASSWORD_TEST_CERT=mail.env["SMTP_TLS_CERT"])
            subprocess.run(["node", str(SCRIPTS / "webmail-client-password-browser.mjs"), browser, str(screenshots)],
                           env=env, check=True, timeout=80)

    with mail.daemon(), closing(sqlite3.connect(mail.directory / "smtp.db")) as db:
        with closing(smtp(phone["password"])) as persistent:
            assert persistent.noop()[0] == 250
        assert exchange(tablet["password"], eas=True)[0] == 200
        with db:
            db.execute("UPDATE provisioned_mailboxes SET service_until=unixepoch()-1, read_until=unixepoch()+120 WHERE mailbox=?", (owner,))
        headers = mail.login(owner)
        create("No new passwords during export", headers=headers, status=403)
        assert expect(mail.api(headers, path))["can_create"] is False
        with ThreadPoolExecutor(max_workers=1) as worker:
            waiting = worker.submit(exchange, tablet["password"], True, ping=True)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not waiting.done():
                if db.execute("SELECT 1 FROM eas_mailbox_ping WHERE device_id='AppPasswordWait'").fetchone():
                    break
                time.sleep(.05)
            else:
                raise AssertionError("ActiveSync did not start a quiet Ping")
            assert not waiting.done()
            revoke(tablet["entry"], headers)
            assert waiting.result(timeout=6)[0] == 401
        assert exchange(tablet["password"], eas=False)[0] == 401
        replacement = "a-new-mailbox-password"
        status, _, _ = mail.http(mail.webmail + "/webmail/auth/password",
                                 {"currentPassword": mail.password, "newPassword": replacement}, headers, context=mail.tls_context)
        assert status == 403  # Export-only sessions cannot change the account password.
        with db:
            db.execute("UPDATE provisioned_mailboxes SET service_until=NULL, read_until=NULL WHERE mailbox=?", (owner,))
        status, _, _ = mail.http(mail.webmail + "/webmail/auth/password",
                                 {"currentPassword": mail.password, "newPassword": replacement}, headers, context=mail.tls_context)
        assert status == 200
        assert db.execute("SELECT COUNT(*) FROM mail_client_passwords").fetchone() == (0,)
        try:
            smtp(phone["password"])
        except smtplib.SMTPAuthenticationError:
            pass
        else:
            raise AssertionError("SMTP accepted an app password after the mailbox password changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--browser", choices=("chromium", "firefox", "webkit"))
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args()
    if args.browser and not args.screenshots:
        parser.error("--browser needs --screenshots")
    with tempfile.TemporaryDirectory(prefix="mail-client-passwords-") as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True), args.browser, args.screenshots)
    print("Verified scoped app passwords over native TLS, selective revocation, in-flight writes, backup and restart.")


if __name__ == "__main__":
    main()
