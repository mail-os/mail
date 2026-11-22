#!/usr/bin/env python3
"""Exercise SMTP malware scanning through real DATA and BDAT transactions."""

import argparse
from contextlib import contextmanager
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import os
from pathlib import Path
import secrets
import smtplib
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
from threading import Thread
import time


EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DOMAIN = "scan.example.test"
USER = f"sender@{DOMAIN}"
RECIPIENT = f"inbox@{DOMAIN}"
PASSWORD = secrets.token_hex(16)


def free_ports(count):
    sockets = [socket.socket() for _ in range(count)]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


@contextmanager
def daemon(command, directory, ready, *, env=None, startup_seconds=10):
    log_path = directory / f"{Path(command[0]).name}-{secrets.token_hex(4)}.log"
    with log_path.open("wb") as log:
        child = subprocess.Popen(command, cwd=directory, env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + startup_seconds
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise RuntimeError(f"{Path(command[0]).name} exited during startup")
                try:
                    if ready():
                        break
                except OSError:
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError(f"{Path(command[0]).name} did not become ready")
            yield
        except Exception:
            print(log_path.read_text(errors="replace")[-8000:])
            raise
        finally:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


class ClamdRequest(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        assert self.rfile.read(10) == b"zINSTREAM\x00"
        raw = bytearray()
        while True:
            length, = struct.unpack("!I", self.rfile.read(4))
            if length == 0:
                break
            chunk = self.rfile.read(length)
            assert len(chunk) == length
            raw.extend(chunk)
        message = BytesParser(policy=policy.SMTP).parsebytes(raw)
        assert not message.get_all("X-Virus-Scanned")
        infected = raw == EICAR or any(part.get_payload(decode=True) == EICAR for part in message.walk())
        self.wfile.write(b"stream: Eicar-Test-Signature FOUND\x00" if infected else b"stream: OK\x00")


@contextmanager
def scanner(directory, clamd, database):
    endpoint = directory / "scanner.sock"
    if clamd:
        config = directory / "clamd.conf"
        config.write_text(f"Foreground yes\nLocalSocket {endpoint}\nDatabaseDirectory {database}\nScanMail yes\n")

        def ping():
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(1)
                sock.connect(str(endpoint))
                sock.sendall(b"zPING\x00")
                return sock.recv(16) == b"PONG\x00"

        with daemon([str(clamd), "--config-file", str(config)], directory, ping, startup_seconds=90):
            yield endpoint
        return

    with socketserver.UnixStreamServer(str(endpoint), ClamdRequest) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield endpoint
        finally:
            server.shutdown()
            thread.join()


def environment(directory, submission):
    return dict(PATH=os.environ["PATH"], SMTP_DB_PATH=str(directory / "smtp.db"),
                SMTP_HOSTNAME=f"mail.{DOMAIN}", SMTP_LOCAL_DOMAINS=DOMAIN,
                SMTP_CATCH_ALL="true",
                SMTP_ENABLE_DNSBL="false", SMTP_ENABLE_GREYLIST="false",
                SMTP_ANTISPAM_CHECK="false", SMTP_SPAM_FILTER="false", IMAP_ENABLED="false",
                CALDAV_ENABLED="false", SUBMISSION_PORT=str(submission))


@contextmanager
def mail(binary, directory, endpoint, *, mode="closed", limit=None, tls=False):
    smtp, submission, smtps = free_ports(3)
    env = environment(directory, submission)
    env.update(SMTP_CLAMAV_TRANSPORT=f"unix:{endpoint}", SMTP_CLAMAV_FAIL_MODE=mode,
               SMTP_CLAMAV_CONNECT_TIMEOUT_MS="250", SMTP_CLAMAV_TIMEOUT_MS="5000")
    if limit is not None:
        env["SMTP_CLAMAV_MAX_STREAM_BYTES"] = str(limit)
    subprocess.run([binary, "user:local", "create", USER, "--email", USER], input=PASSWORD.encode(),
                   cwd=directory, env=env, check=True, capture_output=True)

    tls_context = None
    if tls:
        cert, key = directory / "mail.pem", directory / "mail.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", str(key), "-out", str(cert)], capture_output=True, check=True)
        tls_context = ssl.create_default_context(cafile=str(cert))
        env.update(SMTP_ENABLE_TLS="true", SMTP_TLS_CERT=str(cert), SMTP_TLS_KEY=str(key), SMTPS_PORT=str(smtps))

    def ready():
        for port in ((smtp, submission, smtps) if tls else (smtp,)):
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                pass
        return True

    command = [binary, "serve", "--host", "127.0.0.1", "--port", str(smtp), "--enable-auth"]
    if not tls:
        command.append("--disable-tls")
    with daemon(command, directory, ready, env=env):
        yield smtp, submission, smtps, tls_context


def message(attachment=None):
    mail = EmailMessage(policy=policy.SMTP)
    mail["From"] = USER
    mail["To"] = RECIPIENT
    mail["Subject"] = "Antivirus integration"
    mail["x-virus-scanned"] = "client-verdict"
    mail["X-Virus-Scanned"] = "duplicate-verdict"
    mail.set_content("X-Virus-Scanned: body text survives\n")
    if attachment is not None:
        mail.add_attachment(attachment, maintype="application", subtype="octet-stream", filename="fixture.txt")
    return mail.as_bytes().replace(b"x-virus-scanned: client-verdict\r\n",
                                   b"x-virus-scanned: client-verdict\r\n\tcontinued\r\n", 1)


def submit(client, raw, *, chunked):
    assert client.mail(USER)[0] == 250
    assert client.rcpt(RECIPIENT)[0] == 250
    if not chunked:
        return client.data(raw)
    cut = len(raw) // 2
    client.putcmd("BDAT", str(cut))
    client.send(raw[:cut])
    assert client.getreply()[0] == 250, "Intermediate BDAT must accept a chunk"
    client.putcmd("BDAT", f"{len(raw) - cut} LAST")
    client.send(raw[cut:])
    return client.getreply()


def stored(directory):
    return sorted((directory / "mail").rglob("*.eml*"))


def check_verdicts(binary, directory, endpoint):
    with mail(binary, directory, endpoint, tls=True) as (smtp, submission, smtps, tls_context):
        for port in (smtp, submission, smtps):
            options = dict(local_hostname=f"client.{DOMAIN}", timeout=15)
            client = (smtplib.SMTP_SSL("127.0.0.1", port, context=tls_context, **options)
                      if port == smtps else smtplib.SMTP("127.0.0.1", port, **options))
            with client:
                client.ehlo()
                if port == submission:
                    client.starttls(context=tls_context)
                    client.ehlo()
                if port != smtp:
                    client.login(USER, PASSWORD)
                for chunked in (False, True):
                    previous = stored(directory)
                    code, reply = submit(client, message(EICAR), chunked=chunked)
                    assert code == 554 and b"eicar" in reply.lower(), (code, reply)
                    assert stored(directory) == previous
                    assert client.noop()[0] == 250
                    assert submit(client, message(), chunked=chunked)[0] == 250
                    delivered, = set(stored(directory)) - set(previous)
                    parsed = BytesParser(policy=policy.SMTP).parsebytes(delivered.read_bytes())
                    assert parsed.get_all("X-Virus-Scanned") == ["clean"]
                    assert "X-Virus-Scanned: body text survives" in parsed.get_content()


def check_fail_mode(binary, directory, endpoint, mode, limit, code, tag):
    with mail(binary, directory, endpoint, mode=mode, limit=limit) as (smtp, *_):
        with smtplib.SMTP("127.0.0.1", smtp, local_hostname=f"client.{DOMAIN}", timeout=15) as client:
            client.ehlo()
            for chunked in (False, True):
                before = stored(directory)
                result = submit(client, message(), chunked=chunked)
                assert result[0] == code, result
                if tag:
                    delivered, = set(stored(directory)) - set(before)
                    assert f"X-Virus-Scanned: {tag}\r\n".encode() in delivered.read_bytes()
                else:
                    assert stored(directory) == before
                assert client.noop()[0] == 250


def check_configuration(binary, directory):
    for settings in (
        {"SMTP_CLAMAV_TRANSPORT": "tcp:scanner.example.test:3310"},
        {"SMTP_CLAMAV_FAIL_MODE": "typo"},
        {"SMTP_CLAMAV_TIMEOUT_MS": "0"},
    ):
        env = environment(directory, 0)
        env.update(SMTP_CLAMAV_TRANSPORT=f"unix:{directory / 'scanner.sock'}")
        env.update(settings)
        result = subprocess.run([binary, "serve", "--host", "127.0.0.1", "--disable-tls", "--validate-only"],
                                cwd=directory, env=env, timeout=10, capture_output=True)
        assert result.returncode != 0 and b"InvalidClamAVConfiguration" in result.stderr, result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--clamd", type=Path, help="Use a real clamd and its installed signatures")
    parser.add_argument("--database", type=Path, default=Path("/var/lib/clamav"))
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    clamd = args.clamd.resolve(strict=True) if args.clamd else None
    # Short root for the clamd Unix socket limit on Linux and macOS.
    with tempfile.TemporaryDirectory(prefix="mail-scan-", dir="/tmp") as sandbox:
        root = Path(sandbox)
        check_configuration(binary, root)
        with scanner(root, clamd, args.database.resolve()) as endpoint:
            directory = root / "verdict"
            directory.mkdir()
            check_verdicts(binary, directory, endpoint)
        backend = "clamd" if clamd else "the socket fixture"
        print(f"Verified clean and EICAR verdicts with {backend} over DATA and BDAT on SMTP, submission, and SMTPS.")
        for name, mode, limit, code, tag in (
            ("unavailable-closed", "closed", None, 451, None),
            ("unavailable-open", "open", None, 250, "unavailable"),
            ("size-closed", "closed", 1, 552, None),
            ("size-open", "open", 1, 250, "too-large"),
        ):
            directory = root / name
            directory.mkdir()
            check_fail_mode(binary, directory, root / "missing.sock", mode, limit, code, tag)
        print("Verified fail-open tags, fail-closed refusals, and transaction recovery over both SMTP commands.")


if __name__ == "__main__":
    main()
