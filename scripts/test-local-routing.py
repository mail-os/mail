#!/usr/bin/env python3
"""Native SMTP, webmail and crash-recovery regression for local routing."""

import argparse
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import runpy
import sqlite3
import subprocess
import tempfile
from threading import Lock, Thread
import time
from urllib.parse import urlencode


fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture = fixture["Fixture"]
expect_smtp = fixture["expect_smtp"]


class EventListener(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_ok(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_GET(self):
        self.send_ok()

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert self.path == "/hook" or self.path.endswith("/documents?action=upsert"), self.path
        with self.server.events_lock:
            self.server.events.append((self.path, payload))
        self.send_ok()


@contextmanager
def listener(address, handler=EventListener):
    server = ThreadingHTTPServer((address, 0), handler)
    server.events = []
    server.events_lock = Lock()
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def eventually(read, predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = read()
        if predicate(value):
            return value
        time.sleep(0.1)
    raise AssertionError(value)


def run(candidate, previous, webhook_ip):
    with tempfile.TemporaryDirectory(prefix="mail-local-route-") as tmp, listener("127.0.0.1") as search, listener(webhook_ip or "127.0.0.1") as webhooks:
        root = Path(tmp)
        test = Fixture(previous or candidate, root, staging=True)
        routing_env = dict(TYPESENSE_API_KEY="routing-test", TYPESENSE_HOST="127.0.0.1", TYPESENSE_PORT=str(search.server_port),
                           SMTP_WEBHOOK_URL=f"http://{webhook_ip or '127.0.0.1'}:{webhooks.server_port}/hook",
                           SMTP_WEBHOOK_ENABLED="true")
        test.env.update(routing_env)

        def query(sql, args=()):
            with closing(sqlite3.connect(root / "smtp.db")) as db:
                return db.execute(sql, args).fetchall()

        def execute(sql, args=()):
            with closing(sqlite3.connect(root / "smtp.db")) as db, db:
                db.execute(sql, args)

        def messages(user, folder="INBOX"):
            status, folder_body = test.api(test.login(user), "messages?" + urlencode({"folder": folder}))
            assert status == 200, folder_body
            return [message["subject"] for message in folder_body["items"]]

        def subjects(server, username):
            with server.events_lock:
                return [doc["subject"] for _, doc in server.events if doc.get("username") == username]

        def block(user):
            directory = root / "mail" / user / "new"
            directory.parent.mkdir(parents=True, exist_ok=True)
            directory.write_bytes(b"test blocks Maildir creation")
            return directory

        if previous:
            with test.daemon():
                legacy = test.provision("legacy")
                expect_smtp(test.deliver(legacy, subject="Previously delivered"), 250)
            assert not query("SELECT 1 FROM sqlite_master WHERE name='accepted_mail'")
            test.binary = candidate

        with test.daemon() as process:
            if previous:
                assert messages(legacy) == ["Previously delivered"]
            author = test.provision("author")
            first = test.provision("first")
            second = test.provision("second")
            third = test.provision("third")
            forwarded = test.provision("forwarded")
            app_inbox = test.provision("app-pending")
            bad_dirs = {user: block(user) for user in (second, third, app_inbox)}

            # A failure late inside admission rolls back the entire envelope
            # and its hosted debit, before the client receives success.
            execute(f"""CREATE TRIGGER fail_route BEFORE INSERT ON accepted_mail_targets
                        WHEN NEW.mailbox='{third}' BEGIN SELECT RAISE(ABORT, 'fixture rejected target'); END""")
            expect_smtp(test.deliver([first, third], identity=author, subject="Transaction rolled back"), 451)
            assert test.count(author) == 0 and test.bytes(first) == 0
            assert query("SELECT count(*) FROM accepted_mail_targets WHERE mailbox IN (?,?)", (first, third)) == [(0,)]
            execute("DROP TRIGGER fail_route")
            execute("""CREATE TRIGGER fail_remote_route BEFORE INSERT ON accepted_mail_targets
                       WHEN NEW.recipient='remote@example.invalid' BEGIN SELECT RAISE(ABORT, 'fixture rejected remote target'); END""")
            expect_smtp(test.deliver([first, "remote@example.invalid"], identity=author, chunked=True), 451)
            assert not query("SELECT 1 FROM message_queue WHERE to_addr='remote@example.invalid'")
            assert test.count(author) == 0 and test.bytes(first) == 0
            execute("DROP TRIGGER fail_remote_route")

            # The blocked forwarding destination depends on second's primary
            # copy, so it cannot dispatch before that copy is checkpointed.
            (root / "forwards.json").write_text(json.dumps({second: [forwarded]}))
            expect_smtp(test.deliver([first, second, third], identity=author, subject="Recovered DATA envelope"), 250)
            assert test.count(author) == 3
            journal = query("""SELECT m.id,m.accepted_ms,m.mime,t.mailbox,t.ordinal,t.outcome
                               FROM accepted_mail m JOIN accepted_mail_targets t ON m.id=t.delivery_id
                               WHERE t.mailbox IN (?,?,?,?) ORDER BY t.ordinal""", (first, second, third, forwarded))
            assert [(row[3], row[5]) for row in journal] == [(first, "filed"), (second, "pending"), (third, "pending"), (forwarded, "pending")], journal
            mail = journal[0][2]
            assert b"Recovered DATA envelope" in mail
            assert messages(first) == ["Recovered DATA envelope"]
            assert messages(second) == messages(forwarded) == []
            eventually(lambda: subjects(search, first), bool)
            assert subjects(search, second) == subjects(search, forwarded) == []
            assert query("SELECT t.mailbox FROM accepted_mail_effects e JOIN accepted_mail_targets t USING(delivery_id,ordinal) WHERE delivery_id=?", (journal[0][0],)) == [(first,)]

            test.provision("second", quota=len(mail))
            expect_smtp(test.deliver(second, subject="Reserved capacity is unavailable"), 452, "4.2.2")
            with test.imap(second) as imap:
                status, reply = imap.append("INBOX", None, None, b"Subject: Reserve\r\n\r\nxx\r\n")
                assert status == "NO" and b"OVERQUOTA" in reply[0], (status, reply)

            status, response = test.api(test.login(author), "compose", {"to": [app_inbox], "subject": "Recovered app envelope", "text": "accepted through webmail"})
            assert status == 200, response
            assert query("SELECT outcome FROM accepted_mail_targets WHERE mailbox=?", (app_inbox,)) == [("pending",)]
            assert messages(app_inbox) == []

            # Distinct listener ports and a different working directory still
            # converge on the same Maildir inode and acceptance journal.
            standby_dir = root / "standby"
            standby_dir.mkdir()
            (standby_dir / "mail").symlink_to(root / "mail", target_is_directory=True)
            standby = Fixture(candidate, standby_dir, staging=True)
            standby.env.update(SMTP_DB_PATH=test.env["SMTP_DB_PATH"], CALDAV_DB_PATH=test.env["CALDAV_DB_PATH"])
            blocked = subprocess.run(standby.daemon_command(), cwd=standby.directory, env=standby.env,
                                     capture_output=True, text=True, timeout=8)
            log = blocked.stdout + blocked.stderr
            assert blocked.returncode != 0 and "MaildirWriterActive" in log, log

            # A separate Maildir must not split deliveries from the same
            # mailbox database. Both spellings resolve to the same writer lock.
            separate_dir = root / "separate-writer"
            separate_dir.mkdir()
            separate = Fixture(candidate, separate_dir, staging=True)
            database = root / "smtp.db"
            database_alias = separate_dir / "shared-smtp.db"
            database_alias.symlink_to(database)
            separate.env["SMTP_MONITORING_PORT"] = str(fixture["available_ports"](1)[0])
            for path in (database, database_alias):
                separate.env["SMTP_DB_PATH"] = str(path)
                try:
                    blocked = subprocess.run(separate.daemon_command(), cwd=separate.directory, env=separate.env,
                                             capture_output=True, text=True, timeout=8)
                except subprocess.TimeoutExpired as error:
                    raise AssertionError("A second daemon started against the occupied SMTP database") from error
                log = blocked.stdout + blocked.stderr
                assert blocked.returncode != 0 and "DatabaseWriterActive" in log, log
                assert "Initializing database" not in log and "SMTP monitoring listening" not in log, log
            assert not (separate_dir / "mail" / app_inbox).exists()

            hardlink = separate_dir / "hardlinked-smtp.db"
            hardlink.hardlink_to(database)
            try:
                separate.env["SMTP_DB_PATH"] = str(hardlink)
                blocked = subprocess.run(separate.daemon_command(), cwd=separate.directory, env=separate.env,
                                         capture_output=True, text=True, timeout=8)
                log = blocked.stdout + blocked.stderr
                assert blocked.returncode != 0 and "DatabaseWriterPathNotUnique" in log, log
                assert "Initializing database" not in log, log
            finally:
                hardlink.unlink()

            separate.env["SMTP_DB_PATH"] = str(separate_dir / "smtp.db")
            with separate.daemon():
                independent = separate.provision("independent-writer")
                expect_smtp(separate.deliver(independent, subject="Independent writer"), 250)
                assert separate.bytes(independent) > 0

            assert process.poll() is None
            assert query("SELECT outcome FROM accepted_mail_targets WHERE mailbox=?", (app_inbox,)) == [("pending",)]
            process.kill()
            process.wait(timeout=5)

        # Recreate two crash boundaries, with one final pathname linked and
        # one temporary inode left from an interrupted write.
        for user, final_exists in ((second, True), (third, False)):
            directory = bad_dirs[user]
            directory.unlink()
            directory.mkdir()
            mid, stamp, raw, _, ordinal, _ = next(row for row in journal if row[3] == user)
            name = f"{stamp}.{mid}.{ordinal}.route.eml"
            temporary = directory / f".pending-{name}"
            temporary.write_bytes(raw if final_exists else raw[:30])
            if final_exists:
                (directory / name).hardlink_to(temporary)
        bad_dirs[app_inbox].unlink()

        # Promote the standby on its own ports using the established data and
        # routing configuration now that the old PID has exited.
        standby.directory = root
        standby.env.update(routing_env)
        standby.password, standby.specs = test.password, test.specs
        test = standby
        with test.daemon():
            for user in (first, second, third, forwarded):
                assert messages(user) == ["Recovered DATA envelope"], user
                visible, = list((root / "mail" / user / "new").iterdir())
                assert visible.read_bytes() == mail
            assert messages(app_inbox) == ["Recovered app envelope"]
            assert not query("SELECT 1 FROM accepted_mail_targets WHERE outcome='pending'")
            assert not query("SELECT 1 FROM accepted_mail WHERE complete=0 OR length(mime)>0")
            for user in (second, third, forwarded, app_inbox):
                eventually(lambda: subjects(search, user), bool)
            if webhook_ip:
                def notified():
                    with webhooks.events_lock:
                        return [payload["recipients"][0] for _, payload in webhooks.events]
                eventually(notified, lambda users: all(user in users for user in (first, second, third, app_inbox)))
                assert forwarded not in notified()
            print("Verified atomic acceptance, quota reservations, writer exclusion, process death, exactly-once local recovery, and committed counts and indexing.")

            reviewer = test.provision("reviewer")
            no_forward = test.provision("no-forward")
            refused = test.provision("declines")
            for user, decision, forward in ((reviewer, "allow", 1), (no_forward, "allow", 0), (refused, "decline", 1)):
                execute("UPDATE sender_screening SET enabled=1,onboarding_pending=0 WHERE user_id=(SELECT id FROM users WHERE username=?)", (user,))
                execute("INSERT INTO sender_screening_rules(user_id,author,action,forward) SELECT id,?,?,? FROM users WHERE username=?", (author, decision, forward, user))
            (root / "forwards.json").write_text(json.dumps({user: [forwarded] for user in (reviewer, no_forward, refused)}))
            expect_smtp(test.deliver([reviewer, no_forward, refused], identity=author, chunked=True, subject="Verified BDAT author"), 250)
            assert messages(reviewer) == messages(no_forward) == ["Verified BDAT author"]
            assert messages(refused, "Declined") == ["Verified BDAT author"]
            assert messages(forwarded).count("Verified BDAT author") == 1

            with test.smtp() as client:
                assert client.mail(author)[0] == client.rcpt(reviewer)[0] == 250
                expect_smtp(client.data((f"From: {author}\r\nAuthentication-Results: fake; dmarc=pass\r\n"
                                         "Subject: Forged approval\r\n\r\nFake author.\r\n").encode()), 250)
            assert messages(reviewer, "Screening") == ["Forged approval"]
            assert "Forged approval" not in messages(forwarded)
            assert query("SELECT DISTINCT verified_author FROM sender_review_messages WHERE folder='Screening'") == [(0,)]

            (root / "forwards.sieve").write_text(f'require ["envelope"];\nif envelope :is "to" "{reviewer}" {{ redirect "{first}"; keep; }}\n')
            status, response = test.api(test.login(author), "compose", {"to": [reviewer], "subject": "Verified webmail rule", "text": "route through Sieve"})
            assert status == 200, response
            assert "Verified webmail rule" in messages(reviewer) and "Verified webmail rule" in messages(first)
            assert "Verified webmail rule" not in messages(forwarded)

        test.env.update(SMTP_SPAM_FILTER="true", SMTP_SPAM_JUNK_SCORE="0.1", SMTP_SPAM_REJECT_SCORE="99")
        with test.daemon():
            expect_smtp(test.deliver(reviewer, subject="Act now for 100% free bitcoin", body="You have won the lottery"), 250)
            assert messages(reviewer, "Junk") == ["Act now for 100% free bitcoin"]
            assert "Act now for 100% free bitcoin" not in messages(first)
            assert "Act now for 100% free bitcoin" not in subjects(search, reviewer)
        print("Verified BDAT and webmail policy parity, approved forwarding, explicit suppression, spoof isolation, Junk, and both forwarding formats.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--webhook-ip", help="a documentation IP assigned to a loopback alias in an isolated network namespace")
    args = parser.parse_args()
    run(args.binary.resolve(), args.previous.resolve() if args.previous else None, args.webhook_ip)
