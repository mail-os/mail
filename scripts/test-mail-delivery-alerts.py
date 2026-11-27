#!/usr/bin/env python3
"""Exercise live outbound queue incidents and recovery on disposable services."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager, nullcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
import sys
import tempfile
from threading import Event, Thread
import time
from types import SimpleNamespace
from unittest.mock import patch
import urllib.request


scripts = Path(__file__).resolve().parent
fixtures = runpy.run_path(str(scripts / "test-hosted-limits.py"))
watch = runpy.run_path(str(scripts / "mail-health-watch.py"))
Fixture, smtp_message = fixtures["Fixture"], fixtures["smtp_message"]
WEBHOOK = "https://discord.com/api/webhooks/disposable"
GOOD = "recipient@success.example.test"
WAITING = "recipient@delayed.example.test"
FAILED = "recipient@refusal.example.test"


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.path == "/incident"
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.messages.append(payload)
        self.server.entered.set()
        if self.server.failing:
            self.server.unblock.wait(timeout=15)
            self.send_response(503)
        elif self.server.retry_after is not None:
            self.send_response(429)
            self.send_header("Retry-After", str(self.server.retry_after))
        else:
            self.send_response(204)
        self.end_headers()

    def log_message(self, *_):
        pass


@contextmanager
def receiver():
    with ThreadingHTTPServer(("127.0.0.1", 0), Receiver) as server:
        server.messages = []
        server.entered = Event()
        server.unblock = Event()
        server.failing = True
        server.retry_after = None
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server
        finally:
            server.unblock.set()
            server.shutdown()
            worker.join()


def fake_ses(test):
    directory = test.directory / "tools"
    directory.mkdir()
    aws = directory / "aws"
    aws.write_text("""#!/usr/bin/env python3
import json
from pathlib import Path
import sys
import time

assert sys.argv[1:3] == ['ses', 'send-raw-email']
target, = json.loads(Path(sys.argv[-1].removeprefix('file://')).read_text())['Destinations']
if target.endswith('@refusal.example.test'):
    sys.exit(1)
if target.endswith('@delayed.example.test'):
    deadline = time.monotonic() + 25
    while not Path('release-delivery').exists():
        if time.monotonic() > deadline:
            sys.exit(2)
        time.sleep(.05)
""")
    aws.chmod(0o755)
    test.env["PATH"] = str(directory) + os.pathsep + test.env["PATH"]
    test.env["SMTP_DELIVERY_METHOD"] = "ses"


def insert_queue(db_path, sender, count, recipient, retry_at, prefix):
    stamp = int(time.time())
    rows = [(f"{prefix}-{index}", sender, recipient, "Disposable delivery", retry_at, stamp, stamp)
            for index in range(count)]
    with closing(sqlite3.connect(db_path)) as db, db:
        db.executemany("""
            INSERT INTO message_queue(id,from_addr,to_addr,message_data,status,max_attempts,next_retry,created_at,updated_at)
            VALUES (?,?,?,?,'retry',1,?,?,?)
        """, rows)


def state_of(db_path):
    return {check["name"]: check for check in watch["delivery_checks"](db_path, {}, int(time.time()))}


def wait_for(check, db_path, expected, *, field="count"):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        checks = state_of(db_path)
        value = checks[check].get(field)
        if value == expected:
            return checks[check]
        time.sleep(.1)
    raise AssertionError((check, expected, checks))


@contextmanager
def monitor(root, db_path, sink, host="mail.example.test"):
    status = root / "public/status.json"
    env = root / "mail.env"
    env.write_text(f"DISCORD_WEBHOOK_URL={WEBHOOK}\nSMTP_DB_PATH={db_path}\n")
    (root / "mail").mkdir(exist_ok=True)
    args = ["--state-path", str(root / "private/state.json"), "--status-path", str(status),
            "--env-file", str(env), "--storage-path", str(root), "--probe", "probe.py", "--host", host]
    watchdog = watch["main"]
    probe = subprocess.CompletedProcess([], 0, b'{"ok":true,"checks":[{"name":"SMTP","ok":true}]}')
    run_command = subprocess.run
    open_url = urllib.request.urlopen

    def post_to_fixture(req, *positional, **options):
        if isinstance(req, urllib.request.Request) and req.full_url == WEBHOOK:
            req = urllib.request.Request(f"http://127.0.0.1:{sink.server_port}/incident",
                                         req.data, headers=dict(req.header_items()), method=req.get_method())
        return open_url(req, *positional, **options)

    def check_command(command, *positional, **options):
        if command[:2] == ["python3", "probe.py"] or command[0] == "runuser":
            return probe
        return run_command(command, *positional, **options)

    def check_health(observed_at=None):
        clock = nullcontext() if observed_at is None else patch.object(watch["time"], "time", return_value=observed_at)
        with clock, patch.object(watch["subprocess"], "run", side_effect=check_command), \
            patch.dict(watchdog.__globals__, {"journal_checks": lambda state, now: []}), \
            patch.object(watch["shutil"], "disk_usage", return_value=SimpleNamespace(total=10**10, free=5 * 10**9)):
            watchdog(args)
        return {check["name"]: check for check in json.loads(status.read_text())["checks"]}

    with patch.object(urllib.request, "urlopen", post_to_fixture):
        yield check_health


def verify(binary):
    with tempfile.TemporaryDirectory(prefix="mail-delivery-alerts-") as directory:
        root = Path(directory)
        test = Fixture(binary, root, staging=True)
        fake_ses(test)
        db = root / "smtp.db"
        queue = watch["QUEUE_CHECK"]
        bounces = watch["BOUNCE_CHECK"]
        with test.daemon():
            owner = test.provision("alert-owner", daily=100)
        insert_queue(db, owner, 1000, GOOD, int(time.time()) + 3600, "backlog")
        with receiver() as sink, monitor(root, db, sink) as check_health:
            with test.daemon():
                assert state_of(db)[queue]["ok"], state_of(db)
                assert test.deliver(WAITING, identity=owner)[0] == 250
                assert not wait_for(queue, db, 1001)["ok"]

                with ThreadPoolExecutor(max_workers=1) as executor:
                    check = executor.submit(check_health)
                    try:
                        if not sink.entered.wait(5):
                            check.result(timeout=5)
                            raise AssertionError("Expected the webhook receiver to be contacted")
                        # Keep the receiver blocked while a real SMTP message is accepted.
                        assert test.deliver(owner, identity=owner, subject="Local while alerts wait")[0] == 250
                    finally:
                        sink.unblock.set()
                    assert not check.result(timeout=15)["Admin alert transport"]["ok"]
                assert len(watch["load_state"](root / "private/state.json")["pending"]) == 1
                sink.failing = False
                sink.retry_after = 90
                stamp = int(time.time())
                assert not check_health(stamp)["Admin alert transport"]["ok"]
                assert len(sink.messages) == 2
                assert watch["load_state"](root / "private/state.json")["alert_retry_at"] == stamp + 90
                sink.retry_after = None
                deferred = check_health(stamp + 60)["Admin alert transport"]
                assert len(sink.messages) == 2, "Webhook was retried before Retry-After elapsed"
                assert not deferred["ok"] and deferred["pending"] == 1 and deferred["retry_at"] == stamp + 90
                assert not check_health(stamp + 89)["Admin alert transport"]["ok"]
                assert len(sink.messages) == 2
                assert check_health(stamp + 90)["Admin alert transport"]["ok"]
                assert "alert_retry_at" not in watch["load_state"](root / "private/state.json")
                check_health(stamp + 91)
                assert len(sink.messages) == 3, sink.messages
                assert sink.messages[0] == sink.messages[1] == sink.messages[2], sink.messages
                (root / "release-delivery").touch()
                assert wait_for(queue, db, 1000)["ok"]
                assert check_health()[queue]["ok"]
                assert "checks recovered" in sink.messages[-1]["content"]

            insert_queue(db, owner, 1, FAILED, int(time.time()), "terminal-failure")
            with test.daemon():
                failed = wait_for(bounces, db, 1)
                assert failed["completed"] == 2 and not failed["ok"], failed
                assert not check_health()[bounces]["ok"]
                assert bounces in sink.messages[-1]["content"]
                with test.smtp(owner) as client:
                    recipients = [f"recipient-{index}@success.example.test" for index in range(18)]
                    result = smtp_message(client, owner, recipients, "Successful delivery")
                    assert result[0] == 250, result
                wait_for(bounces, db, 20, field="completed")
                recovered = check_health()[bounces]
                assert recovered["completed"] == 20 and recovered["count"] == 1 and recovered["ok"], recovered
                assert "checks recovered" in sink.messages[-1]["content"]
                count = len(sink.messages)
                check_health()
                assert len(sink.messages) == count
        assert len(sink.messages) == 6, sink.messages
        assert not any(owner in msg["content"] for msg in sink.messages)
        print("Verified live queue and delivery thresholds, failed webhook retry, rate-limit backoff, deduplication, and recovery over a disposable receiver.")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve(strict=True))
