#!/usr/bin/env python3
"""Exercise durable incident deduplication, recovery, alert retries and privacy."""
import importlib.util
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import pathlib
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
from threading import Thread
import types
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

spec = importlib.util.spec_from_file_location('watch', pathlib.Path(__file__).with_name('mail-health-watch.py'))
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)


class HealthTests(unittest.TestCase):
    def test_scanner_uses_the_running_daemon_identity_and_reports_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            process = root / '202'
            process.mkdir()
            environment = process / 'environ'
            environment.write_bytes(b'UNRELATED_SECRET=private\0')
            (process / 'status').write_text('Uid:\t100\t101\t101\t101\nGid:\t200\t201\t201\t201\nGroups:\t201 203 \n')
            with patch.object(watch.subprocess, 'check_output', return_value=b'202\n'), \
                    patch.object(watch.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0)) as scan:
                self.assertEqual(watch.scanner_checks(root), [])
                scan.assert_not_called()
                endpoint = b'unix:/run/fixture-private/scanner.sock'
                environment.write_bytes(b'UNRELATED_SECRET=private\0SMTP_CLAMAV_TRANSPORT=' + endpoint + b'\0')
                self.assertEqual(watch.scanner_checks(root), [{'name': watch.SCANNER_CHECK, 'ok': True}])
                self.assertEqual(scan.call_args.kwargs['input'], endpoint)
                self.assertEqual(scan.call_args.kwargs['user'], 101)
                self.assertEqual(scan.call_args.kwargs['group'], 201)
                self.assertEqual(scan.call_args.kwargs['extra_groups'], [201, 203])
                self.assertEqual(scan.call_args.kwargs['env'], {})
                state = {'checked_at': 20, 'active': []}
                scan.return_value = types.SimpleNamespace(returncode=1, stderr=b'private scanner response')
                degraded = watch.scanner_checks(root)
                self.assertEqual(watch.deploy_gate_failures(degraded), [watch.SCANNER_CHECK])
                watch.reconcile(state, degraded, 21)
                watch.reconcile(state, degraded, 22)
                self.assertEqual(len(state['pending']), 1)
                scan.return_value = types.SimpleNamespace(returncode=0)
                watch.reconcile(state, watch.scanner_checks(root), 23)
                self.assertEqual([event['status'] for event in state['pending']], ['degraded', 'healthy'])
                packed = json.dumps(state)
                self.assertNotIn('private', packed)

    def test_scanner_probe_checks_actual_streaming_over_unix_and_tcp(self):
        with tempfile.TemporaryDirectory() as directory:
            for family, address, response, expected in (
                (socket.AF_UNIX, str(pathlib.Path(directory) / 'scanner.sock'), b'stream: OK\0', 0),
                (socket.AF_INET, ('127.0.0.1', 0), b'stream: scanner fixture failure ERROR\0', 1),
            ):
                received = []
                with socket.socket(family) as server:
                    server.bind(address)
                    server.listen(1)
                    server.settimeout(5)
                    target = (f'unix:{address}' if family == socket.AF_UNIX else
                              f'tcp:127.0.0.1:{server.getsockname()[1]}')

                    def serve():
                        with server.accept()[0] as peer, peer.makefile('rb') as stream:
                            peer.settimeout(4)
                            received.append(stream.read(len(b'zINSTREAM\0')))
                            size = struct.unpack('!I', stream.read(4))[0]
                            received.append(stream.read(size))
                            received.append(stream.read(4))
                            peer.sendall(response[:7])
                            peer.sendall(response[7:])

                    thread = Thread(target=serve, daemon=True)
                    thread.start()
                    result = subprocess.run([sys.executable, '-c', watch.SCANNER_PROBE],
                                            input=target.encode(), capture_output=True, timeout=6)
                    thread.join(5)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(received, [b'zINSTREAM\0', b'Clean Mail scanner health probe\r\n', bytes(4)])

    def test_hosted_report_drives_incidents_and_survives_lost_observation(self):
        now = 2000
        started = {'schema': 1, 'checked_at': now, 'checks': {
            key: {'status': 'healthy'} for key in watch.HOSTED_CHECKS
        }}
        billing = 'billing_webhook_backlog'
        started['checks'][billing] = {'status': 'degraded', 'count': 1, 'customer': 'private@example.test'}
        with tempfile.TemporaryDirectory() as directory:
            env = pathlib.Path(directory) / 'env'
            env.write_text('MAIL_APP_OPERATIONS_URL=http://127.0.0.1:8080/api/operations/health\n'
                           + 'MAIL_OPERATIONS_TOKEN=' + 'a' * 64 + '\n')
            state = {'checked_at': 1, 'active': [], 'events': [], 'pending': []}
            name = watch.HOSTED_CHECKS[billing]
            with patch.object(watch, 'read_hosted_report', return_value=started):
                checks = watch.hosted_checks(env, state, now)
            self.assertIn({'name': name, 'ok': False}, checks)
            self.assertNotIn('private@example.test', json.dumps(checks))
            self.assertEqual(watch.deploy_gate_failures(checks), [])
            watch.reconcile(state, checks, now)
            watch.reconcile(state, checks, now + 1)
            self.assertEqual(len(state['pending']), 1)

            with patch.object(watch, 'read_hosted_report', return_value=started):
                stale = watch.hosted_checks(env, state, now + 121)
            self.assertIn({'name': name, 'ok': False}, stale)
            self.assertIn({'name': watch.HOSTED_MONITOR_CHECK, 'ok': False}, stale)
            watch.reconcile(state, stale, now + 121)
            self.assertEqual(state['pending'][-1]['status'], 'degraded')

            started['checked_at'] = now + 122
            started['checks'][billing] = {'status': 'healthy', 'count': 0}
            with patch.object(watch, 'read_hosted_report', return_value=started):
                checks = watch.hosted_checks(env, state, now + 122)
            watch.reconcile(state, checks, now + 122)
            self.assertEqual(state['active'], [])
            self.assertEqual(state['pending'][-1]['status'], 'healthy')

    def test_hosted_monitor_loses_configuration_without_recovering_incidents(self):
        now = 2000
        name = watch.HOSTED_CHECKS['billing_reconciliation']
        monitor = {'name': watch.HOSTED_MONITOR_CHECK, 'ok': False}
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            env = root / 'env'
            env.write_text('')
            self.assertEqual(watch.hosted_checks(env, {}, now), [])

            report = {'schema': 1, 'checked_at': now, 'checks': {
                key: {'status': 'healthy'} for key in watch.HOSTED_CHECKS
            }}
            state_path = root / 'state.json'
            for prior in ([], [name], [watch.HOSTED_MONITOR_CHECK]):
                with self.subTest(prior=prior):
                    watch.atomic_json(state_path, {'hosted_monitor_configured': True, 'active': prior}, 0o600)
                    state = watch.load_state(state_path)
                    checks = watch.hosted_checks(env, state, now)
                    self.assertEqual(checks, [monitor] + ([{'name': name, 'ok': False}] if name in prior else []))
                    self.assertTrue(state['hosted_monitor_configured'])

            env.write_text('MAIL_APP_OPERATIONS_URL=http://127.0.0.1:8080/api/operations/health\n'
                           + 'MAIL_OPERATIONS_TOKEN=' + 'a' * 64 + '\n')
            report['checks']['billing_reconciliation'] = {'status': 'disabled'}
            with patch.object(watch, 'read_hosted_report', return_value=report):
                disabled = watch.hosted_checks(env, {'active': [name]}, now)
                never_opened = watch.hosted_checks(env, {'active': []}, now)
            self.assertIn(monitor, disabled)
            self.assertIn({'name': name, 'ok': False}, disabled)
            self.assertIn({'name': watch.HOSTED_MONITOR_CHECK, 'ok': True}, never_opened)
            self.assertNotIn(name, {check['name'] for check in never_opened})

    def test_hosted_bearer_stays_with_the_configured_endpoint(self):
        requests = []
        token = 'a' * 64

        class Redirector(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                requests.append((self.path, self.headers.get('Authorization')))
                self.send_response(307)
                self.send_header('Location', '/redirected')
                self.end_headers()

        with ThreadingHTTPServer(('127.0.0.1', 0), Redirector) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = 'http://127.0.0.1:' + str(server.server_port) + '/api/operations/health'
                with self.assertRaises(OSError):
                    watch.read_hosted_report(url, token)
                with self.assertRaises(ValueError):
                    watch.read_hosted_report(url.replace('127.0.0.1', 'mail.example.test'), token)
            finally:
                server.shutdown()
                thread.join()
        self.assertEqual(requests, [('/api/operations/health', 'Bearer ' + token)])

    def test_restic_freshness_handles_boundary_and_missing_or_invalid_receipts(self):
        now = 100000
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            env = root / 'env'
            stamp = root / 'last-success'
            env.write_text(f'MAIL_RESTIC_STATUS_FILE={stamp}\n')
            self.assertEqual(watch.backup_checks(env, now), [{'name': watch.BACKUP_CHECK, 'ok': False}])
            for value, expected in [(10000, True), (9999, False), (100001, False), ('bad', False)]:
                stamp.write_text(f'timestamp={value}\nrepository=private-repository\n')
                checks = watch.backup_checks(env, now)
                self.assertEqual(checks, [{'name': watch.BACKUP_CHECK, 'ok': expected}])
                self.assertEqual(watch.deploy_gate_failures(checks), [])

    def test_staging_backup_preserves_receipt_when_restic_verification_fails(self):
        if subprocess.run(["mv", "--version"], capture_output=True).returncode != 0:
            self.skipTest("The Linux staging script uses GNU mv")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            worker = root / 'mail-staging-restic-backup.sh'
            shutil.copyfile(pathlib.Path(__file__).with_name(worker.name), worker)
            source = root / 'source'
            state = root / 'state'
            credentials = root / 'credentials'
            for path in (source / 'mail', state, credentials):
                path.mkdir(parents=True)
            (source / 'smtp.db').touch()
            (credentials / 'restic-password').write_text('fixture-password')
            config = root / 'mail.env'
            receipt = state / 'last-success'
            config.write_text(f'SMTP_PROFILE=staging\nMAIL_RESTIC_STATUS_FILE={receipt}\n')
            receipt.write_text('timestamp=1\narchive=previous-backup.tgz\n')

            archiver = root / 'mail-backup.sh'
            archiver.write_text(
                'set -eu\n'
                'test -z "$MAIL_BACKUP_ENV_FILE"\n'
                'touch "$BACKUP_DIR/mail-backup-fixture.tgz"\n'
            )
            restic = root / 'restic'
            restic.write_text(
                '#!/bin/sh\n'
                'test -s "$RESTIC_PASSWORD_FILE" || exit 2\n'
                'printf "%s\\n" "$2" >> "$STATE_DIRECTORY/operations"\n'
                'if [ "$2" = check ]; then exit "$FIXTURE_CHECK_STATUS"; fi\n'
            )
            restic.chmod(0o700)
            environment = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", STATE_DIRECTORY=str(state),
                               CREDENTIALS_DIRECTORY=str(credentials), FIXTURE_CHECK_STATUS='12',
                               RESTIC_REPOSITORY='s3:https://s3.us-east-1.amazonaws.com/test-bucket/staging/backups/mail')
            command = ['bash', str(worker), str(source), str(config), '/bin/sh']

            failed = subprocess.run(command, env=environment, capture_output=True)
            self.assertEqual(failed.returncode, 12, failed.stderr)
            self.assertEqual(receipt.read_text(), 'timestamp=1\narchive=previous-backup.tgz\n')
            self.assertEqual((state / 'operations').read_text().splitlines(), ['backup', 'forget', 'check'])
            self.assertFalse(list(state.glob('backup.*')))

            environment['FIXTURE_CHECK_STATUS'] = '0'
            succeeded = subprocess.run(command, env=environment, capture_output=True)
            self.assertEqual(succeeded.returncode, 0, succeeded.stderr)
            timestamp = int(receipt.read_text().splitlines()[0].split('=', 1)[1])
            self.assertGreater(timestamp, 1)
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
            self.assertEqual(watch.backup_checks(config, timestamp), [{'name': watch.BACKUP_CHECK, 'ok': True}])
            self.assertFalse(list(state.glob('backup.*')))

    def test_delivery_minute_window_and_depth_at_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'smtp db.sqlite'
            db = sqlite3.connect(path)
            try:
                db.executescript("""
                    CREATE TABLE message_queue (status TEXT);
                    INSERT INTO message_queue VALUES ('pending'), ('retry'), ('processing'), ('staged');
                    CREATE TABLE outbound_delivery_minutes (minute INTEGER, delivered INTEGER, failed INTEGER);
                    INSERT INTO outbound_delivery_minutes VALUES (85,0,500), (86,19,1), (101,0,500);
                """)
            finally:
                db.close()
            queue, failure, monitor = watch.delivery_checks(path, {}, 100 * 60 + 59)
            self.assertEqual(queue, {'name': watch.QUEUE_CHECK, 'ok': True, 'count': 3})
            self.assertEqual(failure, {'name': watch.BOUNCE_CHECK, 'ok': True, 'count': 1, 'completed': 20})
            self.assertTrue(monitor['ok'])
            self.assertTrue(watch.delivery_checks(path, {}, 101 * 60)[0]['ok'])
            self.assertFalse(watch.delivery_checks(path, {}, 101 * 60)[1]['ok'])

    def test_delivery_telemetry_read_failure_preserves_open_incident(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'absent.db'
            state = {'active': [watch.BOUNCE_CHECK]}
            failure, monitor = watch.delivery_checks(path, state, 100)
            self.assertEqual(failure['name'], watch.BOUNCE_CHECK)
            self.assertFalse(failure['ok'])
            self.assertFalse(monitor['ok'])
            self.assertFalse(path.exists())
            self.assertEqual(watch.deploy_gate_failures([failure, monitor]), [])

    def test_incident_recovery_and_no_repeated_notifications(self):
        state = {'checked_at': 1, 'active': [], 'events': [], 'pending': []}
        watch.reconcile(state, [{'name': 'TLS receive errors', 'ok': False}], 100)
        watch.reconcile(state, [{'name': 'TLS receive errors', 'ok': False}], 101)
        self.assertEqual(len(state['pending']), 1)
        watch.reconcile(state, [{'name': 'TLS receive errors', 'ok': True}], 102)
        self.assertEqual([e['status'] for e in state['pending']], ['degraded', 'healthy'])

    def test_alert_failure_survives_restart_and_retries_without_secret_in_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            env = root / 'env'
            env.write_text('DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/private-secret\n')
            args = types.SimpleNamespace(state_path=root/'private/state.json', status_path=root/'public/status.json',
                                         env_file=env, storage_path=root, probe='probe.py', host='mail.example.com',
                                         database_path=None, mailbox_path=None)
            (root/'mail').mkdir()
            (root/'smtp.db').touch()
            probe = subprocess.CompletedProcess([], 0, json.dumps({'ok': True, 'checks': [{'name': 'SMTP', 'ok': True}]}).encode())
            with patch.object(watch.subprocess, 'run', return_value=probe), patch.object(watch, 'journal_checks', return_value=[]), patch.object(watch, 'delivery_checks', return_value=[]), patch.object(watch.shutil, 'disk_usage', return_value=types.SimpleNamespace(total=10000000000, free=5000000000)):
                with patch.object(watch, 'send_alert', side_effect=RuntimeError('secret')):
                    self.assertEqual(watch.run(args), 1)
                self.assertEqual(len(watch.load_state(args.state_path)['pending']), 1)
                public = args.status_path.read_text()
                self.assertNotIn('private-secret', public)
                with patch.object(watch, 'send_alert') as sent:
                    self.assertEqual(watch.run(args), 0)
                    self.assertEqual(sent.call_count, 1)
                    self.assertEqual(watch.run(args), 0)
                    self.assertEqual(sent.call_count, 1)
                self.assertEqual(args.state_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(args.status_path.stat().st_mode & 0o777, 0o640)

    def test_discord_retry_delay_supports_header_and_fractional_json(self):
        for header, body, expected in [
            ('90', b'{"retry_after": 64.57}', 90),
            (None, b'{"retry_after": 64.57}', 64.57),
            ('nan', b'{"retry_after": 3.25}', 3.25),
            ('-1', b'{"retry_after": true}', 60),
            (None, b'not JSON', 60),
        ]:
            with self.subTest(header=header, body=body):
                headers = {} if header is None else {'Retry-After': header}
                with HTTPError('https://discord.com/api/webhooks/test', 429, '', headers, io.BytesIO(body)) as response:
                    self.assertEqual(watch.discord_retry_delay(response), expected)

    def run_gate(self, root, probe_checks, journal):
        args = types.SimpleNamespace(state_path=root/'private/state.json', status_path=root/'public/status.json',
                                     env_file=root/'env', storage_path=root, probe='probe.py', host='mail.example.com',
                                     deploy_gate=True, database_path=None, mailbox_path=None)
        args.env_file.write_text('')
        (root/'mail').mkdir()
        (root/'smtp.db').touch()
        ok = all(check['ok'] for check in probe_checks)
        probe = subprocess.CompletedProcess([], 0 if ok else 1, json.dumps({'ok': ok, 'checks': probe_checks}).encode())
        with patch.object(watch.subprocess, 'run', return_value=probe), patch.object(watch, 'journal_checks', return_value=journal), patch.object(watch, 'delivery_checks', return_value=[]), patch.object(watch.shutil, 'disk_usage', return_value=types.SimpleNamespace(total=10000000000, free=5000000000)):
            code = watch.run(args)
        return code, json.loads(args.status_path.read_text()), watch.load_state(args.state_path)

    def test_storage_capacity_checks_follow_mounts_without_duplicate_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = pathlib.Path(directory)
            encrypted = runtime / 'encrypted'
            encrypted.mkdir()
            (encrypted/'mail').mkdir()
            (encrypted/'smtp.db').touch()
            mailbox = runtime/'mail'
            database = runtime/'smtp.db'
            mailbox.symlink_to(encrypted/'mail', target_is_directory=True)
            database.symlink_to(encrypted/'smtp.db')
            paths = {runtime: 1, mailbox: 2, database: 2}
            allocated = {1: 100 * 1024**3, 2: 16 * 1024**3}

            def disk_stat(path):
                return types.SimpleNamespace(st_dev=paths[path])

            for free in ({1: 1 * 1024**3, 2: 6 * 1024**3}, {1: 6 * 1024**3, 2: 1}):
                def disk_usage(path):
                    device = paths[path]
                    return types.SimpleNamespace(total=allocated[device], free=free[device])

                with patch.object(pathlib.Path, 'stat', autospec=True, side_effect=disk_stat), \
                        patch.object(watch.shutil, 'disk_usage', side_effect=disk_usage) as usage:
                    checks = watch.storage_capacity_checks(runtime, mailbox, database)
                self.assertEqual([call.args[0] for call in usage.call_args_list], [runtime, mailbox])
                self.assertEqual(checks, [
                    {'name': 'Mail runtime filesystem free space', 'ok': free[1] > allocated[1] // 20},
                    {'name': 'Mail mailbox filesystem free space', 'ok': free[2] > allocated[2] // 20},
                ])

            with patch.object(watch.shutil, 'disk_usage', return_value=types.SimpleNamespace(total=allocated[1], free=free[1])) as usage:
                self.assertEqual(len(watch.storage_capacity_checks(runtime, mailbox, database)), 1)
            self.assertEqual(usage.call_count, 1)

            (encrypted/'smtp.db').unlink()
            with patch.object(watch.shutil, 'disk_usage', return_value=types.SimpleNamespace(total=allocated[1], free=free[1])):
                checks = watch.storage_capacity_checks(runtime, mailbox, database)
            self.assertIn({'name': 'Mail database filesystem free space', 'ok': False}, checks)

    def test_deploy_gate_passes_a_client_tls_error_but_still_alerts_on_it(self):
        # One client's TLS error seconds after the restart failed a deploy
        # whose binary and every protocol probe were fine.
        with tempfile.TemporaryDirectory() as directory:
            code, status, state = self.run_gate(pathlib.Path(directory), [{'name': 'IMAPS TLSv1_3', 'ok': True}],
                                                [{'name': 'TLS receive errors', 'ok': False, 'count': 1}])
            self.assertEqual(code, 0)
            self.assertEqual(status['status'], 'degraded')
            self.assertIn('TLS receive errors', state['active'])
            self.assertEqual(state['pending'][-1]['summary'], 'Mail needs attention: TLS receive errors')

    def test_deploy_gate_fails_a_broken_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            code, status, _ = self.run_gate(pathlib.Path(directory), [{'name': 'IMAPS TLSv1_3', 'ok': False}], [])
            self.assertEqual(code, 1)
            self.assertEqual(status['status'], 'degraded')

    def test_journal_window_and_cursor_no_duplicate_counting(self):
        state = {'failures': [{'name': 'Storage failures', 'at': 1}]}
        entry = {'__CURSOR': 'cursor-1', '__REALTIME_TIMESTAMP': '1000000000',
                 'MESSAGE': 'TLS decrypt error: secret user@example.com'}
        completed = subprocess.CompletedProcess([], 0, (json.dumps(entry)+'\n').encode())
        with patch.object(watch.subprocess, 'run', return_value=completed):
            checks = watch.journal_checks(state, 1000)
        self.assertEqual(state['cursor'], 'cursor-1')
        self.assertEqual(checks[0]['count'], 1)
        self.assertNotIn('user@example.com', json.dumps(state))
        with patch.object(watch.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'')) as run:
            watch.journal_checks(state, 1001)
            self.assertIn('--after-cursor', run.call_args.args[0])
        self.assertEqual(len(state['failures']), 1)

    def test_journal_pages_oldest_first_without_losing_errors(self):
        def page(*entries):
            return subprocess.CompletedProcess([], 0, b''.join((json.dumps(entry)+'\n').encode() for entry in entries))
        def entry(cursor, message):
            return {'__CURSOR': cursor, '__REALTIME_TIMESTAMP': '100000000', 'MESSAGE': message}
        state = {'cursor': 'before', 'failures': []}
        pages = [page(entry('one', 'ordinary'), entry('two', 'Failed to save message: private')),
                 page(entry('three', 'TLS decrypt error: private'), entry('four', 'ordinary')), page()]
        with patch.object(watch, 'JOURNAL_PAGE_SIZE', 2), patch.object(watch.subprocess, 'run', side_effect=pages) as run:
            checks = watch.journal_checks(state, 1000)
        self.assertFalse(state['journal_backlog'])
        self.assertEqual(state['cursor'], 'four')
        self.assertEqual([check['count'] for check in checks], [1, 1, 0])
        self.assertNotIn('private', json.dumps(state))
        commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(all('+2' in command for command in commands))
        self.assertEqual([command[-1] for command in commands], ['before', 'two', 'four'])
        # Old errors newly discovered in a backlog remain visible for a full window.
        with patch.object(watch.subprocess, 'run', return_value=page()):
            self.assertEqual(watch.journal_checks(state, 1001)[0]['count'], 1)

    def test_full_page_advances_cursor_and_next_run_recovers(self):
        entry = {'__CURSOR': 'advanced', '__REALTIME_TIMESTAMP': '1000000000', 'MESSAGE': 'ordinary'}
        page = subprocess.CompletedProcess([], 0, (json.dumps(entry)+'\n').encode())
        state = {'cursor': 'before', 'failures': []}
        with patch.object(watch, 'JOURNAL_PAGE_SIZE', 1), patch.object(watch, 'JOURNAL_MAX_PAGES', 1), patch.object(watch.subprocess, 'run', return_value=page):
            watch.journal_checks(state, 1000)
        self.assertTrue(state['journal_backlog'])
        self.assertEqual(state['cursor'], 'advanced')
        with patch.object(watch.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'')):
            watch.journal_checks(state, 1001)
        self.assertFalse(state['journal_backlog'])

    def test_later_parse_failure_keeps_prior_error_and_cursor_progress(self):
        entry = {'__CURSOR': 'read', '__REALTIME_TIMESTAMP': '1000000000', 'MESSAGE': 'Failed to save message: private'}
        page = subprocess.CompletedProcess([], 0, (json.dumps(entry)+'\n{invalid\n').encode())
        state = {'cursor': 'before', 'failures': []}
        with patch.object(watch.subprocess, 'run', return_value=page):
            with self.assertRaises(json.JSONDecodeError):
                watch.journal_checks(state, 1000)
        self.assertEqual(state['cursor'], 'read')
        self.assertEqual(state['failures'][0]['name'], 'Storage failures')
        self.assertTrue(state['journal_backlog'])

    def test_rotated_cursor_preserves_recent_errors_and_deduplicates_rescan(self):
        entry = {'__CURSOR': 'same', '__REALTIME_TIMESTAMP': '1000000000', 'MESSAGE': 'TLS decrypt error: private'}
        state = {'cursor': 'rotated', 'failures': [{'name': 'TLS receive errors', 'at': 1000, 'seen_at': 1000, 'cursor': 'same'}]}
        responses = [subprocess.CompletedProcess([], 1, b''), subprocess.CompletedProcess([], 0, (json.dumps(entry)+'\n').encode())]
        with patch.object(watch.subprocess, 'run', side_effect=responses):
            checks = watch.journal_checks(state, 1001)
        self.assertEqual(checks[0]['count'], 1)
        self.assertEqual(state['cursor'], 'same')

    def test_corrupt_state_never_silently_discards_alert_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'state'
            path.write_text('{broken')
            with self.assertRaises(json.JSONDecodeError):
                watch.load_state(path)


if __name__ == '__main__':
    unittest.main()
