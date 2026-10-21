#!/usr/bin/env python3
"""Exercise durable incident deduplication, recovery, alert retries and privacy."""
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('watch', pathlib.Path(__file__).with_name('mail-health-watch.py'))
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)


class HealthTests(unittest.TestCase):
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
                                         env_file=env, storage_path=root, probe='probe.py', host='mail.example.com')
            probe = subprocess.CompletedProcess([], 0, json.dumps({'ok': True, 'checks': [{'name': 'SMTP', 'ok': True}]}).encode())
            with patch.object(watch.subprocess, 'run', return_value=probe), patch.object(watch, 'journal_checks', return_value=[]), patch.object(watch.shutil, 'disk_usage', return_value=types.SimpleNamespace(total=10000000000, free=5000000000)):
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

    def test_corrupt_state_never_silently_discards_alert_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'state'
            path.write_text('{broken')
            with self.assertRaises(json.JSONDecodeError):
                watch.load_state(path)


if __name__ == '__main__':
    unittest.main()
