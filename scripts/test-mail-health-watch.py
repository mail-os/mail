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
