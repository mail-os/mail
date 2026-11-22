#!/usr/bin/env python3
"""Persist sanitized mail health and retry incident/recovery alerts outside SMTP.

Runs as root from a systemd timer. Only status.json is readable by mail-server;
webhook credentials, journal cursors and the retry queue remain root-private.
"""
import argparse
from contextlib import closing
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import time
import urllib.parse
import urllib.request


PATTERNS = {
    'TLS receive errors': ('TLS decrypt error:',),
    'Storage failures': ('Failed to save message:', 'Failed to write message data', 'Failed to create message file', 'Failed to create mailbox directory', 'Forward check failed', 'Failed to write forward data'),
    'Pre-greeting DNSBL rejections': ('DNSBL check failed', 'blocked by DNSBL', 'is blacklisted', 'IP blacklisted in DNSBL'),
}
QUEUE_CHECK = 'Outbound queue depth'
BOUNCE_CHECK = 'Queued delivery failure rate'
DELIVERY_STATS_CHECK = 'Outbound delivery statistics'


def atomic_json(path, value, mode):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def load_state(path):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except FileNotFoundError:
        return {'events': [], 'pending': [], 'active': [], 'failures': []}
    # Corrupt state must fail the unit, never silently discard pending alerts.


def env_setting(path, key):
    prefix = key + '='
    for line in pathlib.Path(path).read_text().splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip().strip('\"\'')
    return ''


def send_alert(webhook, content):
    parsed = urllib.parse.urlsplit(webhook)
    if parsed.scheme != 'https' or parsed.hostname not in ('discord.com', 'discordapp.com') or not parsed.path.startswith('/api/webhooks/'):
        raise ValueError('Invalid Discord webhook configuration')
    request = urllib.request.Request(webhook, data=json.dumps({
        'content': content, 'allowed_mentions': {'parse': []},
    }).encode(), headers={'Content-Type': 'application/json', 'User-Agent': 'Stacks-Mail-Health/1.0'}, method='POST')
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status not in (200, 204):
            raise RuntimeError('Alert transport rejected the notification')


# What a deploy cannot vouch for. Journal patterns record what clients and
# peers did (one client tripping a TLS error seconds after a restart says
# nothing about the release), and alert transport is a third party. They keep
# their place in status.json and the alert stream; they just do not decide
# whether a deploy succeeded.
OUTSIDE_DEPLOY_GATE = frozenset(PATTERNS) | {
    'Delivery error monitoring', 'Admin alert transport', QUEUE_CHECK, BOUNCE_CHECK, DELIVERY_STATS_CHECK,
}


def deploy_gate_failures(checks):
    return [c['name'] for c in checks if not c['ok'] and c['name'] not in OUTSIDE_DEPLOY_GATE]


JOURNAL_PAGE_SIZE = 10000
JOURNAL_MAX_PAGES = 8


def journal_checks(state, now):
    # Read oldest-first, not the last N entries after a cursor. Tail sampling
    # both loses intervening errors and gets stuck when it refuses a full page.
    failures = [failure for failure in state.get('failures', [])
                if failure.get('seen_at', failure['at']) >= now - 300]
    known = {(failure['name'], failure.get('cursor')) for failure in failures if failure.get('cursor')}
    deadline = time.monotonic() + 10
    state['journal_backlog'] = True
    for _ in range(JOURNAL_MAX_PAGES):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        command = ['journalctl', '-u', 'mail.service', '--no-pager', '-o', 'json', '-n', f'+{JOURNAL_PAGE_SIZE}']
        if state.get('cursor'):
            command += ['--after-cursor', state['cursor']]
        else:
            command += ['--since', '5 minutes ago']
        result = subprocess.run(command, capture_output=True, timeout=remaining)
        if result.returncode and state.get('cursor'):
            # Rotation can invalidate a cursor. Keep recent detected errors
            # and deduplicate the bounded rescan by journal cursor.
            command = command[:command.index('--after-cursor')] + ['--since', '5 minutes ago']
            result = subprocess.run(command, capture_output=True, timeout=max(.1, deadline - time.monotonic()))
        result.check_returncode()
        lines = result.stdout.splitlines()
        try:
            for line in lines:
                item = json.loads(line)
                cursor = item['__CURSOR']
                message = item.get('MESSAGE', '')
                at = int(item.get('__REALTIME_TIMESTAMP', now * 1000000)) // 1000000
                for name, patterns in PATTERNS.items():
                    if any(pattern in message for pattern in patterns) and (name, cursor) not in known:
                        failures.append({'name': name, 'at': at, 'seen_at': now, 'cursor': cursor})
                        known.add((name, cursor))
                state['cursor'] = cursor
        finally:
            # Commit progress even when a later page fails or exceeds this run's
            # budget. Bound each category independently so a TLS flood cannot
            # erase a detected storage error. No message content enters state.
            state['failures'] = [failure for name in PATTERNS
                                 for failure in [f for f in failures if f['name'] == name][-1000:]]
        if len(lines) < JOURNAL_PAGE_SIZE:
            state['journal_backlog'] = False
            break
    return [{'name': name, 'ok': not any(f['name'] == name for f in failures),
             'count': sum(f['name'] == name for f in failures)} for name in PATTERNS]


def delivery_checks(path, state, now):
    previous = set(state.get('active', []))
    try:
        uri = pathlib.Path(path).resolve().as_uri() + '?mode=ro'
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            db.execute('BEGIN')
            depth, = db.execute(
                "SELECT COUNT(*) FROM message_queue WHERE status IN ('pending','retry','processing')"
            ).fetchone()
            minute = now // 60
            delivered, failed = db.execute(
                'SELECT COALESCE(SUM(delivered),0), COALESCE(SUM(failed),0) '
                'FROM outbound_delivery_minutes WHERE minute BETWEEN ? AND ?',
                (minute - 14, minute),
            ).fetchone()
    except (OSError, sqlite3.Error):
        # A read failure must not announce recovery for an existing incident.
        return [{'name': name, 'ok': False} for name in (QUEUE_CHECK, BOUNCE_CHECK) if name in previous] + [
            {'name': DELIVERY_STATS_CHECK, 'ok': False},
        ]
    completed = delivered + failed
    return [
        {'name': QUEUE_CHECK, 'ok': depth <= 1000, 'count': depth},
        {'name': BOUNCE_CHECK, 'ok': 100 * failed <= 5 * completed, 'count': failed, 'completed': completed},
        {'name': DELIVERY_STATS_CHECK, 'ok': True},
    ]


def reconcile(state, checks, now):
    active = sorted(check['name'] for check in checks if not check['ok'])
    previous = state.get('active', [])
    first_run = 'checked_at' not in state
    if active != previous or first_run:
        event = {'at': now, 'status': 'degraded' if active else 'healthy',
                 'summary': ('Mail needs attention: ' + ', '.join(active)) if active else ('Mail health monitoring enabled' if first_run else 'Mail checks recovered')}
        state.setdefault('events', []).insert(0, event)
        state['events'] = state['events'][:100]
        state.setdefault('pending', []).append(event)
    state['active'] = active
    state['checked_at'] = now


def run(args):
    now = int(time.time())
    state = load_state(args.state_path)
    command = ['python3', args.probe, '--host', args.host, '--connect-host', '127.0.0.1', '--timeout', '4', '--json']
    try:
        probe = subprocess.run(command, capture_output=True, timeout=90)
        result = json.loads(probe.stdout)
        checks = result['checks']
        if not checks or (probe.returncode == 0) != bool(result['ok']):
            raise RuntimeError('Inconsistent probe result')
    except Exception:
        checks = [{'name': 'Mail protocol monitor', 'ok': False}]
    try:
        checks += journal_checks(state, now)
        checks.append({'name': 'Delivery error monitoring', 'ok': not state.get('journal_backlog', False)})
    except Exception:
        checks.append({'name': 'Delivery error monitoring', 'ok': False})
    try:
        configured_database = env_setting(args.env_file, 'SMTP_DB_PATH')
    except OSError:
        configured_database = ''
    database = args.database_path or pathlib.Path(args.storage_path) / (configured_database or 'smtp.db')
    checks += delivery_checks(database, state, now)
    disk = shutil.disk_usage(args.storage_path)
    checks.append({'name': 'Mail storage free space', 'ok': disk.free > max(512 * 1024 * 1024, disk.total // 20)})
    storage_probe = "import os,sys,tempfile; f=tempfile.NamedTemporaryFile(dir=sys.argv[1],prefix='.health-',delete=True); f.write(b'mail health'); f.flush(); os.fsync(f.fileno()); f.close()"
    try:
        subprocess.run(['runuser', '-u', 'mail-server', '--', 'python3', '-c', storage_probe, str(pathlib.Path(args.storage_path) / 'mail')], capture_output=True, timeout=10, check=True)
        checks.append({'name': 'Mail storage write and sync', 'ok': True})
    except Exception:
        checks.append({'name': 'Mail storage write and sync', 'ok': False})
    reconcile(state, checks, now)
    # Commit the notification before attempting delivery, so a crash cannot lose it.
    atomic_json(args.state_path, state, 0o600)
    notification_ok = False
    try:
        webhook = env_setting(args.env_file, 'DISCORD_WEBHOOK_URL')
        if webhook:
            for event in list(state['pending'])[:4]:
                stamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(event['at']))
                send_alert(webhook, f"{args.host}: {event['summary']} ({stamp}). Open /status in webmail for checks and incident history.")
                state['pending'].remove(event)
                state['last_alert_at'] = now
                atomic_json(args.state_path, state, 0o600)
            notification_ok = True
    except Exception:
        # Never log the exception: transport exceptions can contain the webhook URL.
        print('Admin notification delivery failed; queued alerts will retry', flush=True)
    checks.append({'name': 'Admin alert transport', 'ok': notification_ok, 'pending': len(state['pending'])})
    status = {'schema': 1, 'checked_at': now, 'stale_after': 180,
              'status': 'healthy' if all(c['ok'] for c in checks) else 'degraded',
              'checks': checks, 'events': state.get('events', []),
              'last_alert_at': state.get('last_alert_at')}
    atomic_json(args.status_path, status, 0o640)
    failed = [c['name'] for c in checks if not c['ok']]
    print(json.dumps({'status': status['status'], 'failed': failed, 'pending_alerts': len(state['pending'])}), flush=True)
    if getattr(args, 'deploy_gate', False):
        gate = deploy_gate_failures(checks)
        for name in failed:
            if name not in gate:
                print(f'Not judged by the deploy gate (still alerted): {name}', flush=True)
        return int(bool(gate))
    return int(status['status'] != 'healthy')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', default='/opt/mail/maintenance/mail-health.py')
    parser.add_argument('--host', default='mail.stacksjs.com')
    parser.add_argument('--state-path', default='/var/lib/mail-health/private/state.json')
    parser.add_argument('--status-path', default='/var/lib/mail-health/public/status.json')
    parser.add_argument('--storage-path', default='/opt/mail')
    parser.add_argument('--database-path', type=pathlib.Path,
                        help='Override SMTP_DB_PATH from the mail environment file')
    parser.add_argument('--env-file', default='/etc/mail/mail.env')
    parser.add_argument('--deploy-gate', action='store_true',
                        help='Exit by the protocol and storage checks only; status and alerts are unchanged')
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
