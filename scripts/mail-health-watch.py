#!/usr/bin/env python3
"""Persist sanitized mail health and retry incident/recovery alerts outside SMTP.

Runs as root from a systemd timer. Only status.json is readable by mail-server;
webhook credentials, journal cursors and the retry queue remain root-private.
"""
import argparse
from contextlib import closing
import json
import math
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
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
HOSTED_MONITOR_CHECK = 'Hosted operations monitor'
BACKUP_CHECK = 'Verified off-host backup freshness'
SCANNER_CHECK = 'Mail malware scanner'
HOSTED_CHECKS = {
    'provisioning_listener': 'Hosted provisioning listener',
    'free_provisioning_backlog': 'Free mailbox provisioning backlog',
    'paid_provisioning_backlog': 'Paid mailbox provisioning backlog',
    'billing_webhook_backlog': 'Hosted billing webhook backlog',
    'billing_reconciliation': 'Hosted billing reconciliation',
    'billing_mailbox_access': 'Hosted billing mailbox access updates',
}
BACKUP_STATUS = pathlib.Path('/var/lib/mail-storage/data/restic/last-success')
BACKUP_TIMER = pathlib.Path('/etc/systemd/system/mail-restic-backup.timer')
SYNC_MONITOR_CHECK = 'Client synchronization monitor'
SYNC_CHECKS = {protocol + ' client synchronization' for protocol in ('IMAP', 'CalDAV', 'CardDAV', 'ActiveSync', 'EWS')}


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


# Run with Mail's effective identity. A clean INSTREAM checks the scan pipeline
# as well as the socket. A PING alone can succeed when signature loading fails.
SCANNER_PROBE = r'''
import ipaddress
import socket
import struct
import sys

target = sys.stdin.read()
if target.startswith(('unix:', '/')):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(3)
    client.connect(target.removeprefix('unix:'))
else:
    host, _, port = target.removeprefix('tcp:').rpartition(':')
    address = ipaddress.ip_address(host.removeprefix('[').removesuffix(']'))
    client = socket.create_connection((str(address), int(port)), timeout=3)

with client:
    payload = b'Clean Mail scanner health probe\r\n'
    client.sendall(b'zINSTREAM\0' + struct.pack('!I', len(payload)) + payload + bytes(4))
    reply = bytearray()
    while b'\0' not in reply and len(reply) < 1024:
        chunk = client.recv(1024 - len(reply))
        if not chunk:
            break
        reply.extend(chunk)
    sys.exit(reply != b'stream: OK\0')
'''


def scanner_checks(proc_root=pathlib.Path('/proc')):
    try:
        pid = int(subprocess.check_output(
            ['systemctl', 'show', 'mail.service', '-p', 'MainPID', '--value'],
            timeout=3, stderr=subprocess.DEVNULL,
        ))
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    if pid <= 1:
        return []  # Listener checks already report a stopped daemon.

    try:
        process = proc_root / str(pid)
        variables = process.joinpath('environ').read_bytes().split(b'\0')
        prefix = b'SMTP_CLAMAV_TRANSPORT='
        endpoint = next((value[len(prefix):] for value in variables if value.startswith(prefix)), b'')
        if not endpoint:
            return []
        credentials = dict(line.split(':', 1) for line in process.joinpath('status').read_text().splitlines() if ':' in line)
        uid = int(credentials['Uid'].split()[1])
        gid = int(credentials['Gid'].split()[1])
        groups = [int(group) for group in credentials['Groups'].split()]
        result = subprocess.run(
            [sys.executable, '-c', SCANNER_PROBE], input=endpoint,
            user=uid, group=gid, extra_groups=groups, env={},
            capture_output=True, timeout=7,
        )
        ok = result.returncode == 0
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError):
        ok = False
    return [{'name': SCANNER_CHECK, 'ok': ok}]


class AlertRateLimited(Exception):
    def __init__(self, retry_after):
        super().__init__('Alert transport is rate limited')
        self.retry_after = retry_after


def retry_after_seconds(value):
    try:
        seconds = float(str(value))
    except ValueError:
        return None
    return seconds if math.isfinite(seconds) and seconds >= 0 else None


def discord_retry_delay(error):
    delay = retry_after_seconds(error.headers.get('Retry-After'))
    if delay is not None:
        return delay
    try:
        body = json.loads(error.read(4096))
    except (OSError, ValueError):
        body = None
    delay = retry_after_seconds(body.get('retry_after')) if isinstance(body, dict) else None
    return 60 if delay is None else delay


def send_alert(webhook, content):
    parsed = urllib.parse.urlsplit(webhook)
    if parsed.scheme != 'https' or parsed.hostname not in ('discord.com', 'discordapp.com') or not parsed.path.startswith('/api/webhooks/'):
        raise ValueError('Invalid Discord webhook configuration')
    request = urllib.request.Request(webhook, data=json.dumps({
        'content': content, 'allowed_mentions': {'parse': []},
    }).encode(), headers={'Content-Type': 'application/json', 'User-Agent': 'Stacks-Mail-Health/1.0'}, method='POST')
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status not in (200, 204):
                raise RuntimeError('Alert transport rejected the notification')
    except urllib.error.HTTPError as error:
        with error:
            if error.code == 429:
                raise AlertRateLimited(discord_retry_delay(error)) from None
            raise


# What a deploy cannot vouch for. Journal patterns record what clients and
# peers did (one client tripping a TLS error seconds after a restart says
# nothing about the release), and alert transport is a third party. They keep
# their place in status.json and the alert stream; they just do not decide
# whether a deploy succeeded.
OUTSIDE_DEPLOY_GATE = frozenset(PATTERNS) | {
    'Delivery error monitoring', 'Admin alert transport', QUEUE_CHECK, BOUNCE_CHECK, DELIVERY_STATS_CHECK,
    HOSTED_MONITOR_CHECK, BACKUP_CHECK, SYNC_MONITOR_CHECK,
} | frozenset(HOSTED_CHECKS.values()) | SYNC_CHECKS


def deploy_gate_failures(checks):
    return [c['name'] for c in checks if not c['ok'] and c['name'] not in OUTSIDE_DEPLOY_GATE]


def storage_capacity_checks(runtime, mailbox, database):
    checks = []
    seen = set()
    for name, path in [('Mail runtime filesystem free space', runtime),
                       ('Mail mailbox filesystem free space', mailbox),
                       ('Mail database filesystem free space', database)]:
        try:
            device = path.stat().st_dev  # Follow deployment symlinks to the data mount.
            if device in seen:
                continue
            seen.add(device)
            disk = shutil.disk_usage(path)
            ok = disk.free > max(512 * 1024 * 1024, disk.total // 20)
        except OSError:
            ok = False
        checks.append({'name': name, 'ok': ok})
    return checks


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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_hosted_report(url, token):
    parsed = urllib.parse.urlsplit(url)
    loopback_http = parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'
    if (not (parsed.scheme == 'https' or loopback_http) or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path != '/api/operations/health' or not re.fullmatch(r'[0-9a-f]{64}', token)):
        raise ValueError('Invalid hosted health configuration')
    request = urllib.request.Request(url, headers={
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/json',
        'Cache-Control': 'no-store',
    })
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=12) as response:
            payload = response.read(4097)
            if response.status != 200 or len(payload) > 4096:
                raise ValueError('Invalid hosted health response')
    except urllib.error.HTTPError as error:
        error.close()
        raise
    return json.loads(payload)


def hosted_checks(env_file, state, now):
    active = set(state.get('active', []))
    previous = active.intersection(HOSTED_CHECKS.values())
    try:
        url = env_setting(env_file, 'MAIL_APP_OPERATIONS_URL')
        token = env_setting(env_file, 'MAIL_OPERATIONS_TOKEN')
        if url or token:
            state['hosted_monitor_configured'] = True
        report = read_hosted_report(url, token)
        checked_at = report.get('checked_at')
        checks = report.get('checks')
        if (report.get('schema') != 1 or type(checked_at) is not int
                or not (now - 120 <= checked_at <= now + 30)
                or not isinstance(checks, dict) or set(checks) != set(HOSTED_CHECKS)):
            raise ValueError('Stale or incompatible hosted health report')
        results = []
        monitor_ok = True
        for key, name in HOSTED_CHECKS.items():
            observation = checks[key]
            status = observation.get('status')
            if status not in ('healthy', 'degraded', 'disabled', 'unavailable'):
                raise ValueError('Invalid hosted health check')
            if status == 'disabled':
                if name not in previous:
                    continue
                # A disabled check cannot confirm recovery of an open incident.
                monitor_ok = False
            # Backlog counts stay on the authenticated operator endpoint.
            results.append({'name': name, 'ok': status == 'healthy'})
        return [{'name': HOSTED_MONITOR_CHECK, 'ok': monitor_ok}, *results]
    except (OSError, ValueError, AttributeError, TypeError):
        if not previous and HOSTED_MONITOR_CHECK not in active and not state.get('hosted_monitor_configured'):
            return []
        # Loss of the reader cannot recover an incident in the service it watches.
        return [{'name': HOSTED_MONITOR_CHECK, 'ok': False}] + [
            {'name': name, 'ok': False} for name in sorted(previous)
        ]


def backup_checks(env_file, state, now):
    try:
        override = env_setting(env_file, 'MAIL_RESTIC_STATUS_FILE')
    except OSError:
        override = ''
    if not override and not BACKUP_TIMER.is_file():
        # Losing the source of an observation cannot confirm recovery.
        if BACKUP_CHECK in state.get('active', []):
            return [{'name': BACKUP_CHECK, 'ok': False}]
        return []
    try:
        with pathlib.Path(override or BACKUP_STATUS).open() as stream:
            lines = stream.read(4096).splitlines()
        stamp, = [line.removeprefix('timestamp=') for line in lines if line.startswith('timestamp=')]
        age = now - int(stamp)
        return [{'name': BACKUP_CHECK, 'ok': 0 <= age <= 90000}]
    except (OSError, ValueError):
        return [{'name': BACKUP_CHECK, 'ok': False}]


def sync_checks(env_file, host, state):
    active = set(state.get('active', []))
    previous = active & SYNC_CHECKS
    monitor_failed = SYNC_MONITOR_CHECK in active
    try:
        config = env_setting(env_file, 'MAIL_SYNC_HEALTH_CONFIG')
        state['sync_monitor_configured'] = bool(config)
        if not config:
            if previous or monitor_failed:
                raise ValueError('Missing client sync configuration during an incident')
            return []
        runner = pathlib.Path(__file__).with_name('mail-sync-health.py')
        process = subprocess.run(['python3', str(runner), '--host', host, '--connect-host', '127.0.0.1',
                                  '--config', config], capture_output=True, timeout=35)
        checks = json.loads(process.stdout)['checks']
        if not isinstance(checks, list) or not checks or len(checks) > len(SYNC_CHECKS):
            raise ValueError('Invalid sync checks')
        normalized = []
        seen = set()
        for check in checks:
            name, ok, error = check['name'], check['ok'], check.get('error')
            if name not in SYNC_CHECKS or name in seen or type(ok) is not bool:
                raise ValueError('Invalid sync check')
            if not ok and error not in ('transport', 'authentication', 'invalid_sync'):
                raise ValueError('Invalid sync failure')
            seen.add(name)
            normalized.append({'name': name, 'ok': ok} if ok else {'name': name, 'ok': ok, 'error': error})
        if process.returncode != int(not all(check['ok'] for check in normalized)):
            raise ValueError('Inconsistent sync checks')
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired):
        if not previous and not monitor_failed and not state.get('sync_monitor_configured'):
            return []
        normalized, seen = [], set()

    missing = previous - seen
    if missing or not normalized:
        normalized.append({'name': SYNC_MONITOR_CHECK, 'ok': False})
        normalized.extend({'name': name, 'ok': False} for name in sorted(missing))
    return normalized


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
    runtime = pathlib.Path(args.storage_path)
    database = args.database_path or runtime / (configured_database or 'smtp.db')
    mailbox = args.mailbox_path or runtime / 'mail'
    checks += delivery_checks(database, state, now)
    checks += hosted_checks(args.env_file, state, now)
    checks += backup_checks(args.env_file, state, now)
    checks += sync_checks(args.env_file, args.host, state)
    checks += scanner_checks()
    checks += storage_capacity_checks(runtime, mailbox, database)
    storage_probe = "import os,sys,tempfile; f=tempfile.NamedTemporaryFile(dir=sys.argv[1],prefix='.health-',delete=True); f.write(b'mail health'); f.flush(); os.fsync(f.fileno()); f.close()"
    try:
        subprocess.run(['runuser', '-u', 'mail-server', '--', 'python3', '-c', storage_probe, str(mailbox)], capture_output=True, timeout=10, check=True)
        checks.append({'name': 'Mail storage write and sync', 'ok': True})
    except Exception:
        checks.append({'name': 'Mail storage write and sync', 'ok': False})
    reconcile(state, checks, now)
    # Commit the notification before attempting delivery, so a crash cannot lose it.
    atomic_json(args.state_path, state, 0o600)
    notification_ok = False
    webhook = ''
    retry_at = state.get('alert_retry_at')
    try:
        webhook = env_setting(args.env_file, 'DISCORD_WEBHOOK_URL')
        if webhook and (retry_at is None or time.time() >= retry_at):
            retry_at = None
            state.pop('alert_retry_at', None)
            for event in list(state['pending'])[:4]:
                stamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(event['at']))
                send_alert(webhook, f"{args.host}: {event['summary']} ({stamp}). Open /status in webmail for checks and incident history.")
                state['pending'].remove(event)
                state['last_alert_at'] = now
                atomic_json(args.state_path, state, 0o600)
            notification_ok = True
    except AlertRateLimited as error:
        # Measure from the receiver response after the health checks, and
        # round up so fractional seconds cannot cause an early retry.
        retry_at = math.ceil(time.time() + error.retry_after)
        state['alert_retry_at'] = retry_at
        atomic_json(args.state_path, state, 0o600)
        print('Admin notification rate limited; queued alerts will retry after the receiver window', flush=True)
    except Exception:
        # Never log the exception: transport exceptions can contain the webhook URL.
        print('Admin notification delivery failed; queued alerts will retry', flush=True)
    transport = {'name': 'Admin alert transport', 'ok': notification_ok, 'pending': len(state['pending'])}
    if webhook and retry_at is not None:
        transport['retry_at'] = retry_at
    checks.append(transport)
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', default='/opt/mail/maintenance/mail-health.py')
    parser.add_argument('--host', default='mail.stacksjs.com')
    parser.add_argument('--state-path', default='/var/lib/mail-health/private/state.json')
    parser.add_argument('--status-path', default='/var/lib/mail-health/public/status.json')
    parser.add_argument('--storage-path', default='/opt/mail', help='Mail runtime directory')
    parser.add_argument('--mailbox-path', type=pathlib.Path,
                        help='Override the mailbox directory (defaults to mail under the runtime directory)')
    parser.add_argument('--database-path', type=pathlib.Path,
                        help='Override SMTP_DB_PATH from the mail environment file')
    parser.add_argument('--env-file', default='/etc/mail/mail.env')
    parser.add_argument('--deploy-gate', action='store_true',
                        help='Exit by the protocol, scanner and storage checks; status and alerts are unchanged')
    return run(parser.parse_args(argv))


if __name__ == '__main__':
    raise SystemExit(main())
