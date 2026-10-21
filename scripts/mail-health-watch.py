#!/usr/bin/env python3
"""Persist sanitized mail health and retry incident/recovery alerts outside SMTP.

Runs as root from a systemd timer. Only status.json is readable by mail-server;
webhook credentials, journal cursors and the retry queue remain root-private.
"""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import time
import urllib.parse
import urllib.request


PATTERNS = {
    'TLS receive errors': ('TLS decrypt error:',),
    'Storage failures': ('Failed to save message:', 'Failed to write message data', 'Failed to create message file', 'Failed to create mailbox directory', 'Forward check failed', 'Failed to write forward data'),
    'Pre-greeting DNSBL rejections': ('DNSBL check failed', 'blocked by DNSBL', 'is blacklisted', 'IP blacklisted in DNSBL'),
}


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


def webhook_from_env(path):
    for line in pathlib.Path(path).read_text().splitlines():
        if line.startswith('DISCORD_WEBHOOK_URL='):
            return line.split('=', 1)[1].strip().strip('\"\'')
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


def journal_checks(state, now):
    command = ['journalctl', '-u', 'mail.service', '--no-pager', '-o', 'json', '-n', '10000']
    if state.get('cursor'):
        command += ['--after-cursor', state['cursor']]
    else:
        command += ['--since', '5 minutes ago']
    result = subprocess.run(command, capture_output=True, timeout=10)
    if result.returncode and state.get('cursor'):
        # Journal rotation can invalidate a cursor. Rescan one bounded window.
        command = command[:command.index('--after-cursor')] + ['--since', '5 minutes ago']
        result = subprocess.run(command, capture_output=True, timeout=10)
        if result.returncode == 0:
            state['failures'] = []
    result.check_returncode()
    lines = result.stdout.splitlines()
    if len(lines) >= 10000:
        raise RuntimeError('Journal sampling limit exceeded')
    failures = [failure for failure in state.get('failures', []) if failure['at'] >= now - 300]
    for line in lines:
        item = json.loads(line)
        state['cursor'] = item.get('__CURSOR', state.get('cursor'))
        message = item.get('MESSAGE', '')
        at = int(item.get('__REALTIME_TIMESTAMP', now * 1000000)) // 1000000
        for name, patterns in PATTERNS.items():
            if any(pattern in message for pattern in patterns):
                failures.append({'name': name, 'at': at})
    state['failures'] = failures[-1000:]
    return [{'name': name, 'ok': not any(f['name'] == name for f in failures),
             'count': sum(f['name'] == name for f in failures)} for name in PATTERNS]


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
        checks.append({'name': 'Delivery error monitoring', 'ok': True})
    except Exception:
        checks.append({'name': 'Delivery error monitoring', 'ok': False})
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
        webhook = webhook_from_env(args.env_file)
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
    print(json.dumps({'status': status['status'], 'failed': [c['name'] for c in checks if not c['ok']], 'pending_alerts': len(state['pending'])}), flush=True)
    return int(status['status'] != 'healthy')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', default='/opt/mail/maintenance/mail-health.py')
    parser.add_argument('--host', default='mail.stacksjs.com')
    parser.add_argument('--state-path', default='/var/lib/mail-health/private/state.json')
    parser.add_argument('--status-path', default='/var/lib/mail-health/public/status.json')
    parser.add_argument('--storage-path', default='/opt/mail')
    parser.add_argument('--env-file', default='/etc/mail/mail.env')
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
