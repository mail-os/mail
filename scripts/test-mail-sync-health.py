#!/usr/bin/env python3
"""Run all authenticated sync canaries and alert transitions on native Mail."""
import json
from pathlib import Path
import runpy
import secrets
import subprocess
import sys
import tempfile
from urllib.parse import quote


SCRIPTS = Path(__file__).resolve().parent
WATCH = runpy.run_path(str(SCRIPTS / 'test-mail-delivery-alerts.py'))
SYNC = runpy.run_path(str(SCRIPTS / 'mail-sync-health.py'))
Fixture = WATCH['Fixture']
Probe = SYNC['Probe']
CHECKS = SYNC['CHECKS']
available_ports = WATCH['fixtures']['available_ports']


def run_canary(path):
    process = subprocess.run(['python3', str(SCRIPTS / 'mail-sync-health.py'), '--host', '127.0.0.1',
                              '--config', str(path)], capture_output=True, timeout=25)
    assert process.returncode in (0, 1), process.returncode
    assert not process.stderr, process.stderr
    return {check['name']: check for check in json.loads(process.stdout)['checks']}


def verify(binary, directory):
    test = Fixture(binary, directory, staging=True)
    with test.daemon():
        mailbox = test.provision('sync-canary')
        config = {
            'mailbox': mailbox, 'password': test.password, 'canary_id': secrets.token_hex(16),
            'imaps_port': test.imaps_port, 'dav_port': int(test.env['CALDAV_SSL_PORT']),
            'ca_file': test.env['SMTP_TLS_CERT'],
        }
        config_path = directory / 'canary.json'
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o600)
        canary = Probe('127.0.0.1', None, config)
        address = quote(mailbox, safe='@')
        collection = f'/addressbooks/{address}/Mail-Health-Contacts/'
        previous_marker = canary.marker + '-0000000000000000'
        resources = [
            (f'/calendars/{address}/Mail-Health/{previous_marker}.ics', 'text/calendar', canary.dav_document('caldav', previous_marker)),
            (f'{collection}{previous_marker}.vcf', 'text/vcard', canary.dav_document('carddav', previous_marker)),
        ]
        # Leave real, identifiable prior-run resources for crash recovery.
        for path, media, body in resources:
            canary.request('PUT', path, body, {'Content-Type': media}, expected=(201,))
        with test.imap(mailbox) as connection:
            previous = (f'Subject: interrupted canary\r\nMessage-ID: {canary.message_id}\r\n'
                        f'X-Mail-Health: {canary.marker}\r\n\r\nold probe').encode()
            assert connection.append('INBOX', None, None, previous)[0] == 'OK'

        good = run_canary(config_path)
        assert good == {name: {'name': name, 'ok': True} for name in CHECKS.values()}, good
        for path, *_ in resources:
            canary.request('GET', path, expected=(404,))
        with test.imap(mailbox) as connection:
            assert connection.select('INBOX', readonly=True) == ('OK', [b'0'])

        bad = directory / 'bad.json'
        bad.write_text(json.dumps({**config, 'protocols': ['imap'], 'password': 'incorrect-canary-password'}))
        assert run_canary(bad) == {CHECKS['imap']: {'name': CHECKS['imap'], 'ok': False, 'error': 'authentication'}}
        unused_port, = available_ports(1)
        bad.write_text(json.dumps({**config, 'protocols': ['caldav'], 'dav_port': unused_port}))
        assert run_canary(bad) == {CHECKS['caldav']: {'name': CHECKS['caldav'], 'ok': False, 'error': 'transport'}}
        bad.unlink()

        with WATCH['receiver']() as sink, WATCH['monitor'](directory, directory / 'smtp.db', sink, host='127.0.0.1') as monitor:
            sink.failing = False
            with (directory / 'mail.env').open('a') as settings:
                settings.write(f'MAIL_SYNC_HEALTH_CONFIG={config_path}\n')
            status = monitor()
            assert all(status[name]['ok'] for name in CHECKS.values()), status
            initial_alerts = len(sink.messages)

            foreign = b'BEGIN:VCARD\r\nVERSION:3.0\r\nUID:unrelated-data\r\nFN:Leave this alone\r\nEND:VCARD\r\n'
            contact_path = resources[1][0]
            canary.request('PUT', contact_path, foreign, {'Content-Type': 'text/vcard'}, expected=(201,))
            failed = monitor()
            name = CHECKS['carddav']
            assert failed[name] == {'name': name, 'ok': False, 'error': 'invalid_sync'}, failed
            assert all(failed[other]['ok'] for other in CHECKS.values() if other != name), failed
            assert canary.request('GET', contact_path)[2] == foreign
            assert len(sink.messages) == initial_alerts + 1 and name in sink.messages[-1]['content']
            monitor()
            assert len(sink.messages) == initial_alerts + 1

            hidden_config = config_path.with_suffix('.offline')
            config_path.rename(hidden_config)
            interrupted = monitor()
            assert not interrupted[name]['ok'] and not interrupted['Client synchronization monitor']['ok']
            assert len(sink.messages) == initial_alerts + 2
            hidden_config.rename(config_path)

            canary.request('DELETE', contact_path, expected=(204,))
            assert monitor()[name]['ok']
            assert len(sink.messages) == initial_alerts + 3 and 'checks recovered' in sink.messages[-1]['content']
            exposed = json.dumps(sink.messages) + (directory / 'public/status.json').read_text()
            assert all(secret not in exposed for secret in (mailbox, test.password, canary.marker, 'Leave this alone'))

        unexpected_mail = b'Subject: Unrelated mail\r\nMessage-ID: <unrelated@example.test>\r\n\r\nKeep this.'
        with test.imap(mailbox) as connection:
            assert connection.append('INBOX', None, None, unexpected_mail)[0] == 'OK'
        bad.write_text(json.dumps({**config, 'protocols': ['imap']}))
        assert run_canary(bad) == {CHECKS['imap']: {'name': CHECKS['imap'], 'ok': False, 'error': 'invalid_sync'}}
        with test.imap(mailbox) as connection:
            assert connection.select('INBOX', readonly=True) == ('OK', [b'1'])
            assert connection.fetch('1', '(BODY.PEEK[])')[1][0][1] == unexpected_mail

        print('Verified IMAP UID state, both DAV change tokens, ActiveSync SyncKey and EWS SyncState over native TLS.')
        print('Verified scoped cleanup, authentication classification, a CardDAV incident, deduplication and recovery.')


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='mail-sync-health-') as scratch:
        verify(Path(sys.argv[1]).resolve(strict=True), Path(scratch))
