#!/usr/bin/env python3
"""Run the bundled Compose topology with fresh volumes and a prebuilt Mail image."""

import json
from pathlib import Path
import smtplib
import subprocess
import time
from urllib.parse import urlencode
from urllib.request import urlopen
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
PROJECT = 'mail-monitoring-test-' + uuid4().hex[:12]
COMPOSE = ['docker', 'compose', '--project-name', PROJECT, '--file', str(ROOT / 'packages/zig/docker-compose.yml')]


def compose(*args):
    return subprocess.check_output([*COMPOSE, *args], text=True, timeout=90).strip()


def container(service):
    identifier = compose('ps', '-q', service)
    assert identifier, service
    return json.loads(subprocess.check_output(['docker', 'inspect', identifier], text=True, timeout=15))[0]


def published_port(service, port):
    return int(compose('port', service, str(port)).rsplit(':', 1)[1])


def expect_sample(prometheus, metric, expected):
    query = urlencode({'query': f'{metric}{{job="mail"}}'})
    deadline = time.monotonic() + 40
    result = None
    while time.monotonic() < deadline:
        try:
            with urlopen(f'http://127.0.0.1:{prometheus}/api/v1/query?{query}', timeout=2) as response:
                result = json.load(response)
            assert result['status'] == 'success', result
            samples = result['data']['result']
            if len(samples) == 1 and float(samples[0]['value'][1]) == expected:
                assert samples[0]['metric']['instance'] == 'mail:8025', samples
                return
        except OSError:
            pass
        time.sleep(0.5)
    raise AssertionError(f'{metric} never reached {expected}: {result}')


def verify():
    assert set(compose('config', '--services').splitlines()) == {'mail', 'prometheus', 'grafana'}
    compose('up', '-d', '--no-build', '--wait', '--wait-timeout', '75')
    mail = container('mail')
    mounts = {mount['Destination']: mount for mount in mail['Mounts']}
    assert mounts['/var/mail']['Name'] == f'{PROJECT}_smtp-mail', mounts['/var/mail']
    assert mail['NetworkSettings']['Ports'].get('8025/tcp') is None
    for service in ('prometheus', 'grafana'):
        monitor = container(service)
        assert monitor['Image'] != mail['Image']
        assert all(m['Source'] != mounts['/var/mail']['Source'] and m['Destination'] != '/var/mail'
                   for m in monitor['Mounts'])

    prometheus = published_port('prometheus', 9090)
    expect_sample(prometheus, 'up', 1)
    expect_sample(prometheus, 'mail_smtp_ready', 1)
    expect_sample(prometheus, 'mail_smtp_connections_active', 0)
    with smtplib.SMTP('127.0.0.1', published_port('mail', 2525), timeout=3) as client:
        assert client.ehlo()[0] == 250
        expect_sample(prometheus, 'mail_smtp_connections_active', 1)
        expect_sample(prometheus, 'mail_smtp_connections_admitted_total', 1)
    expect_sample(prometheus, 'mail_smtp_connections_active', 0)
    compose('exec', '-T', 'mail', 'sh', '-ec', 'test -s /var/mail/users.db && touch /var/mail/.compose-monitoring-fixture')

    compose('stop', 'mail')
    expect_sample(prometheus, 'up', 0)
    compose('up', '-d', '--force-recreate', '--no-build', '--no-deps', '--wait', '--wait-timeout', '75', 'mail')
    assert container('mail')['Id'] != mail['Id']
    compose('exec', '-T', 'mail', 'sh', '-ec', 'test -s /var/mail/users.db && test -f /var/mail/.compose-monitoring-fixture')
    expect_sample(prometheus, 'up', 1)
    expect_sample(prometheus, 'mail_smtp_ready', 1)
    expect_sample(prometheus, 'mail_smtp_connections_admitted_total', 0)
    print('Prometheus scraped the only Mail daemon, tracked a live SMTP session, and followed stop and replacement.')


if __name__ == '__main__':
    try:
        verify()
    except Exception:
        subprocess.run([*COMPOSE, 'logs', '--no-color', '--tail', '50'], timeout=25, check=False)
        raise
    finally:
        subprocess.run([*COMPOSE, 'down', '--volumes', '--remove-orphans'], timeout=45, check=True)
