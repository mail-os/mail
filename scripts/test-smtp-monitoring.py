#!/usr/bin/env python3
"""Exercise the native SMTP readiness and Prometheus endpoints."""

import argparse
from contextlib import contextmanager
from http.client import HTTPConnection
import os
from pathlib import Path
import re
import smtplib
import socket
import subprocess
from tempfile import TemporaryDirectory
import time


@contextmanager
def daemon(binary, root, smtp_port, metrics_port=None):
    env = dict(PATH=os.environ['PATH'], SMTP_HOSTNAME='mail.example.test',
               SMTP_DB_PATH=str(root / 'smtp.db'), SMTP_ANTISPAM_CHECK='false', SMTP_SPAM_FILTER='false',
               IMAP_ENABLED='false', CALDAV_ENABLED='false')
    if metrics_port is not None:
        env['SMTP_MONITORING_PORT'] = str(metrics_port)
    with (root / 'mail-test.log').open('w+') as log:
        process = subprocess.Popen([str(binary), 'serve', '--host', '127.0.0.1', '--port', str(smtp_port), '--disable-tls'],
                                   cwd=root, env=env, stdout=log, stderr=log)
        try:
            yield process
        except Exception:
            log.seek(0)
            print(log.read()[-6000:])
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def http(port, path, method='GET'):
    connection = HTTPConnection('127.0.0.1', port, timeout=2)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, response.getheader('Content-Type'), response.read().decode()
    finally:
        connection.close()


def available_ports():
    with socket.socket() as smtp, socket.socket() as monitor:
        for listener in (smtp, monitor):
            listener.bind(('127.0.0.1', 0))
        return smtp.getsockname()[1], monitor.getsockname()[1]


def wait_ready(port, process):
    for _ in range(50):
        assert process.poll() is None, 'Mail exited before readiness'
        try:
            if http(port, '/healthz')[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise AssertionError('Mail never reported ready')


def metrics(port):
    status, content_type, body = http(port, '/metrics')
    assert status == 200 and content_type == 'text/plain; version=0.0.4; charset=utf-8', (status, content_type)
    return {name: int(value) for name, value in re.findall(r'^(mail_\w+) (\d+)$', body, re.M)}


def verify(binary, root):
    smtp_port, metrics_port = available_ports()
    with daemon(binary, root, smtp_port, metrics_port) as process:
        wait_ready(metrics_port, process)
        before = metrics(metrics_port)
        assert before['mail_smtp_ready'] == 1 and before['mail_smtp_connections_active'] == 0, before
        assert http(metrics_port, '/unknown')[0] == 404
        assert http(metrics_port, '/metrics', 'POST')[0] == 405
        with smtplib.SMTP('127.0.0.1', smtp_port, timeout=3) as client:
            assert client.ehlo()[0] == 250
            active = metrics(metrics_port)
            assert active['mail_smtp_connections_active'] == 1, active
            assert active['mail_smtp_connections_admitted_total'] == before['mail_smtp_connections_admitted_total'] + 1
            process.terminate()
            for _ in range(50):
                try:
                    unavailable = http(metrics_port, '/healthz')[0] == 503
                except OSError:
                    unavailable = True
                if unavailable:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError('Mail still reported ready during shutdown')
        process.wait(5)
    try:
        http(metrics_port, '/healthz')
    except OSError:
        pass
    else:
        raise AssertionError('The monitoring endpoint outlived its Mail daemon')

    with daemon(binary, root, smtp_port, metrics_port) as process:
        wait_ready(metrics_port, process)
        assert metrics(metrics_port)['mail_smtp_connections_admitted_total'] == 0
    print('Verified native readiness, Prometheus format, live SMTP metrics, shutdown, and restart.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix='mail-smtp-monitoring-') as directory:
        verify(args.binary.resolve(strict=True), Path(directory))
