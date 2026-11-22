#!/usr/bin/env python3
"""Exercise the real mail binary over verified TLS in an isolated temporary mailbox."""
import argparse
import contextlib
import os
import pathlib
import shutil
import shlex
import smtplib
import socket
import ssl
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def server(binary, directory, cert, key, reject=False, preload=None, fail_sync=False):
    port = free_port()
    env = dict(os.environ, SMTP_CATCH_ALL='true', SMTP_CATCH_ALL_MAILBOX='dev',
               SMTP_HOSTNAME='localhost', SMTP_ANTISPAM_CHECK='false', SMTP_SPAM_FILTER='false',
               SMTP_ENABLE_DNSBL='true', SMTP_DNSBL_REJECT=str(reject).lower(),
               SMTP_ENABLE_GREYLIST='false', SMTP_TLS_CERT=str(cert), SMTP_TLS_KEY=str(key),
               SMTP_DB_PATH=str(directory / 'smtp.db'), IMAP_ENABLED='false', CALDAV_ENABLED='false',
               SMTP_ENABLE_WEBMAIL='false', SMTPS_PORT=str(free_port()), SUBMISSION_PORT=str(free_port()))
    if fail_sync:
        env['MAIL_TEST_FAIL_SYNC'] = '1'
    else:
        env.pop('MAIL_TEST_FAIL_SYNC', None)
    if preload:
        env['LD_PRELOAD'] = str(preload)
    with (directory / 'server.log').open('w') as log:
        process = subprocess.Popen([str(binary), 'serve', '--host', '127.0.0.1', '--port', str(port),
                                    '--enable-tls', '--disable-auth'], cwd=directory, env=env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('Candidate mail server exited')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2) as sock:
                        sock.settimeout(.5)
                        if sock.recv(1024).startswith(b'220'):
                            yield port
                            return
                except (OSError, TimeoutError):
                    time.sleep(.1)
            raise RuntimeError('Candidate server did not serve an SMTP greeting')
        except BaseException:
            print((directory / 'server.log').read_text(), file=sys.stderr)
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix='mail-tls-e2e-') as temporary:
        root = pathlib.Path(temporary)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
        preload = None
        if sys.platform.startswith('linux'):
            # Every DNSBL query is deliberately listed. The default policy must
            # STILL greet the sender; opt-in rejection must happen at SMTP RCPT.
            source = root / 'dnsbl.c'
            source.write_text('''#define _GNU_SOURCE
#include <dlfcn.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int fsync(int fd) {
    int (*real)(int) = dlsym(RTLD_NEXT,"fsync");
    char name[64], path[4096];
    snprintf(name,sizeof(name),"/proc/self/fd/%d",fd);
    ssize_t n=readlink(name,path,sizeof(path)-1);
    if(n>=0) { path[n]=0; if(getenv("MAIL_TEST_FAIL_SYNC") && strstr(path,"/.pending-")) { errno=ENOSPC; return -1; } }
    return real(fd);
}
int getaddrinfo(const char *name, const char *service, const struct addrinfo *hints, struct addrinfo **out) {
    int (*real)(const char *,const char *,const struct addrinfo *,struct addrinfo **) = dlsym(RTLD_NEXT,"getaddrinfo");
    if (name && (strstr(name,".spamhaus.org") || strstr(name,".spamcop.net") || strstr(name,".barracudacentral.org") || strstr(name,".sorbs.net"))) name="127.0.0.2";
    return real(name,service,hints,out);
}
''')
            preload = root / 'dnsbl.so'
            compiler = shlex.split(os.environ.get('CC', shutil.which('cc') or 'cc'))
            subprocess.run(compiler + ['-shared', '-fPIC', str(source), '-ldl', '-o', str(preload)], check=True)
        mailbox = root / 'mailbox'
        mailbox.mkdir()
        with server(binary, mailbox, cert, key, preload=preload) as port:
            subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('mail-health.py')), '--host', 'localhost',
                            '--connect-host', '127.0.0.1', '--smtp-port', str(port), '--smtp-only', '--ca-file', str(cert)], check=True)
            # Random transcript digests expose short ECDSA INTEGER encodings.
            # A single handshake almost always missed non-minimal leading zeros.
            ctx = ssl.create_default_context(cafile=cert)
            ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            for _ in range(512):
                with smtplib.SMTP('localhost', port, local_hostname='mail-health.stacksjs.com', timeout=10) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=ctx)
                    smtp.ehlo()
            print('PASS 512 independently verified ECDSA TLS 1.3 handshakes', flush=True)
            for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                ctx = ssl.create_default_context(cafile=cert)
                ctx.minimum_version = ctx.maximum_version = version
                marker = f'mail-tls-receipt-{version.name}'
                with smtplib.SMTP('localhost', port, local_hostname='mail-health.stacksjs.com', timeout=10) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=ctx)
                    smtp.ehlo()
                    smtp.sendmail('sender@example.test', ['recipient@example.test'],
                                  f'From: sender@example.test\r\nTo: recipient@example.test\r\nSubject: {marker}\r\n\r\n{marker}\r\n')
                files = [p for p in (mailbox / 'mail').rglob('*') if p.is_file() and marker.encode() in p.read_bytes()]
                if len(files) != 1:
                    raise RuntimeError(f'SMTP accepted {marker}, but {len(files)} durable mailbox copies exist')
                if b'with ESMTPS' not in files[0].read_bytes():
                    raise RuntimeError('Receipt did not record encrypted SMTP transport')
                print(f'PASS encrypted SMTP {version.name} accepted and readable in Maildir', flush=True)
            if preload:
                print('PASS DNSBL-listed sender greeted and delivered under score-only policy', flush=True)
        if preload:
            rejected = root / 'reject-policy'
            rejected.mkdir()
            with server(binary, rejected, cert, key, reject=True, preload=preload) as port:
                with smtplib.SMTP('localhost', port, local_hostname='mail-health.stacksjs.com', timeout=10) as smtp:
                    smtp.ehlo()
                    smtp.mail('sender@example.test')
                    code, _ = smtp.rcpt('recipient@example.test')
                    if code != 554:
                        raise RuntimeError(f'Opt-in DNSBL rejection returned {code}, expected 554')
                print('PASS opt-in DNSBL rejection returns an explicit SMTP 554 at RCPT', flush=True)
            failed = root / 'storage-failure'
            failed.mkdir()
            message = b'Subject: storage-failure-must-recover\r\n\r\naccepted in journal\r\n'
            with server(binary, failed, cert, key, preload=preload, fail_sync=True) as port:
                with smtplib.SMTP('localhost', port, local_hostname='mail-health.stacksjs.com', timeout=10) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=ssl.create_default_context(cafile=cert))
                    smtp.ehlo()
                    smtp.sendmail('sender@example.test', ['recipient@example.test'], message)
                with contextlib.closing(sqlite3.connect(failed / 'smtp.db')) as db:
                    id_, raw, outcome, attempts, reserved = db.execute(
                        'SELECT m.id,m.mime,t.outcome,t.attempts,t.queued_bytes FROM accepted_mail m '
                        'JOIN accepted_mail_targets t ON t.delivery_id=m.id'
                    ).fetchone()
                if outcome != 'pending' or attempts < 1 or reserved != len(raw):
                    raise RuntimeError(f'Expected a pending delivery with {len(raw)} reserved bytes after sync failure, got {(outcome, attempts, reserved)}')
                if not raw.replace(b'\r\n', b'\n').rstrip(b'\n').endswith(message.replace(b'\r\n', b'\n').rstrip(b'\n')):
                    raise RuntimeError('The pending delivery did not retain the submitted subject and body')
                if any(p.is_file() for p in (failed / 'mail').rglob('*')):
                    raise RuntimeError('Storage failure exposed a partial or unsynced mailbox message')
            with server(binary, failed, cert, key, preload=preload):
                with contextlib.closing(sqlite3.connect(failed / 'smtp.db')) as db:
                    result = db.execute(
                        'SELECT m.complete,t.outcome,t.queued_bytes FROM accepted_mail m '
                        'JOIN accepted_mail_targets t ON t.delivery_id=m.id WHERE m.id=?', (id_,)
                    ).fetchall()
                copies = [p.read_bytes() for p in (failed / 'mail').rglob('*') if p.is_file()]
                if result != [(1, 'filed', 0)] or copies != [raw]:
                    raise RuntimeError('Storage recovery failed to publish one exact copy and release its reservation')
            print('PASS storage sync failure leaves an accepted journal record and recovery publishes one exact copy', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
