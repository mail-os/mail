#!/usr/bin/env python3
"""Verify mail commands after TLS, including padded TLS 1.3 peer records.

No authentication or message delivery is performed. Certificate verification is
mandatory. Padding probes use Node.js or Bun's independent AEAD implementation;
traffic secrets exist only in a private temporary directory and subprocess stdin.
"""
import argparse
import json
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time


# Independent of zig-tls: construct a TLS 1.3 AES-GCM record using the negotiated
# client's traffic secret. This is the interoperability case ordinary TLS probes
# missed in the AWS delivery incident. Never print the secret or generated record.
ENCRYPT_RECORD = r"""
const crypto = require('node:crypto');
const data = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const sha384 = data.cipher === 'TLS_AES_256_GCM_SHA384';
if (!sha384 && data.cipher !== 'TLS_AES_128_GCM_SHA256') throw Error('Expected AES-GCM');
const secret = Buffer.from(data.secret, 'hex');
function expand(label, length) {
  const name = Buffer.from('tls13 ' + label);
  const info = Buffer.concat([Buffer.from([length >> 8, length & 255, name.length]), name, Buffer.from([0, 1])]);
  return crypto.createHmac(sha384 ? 'sha384' : 'sha256', secret).update(info).digest().subarray(0, length);
}
const key = expand('key', sha384 ? 32 : 16), iv = expand('iv', 12);
const plain = Buffer.concat([Buffer.from('EHLO mail-health.stacksjs.com\r\n'), Buffer.from([23]), Buffer.alloc(data.padding)]);
const size = plain.length + 16;
const header = Buffer.from([23, 3, 3, size >> 8, size & 255]);
const cipher = crypto.createCipheriv(sha384 ? 'aes-256-gcm' : 'aes-128-gcm', key, iv);
cipher.setAAD(header);
process.stdout.write(Buffer.concat([header, cipher.update(plain), cipher.final(), cipher.getAuthTag()]));
"""


def reply(stream, expected):
    """Read a complete bounded SMTP response, rejecting truncated replies."""
    for _ in range(100):
        line = stream.readline(8193)
        if len(line) > 8192 or not line.endswith(b'\n'):
            raise RuntimeError('Truncated or oversized SMTP response')
        if not line.startswith(str(expected).encode()):
            raise RuntimeError(f'Expected SMTP {expected}, received {line[:120]!r}')
        if line[3:4] == b' ':
            return
        if line[3:4] != b'-':
            raise RuntimeError('Malformed SMTP continuation')
    raise RuntimeError('Too many SMTP response lines')


def starttls_socket(args, port):
    sock = socket.create_connection((args.connect_host or args.host, port), args.timeout)
    try:
        stream = sock.makefile('rb')
        reply(stream, 220)
        sock.sendall(b'EHLO mail-health.stacksjs.com\r\n')
        reply(stream, 250)
        sock.sendall(b'STARTTLS\r\n')
        reply(stream, 220)
        stream.close()
        return sock
    except BaseException:
        sock.close()
        raise


def context(args, version):
    ctx = ssl.create_default_context(cafile=args.ca_file)
    ctx.minimum_version = ctx.maximum_version = version
    return ctx


def smtp(args, port, version, implicit=False):
    raw = (socket.create_connection((args.connect_host or args.host, port), args.timeout)
           if implicit else starttls_socket(args, port))
    with raw:
        with context(args, version).wrap_socket(raw, server_hostname=args.host) as secure:
            with secure.makefile('rb') as stream:
                if implicit:
                    reply(stream, 220)
                secure.sendall(b'EHLO mail-health.stacksjs.com\r\n')
                reply(stream, 250)
                secure.sendall(b'NOOP\r\n')
                reply(stream, 250)
                secure.sendall(b'QUIT\r\n')
                reply(stream, 221)


def imaps(args):
    with socket.create_connection((args.connect_host or args.host, args.imaps_port), args.timeout) as raw:
        with context(args, ssl.TLSVersion.TLSv1_3).wrap_socket(raw, server_hostname=args.host) as secure:
            with secure.makefile('rb') as stream:
                if not stream.readline(8193).startswith(b'* OK'):
                    raise RuntimeError('Missing IMAPS greeting')
                secure.sendall(b'health CAPABILITY\r\n')
                for _ in range(100):
                    line = stream.readline(8193)
                    if not line or len(line) > 8192:
                        raise RuntimeError('Truncated IMAPS response')
                    if line.startswith(b'health OK'):
                        return
                    if line.startswith(b'health '):
                        raise RuntimeError('IMAPS CAPABILITY failed')
                raise RuntimeError('Too many IMAPS response lines')


def padded_smtp(args, padding):
    runtime = shutil.which('node') or shutil.which('bun')
    if not runtime:
        raise RuntimeError('Node.js or Bun is required for the TLS padding probe')
    with tempfile.TemporaryDirectory(prefix='mail-health-tls-') as directory:
        with starttls_socket(args, args.smtp_port) as raw:
            ctx = context(args, ssl.TLSVersion.TLSv1_3)
            keylog = pathlib.Path(directory) / 'keylog'
            ctx.keylog_filename = str(keylog)
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            secure = ctx.wrap_bio(incoming, outgoing, server_hostname=args.host)
            while True:
                try:
                    secure.do_handshake()
                    raw.sendall(outgoing.read())
                    break
                except ssl.SSLWantReadError:
                    if outgoing.pending:
                        raw.sendall(outgoing.read())
                    chunk = raw.recv(65536)
                    if not chunk:
                        raise RuntimeError('Server closed during TLS handshake')
                    incoming.write(chunk)
            secret = next(line.split()[2] for line in keylog.read_text().splitlines()
                          if line.startswith('CLIENT_TRAFFIC_SECRET_0 '))
            result = subprocess.run([runtime, '-e', ENCRYPT_RECORD], input=json.dumps({
                'cipher': secure.cipher()[0], 'secret': secret, 'padding': padding,
            }).encode(), capture_output=True, timeout=args.timeout, check=True)
            raw.sendall(result.stdout)
            response = bytearray()
            while b'250 ' not in response:
                try:
                    chunk = secure.read(16384)
                    if not chunk:
                        raise RuntimeError('Server closed before padded SMTP response')
                    response.extend(chunk)
                    if len(response) > 65536:
                        raise RuntimeError('Oversized padded SMTP response')
                except ssl.SSLWantReadError:
                    chunk = raw.recv(65536)
                    if not chunk:
                        raise RuntimeError('Server closed before padded SMTP response')
                    incoming.write(chunk)
            import io
            reply(io.BytesIO(response), 250)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='mail.stacksjs.com', help='Verified TLS hostname')
    parser.add_argument('--connect-host', help='Optional IP or host to connect to; TLS hostname is still verified')
    parser.add_argument('--smtp-port', type=int, default=25)
    parser.add_argument('--submission-port', type=int, default=587)
    parser.add_argument('--smtps-port', type=int, default=465)
    parser.add_argument('--imaps-port', type=int, default=993)
    parser.add_argument('--smtp-only', action='store_true', help='Probe one SMTP listener, including padding')
    parser.add_argument('--ca-file', help='Additional test CA bundle')
    parser.add_argument('--timeout', type=float, default=10)
    parser.add_argument('--json', action='store_true', help='Emit a sanitized structured result')
    args = parser.parse_args()
    probes = []
    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        probes.append((f'SMTP STARTTLS {version.name}', lambda v=version: smtp(args, args.smtp_port, v)))
        if not args.smtp_only:
            probes.append((f'Submission STARTTLS {version.name}', lambda v=version: smtp(args, args.submission_port, v)))
            probes.append((f'SMTPS {version.name}', lambda v=version: smtp(args, args.smtps_port, v, True)))
    if not args.smtp_only:
        probes.append(('IMAPS greeting and CAPABILITY', lambda: imaps(args)))
    for padding in (0, 1, 16, 255):
        probes.append((f'SMTP TLSv1_3 with {padding} padding bytes', lambda p=padding: padded_smtp(args, p)))
    failed = False
    checks = []
    for name, run in probes:
        started = time.monotonic()
        try:
            run()
            checks.append({'name': name, 'ok': True, 'duration_ms': round((time.monotonic() - started) * 1000)})
            if not args.json:
                print(f'PASS {name}', flush=True)
        except Exception as error:
            failed = True
            # Dashboard data never includes server responses, addresses or secrets.
            checks.append({'name': name, 'ok': False, 'error': type(error).__name__, 'duration_ms': round((time.monotonic() - started) * 1000)})
            if not args.json:
                print(f'FAIL {name}: {type(error).__name__}: {error}', file=sys.stderr, flush=True)
    if args.json:
        print(json.dumps({'ok': not failed, 'checks': checks}))
    return int(failed)


if __name__ == '__main__':
    sys.exit(main())
