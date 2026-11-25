#!/usr/bin/env python3
"""Exercise outbound DKIM configuration and signing through the real daemon."""

import base64
from email import policy
from email.parser import BytesParser
import hashlib
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import time


fixture = runpy.run_path(str(Path(__file__).with_name('test-hosted-limits.py')))
PRIMARY = fixture['DOMAIN']
ADDITIONAL = 'custom.example.test'
DESTINATION = 'receiver@external.example.test'


def openssl(*args):
    return subprocess.run(['openssl', *args], capture_output=True, check=True).stdout


def check_configuration(test, settings, expected=None, *, validate_only=True):
    command = [str(test.binary), 'serve', '--host', '127.0.0.1',
               '--port', str(test.smtp_port), '--disable-tls']
    if validate_only:
        command.append('--validate-only')
    result = subprocess.run(command, cwd=test.directory, env={**test.env, **settings},
                            capture_output=True, timeout=10)
    if expected is None:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0 and expected in result.stdout + result.stderr, result


def capture_ses(test):
    tools = test.directory / 'tools'
    tools.mkdir()
    aws = tools / 'aws'
    aws.write_text("""#!/usr/bin/env python3
import base64
import json
from pathlib import Path
import sys

assert sys.argv[1:3] == ['ses', 'send-raw-email']
payload = json.loads(Path(sys.argv[-1].removeprefix('file://')).read_text())
assert payload['Destinations'] == ['receiver@external.example.test']
message = Path('received-' + payload['Source'].split('@')[1] + '.eml')
temporary = message.with_suffix('.tmp')
temporary.write_bytes(base64.b64decode(payload['RawMessage']['Data'], validate=True))
temporary.replace(message)
""")
    aws.chmod(0o755)
    test.env.update(SMTP_DELIVERY_METHOD='ses', PATH=str(tools) + os.pathsep + test.env['PATH'])


def verify_receipt(test, domain, selector, public_key):
    receipt = test.directory / f'received-{domain}.eml'
    deadline = time.monotonic() + 15
    while not receipt.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    raw = receipt.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)
    signature, = message.get_all('DKIM-Signature')
    tags = dict(tag.strip().split('=', 1) for tag in str(signature).split(';'))
    assert (tags['d'], tags['s'], tags['a'], tags['c']) == (domain, selector, 'rsa-sha256', 'relaxed/relaxed'), tags

    # This fixture sends unique, unfolded headers and a single-line ASCII body.
    # Recreate the specified signing input and verify it with OpenSSL and the
    # corresponding public key, independently of Mail's RSA implementation.
    _, body = re.split(br'\r?\n\r?\n', raw, maxsplit=1)
    assert body.rstrip(b'\r\n') == b'Test delivery'
    assert base64.b64decode(tags['bh']) == hashlib.sha256(b'Test delivery\r\n').digest()
    values = {name.lower().encode(): b' '.join(value.encode().split())
              for name, value in message.raw_items()}
    signed = b''.join(name + b':' + values[name] + b'\r\n' for name in tags['h'].encode().split(b':'))
    signed += b'dkim-signature:' + values[b'dkim-signature'].rsplit(b'b=', 1)[0] + b'b='
    signature_file = test.directory / 'signature'
    input_file = test.directory / 'signature-input'
    signature_file.write_bytes(base64.b64decode(tags['b']))
    input_file.write_bytes(signed)
    assert openssl('dgst', '-sha256', '-verify', public_key, '-signature', signature_file, input_file).strip() == b'Verified OK'


def verify(binary, directory):
    test = fixture['Fixture'](binary, directory)
    primary, additional, ec = (directory / f'{name}.pem' for name in ('primary', 'additional', 'ec'))
    openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', primary)
    extra_pkcs8 = directory / 'extra-pkcs8.pem'
    openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', extra_pkcs8)
    try:
        traditional = openssl('rsa', '-in', extra_pkcs8, '-traditional')
    except subprocess.CalledProcessError:
        # LibreSSL's rsa command writes PKCS#1 without the option.
        traditional = openssl('rsa', '-in', extra_pkcs8)
    additional.write_bytes(traditional)
    assert primary.read_bytes().startswith(b'-----BEGIN PRIVATE KEY-----')
    assert traditional.startswith(b'-----BEGIN RSA PRIVATE KEY-----'), 'The RSA conversion did not produce PKCS#1 PEM'
    openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-out', ec)
    public_keys = [directory / f'{domain}.pub' for domain in (PRIMARY, ADDITIONAL)]
    for key, public in zip((primary, additional), public_keys):
        openssl('pkey', '-in', key, '-pubout', '-out', public)

    settings = dict(DKIM_DOMAIN=PRIMARY, DKIM_SELECTOR='mail', DKIM_PRIVATE_KEY_PATH=str(primary),
                    DKIM_EXTRA_KEYS=f'{ADDITIONAL}:custom:{additional}')
    check_configuration(test, {'DKIM_DOMAIN': PRIMARY}, b'DKIM_DOMAIN, DKIM_SELECTOR and DKIM_PRIVATE_KEY_PATH')
    check_configuration(test, {**settings, 'DKIM_PRIVATE_KEY_PATH': str(ec)}, b'UnsupportedDkimKeyAlgorithm')
    missing = {**settings, 'DKIM_EXTRA_KEYS': f'{ADDITIONAL}:missing:{directory / "missing.pem"}'}
    check_configuration(test, missing, b'Outbound DKIM key read failed')
    check_configuration(test, missing, b'Outbound DKIM key read failed', validate_only=False)
    check_configuration(test, {**settings, 'DKIM_EXTRA_KEYS': ADDITIONAL}, b'Invalid DKIM_EXTRA_KEYS entry')
    check_configuration(test, {**settings, 'DKIM_EXTRA_KEYS': f'{PRIMARY.upper()}:duplicate:{additional}'},
                        b'DuplicateDkimDomain')
    truncated = directory / 'truncated.pem'
    truncated.write_bytes(b'-----BEGIN PRIVATE KEY-----\nMAEC\n-----END PRIVATE KEY-----\n')
    check_configuration(test, {**settings, 'DKIM_PRIVATE_KEY_PATH': str(truncated)}, b'Outbound DKIM signer failed')
    check_configuration(test, {**settings, 'DKIM_EXTRA_KEYS': ','.join(
        f'domain{index}.example.test:mail:{additional}' for index in range(32))}, b'TooManyDkimSigners')
    check_configuration(test, settings)
    # Preserve support for PEM files with metadata before the key block.
    primary.write_bytes(b'Bag Attributes\n' + primary.read_bytes())
    check_configuration(test, settings)

    test.env.update(settings, SMTP_LOCAL_DOMAINS=f'{PRIMARY},{ADDITIONAL}')
    capture_ses(test)
    with test.daemon():
        primary_sender = test.provision('primary')
        additional_sender = 'extra@' + ADDITIONAL
        result = subprocess.run([str(binary), 'user:local', 'create', additional_sender],
                                cwd=directory, env=test.env, input=(test.password + '\n').encode(),
                                capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr
        for sender, domain, selector, public in zip((primary_sender, additional_sender),
                                                    (PRIMARY, ADDITIONAL), ('mail', 'custom'), public_keys):
            fixture['expect_smtp'](test.deliver(DESTINATION, identity=sender, body='Test delivery'), 250)
            verify_receipt(test, domain, selector, public)


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='mail-outbound-dkim-') as path:
        verify(Path(sys.argv[1]).resolve(strict=True), Path(path))
    print('Primary PKCS#8 and additional-domain PKCS#1 signatures verified. Invalid signer settings failed configuration validation.')
