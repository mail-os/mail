#!/usr/bin/env python3
"""Exercise incremental sync against a dedicated, disposable Mail account."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import http.client
import imaplib
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
from urllib.parse import quote, urlencode, urlsplit, unquote


CHECKS = {
    'imap': 'IMAP client synchronization',
    'caldav': 'CalDAV client synchronization',
    'carddav': 'CardDAV client synchronization',
    'activesync': 'ActiveSync client synchronization',
    'ews': 'EWS client synchronization',
}
MAIL_PROTOCOLS = ('imap', 'activesync', 'ews')
DAV_COLLECTIONS = {
    'caldav': ('calendars', 'Mail-Health', 'ics', 'text/calendar'),
    'carddav': ('addressbooks', 'Mail-Health-Contacts', 'vcf', 'text/vcard'),
}
SOAP = 'http://schemas.xmlsoap.org/soap/envelope/'
MESSAGES = 'http://schemas.microsoft.com/exchange/services/2006/messages'
TYPES = 'http://schemas.microsoft.com/exchange/services/2006/types'
TIMEOUT = 4
MAX_RESPONSE = 256 * 1024


class AuthenticationFailed(Exception):
    pass


def require(condition):
    if not condition:
        raise ValueError('Invalid canary sync response')


def result(protocol, action):
    try:
        value = action()
        return {'name': CHECKS[protocol], 'ok': True}, value
    except AuthenticationFailed:
        error = 'authentication'
    except (OSError, http.client.HTTPException, imaplib.IMAP4.abort):
        error = 'transport'
    except (ValueError, ET.ParseError, imaplib.IMAP4.error):
        error = 'invalid_sync'
    return {'name': CHECKS[protocol], 'ok': False, 'error': error}, None


def load_config(path):
    with Path(path).open() as stream:
        config = json.loads(stream.read(8193))
    mailbox = config.get('mailbox', '')
    password = config.get('password', '')
    canary = config.get('canary_id', '')
    protocols = config.get('protocols', list(CHECKS))
    require(isinstance(mailbox, str) and re.fullmatch(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9.-]+', mailbox))
    require(isinstance(password, str) and password.isascii() and 1 <= len(password) <= 256 and password.isprintable())
    require(isinstance(canary, str) and re.fullmatch(r'[a-f0-9]{32}', canary))
    require(isinstance(protocols, list) and protocols and all(key in CHECKS for key in protocols))
    for key, default in [('dav_port', 443), ('imaps_port', 993)]:
        port = config.setdefault(key, default)
        require(type(port) is int and 0 < port <= 65535)
    return config, set(protocols)


class CanaryIMAP(imaplib.IMAP4_SSL):
    def __init__(self, probe):
        self.connect_host = probe.connect_host
        super().__init__(probe.host, probe.config['imaps_port'], ssl_context=probe.tls, timeout=TIMEOUT)

    def _create_socket(self, timeout):
        with socket.create_connection((self.connect_host, self.port), timeout) as raw:
            return self.ssl_context.wrap_socket(raw, server_hostname=self.host)


class Probe:
    def __init__(self, host, connect_host, config):
        self.host = host
        self.connect_host = connect_host or host
        self.config = config
        self.mailbox = config['mailbox']
        self.password = config['password']
        self.marker = 'mail-health-' + config['canary_id']
        self.message_id = f'<{self.marker}@example.invalid>'
        self.tls = ssl.create_default_context(cafile=config.get('ca_file'))
        self.auth = 'Basic ' + base64.b64encode(f'{self.mailbox}:{self.password}'.encode()).decode()

    def request(self, method, path, body=None, headers=None, expected=(200,)):
        port = self.config['dav_port']
        with closing(http.client.HTTPSConnection(self.host, port, timeout=TIMEOUT, context=self.tls)) as conn:
            with socket.create_connection((self.connect_host, port), TIMEOUT) as raw:
                conn.sock = self.tls.wrap_socket(raw, server_hostname=self.host)
                conn.request(method, path, body, {'Authorization': self.auth, **(headers or {})})
                response = conn.getresponse()
                if response.status == 401 and response.status not in expected:
                    raise AuthenticationFailed()
                require(response.status in expected)
                data = response.read(MAX_RESPONSE + 1)
                require(len(data) <= MAX_RESPONSE)
                return response.status, response.headers, data

    def dav_report(self, path, token):
        request = (f'<d:sync-collection xmlns:d="DAV:"><d:sync-token>{escape(token)}</d:sync-token>'
                   '<d:sync-level>1</d:sync-level><d:limit><d:nresults>8</d:nresults></d:limit>'
                   '<d:prop><d:getetag/></d:prop></d:sync-collection>')
        _, _, body = self.request('REPORT', path, request, {'Depth': '0', 'Content-Type': 'application/xml'}, (207,))
        root = ET.fromstring(body)
        next_token = root.findtext('{DAV:}sync-token')
        require(root.tag == '{DAV:}multistatus' and next_token and len(next_token) <= 512)
        return next_token, root.findall('{DAV:}response')

    def dav_document(self, protocol, marker):
        if protocol == 'caldav':
            return ('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail//Sync Canary//EN\r\nBEGIN:VEVENT\r\n'
                    f'UID:{marker}\r\nSUMMARY:Mail sync canary\r\n'
                    'DTSTAMP:20260101T120000Z\r\nDTSTART:20300101T120000Z\r\nDTEND:20300101T121000Z\r\n'
                    'END:VEVENT\r\nEND:VCALENDAR\r\n').encode()
        return ('BEGIN:VCARD\r\nVERSION:3.0\r\n'
                f'UID:{marker}\r\nFN:Mail Sync Canary\r\nN:Canary;Mail Sync;;;\r\nEND:VCARD\r\n').encode()

    def remove_dav(self, resource, document):
        status, headers, body = self.request('GET', resource, expected=(200, 404))
        if status == 200:
            # Never delete an unexpected resource that happens to occupy the path.
            require(body == document and headers.get('ETag'))
            self.request('DELETE', resource, headers={'If-Match': headers['ETag']}, expected=(204,))

    def dav_sync(self, protocol):
        root, collection, suffix, media = DAV_COLLECTIONS[protocol]
        path = f'/{root}/{quote(self.mailbox, safe="@")}/{collection}/'
        token, members = self.dav_report(path, '')
        matching_path = re.compile(re.escape(unquote(path + self.marker)) + rf'-([0-9a-f]{{16}})\.{suffix}')
        cleaned = False
        for member in members:
            href = unquote(urlsplit(member.findtext('{DAV:}href') or '').path)
            match = matching_path.fullmatch(href)
            if match:
                previous = f'{self.marker}-{match[1]}'
                self.remove_dav(f'{path}{previous}.{suffix}', self.dav_document(protocol, previous))
                cleaned = True
        if cleaned:
            token, _ = self.dav_report(path, token)
        # A fresh UID leaves earlier tombstones intact for ordinary DAV clients.
        marker = f'{self.marker}-{secrets.token_hex(8)}'
        resource = f'{path}{marker}.{suffix}'
        document = self.dav_document(protocol, marker)
        created = False
        try:
            _, headers, _ = self.request('PUT', resource, document, {'Content-Type': media, 'If-None-Match': '*'}, (201,))
            created = True
            next_token, changes = self.dav_report(path, token)
            etag = headers.get('ETag')
            require(etag and next_token != token and self.dav_change(changes, resource, etag=etag))
        finally:
            if created:
                self.remove_dav(resource, document)
        final_token, changes = self.dav_report(path, next_token)
        require(final_token != next_token and self.dav_change(changes, resource))

    @staticmethod
    def dav_change(changes, resource, *, etag=None):
        for change in changes:
            href = change.findtext('{DAV:}href') or ''
            if unquote(urlsplit(href).path) != unquote(resource):
                continue
            if etag is None:
                return (change.findtext('{DAV:}status') or '').split()[1:2] == ['404']
            return change.findtext('{DAV:}propstat/{DAV:}prop/{DAV:}getetag') == etag
        return False

    def eas_sync(self, key):
        body = b'\x03\x01\x6a\x00\x45\x5c\x4f\x4b\x03' + key + b'\x00\x01\x52\x031\x00\x01\x01\x01\x01'
        query = urlencode({'Cmd': 'Sync', 'User': self.mailbox, 'DeviceId': 'MailHealthCanary', 'DeviceType': 'HealthProbe'})
        _, headers, data = self.request('POST', '/Microsoft-Server-ActiveSync?' + query, body, {
            'MS-ASProtocolVersion': '14.1', 'Content-Type': 'application/vnd.ms-sync.wbxml',
        })
        require(headers.get('Content-Type', '').split(';')[0] == 'application/vnd.ms-sync.wbxml')
        prefix = re.match(rb'\x03\x01\x6a\x00(?:\x00\x00)?\x45\x5c\x4f\x52\x031\x00\x01'
                          rb'\x4b\x03([A-Za-z0-9-]{1,64})\x00\x01\x4e\x031\x00\x01', data)
        require(prefix and prefix[1] != b'0' and data.endswith(b'\x01\x01\x01'))
        changes = re.findall(rb'\x47\x4d\x03(1:[0-9]+:[a-f0-9]{32})\x00\x01', data[prefix.end():])
        return prefix[1], changes, data

    def ews(self, operation, request):
        envelope = (f'<s:Envelope xmlns:s="{SOAP}" xmlns:m="{MESSAGES}" xmlns:t="{TYPES}">'
                    f'<s:Body><m:{operation}>{request}</m:{operation}></s:Body></s:Envelope>')
        _, _, data = self.request('POST', '/EWS/Exchange.asmx', envelope, {'Content-Type': 'text/xml'})
        root = ET.fromstring(data)
        responses = root.findall(f'.//{{{MESSAGES}}}{operation}ResponseMessage')
        require(len(responses) == 1 and responses[0].get('ResponseClass') == 'Success'
                and responses[0].findtext(f'{{{MESSAGES}}}ResponseCode') == 'NoError')
        return responses[0]

    def ews_sync(self, state):
        token = f'<m:SyncState>{escape(state)}</m:SyncState>' if state else ''
        reply = self.ews('SyncFolderItems', (
            '<m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>'
            '<m:SyncFolderId><t:DistinguishedFolderId Id="inbox"/></m:SyncFolderId>'
            f'{token}<m:MaxChangesReturned>8</m:MaxChangesReturned>'))
        next_state = reply.findtext(f'{{{MESSAGES}}}SyncState')
        require(next_state and len(next_state) <= 128
                and reply.findtext(f'{{{MESSAGES}}}IncludesLastItemInRange') == 'true')
        added = reply.findall(f'{{{MESSAGES}}}Changes/{{{TYPES}}}Create//{{{TYPES}}}ItemId')
        return next_state, [item.get('Id') for item in added]

    def imap_connection(self):
        client = CanaryIMAP(self)
        try:
            require('UIDPLUS' in client.capabilities)
            try:
                client.login(self.mailbox, self.password)
            except imaplib.IMAP4.abort:
                raise
            except imaplib.IMAP4.error:
                raise AuthenticationFailed() from None
            status, count = client.select('INBOX')
            require(status == 'OK' and count in ([b'0'], [b'1']))
            return client
        except BaseException:
            client.shutdown()
            raise

    def cleanup_mailbox(self, client):
        status, rows = client.uid('SEARCH', None, 'ALL')
        require(status == 'OK' and len(rows) == 1)
        uids = rows[0].split()
        require(len(uids) <= 1)
        for uid in uids:
            status, headers = client.uid('FETCH', uid, '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID X-MAIL-HEALTH)])')
            require(status == 'OK')
            fields = {line.lower() for part in headers if isinstance(part, tuple) for line in part[1].splitlines()}
            require(f'message-id: {self.message_id}'.encode() in fields and f'x-mail-health: {self.marker}'.encode() in fields)
            require(client.uid('STORE', uid, '+FLAGS.SILENT', r'(\Deleted)')[0] == 'OK')
            require(client.uid('EXPUNGE', uid)[0] == 'OK')

    def mailbox_sync(self, protocols):
        results = {}
        preparations = {}
        client = None
        try:
            client = self.imap_connection()
            self.cleanup_mailbox(client)
            require(client.select('INBOX')[0] == 'OK')
            validity = client.response('UIDVALIDITY')[1][0]
            next_uid = client.response('UIDNEXT')[1][0]
            require(validity and validity.isdigit() and next_uid and next_uid.isdigit())

            if 'activesync' in protocols:
                results['activesync'], preparations['activesync'] = result('activesync', self.eas_baseline)
            if 'ews' in protocols:
                results['ews'], preparations['ews'] = result('ews', self.ews_baseline)

            message = (f'From: {self.mailbox}\r\nTo: {self.mailbox}\r\nSubject: {self.marker}\r\n'
                       f'Message-ID: {self.message_id}\r\nX-Mail-Health: {self.marker}\r\n\r\n'
                       'Disposable Mail synchronization probe.\r\n').encode()
            try:
                require(client.append('INBOX', r'(\Seen)', None, message)[0] == 'OK')
                appended = client.response('APPENDUID')[1][0]
                require(appended and re.fullmatch(rb'[0-9]+ [0-9]+', appended))
                written_validity, uid = appended.split()
                require(written_validity == validity and int(uid) >= int(next_uid))
                require(client.select('INBOX')[0] == 'OK')
                require(client.response('UIDVALIDITY')[1][0] == validity)
                status, seen = client.uid('SEARCH', None, 'ALL')
                require(status == 'OK' and seen == [uid])
                results['imap'] = {'name': CHECKS['imap'], 'ok': True}
                for protocol, before in preparations.items():
                    if before is not None:
                        action = self.eas_changed if protocol == 'activesync' else self.ews_changed
                        results[protocol], _ = result(protocol, lambda: action(before, uid))
            finally:
                self.cleanup_mailbox(client)
        finally:
            if client is not None:
                client.shutdown()
        return [results[key] for key in MAIL_PROTOCOLS if key in protocols]

    def eas_baseline(self):
        key, changes, _ = self.eas_sync(b'0')
        require(not changes)
        key, changes, _ = self.eas_sync(key)
        require(not changes)
        return key

    def eas_changed(self, previous, uid):
        key, changes, data = self.eas_sync(previous)
        require(key != previous and len(changes) == 1 and changes[0].split(b':')[1] == uid
                and self.marker.encode() + b'\x00' in data)
        _, repeated, _ = self.eas_sync(key)
        require(not repeated)

    def ews_baseline(self):
        state, changes = self.ews_sync('')
        require(not changes)
        return state

    def ews_changed(self, previous, _uid):
        state, changes = self.ews_sync(previous)
        require(state != previous and len(changes) == 1 and changes[0])
        identity = escape(changes[0], {'"': '&quot;'})
        item = self.ews('GetItem', '<m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape>'
                                 f'<m:ItemIds><t:ItemId Id="{identity}"/></m:ItemIds>')
        require(item.findtext(f'.//{{{TYPES}}}Subject') == self.marker)
        _, repeated = self.ews_sync(state)
        require(not repeated)


def checks_for(probe, protocols):
    mail = protocols.intersection(MAIL_PROTOCOLS)
    with ThreadPoolExecutor(max_workers=3) as pool:
        dav = [pool.submit(result, protocol, lambda key=protocol: probe.dav_sync(key))
               for protocol in DAV_COLLECTIONS if protocol in protocols]
        if mail:
            failure, checks = result('imap', lambda: probe.mailbox_sync(mail))
            if checks is None:
                checks = [{**failure, 'name': CHECKS[key]} for key in MAIL_PROTOCOLS if key in mail]
        else:
            checks = []
        return checks + [job.result()[0] for job in dav]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--connect-host')
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    try:
        config, protocols = load_config(args.config)
        checks = checks_for(Probe(args.host, args.connect_host, config), protocols)
    except (OSError, ValueError, AttributeError, TypeError):
        return 2
    print(json.dumps({'checks': checks}))
    return 0 if all(check['ok'] for check in checks) else 1


if __name__ == '__main__':
    raise SystemExit(main())
