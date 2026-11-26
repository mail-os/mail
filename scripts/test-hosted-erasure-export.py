#!/usr/bin/env python3
"""Verify the audited export command against disposable hosted mailboxes."""

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import runpy
import sqlite3
from stat import S_IMODE
import tarfile
from tempfile import TemporaryDirectory
import time

fixture = runpy.run_path(str(Path(__file__).with_name('test-hosted-operator.py')))
Fixture, cli, expect_smtp = (fixture[name] for name in ('Fixture', 'cli', 'expect_smtp'))


def verify(test, db):
    mailbox = test.provision('exit-archive')
    peer = test.provision('exit-archive-unrelated')
    expect_smtp(test.deliver(mailbox, identity=peer, subject='Retained export specimen',
                             body='Original archived data.\r\n' * 900), 250)
    original, = (test.directory / 'mail' / mailbox / 'new').iterdir()
    raw = original.read_bytes()
    spec = test.specs[mailbox]
    preliminary = cli(test, 'hosted-erasure-preflight', mailbox, spec['actor'], 'exit-review-193')
    assert preliminary.returncode == 0, preliminary.stderr
    request = {
        'version': 1,
        'mailbox': mailbox,
        'assignment_actor': spec['actor'],
        'identity': json.loads(preliminary.stdout)['observation']['identity'],
        'case_reference': 'exit-review-193',
        'recipient_verification_reference': 'authenticated-support-40',
        'recipient': 'verified-recipient@example.test',
        'expires_at': int(time.time()) + 3600,
    }
    reviewed = test.directory / 'reviewed.json'
    archive = test.directory / 'export.tar'

    def run(overrides=None, *, output=archive, env=None):
        reviewed.write_text(json.dumps({**request, **(overrides or {})}))
        reviewed.chmod(0o600)
        return cli(test, 'hosted-erasure-export', str(reviewed), str(output), env=env)

    def refuse(error, overrides=None, *, output=archive, env=None):
        result = run(overrides, output=output, env=env)
        assert result.returncode != 0 and not result.stdout and error in result.stderr, result

    def prepared():
        return db.execute("SELECT id,actor,target,details FROM audit_log WHERE action='hosted.erasure.export.prepared' ORDER BY id").fetchall()

    older = test.directory / 'before-ending.db'
    with closing(sqlite3.connect(older)) as backup:
        db.backup(backup)
    refuse('MailboxStillReadable')
    assert not archive.exists() and not prepared()

    test.provision('exit-archive', enabled=False)
    current = cli(test, 'hosted-erasure-preflight', mailbox, spec['actor'], request['case_reference'])
    assert current.returncode == 0, current.stderr
    request['identity'] = json.loads(current.stdout)['observation']['identity']
    refuse('ManagedMailboxNotFound', {'assignment_actor': test.specs[peer]['actor']})
    refuse('AssignmentChanged', {'identity': {**request['identity'], 'initial_provisioning_operation': 'different-operation'}})
    refuse('AssignmentChanged', env=dict(test.env, SMTP_DB_PATH=str(older)))
    refuse('InvalidExportExpiry', {'expires_at': int(time.time()) - 1})
    refuse('InvalidEmail', {'recipient': 'not-an-address'})
    refuse('InvalidEmail', {'recipient': 'Another Person <verified-recipient@example.test>'})
    refuse('InvalidCaseReference', {'recipient_verification_reference': 'invalid\ncase'})
    assert not archive.exists() and not prepared()

    with db:
        db.execute("""CREATE TRIGGER deny_export_audit BEFORE INSERT ON audit_log
                        WHEN NEW.action='hosted.erasure.export.prepared' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END""")
    refuse('StepFailed')
    assert not archive.exists() and not prepared()
    with db:
        db.execute('DROP TRIGGER deny_export_audit')

    archive.write_bytes(b'original target')
    refuse('PathAlreadyExists')
    assert archive.read_bytes() == b'original target'
    assert len(prepared()) == 1
    archive.unlink()

    result = run()
    assert result.returncode == 0, result.stderr
    assert S_IMODE(archive.stat().st_mode) == 0o600
    receipt = json.loads(result.stdout)
    assert receipt['state'] == 'private_archive_published' and receipt['mailbox'] == mailbox, receipt
    record = receipt['prepared']
    archive_bytes = archive.read_bytes()
    assert record == {**{key: request[key] for key in ('identity', 'case_reference', 'recipient_verification_reference', 'recipient', 'expires_at')},
                      'archive_sha256': hashlib.sha256(archive_bytes).hexdigest(), 'archive_bytes': len(archive_bytes)}, record
    audit_id, operator, target, content = prepared()[-1]
    assert (audit_id, operator, target) == (receipt['audit_id'], f'local-operator:{os.geteuid()}', mailbox)
    assert json.loads(content) == record and spec['actor'] not in result.stdout and str(archive) not in content
    with tarfile.open(archive) as bundle:
        assert json.load(bundle.extractfile('manifest.json'))['mailbox'] == mailbox
        copies = [bundle.extractfile(member).read() for member in bundle.getmembers() if member.name.endswith('.eml')]
        assert copies == [raw]
    assert original.read_bytes() == raw
    expect_smtp(test.deliver(peer, subject='Unrelated mailbox remained available'), 250)
    handoff = {key: request[key] for key in (
        'version', 'mailbox', 'assignment_actor', 'case_reference', 'recipient_verification_reference', 'recipient',
    )}
    handoff['export_audit_id'] = receipt['audit_id']
    handoff_input = test.directory / 'handoff.json'
    delivered = test.directory / 'approved-channel.tar'

    def pass_archive(overrides=None, source=archive, output=delivered, env=None, mode=0o600):
        handoff_input.write_text(json.dumps({**handoff, **(overrides or {})}))
        handoff_input.chmod(mode)
        return cli(test, 'hosted-erasure-handoff', str(handoff_input), str(source), str(output), env=env)

    def refused_handoff(error, overrides=None, **kwargs):
        result = pass_archive(overrides, **kwargs)
        assert result.returncode != 0 and not result.stdout and error in result.stderr, result
        assert not delivered.exists()

    def handoff_audits():
        return db.execute("SELECT id,details FROM audit_log WHERE action='hosted.erasure.export.handoff_authorized'").fetchall()

    refused_handoff('ExportHandoffReviewNotPrivate', mode=0o644)
    refused_handoff('ExportRecipientChanged', {'recipient': 'another-recipient@example.test'})
    refused_handoff('ExportRecipientChanged', {'recipient_verification_reference': 'unverified-approval'})
    refused_handoff('ExportRecipientChanged', {'case_reference': 'unrelated-case'})
    refused_handoff('ExportAuditNotFound', {'mailbox': peer})
    refused_handoff('ManagedMailboxNotFound', {'assignment_actor': test.specs[peer]['actor']})
    refused_handoff('ExportAuditNotFound', env=dict(test.env, SMTP_DB_PATH=str(older)))
    tampered = test.directory / 'tampered.tar'
    tampered.write_bytes(bytes([archive_bytes[0] ^ 1]) + archive_bytes[1:])
    tampered.chmod(0o600)
    refused_handoff('ExportArchiveChanged', source=tampered)
    tampered.write_bytes(archive_bytes)
    tampered.chmod(0o644)
    refused_handoff('ExportArchiveNotPrivate', source=tampered)
    assert not handoff_audits()

    with db:
        db.execute("""CREATE TRIGGER deny_handoff_audit BEFORE INSERT ON audit_log
                       WHEN NEW.action='hosted.erasure.export.handoff_authorized'
                       BEGIN SELECT RAISE(ABORT,'fixture handoff audit failure'); END""")
    refused_handoff('StepFailed')
    with db:
        db.execute('DROP TRIGGER deny_handoff_audit')
    assert not handoff_audits()

    result = pass_archive()
    assert result.returncode == 0, result.stderr
    ready = json.loads(result.stdout)
    assert ready['state'] == 'private_handoff_ready' and ready['export_audit_id'] == receipt['audit_id']
    assert ready['prepared'] == record and delivered.read_bytes() == archive_bytes
    assert S_IMODE(delivered.stat().st_mode) == 0o600
    retry = pass_archive()
    assert retry.returncode == 0 and json.loads(retry.stdout) == ready, retry
    audit, = handoff_audits()
    assert audit[0] == ready['audit_id']
    assert json.loads(audit[1])['recipient'] == record['recipient']
    assert json.loads(audit[1])['expires_at'] == record['expires_at']

    output_conflict = test.directory / 'some-other-handoff.tar'
    output_conflict.write_bytes(b'existing private operator data')
    output_conflict.chmod(0o600)
    conflict = pass_archive(output=output_conflict)
    assert conflict.returncode != 0 and 'ExportArchiveChanged' in conflict.stderr
    assert output_conflict.read_bytes() == b'existing private operator data'
    assert handoff_audits() == [audit]

    expires = test.directory / 'after-deadline.db'
    with closing(sqlite3.connect(expires)) as snapshot:
        db.backup(snapshot)
        with snapshot:
            snapshot.execute("UPDATE audit_log SET details=json_set(details,'$.expires_at',?) WHERE id=?",
                             (int(time.time()) - 1, receipt['audit_id']))
    expired = pass_archive(output=test.directory / 'after-expiration.tar', env=dict(test.env, SMTP_DB_PATH=str(expires)))
    assert expired.returncode != 0 and 'InvalidExportExpiry' in expired.stderr
    assert not (test.directory / 'after-expiration.tar').exists()
    assert delivered.read_bytes() == archive_bytes and handoff_audits() == [audit]
    print('Verified audited export and recipient-bound private handoff, exact archive bytes, expiry, refusal, and audited retry.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix='mail-erasure-export-') as directory:
        root = Path(directory)
        test = Fixture(args.binary.resolve(strict=True), root, staging=True)
        with test.daemon(), closing(sqlite3.connect(root / 'smtp.db')) as db:
            verify(test, db)
