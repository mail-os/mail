#!/usr/bin/env python3
"""Verify hosted erasure exports, handoffs, and review receipts on disposable mailboxes."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import runpy
import secrets
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

    verify_review(test, db, request, receipt['audit_id'], ready['audit_id'], peer, original)


def verify_review(test, db, export, export_audit, handoff_audit, peer, original):
    mailbox, actor, case = (export[key] for key in ('mailbox', 'assignment_actor', 'case_reference'))
    old = test.directory / 'before-inventory.db'
    with closing(sqlite3.connect(old)) as snapshot:
        db.backup(snapshot)

    def inspect(owner, assignment, reference):
        result = cli(test, 'hosted-erasure-inventory', owner, assignment, reference)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)['audit_id']

    request = {
        'version': 1,
        'request_id': 'erase-fixture-17',
        'mailbox': mailbox,
        'assignment_actor': actor,
        'case_reference': case,
        'inventory_audit_id': inspect(mailbox, actor, case),
        'retention_disposition': 'cleared',
        'export_disposition': 'resolved',
        'export_handoff_audit_id': handoff_audit,
        'evidence': {
            'authorization_reference': 'support-authorization-17',
            'retention_reference': 'retention-reviewed-17',
            'backup_reference': 'backup-disposition-17',
            'billing_reference': 'billing-disposition-17',
            'search_reference': 'search-disposition-17',
            'export_resolution_reference': 'export-delivery-and-expiry-17',
        },
    }
    path = test.directory / 'erasure-review.json'

    def run_review(overrides=None, *, mode=0o600, env=None):
        path.write_text(json.dumps({**request, **(overrides or {})}))
        path.chmod(mode)
        return cli(test, 'hosted-erasure-review', str(path), env=env)

    def refuse(error, overrides=None, **kwargs):
        result = run_review(overrides, **kwargs)
        assert result.returncode != 0 and not result.stdout and error in result.stderr, result

    def reviews():
        return db.execute("""SELECT id,actor,target,details FROM audit_log
                             WHERE action='hosted.erasure.review.accepted' ORDER BY id""").fetchall()

    refuse('ErasureReviewNotPrivate', mode=0o644)
    path.chmod(0o600)
    link = test.directory / 'linked-review.json'
    link.symlink_to(path)
    result = cli(test, 'hosted-erasure-review', str(link))
    assert result.returncode != 0 and not result.stdout, result
    refuse('RetentionHold', {'retention_disposition': 'held'})
    refuse('InvalidCaseReference', {'evidence': {**request['evidence'], 'backup_reference': ''}})
    refuse('InvalidExportDisposition', {'export_handoff_audit_id': None})
    refuse('ExportHandoffAuditNotFound', {'export_handoff_audit_id': export_audit})
    refuse('ExportResolutionRequired', {'export_disposition': 'not_requested', 'export_handoff_audit_id': None})
    refuse('ManagedMailboxNotFound', {'assignment_actor': test.specs[peer]['actor']})
    refuse('InventoryCaseChanged', {'case_reference': 'another-case'})
    refuse('InventoryAuditNotFound', env=dict(test.env, SMTP_DB_PATH=str(old)))
    wrong_case = inspect(mailbox, actor, 'another-case')
    refuse('ExportHandoffAssignmentChanged', {'case_reference': 'another-case', 'inventory_audit_id': wrong_case})
    refuse('InventoryUnresolved', env=dict(test.env, CALDAV_DB_PATH=str(test.directory / 'missing-dav.db')))

    msg = original.read_bytes()
    extra = original.with_name('review-contents-changed')
    extra.write_bytes(b'fixture changed since inventory')
    try:
        refuse('InventoryChanged')
    finally:
        extra.unlink()

    with db:
        db.execute("""INSERT INTO webmail_records(username,kind,id,payload,state,revision)
                      VALUES(?,'outbox','erasure-unconfirmed','{}','unknown',1)""", (mailbox,))
    refuse('DeliveryUnresolved')
    with db:
        db.execute("DELETE FROM webmail_records WHERE id='erasure-unconfirmed'")
        now = int(time.time())
        db.execute("""INSERT INTO message_queue(id,from_addr,to_addr,message_data,status,next_retry,created_at,updated_at)
                      VALUES('erasure-legacy-queue',?,'external@example.test','fixture','retry',?,?,?)""",
                   (mailbox, now + 3600, now, now))
    refuse('DeliveryUnresolved')
    with db:
        db.execute("DELETE FROM message_queue WHERE id='erasure-legacy-queue'")
        peer_id = db.execute("SELECT id FROM users WHERE username=?", (peer,)).fetchone()[0]
        db.execute("""INSERT INTO accepted_mail(id,accepted_at,accepted_ms,envelope_from,author,verified_author,remote_addr,mime)
                      VALUES('erasure-legacy-pending',?,?,?,?,1,'127.0.0.1','fixture')""",
                   (now, now * 1000, mailbox, mailbox))
        db.execute("""INSERT INTO accepted_mail_targets
                      (delivery_id,ordinal,recipient,mailbox,mailbox_id,folder,outcome,queued_bytes,retry_at,is_primary)
                      VALUES('erasure-legacy-pending',0,?,?,?,'INBOX','pending',7,?,1)""",
                   (peer, peer, peer_id, now + 3600))
    refuse('DeliveryUnresolved')
    with db:
        db.execute("DELETE FROM accepted_mail_targets WHERE delivery_id='erasure-legacy-pending'")
        db.execute("DELETE FROM accepted_mail WHERE id='erasure-legacy-pending'")
        db.execute("""CREATE TRIGGER deny_review_audit BEFORE INSERT ON audit_log
                      WHEN NEW.action='hosted.erasure.review.accepted' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END""")
    refuse('StepFailed')
    assert not reviews()
    with db:
        db.execute('DROP TRIGGER deny_review_audit')

    # Both operators submit the same already-written input.
    with ThreadPoolExecutor(max_workers=2) as pool:
        first, retry = pool.map(lambda _: cli(test, 'hosted-erasure-review', str(path)), range(2))
    assert first.returncode == retry.returncode == 0, (first, retry)
    receipt = json.loads(first.stdout)
    assert receipt == {'version': 1, 'state': 'review_recorded_data_retained', 'mailbox': mailbox,
                       'request_id': request['request_id'], 'audit_id': receipt['audit_id']}, receipt
    assert json.loads(retry.stdout) == receipt, retry
    audit, = reviews()
    assert audit[:3] == (receipt['audit_id'], f'local-operator:{os.geteuid()}', mailbox)
    assert json.loads(audit[3]) == {**{key: value for key, value in request.items()
                                      if key not in ('mailbox', 'assignment_actor')}, 'identity': export['identity']}
    assert actor not in audit[3] and export['recipient'] not in audit[3]
    refuse('ErasureReviewConflict', {'evidence': {**request['evidence'], 'backup_reference': 'other-backup'}})
    assert reviews() == [audit] and original.read_bytes() == msg

    other_request = {**request, 'request_id': 'erase-fixture-other-request'}
    alternate = run_review({'request_id': other_request['request_id']})
    assert alternate.returncode == 0, alternate.stderr
    other_audit = json.loads(alternate.stdout)['audit_id']
    verify_begin(test, db, request, receipt['audit_id'], other_request, other_audit, old, peer, original, msg)

    peer_actor = test.specs[peer]['actor']
    peer_review = {'mailbox': peer, 'assignment_actor': peer_actor, 'export_disposition': 'not_requested',
                   'export_handoff_audit_id': None}
    refuse('MailboxStillReadable', {**peer_review, 'inventory_audit_id': inspect(peer, peer_actor, case)})
    test.provision('exit-archive-unrelated', enabled=False)
    refuse('InventoryAuditNotFound', peer_review)
    peer_review['inventory_audit_id'] = inspect(peer, peer_actor, case)
    refuse('ErasureReviewConflict', peer_review)
    no_export = run_review({**peer_review, 'request_id': 'erase-fixture-no-export'})
    assert no_export.returncode == 0, no_export.stderr
    assert json.loads(no_export.stdout)['mailbox'] == peer
    assert len(reviews()) == 3 and original.read_bytes() == msg
    assert db.execute("SELECT count(*) FROM users WHERE username IN (?,?)", (mailbox, peer)).fetchone() == (2,)
    print('Verified hosted erasure review receipt, held and readable refusal, scoped inventory, queued work, audit rollback, and retry.')


def verify_begin(test, db, review, review_id, other_review, other_id, old, peer, original, message):
    path = test.directory / 'begin-review.json'
    mailbox = review['mailbox']

    def begin(input=review, audit_id=review_id, env=None):
        path.write_text(json.dumps(input))
        path.chmod(0o600)
        return cli(test, 'hosted-erasure-begin', str(path), str(audit_id), env=env)

    def refuse(reason, **kwargs):
        reply = begin(**kwargs)
        assert reply.returncode and not reply.stdout and reason in reply.stderr, reply

    def queries():
        rows = db.execute("SELECT request_id, mailbox, native_user_id, review_audit_id, start_audit_id FROM hosted_erasure_operations").fetchall()
        audits = db.execute("SELECT id,actor,target,details FROM audit_log WHERE action='hosted.erasure.started'").fetchall()
        return rows, audits

    refuse('InvalidErasureReviewAuditId', audit_id=0)
    refuse('RetentionHold', input={**review, 'retention_disposition': 'held'})
    refuse('ManagedMailboxNotFound', input={**review, 'assignment_actor': test.specs[peer]['actor']})
    refuse('ErasureReviewAuditNotFound', audit_id=review['inventory_audit_id'])
    refuse('ErasureReviewAuditNotFound', env=dict(test.env, SMTP_DB_PATH=str(old)))
    refuse('ErasureReviewConflict', input={**review, 'evidence': {**review['evidence'], 'retention_reference': 'changed'}})
    refuse('ErasureReviewConflict', input=other_review)

    stray = original.with_name('unreviewed-file')
    stray.write_bytes(b'added after review')
    try:
        refuse('InventoryChanged')
    finally:
        stray.unlink()
    with db:
        db.execute("""INSERT INTO webmail_records(username,kind,id,payload,state,revision)
                      VALUES(?,'outbox','pending-erasure-start','{}','unknown',1)""", (mailbox,))
    refuse('DeliveryUnresolved')
    with db:
        db.execute("DELETE FROM webmail_records WHERE id='pending-erasure-start'")
        db.execute("""CREATE TRIGGER deny_erasure_reservation BEFORE INSERT ON hosted_erasure_operations
                      BEGIN SELECT RAISE(ABORT,'fixture reservation failure'); END""")
    refuse('StepFailed')
    assert queries() == ([], [])
    with db:
        db.execute('DROP TRIGGER deny_erasure_reservation')

    # Concurrent retries share the exact same private review.
    with ThreadPoolExecutor(max_workers=2) as pool:
        one, two = pool.map(lambda _: cli(test, 'hosted-erasure-begin', str(path), str(review_id)), range(2))
    assert one.returncode == two.returncode == 0, (one, two)
    started = json.loads(one.stdout)
    assert json.loads(two.stdout) == started
    assert started == {
        'version': 1, 'state': 'erasure_started_data_retained', 'mailbox': mailbox,
        'request_id': review['request_id'], 'review_audit_id': review_id, 'audit_id': started['audit_id'],
    }, started
    identity = db.execute("SELECT id FROM users WHERE username=?", (mailbox,)).fetchone()[0]
    reservation, reservation_audits = queries()
    assert reservation == [(review['request_id'], mailbox, identity, review_id, started['audit_id'])], reservation
    row, = reservation_audits
    assert row[:3] == (started['audit_id'], f'local-operator:{os.geteuid()}', mailbox)
    audit_details = json.loads(row[3])
    assert audit_details['identity']['native_user_id'] == identity and audit_details['review_audit_id'] == review_id
    assert audit_details['case_reference'] == review['case_reference']

    refuse('ErasureAlreadyStarted', input=other_review, audit_id=other_id)
    assert cli(test, 'enable', mailbox).returncode != 0
    spec = test.specs[mailbox]
    endpoint = test.private + "/provisioning/v1/mailbox"
    update = dict(spec, operation_id=secrets.token_hex(16), revision=spec['revision'] + 1, enabled=True)
    reply = test.http(endpoint, update, test.auth)
    assert reply[0] == 409 and json.loads(reply[2])['error'] == 'mailbox_unavailable', reply
    recreate = dict(spec, actor=secrets.token_hex(16), operation_id=secrets.token_hex(16), revision=1,
                    initial_password=test.password, initial_recovery='other@recovery.example.test', enabled=True)
    reply = test.http(endpoint, recreate, test.auth)
    assert reply[0] == 409 and json.loads(reply[2])['error'] == 'mailbox_unavailable', reply
    renew = {key: update[key] for key in ('mailbox', 'actor', 'operation_id', 'revision')}
    now = int(time.time())
    renew['access_window'] = {'service_until': now + 900, 'read_until': now + 1800}
    reply = test.http(endpoint + '/access', renew, test.auth)
    assert reply[0] == 409 and json.loads(reply[2])['error'] == 'mailbox_unavailable', reply
    expect_smtp(test.deliver(mailbox, subject='Erasure mailbox remains closed'), 550)
    expect_smtp(test.deliver(peer, subject='Separate mailbox still receives'), 250)
    assert original.read_bytes() == message and queries() == (reservation, reservation_audits)

    after = test.directory / 'after-erasure-start.db'
    with closing(sqlite3.connect(after)) as snapshot:
        db.backup(snapshot)
    repeated = begin(env=dict(test.env, SMTP_DB_PATH=str(after)))
    assert repeated.returncode == 0 and json.loads(repeated.stdout) == started, repeated

    with closing(sqlite3.connect(after)) as restored:
        for statement in (
            "UPDATE provisioned_mailboxes SET revision=revision+1 WHERE mailbox=?",
            "UPDATE users SET enabled=1 WHERE username=?",
        ):
            try:
                restored.execute(statement, (mailbox,))
            except sqlite3.IntegrityError as error:
                assert 'mailbox erasure started' in str(error), error
            else:
                raise AssertionError("A restored reservation allowed a SQL update")
        restored.rollback()
    print('Verified audited erasure start, retained data, pending-delivery and stale-review refusal, rollback, concurrency, and preserved reservation after backup.')


def verify_expired_begin(test, db):
    mailbox = test.provision('expired-erasure')
    spec = test.specs[mailbox]
    now = int(time.time())
    change = {**spec, 'operation_id': secrets.token_hex(16), 'revision': 2,
              'access_window': {'service_until': now - 120, 'read_until': now - 60}}
    del change['initial_recovery'], change['initial_password']
    result = test.http(test.private + '/provisioning/v1/mailbox', change, test.auth)
    assert result[0] == 200, result
    user, enabled = db.execute("SELECT id,enabled FROM users WHERE username=?", (mailbox,)).fetchone()
    assert enabled == 1
    case = 'expired-exit-case'
    snapshot = cli(test, 'hosted-erasure-inventory', mailbox, spec['actor'], case)
    assert snapshot.returncode == 0, snapshot.stderr
    review = {
        'version': 1, 'request_id': 'expired-erasure-request', 'mailbox': mailbox,
        'assignment_actor': spec['actor'], 'case_reference': case,
        'inventory_audit_id': json.loads(snapshot.stdout)['audit_id'],
        'retention_disposition': 'cleared', 'export_disposition': 'not_requested',
        'evidence': dict.fromkeys(('authorization_reference', 'retention_reference', 'backup_reference',
                                   'billing_reference', 'search_reference', 'export_resolution_reference'), 'expired-case-evidence'),
    }
    path = test.directory / 'expired-erasure-review.json'
    path.write_text(json.dumps(review))
    path.chmod(0o600)
    accepted = cli(test, 'hosted-erasure-review', str(path))
    assert accepted.returncode == 0, accepted.stderr
    audit_id = str(json.loads(accepted.stdout)['audit_id'])
    with db:
        db.execute("""CREATE TRIGGER deny_expired_reservation BEFORE INSERT ON hosted_erasure_operations
                      BEGIN SELECT RAISE(ABORT, 'fixture reservation failure'); END""")
    attempt = cli(test, 'hosted-erasure-begin', str(path), audit_id)
    assert attempt.returncode and 'StepFailed' in attempt.stderr, attempt
    assert db.execute("SELECT enabled FROM users WHERE id=?", (user,)).fetchone() == (1,)
    assert db.execute("SELECT count(*) FROM audit_log WHERE action='hosted.erasure.started' AND target=?", (mailbox,)).fetchone() == (0,)
    with db:
        db.execute('DROP TRIGGER deny_expired_reservation')
    attempt = cli(test, 'hosted-erasure-begin', str(path), audit_id)
    assert attempt.returncode == 0, attempt.stderr
    assert db.execute("SELECT enabled FROM users WHERE id=?", (user,)).fetchone() == (0,)
    print('Verified erasure start disables an expired mailbox and rolls back that change if reservation fails.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix='mail-erasure-export-') as directory:
        root = Path(directory)
        test = Fixture(args.binary.resolve(strict=True), root, staging=True)
        with test.daemon(), closing(sqlite3.connect(root / 'smtp.db')) as db:
            verify(test, db)
            verify_expired_begin(test, db)
