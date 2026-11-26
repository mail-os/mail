#!/usr/bin/env python3
"""Erase only the reviewed Maildir of a disposable hosted mailbox."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
from pathlib import Path
import runpy
import sqlite3
from tempfile import TemporaryDirectory

fixtures = runpy.run_path(str(Path(__file__).with_name('test-hosted-operator.py')))
Fixture, cli, expect_smtp = (fixtures[key] for key in ('Fixture', 'cli', 'expect_smtp'))


def verify(test):
    root = test.directory / 'mail'
    database = test.directory / 'smtp.db'
    previous = test.directory / 'before-start.db'
    path = test.directory / 'review.json'
    with test.daemon(), closing(sqlite3.connect(database)) as db:
        mailbox = test.provision('erase-maildir')
        peer = test.provision('retain-maildir')
        expect_smtp(test.deliver(mailbox, subject='Reviewed message'), 250)
        expect_smtp(test.deliver(peer, subject='Separate owner message'), 250)
        owned, unrelated = root / mailbox, root / peer
        specimen, = (owned / 'new').iterdir()
        peer_file, = (unrelated / 'new').iterdir()
        original, independent = specimen.read_bytes(), peer_file.read_bytes()
        nested = owned / '.Archive' / 'cur'
        nested.mkdir(parents=True)
        (nested / 'retained-for-review.eml').write_bytes(original)
        test.provision('erase-maildir', enabled=False)
        actor = test.specs[mailbox]['actor']
        case = 'maildir-erasure-fixture'
        inv = cli(test, 'hosted-erasure-inventory', mailbox, actor, case)
        assert inv.returncode == 0, inv.stderr
        review = {
            'version': 1, 'request_id': 'maildir-erasure-request', 'mailbox': mailbox, 'assignment_actor': actor,
            'case_reference': case, 'inventory_audit_id': json.loads(inv.stdout)['audit_id'],
            'retention_disposition': 'cleared', 'export_disposition': 'not_requested',
            'evidence': dict.fromkeys(('authorization_reference', 'retention_reference', 'backup_reference',
                                       'billing_reference', 'search_reference', 'export_resolution_reference'), 'fixture-case'),
        }
        path.write_text(json.dumps(review))
        path.chmod(0o600)
        approved = cli(test, 'hosted-erasure-review', str(path))
        assert approved.returncode == 0, approved.stderr
        approved_id = json.loads(approved.stdout)['audit_id']
        with closing(sqlite3.connect(previous)) as snapshot:
            db.backup(snapshot)
        started = cli(test, 'hosted-erasure-begin', str(path), str(approved_id))
        assert started.returncode == 0, started.stderr
        start_id = json.loads(started.stdout)['audit_id']

        def erase(audit_id=start_id, *, env=None):
            return cli(test, 'hosted-erasure-maildir', str(path), str(audit_id), env=env)

        def refuse(error, audit_id=start_id, **kwargs):
            result = erase(audit_id, **kwargs)
            assert result.returncode and not result.stdout and error in result.stderr, result

        refuse('MaildirWriterActive')
        assert specimen.read_bytes() == original

    with closing(sqlite3.connect(database)) as db:
        def journal():
            return db.execute("""SELECT nonce,phase,completion_audit_id FROM hosted_erasure_maildir_steps
                                 WHERE start_audit_id=?""", (start_id,)).fetchone()

        refuse('ErasureStartNotFound', approved_id)
        refuse('ErasureStartNotFound', env=dict(test.env, SMTP_DB_PATH=str(previous)))
        refuse('ErasureDirectoryChanged', env=dict(test.env, MAIL_ROOT=str(unrelated)))
        path.write_text(json.dumps({**review, 'assignment_actor': test.specs[peer]['actor']}))
        refuse('ManagedMailboxNotFound')
        path.write_text(json.dumps(review))

        legacy = root / mailbox.split('@')[0]
        legacy.mkdir()
        refuse('InventoryUnresolved')
        legacy.rmdir()
        assert journal() is None

        still_shared = unrelated / 'linked-reviewed-message'
        still_shared.hardlink_to(specimen)
        refuse('SharedMaildirEntry')
        assert journal() is None and still_shared.read_bytes() == original
        still_shared.unlink()

        unknown = specimen.with_name('arrived-after-review')
        unknown.write_bytes(b'changed inventory')
        refuse('InventoryChanged')
        unknown.unlink()
        assert journal() is None and specimen.read_bytes() == original

        with db:
            db.execute("""CREATE TRIGGER interrupt_before_removing BEFORE UPDATE OF phase ON hosted_erasure_maildir_steps
                          WHEN NEW.phase='removing' BEGIN SELECT RAISE(ABORT,'interrupted after rename'); END""")
        refuse('StepFailed')
        nonce, phase, completion = journal()
        assert (phase, completion) == ('planned', None)
        staged = root / f'.hosted-erasure-{start_id}-{nonce}'
        staged_specimen = staged / specimen.relative_to(owned)
        assert not owned.exists() and staged_specimen.read_bytes() == original
        with db:
            db.execute('DROP TRIGGER interrupt_before_removing')

        same_name = root / '.fixture-original-staged'
        staged.rename(same_name)
        staged.mkdir()
        (staged / 'other-message').write_text('unrelated directory')
        refuse('ErasureDirectoryChanged')
        assert (staged / 'other-message').read_text() == 'unrelated directory'
        (staged / 'other-message').unlink()
        staged.rmdir()
        same_name.rename(staged)

        link = staged / 'unexpected-link'
        link.symlink_to(peer_file)
        refuse('InventoryUnresolved')
        assert journal() == (nonce, 'removing', None)
        assert link.is_symlink() and staged_specimen.read_bytes() == original and peer_file.read_bytes() == independent
        link.unlink()

        with db:
            db.execute("""CREATE TRIGGER interrupt_after_removing BEFORE INSERT ON audit_log
                          WHEN NEW.action='hosted.erasure.maildir.removed'
                          BEGIN SELECT RAISE(ABORT,'interrupted after unlink'); END""")
        refuse('StepFailed')
        assert not staged.exists() and not owned.exists()
        assert journal() == (nonce, 'removing', None)
        with db:
            db.execute('DROP TRIGGER interrupt_after_removing')

        # The shared writer lock may make one concurrent operator retry.
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(lambda _: erase(), range(2)))
        successes = [json.loads(result.stdout) for result in replies if result.returncode == 0]
        assert successes and all(result.returncode == 0 or 'MaildirWriterActive' in result.stderr for result in replies), replies
        result = erase()
        assert result.returncode == 0, result.stderr
        receipt = json.loads(result.stdout)
        assert all(row == receipt for row in successes), successes
        assert receipt == {
            'version': 1, 'state': 'maildir_removed_other_stores_pending', 'mailbox': mailbox,
            'request_id': review['request_id'], 'start_audit_id': start_id, 'audit_id': receipt['audit_id'],
        }, receipt
        assert journal() == (nonce, 'complete', receipt['audit_id'])
        assert db.execute("SELECT id FROM audit_log WHERE action='hosted.erasure.maildir.removed'").fetchall() == [(receipt['audit_id'],)]
        assert db.execute('SELECT enabled FROM users WHERE username=?', (mailbox,)).fetchone() == (0,)
        assert peer_file.read_bytes() == independent
        owned.mkdir()
        refuse('ErasureDirectoryChanged')
        owned.rmdir()

    with test.daemon():
        expect_smtp(test.deliver(mailbox, subject='Reserved address'), 550)
        expect_smtp(test.deliver(peer, subject='Unrelated delivery still works'), 250)
        assert peer_file.read_bytes() == independent and not owned.exists()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix='mail-erase-maildir-') as directory:
        verify(Fixture(args.binary.resolve(strict=True), Path(directory), staging=True))
    print('Verified offline Maildir removal, two interrupted phases, isolated scope, and one durable receipt.')
