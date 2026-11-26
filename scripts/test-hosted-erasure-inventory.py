#!/usr/bin/env python3
"""Verify a private retained-store inventory with two real hosted mailboxes."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import runpy
import sqlite3
from tempfile import TemporaryDirectory
import time

scripts = Path(__file__).resolve().parent
operator = runpy.run_path(str(scripts / 'test-hosted-operator.py'))
portable = runpy.run_path(str(scripts / 'test-mailbox-export.py'))
Fixture, cli, expect_smtp = (operator[key] for key in ('Fixture', 'cli', 'expect_smtp'))
DavClient, put_dav, EVENT, CARD, command = (portable[key] for key in ('DavClient', 'put_dav', 'EVENT', 'CARD', 'command'))


def verify(test, db):
    mailbox = test.provision('inventory-owner')
    peer = test.provision('inventory-peer')
    for user, volume in ((mailbox, 1), (peer, 4)):
        for n in range(volume):
            expect_smtp(test.deliver(user, subject=f'Private fixture {n}'), 250)
        client = DavClient(test, user)
        label = 'Inventory' if user == mailbox else 'Unrelated'
        put_dav(client, f'/calendars/{user}/{label}/item.ics', 'text/calendar', EVENT)
        put_dav(client, f'/addressbooks/{user}/{label}/item.vcf', 'text/vcard', CARD)

    command(test, 'team', 'create', 'inventory-share', 'Fixture team', mailbox)
    command(test, 'team', 'member', 'inventory-share', peer, 'member')
    command(test, 'team', 'grant', 'inventory-share', mailbox, peer, 'mailbox')
    command(test, 'team', 'create', 'inventory-peer-only', 'Unrelated team', peer)
    owner_id, peer_id = (db.execute('SELECT id FROM users WHERE username=?', (user,)).fetchone()[0]
                         for user in (mailbox, peer))
    with db:
        db.execute('CREATE TABLE retained_unreviewed_fixture(user_id INTEGER NOT NULL)')
        db.execute('INSERT INTO retained_unreviewed_fixture VALUES(?)', (owner_id,))
        db.executemany("""INSERT INTO mail_file_links(user_id,id,token_hash,filename,data,size,expires_at)
                          VALUES(?,?,?,?,X'51',1,?)""",
                       [(uid, f'link-{n}', f'token-{uid}-{n}', 'private-link.bin', int(time.time()) + 900)
                        for uid, n in [(owner_id, 1), (peer_id, 1), (peer_id, 2)]])

    maildir = test.directory / 'mail'
    owner_root = maildir / mailbox
    peer_file = next((maildir / peer / 'new').glob('*.eml'))
    (owner_root / 'linked-peer.eml').symlink_to(peer_file)
    (maildir / mailbox.split('@')[0]).mkdir()
    fixture_bytes = sum(p.stat().st_size for p in owner_root.rglob('*') if p.is_file() and not p.is_symlink())
    fixture_files = sum(1 for p in owner_root.rglob('*') if p.is_file() and not p.is_symlink())
    assignment = test.specs[mailbox]['actor']
    case = 'retained-mailbox-review'

    def run(user=mailbox, actor=assignment, *, env=None):
        return cli(test, 'hosted-erasure-inventory', user, actor, case, env=env)

    def report(**env_overrides):
        result = run(env=dict(test.env, **env_overrides))
        assert result.returncode == 0, result.stderr
        assert all(value not in result.stdout for value in (peer, assignment, 'private-link.bin', 'Private fixture'))
        return json.loads(result.stdout)

    wrong = run(mailbox, test.specs[peer]['actor'])
    assert wrong.returncode and not wrong.stdout and 'ManagedMailboxNotFound' in wrong.stderr, wrong
    wrong = run(peer, assignment)
    assert wrong.returncode and not wrong.stdout and 'ManagedMailboxNotFound' in wrong.stderr, wrong
    current = report()
    inventory = current['inventory']
    assert current['mailbox'] == mailbox and current['case_reference'] == case
    assert inventory['identity']['native_user_id'] == owner_id
    assert inventory['maildir'] == {'state': 'observed', 'legacy_short_name_present': True,
                                  'counts': {'files': fixture_files, 'bytes': fixture_bytes, 'symbolic_links': 1, 'other_entries': 0}}
    counts = {row['table']: row['matching_rows'] for row in inventory['sqlite']['tables']}
    present = {name for (name,) in db.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
    assert not {table for table, count in counts.items() if table in present and count is None}, counts
    assert counts['mail_file_links'] == 1 and counts['mail_team_grants'] == 1 and counts['mail_team_members'] == 1, counts
    assert counts['accepted_mail_targets'] >= 1 and counts['mail_calendar_tasks'] == 0
    assert 'retained_unreviewed_fixture' in inventory['sqlite']['unscoped_tables']
    assert inventory['dav']['state'] == 'mapped' and inventory['dav']['legacy_name_candidates'] == 0
    dav = {row['table']: row['matching_rows'] for row in inventory['dav']['tables']}
    assert dav['dav_events'] == dav['dav_contacts'] == 1, dav
    assert {'search_provider', 'backup_catalog', 'hosted_billing', 'support_and_retention'} == set(inventory['external_evidence_required'])
    action, who, target, details = db.execute('SELECT action,actor,target,details FROM audit_log WHERE id=?', (current['audit_id'],)).fetchone()
    assert (action, who, target) == ('hosted.erasure.inventory', f'local-operator:{os.geteuid()}', mailbox)
    assert json.loads(details) == {'case_reference': case, 'inventory': inventory}

    missing = test.directory / 'no-dav.sqlite'
    absent = report(CALDAV_DB_PATH=str(missing), MAIL_ROOT=str(test.directory / 'no-maildir'))['inventory']
    assert absent['dav']['state'] == 'missing' and not missing.exists()
    assert absent['maildir']['state'] == 'absent' and absent['maildir']['counts'] is None
    old_dav = test.directory / 'unmapped-dav.sqlite'
    with closing(sqlite3.connect(old_dav)) as old, old:
        old.execute('CREATE TABLE dav_users(id INTEGER PRIMARY KEY, username TEXT NOT NULL)')
        old.execute('INSERT INTO dav_users(username) VALUES (?)', (mailbox.split('@')[0],))
    legacy = report(CALDAV_DB_PATH=str(old_dav))['inventory']['dav']
    assert legacy == {'state': 'legacy_owner_unresolved', 'legacy_name_candidates': 1, 'tables': [],
                      'store_stamp': None, 'owner_id': None}
    with closing(sqlite3.connect(old_dav)) as old:
        assert 'mailbox_id' not in [col[1] for col in old.execute('PRAGMA table_info(dav_users)')]

    old_smtp = test.directory / 'legacy-review.sqlite'
    with closing(sqlite3.connect(old_smtp)) as old:
        db.backup(old)
        with old:
            old.execute('DROP TABLE webmail_uploads')
    earlier = report(SMTP_DB_PATH=str(old_smtp))['inventory']
    assert earlier['identity'] == inventory['identity']
    assert next(row for row in earlier['sqlite']['tables'] if row['table'] == 'webmail_uploads')['matching_rows'] is None
    with closing(sqlite3.connect(old_smtp)) as old:
        assert not old.execute("SELECT 1 FROM sqlite_schema WHERE name='webmail_uploads'").fetchone()

    with db:
        db.execute("""CREATE TRIGGER deny_inventory BEFORE INSERT ON audit_log
                      WHEN NEW.action='hosted.erasure.inventory' BEGIN SELECT RAISE(ABORT,'fixture'); END""")
    denied = run()
    assert denied.returncode and not denied.stdout, denied
    assert peer_file.exists() and owner_root.exists()
    print('Verified mailbox-scoped filesystem, SQLite and DAV inventory, unresolved stores, old snapshots, and audit refusal.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix='mail-erasure-inventory-') as directory:
        root = Path(directory)
        test = Fixture(args.binary.resolve(strict=True), root, staging=True)
        with test.daemon(), closing(sqlite3.connect(root / 'smtp.db')) as db:
            verify(test, db)
