#!/usr/bin/env python3
"""Exercise storage alert classification through real staged SMTP intake."""

from contextlib import closing
import json
from pathlib import Path
import runpy
import sqlite3
import subprocess
import sys
import tempfile
from unittest.mock import patch


scripts = Path(__file__).parent
fixture = runpy.run_path(str(scripts / 'test-hosted-limits.py'))
watchdog = runpy.run_path(str(scripts / 'mail-health-watch.py'))


def storage_check(lines):
    # Feed the daemon's actual log lines through the watchdog's journal reader
    # without depending on systemd on the test runner.
    journal = ''.join(json.dumps({'__CURSOR': str(index), 'MESSAGE': line}) + '\n'
                      for index, line in enumerate(lines)).encode()
    result = subprocess.CompletedProcess([], 0, journal)
    with patch.object(subprocess, 'run', return_value=result):
        return next(check for check in watchdog['journal_checks']({}, 1000)
                    if check['name'] == 'Storage failures')


def verify(binary):
    expect_smtp = fixture['expect_smtp']
    with tempfile.TemporaryDirectory(prefix='mail-storage-alerts-') as directory:
        test = fixture['Fixture'](binary, Path(directory), staging=True)
        with test.daemon():
            log, = test.directory.glob('mail-*.log')
            sink = test.provision('sink')
            full = test.provision('full', quota=1)
            expect_smtp(test.deliver(full), 452, '4.2.2')
            expect_smtp(test.deliver(full, chunked=True), 452, '4.2.2')
            sender = test.provision('sender', daily=1)
            expect_smtp(test.deliver(sink, identity=sender), 250)
            expect_smtp(test.deliver(sink, identity=sender), 452, '4.7.0')

            paused = test.provision('paused')
            with test.smtp() as smtp:
                expect_smtp(smtp.mail(fixture['EXTERNAL']), 250)
                expect_smtp(smtp.rcpt(paused), 250)
                test.provision('paused', enabled=False)
                expect_smtp(smtp.data(b'Subject: Suspension\r\n\r\nFixture message\r\n'), 550, '5.2.1')

            lines = log.read_text().splitlines()
            check = storage_check(lines)
            assert check['ok'] and check['count'] == 0, check
            for rejection in ('HostedStorageFull', 'HostedSendingLimit', 'HostedRecipientDisabled'):
                assert any(f'SMTP message refused by mailbox policy: error.{rejection}' in line for line in lines), rejection

            # Abort the real delivery journal insert in the fixture database.
            with closing(sqlite3.connect(test.directory / 'smtp.db')) as db:
                db.execute("""CREATE TRIGGER fail_mail_storage BEFORE INSERT ON accepted_mail
                              BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END""")
            expect_smtp(test.deliver(sink), 451, '4.3.0')
            check = storage_check(log.read_text().splitlines()[len(lines):])
            assert not check['ok'] and check['count'] == 1, check

    print('SMTP quota and suspension refusals kept storage health clear. An injected delivery-journal failure raised one alert.')


if __name__ == '__main__':
    verify(Path(sys.argv[1]).resolve(strict=True))
