#!/usr/bin/env python3
"""Verify the Mail delivery page in browsers with a disposable native HTTPS mailbox."""

import argparse
import os
from pathlib import Path
import runpy
import subprocess
import tempfile


SCRIPTS = Path(__file__).resolve().parent
Fixture = runpy.run_path(str(SCRIPTS / "test-hosted-limits.py"))["Fixture"]
ENGINES = ("chromium", "firefox", "webkit")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("screenshots", type=Path)
    parser.add_argument("--engine", choices=ENGINES, action="append")
    args = parser.parse_args()
    for engine in args.engine or ENGINES:
        with tempfile.TemporaryDirectory(prefix="mail-status-") as directory:
            fixture = Fixture(args.binary.resolve(strict=True), Path(directory), staging=True)
            with fixture.daemon():
                owner = fixture.provision("delivery")
                env = dict(os.environ, MAIL_STATUS_URL=fixture.webmail, MAIL_STATUS_OWNER=owner,
                           MAIL_STATUS_PASSWORD=fixture.password, MAIL_STATUS_DB=fixture.env["SMTP_DB_PATH"])
                subprocess.run(["node", str(SCRIPTS / "webmail-status-browser.mjs"), engine,
                                str(args.screenshots.resolve() / engine)], env=env, check=True)


if __name__ == "__main__":
    main()
