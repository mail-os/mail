#!/usr/bin/env python3
"""Verify native EWS draft and submission scanning before any mailbox writes."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.parser import BytesParser
from pathlib import Path
import runpy
import secrets
import tempfile
from types import SimpleNamespace
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape, quoteattr


HERE = Path(__file__).resolve().parent
hosted = SimpleNamespace(**runpy.run_path(str(HERE / "test-hosted-limits.py")))
clamav = SimpleNamespace(**runpy.run_path(str(HERE / "test-smtp-clamav.py")))
intake = SimpleNamespace(**runpy.run_path(str(HERE / "test-client-intake-clamav.py")))
CLEAN = b"Known clean EWS attachment data"
VIRUS = "ErrorVirusDetected"
BUSY = "ErrorServerBusy"
TOO_BIG = "ErrorMessageSizeExceeded"


def check(test, owner, request, *codes):
    response = test.ews(owner, request)
    assert hosted.ews_codes(response) == list(codes), (request[:160], response)
    return ET.fromstring(response[2])


def file_xml(data, name="sample.txt"):
    encoded = base64.b64encode(data).decode()
    wrapped = "\n ".join(encoded[index:index + 32] for index in range(0, len(encoded), 32))
    return (f"<t:FileAttachment><t:Name>{escape(name)}</t:Name>"
            f"<t:ContentType>application/octet-stream</t:ContentType>"
            f"<t:Content>{wrapped}</t:Content></t:FileAttachment>")


def message(to, *files, subject="EWS scanner fixture", bcc=None):
    return (f"<t:Message><t:Subject>{escape(subject)}</t:Subject>"
            "<t:Body BodyType='Text'>Original EWS body</t:Body>"
            f"<t:ToRecipients><t:Mailbox><t:EmailAddress>{escape(to)}</t:EmailAddress></t:Mailbox></t:ToRecipients>"
            + (f"<t:BccRecipients><t:Mailbox><t:EmailAddress>{escape(bcc)}</t:EmailAddress></t:Mailbox></t:BccRecipients>" if bcc else "")
            + (f"<t:Attachments>{''.join(files)}</t:Attachments>" if files else "")
            + "</t:Message>")


def mime_message(raw):
    return f"<t:Message><t:MimeContent>{base64.b64encode(raw).decode()}</t:MimeContent></t:Message>"


def create(disposition, *items):
    return f"<m:CreateItem MessageDisposition={quoteattr(disposition)}><m:Items>{''.join(items)}</m:Items></m:CreateItem>"


def attach(item, *files):
    return (f'<m:CreateAttachment><m:ParentItemId Id={quoteattr(item["Id"])} ChangeKey={quoteattr(item["ChangeKey"])} />'
            f"<m:Attachments>{''.join(files)}</m:Attachments></m:CreateAttachment>")


def item_id(tree):
    return tree.find(".//{*}ItemId").attrib


def get_mime(test, owner, item):
    request = f'<m:GetItem><m:ItemIds><t:ItemId Id={quoteattr(item["Id"])} /></m:ItemIds></m:GetItem>'
    tree = check(test, owner, request, "NoError")
    return item_id(tree), base64.b64decode(tree.findtext(".//{*}MimeContent"))


def attachments_of(raw):
    mime = BytesParser(policy=policy.SMTP).parsebytes(raw)
    attachments = [(part.get_filename(), part.get_payload(decode=True)) for part in mime.iter_attachments()]
    return mime, attachments


def original_result(test, owner, sink, size, usage):
    assert test.bytes(owner) == size and test.bytes(sink) == 0 and test.count(owner) == usage


def verify_enabled(test, owner, sink, blind, infected_id):
    infected = file_xml(clamav.EICAR, "eicar.txt")
    clean = file_xml(CLEAN, "clean.txt")
    second = file_xml(CLEAN + b" 2", "second & clean.txt")
    initial = test.bytes(owner)
    for disposition in ("SaveOnly", "SendOnly", "SendAndSaveCopy"):
        check(test, owner, create(disposition, message(sink, infected)), VIRUS)
    check(test, owner, create("SendAndSaveCopy", mime_message(intake.mime(owner, sink, clamav.EICAR))), VIRUS)
    original_result(test, owner, sink, initial, 0)

    batch = check(test, owner, create("SaveOnly", message(sink, infected), message(sink, clean, subject="Clean EWS draft", bcc=blind)),
                  VIRUS, "NoError")
    child = item_id(batch)
    assert child["Id"].startswith("drafts:")
    assert get_mime(test, owner, child)[0] == child
    before = get_mime(test, owner, child)
    assert attachments_of(before[1])[1] == [("clean.txt", CLEAN)]

    check(test, owner, attach(child, second, infected), VIRUS)
    check(test, owner, attach(child, clean.replace(base64.b64encode(CLEAN).decode()[:32], "%%%")), "ErrorInvalidPropertyValue")
    check(test, owner, attach(child, "<t:ItemAttachment><t:Name>Nested</t:Name></t:ItemAttachment>"), "ErrorInvalidOperation")
    check(test, sink, attach(child, second), "ErrorItemNotFound")
    assert get_mime(test, owner, child) == before
    assert test.count(owner) == 0

    updated = check(test, owner, attach(child, second), "NoError")
    marker = updated.find(".//{*}AttachmentId").attrib
    assert marker["RootItemId"] == child["Id"] and marker["RootItemChangeKey"] != child["ChangeKey"]
    key, after = get_mime(test, owner, child)
    assert key["ChangeKey"] == marker["RootItemChangeKey"]
    assert attachments_of(after)[1] == [("clean.txt", CLEAN), ("second & clean.txt", CLEAN + b" 2")]
    check(test, owner, attach(child, second), "ErrorIrresolvableConflict")
    assert get_mime(test, owner, child) == (key, after)

    def add_contender(number):
        attachment = file_xml(CLEAN, f"concurrent-{number}.txt")
        return hosted.ews_codes(test.ews(owner, attach(key, attachment)))[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(add_contender, (1, 2))) == ["ErrorIrresolvableConflict", "NoError"]
    key, after_race = get_mime(test, owner, child)
    _, after_files = attachments_of(after_race)
    assert after_files[:2] == [("clean.txt", CLEAN), ("second & clean.txt", CLEAN + b" 2")]
    assert len(after_files) == 3 and after_files[2][0].startswith("concurrent-")

    check(test, owner, hosted.send_ews_items(infected_id["Id"], child["Id"]), VIRUS, "NoError")
    assert test.count(owner) == 2 and test.bytes(sink) > 0 and test.bytes(blind) > 0
    check(test, owner, create("SendAndSaveCopy", message(sink, clean, subject="Direct clean EWS mail")), "NoError")
    imported = item_id(check(test, owner, create("SaveOnly", mime_message(intake.mime(blind, sink, CLEAN))), "NoError"))
    wire, files = attachments_of(get_mime(test, owner, imported)[1])
    assert wire["From"] == owner and files == [("intake.txt", CLEAN)]
    assert test.count(owner) == 3

    # EWS must not replace the MIME underneath a revisioned webmail draft.
    session = test.login(owner)
    status, draft = test.api(session, "drafts", {"draftId": secrets.token_hex(16), "subject": "Webmail-owned scan test", "to": [sink]})
    assert status == 200, draft
    saved, = (test.directory / "mail" / owner / "Drafts").glob("*.eml:2,DS")
    webmail_file = saved.read_bytes()
    webmail_item = {"Id": "drafts:" + saved.name.split(":2,", 1)[0], "ChangeKey": "ck0"}
    check(test, owner, attach(webmail_item, second), "ErrorInvalidOperation")
    assert saved.read_bytes() == webmail_file
    return key


def verify_size(test, owner, sink, limit):
    headers = f"From: {owner}\r\nTo: {sink}\r\nSubject: Scanner boundary\r\n\r\n".encode()
    raw = headers + b"x" * (limit - len(headers) - 2) + b"\r\n"
    exact = item_id(check(test, owner, create("SaveOnly", mime_message(raw)), "NoError"))
    assert get_mime(test, owner, exact)[1] == raw
    used = test.count(owner)
    before = test.bytes(owner)
    over = raw[:-2] + b"x\r\n"
    for disposition in ("SaveOnly", "SendAndSaveCopy"):
        check(test, owner, create(disposition, mime_message(over)), TOO_BIG)
    # The decoded attachment is small enough, but the final updated draft is not.
    check(test, owner, attach(exact, file_xml(CLEAN)), TOO_BIG)
    assert get_mime(test, owner, exact)[1] == raw
    assert test.bytes(owner) == before and test.count(owner) == used


def verify_outage(test, owner, sink, item):
    before = test.bytes(owner)
    used = test.count(owner)
    check(test, owner, create("SaveOnly", message(sink)), BUSY)
    check(test, owner, create("SendAndSaveCopy", message(sink, file_xml(CLEAN))), BUSY)
    check(test, owner, attach(item, file_xml(CLEAN)), BUSY)
    check(test, owner, hosted.send_ews_items(item["Id"]), BUSY)
    assert test.bytes(owner) == before and test.count(owner) == used
    return used


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--clamd", type=Path)
    parser.add_argument("--database", type=Path, default=Path("/var/lib/clamav"))
    args = parser.parse_args()
    executable = args.clamd.resolve(strict=True) if args.clamd else None
    signatures = args.database.resolve()
    with tempfile.TemporaryDirectory(prefix="mail-ews-scan-", dir="/tmp") as directory:
        root = Path(directory)
        scanner_dir = root / "scanner"
        scanner_dir.mkdir()
        endpoint = scanner_dir / "scanner.sock"
        test = hosted.Fixture(args.binary.resolve(strict=True), root, staging=True)
        with test.daemon():
            owner = test.provision("ews-scan-owner")
            sink = test.provision("ews-scan-sink")
            blind = test.provision("ews-scan-blind")
            # An already-stored draft must be rescanned at SendItem.
            infected = item_id(check(test, owner, create("SaveOnly", message(sink, file_xml(clamav.EICAR))), "NoError"))
        test.env.update(SMTP_CLAMAV_TRANSPORT=f"unix:{endpoint}", SMTP_CLAMAV_FAIL_MODE="closed")
        with test.daemon():
            with clamav.scanner(scanner_dir, executable, signatures):
                draft = verify_enabled(test, owner, sink, blind, infected)
            endpoint.unlink(missing_ok=True)
            used = verify_outage(test, owner, sink, draft)
            with clamav.scanner(scanner_dir, executable, signatures):
                check(test, owner, attach(draft, file_xml(CLEAN, "after-outage.txt")), "NoError")
                check(test, owner, hosted.send_ews_items(draft["Id"]), "NoError")
                assert test.count(owner) == used + 2
        endpoint.unlink(missing_ok=True)
        print("Verified EWS mail and file intake, batch results, and recovery from a scanner outage without restarting Mail.")
        test.env["SMTP_CLAMAV_MAX_STREAM_BYTES"] = "1024"
        with clamav.scanner(scanner_dir, executable, signatures), test.daemon():
            verify_size(test, owner, sink, 1024)
        print("Verified the exact EWS scan-size boundary and rejection one byte over without a write or debit.")


if __name__ == "__main__":
    main()
