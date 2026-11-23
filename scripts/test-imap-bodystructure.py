#!/usr/bin/env python3
"""Check real IMAP BODYSTRUCTURE and section bytes through STARTTLS."""

import argparse
from base64 import b64decode
from pathlib import Path
import re
import runpy
import tempfile

Fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))["Fixture"]

PLAIN = (b"Plain rendering", b"Second line")
HTML = b"<p>HTML rendering</p>"
ENCODED = b"AAEC/w=="
BINARY_HEADERS = (
    b"cOnTeNt-tYpE: application/octet-stream; name=sample.bin",
    b"Content-Disposition: attachment;",
    b" filename*=utf-8''sample%2Ebin",
    b"Content-Transfer-Encoding: base64",
    b"Content-ID: <asset@example.test>",
    b'Content-Description: A "binary" file',
)
EMBEDDED_HEADERS = (
    b'From: "Ada, Jr." <ada@example.test>',
    b"To: Reviewers: Chris <chris@example.test>, Dana <dana@example.test>;",
    b"Subject: Attached message",
    b"Message-ID: <embedded@example.test>",
    b"Content-Type: text/plain",
)
EMBEDDED_BODY = b"Attached body"
NESTED = (
    b"From: Alex <alex@example.test>",
    b"To: Reader <reader@example.test>",
    b"Subject: Nested MIME fixture",
    b"MIME-Version: 1.0",
    b'Content-Type: multipart/mixed; boundary="outer"',
    b"",
    b"--outer",
    b"Content-Type: multipart/alternative; boundary=inner",
    b"",
    b"--inner",
    b"Content-Type: text/plain; charset=utf-8",
    b"",
    *PLAIN,
    b"--inner",
    b"Content-Type: text/html; charset=utf-8",
    b"",
    HTML,
    b"--inner--",
    b"--outer",
    *BINARY_HEADERS,
    b"",
    ENCODED,
    b"--outer",
    b"Content-Type: message/rfc822",
    b"Content-Disposition: attachment; filename=forwarded.eml",
    b"",
    *EMBEDDED_HEADERS,
    b"",
    EMBEDDED_BODY,
    b"--outer--",
)


def fetch(client, uid, items):
    status, data = client.uid("FETCH", uid, items)
    assert status == "OK", (status, data)
    return data


def append(client, raw):
    # imaplib.append canonicalizes bare LF. Send a literal to exercise exact
    # storage of both imported LF and canonical CRLF messages.
    client.literal = raw
    status, data = client._simple_command("APPEND", "INBOX")
    assert status == "OK", data
    assert client.select("INBOX")[0] == "OK"
    status, ids = client.uid("SEARCH", "ALL")
    assert status == "OK", ids
    return ids[0].split()[-1]


def sections(data):
    out = {}
    for item in data:
        if isinstance(item, tuple):
            label = re.search(rb"(BODY\[[^\]]*\](?:<\d+>)?) \{\d+\}$", item[0])
            assert label, item[0]
            out[label.group(1)] = item[1]
    return out


def expected_structure(ending, embedded):
    plain_size = len(ending.join(PLAIN))
    structure = (
        b'(('
        + b'("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" %d 1 NIL NIL NIL NIL)' % plain_size
        + b'("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "7BIT" %d 0 NIL NIL NIL NIL)' % len(HTML)
        + b' "ALTERNATIVE" ("BOUNDARY" "inner") NIL NIL NIL)'
        + b'("APPLICATION" "OCTET-STREAM" ("NAME" "sample.bin") "<asset@example.test>" '
        + rb'"A \"binary\" file" "BASE64" 8 NIL ("ATTACHMENT" ("FILENAME" "sample.bin")) NIL NIL)'
        + b'("MESSAGE" "RFC822" NIL NIL NIL "7BIT" %d ' % len(embedded)
        + b'(NIL "Attached message" (("Ada, Jr." NIL "ada" "example.test")) '
        + b'(("Ada, Jr." NIL "ada" "example.test")) (("Ada, Jr." NIL "ada" "example.test")) '
        + b'((NIL NIL "Reviewers" NIL)("Chris" NIL "chris" "example.test")'
        + b'("Dana" NIL "dana" "example.test")(NIL NIL NIL NIL)) NIL NIL NIL "<embedded@example.test>") '
        + b'("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" %d 0 NIL NIL NIL NIL)' % len(EMBEDDED_BODY)
        + b' %d NIL ("ATTACHMENT" ("FILENAME" "forwarded.eml")) NIL NIL)' % embedded.count(b"\n")
        + b' "MIXED" ("BOUNDARY" "outer") NIL NIL NIL)'
    )
    return structure


def verify_nested(client, ending):
    raw = ending.join(NESTED)
    embedded = ending.join((*EMBEDDED_HEADERS, b"", EMBEDDED_BODY))
    uid = append(client, raw)
    response = fetch(client, uid, "(BODYSTRUCTURE)")[0]
    actual = response.split(b" BODYSTRUCTURE ", 1)[1][:-1]
    assert actual == expected_structure(ending, embedded), (actual, expected_structure(ending, embedded))
    response = fetch(
        client, uid, "(BODY.PEEK[1.1] BODY.PEEK[1.2] BODY.PEEK[2]<2.3> BODY.PEEK[2]"
        " BODY.PEEK[2.MIME] BODY.PEEK[3] BODY.PEEK[3.HEADER] BODY.PEEK[3.TEXT]"
        " BODY.PEEK[3.HEADER.FIELDS (SUBJECT)] BODY.PEEK[3.1] BODY.PEEK[99])",
    )
    assert sections(response) == {
        b"BODY[1.1]": ending.join(PLAIN),
        b"BODY[1.2]": HTML,
        b"BODY[2]<2>": ENCODED[2:5],
        b"BODY[2]": ENCODED,
        b"BODY[2.MIME]": ending.join((*BINARY_HEADERS, b"", b"")),
        b"BODY[3]": embedded,
        b"BODY[3.HEADER]": ending.join((*EMBEDDED_HEADERS, b"", b"")),
        b"BODY[3.TEXT]": EMBEDDED_BODY,
        b"BODY[3.HEADER.FIELDS (SUBJECT)]": b"Subject: Attached message" + ending + b"\r\n",
        b"BODY[3.1]": EMBEDDED_BODY,
    }, response
    assert b"BODY[99] NIL" in response[-1], response
    attachment = b64decode(sections(response)[b"BODY[2]"], validate=True)
    assert attachment == b"\x00\x01\x02\xff", attachment
    assert b"\\Seen" not in fetch(client, uid, "(FLAGS)")[0]
    response = fetch(client, uid, "(BODY.PEEK[1.2] BODY[2])")
    assert b"\\Seen" in response[0][0], response


def verify_limit(client, raw):
    header, body = raw.split(b"\n\n", 1)
    uid = append(client, raw)
    response = fetch(client, uid, "(BODYSTRUCTURE BODY.PEEK[1] BODY.PEEK[2])")
    expected = b'("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" %d %d NIL NIL NIL NIL)' % (
        len(body), body.count(b"\n"),
    )
    assert b" BODYSTRUCTURE " + expected in response[0][0], response[0][0]
    assert sections(response) == {b"BODY[1]": body}
    assert b"BODY[2] NIL" in response[-1], response[-1]
    assert sections(fetch(client, uid, "(BODY.PEEK[HEADER])"))[b"BODY[HEADER]"] == header + b"\n\n"


def verify_empty_section(client):
    raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n--b--"
    uid = append(client, raw)
    assert sections(fetch(client, uid, "(BODY.PEEK[1.MIME] BODY.PEEK[1])")) == {
        b"BODY[1.MIME]": b"Content-Type: text/plain\r\n\r\n",
        b"BODY[1]": b"",
    }


def verify_utf8_filename(client):
    raw = (b"Content-Type: application/octet-stream\r\n"
           b"Content-Disposition: attachment; filename*=utf-8''caf%C3%A9.bin\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\n" + ENCODED)
    uid = append(client, raw)
    structure = fetch(client, uid, "(BODYSTRUCTURE)")
    assert structure[0][0].endswith(b'("ATTACHMENT" ("FILENAME" {9}'), structure
    assert structure[0][1] == "café.bin".encode(), structure
    assert sections(fetch(client, uid, "(BODY.PEEK[1])"))[b"BODY[1]"] == ENCODED


def run(binary):
    with tempfile.TemporaryDirectory(prefix="mail-imap-bodystructure-") as directory:
        fixture = Fixture(binary, Path(directory), staging=True)
        with fixture.daemon():
            recipient = fixture.provision("reader")
            with fixture.imap(recipient) as client:
                for ending in (b"\r\n", b"\n"):
                    verify_nested(client, ending)
                verify_empty_section(client)
                verify_utf8_filename(client)
                opening = [f"Content-Type: multipart/mixed; boundary=b{n}\n\n--b{n}\n".encode() for n in range(12)]
                closing = [f"\n--b{n}--".encode() for n in reversed(range(12))]
                verify_limit(client, b"".join(opening) + b"\nhello" + b"".join(closing))
                verify_limit(client, b"Content-Type: multipart/mixed; boundary=b\n\n" + b"--b\n\nx\n" * 10_000 + b"--b--")
    print("Verified nested BODYSTRUCTURE, listed attachments, raw CRLF and LF sections, partial fetches, flags, and MIME limits.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    run(parser.parse_args().binary.resolve())
