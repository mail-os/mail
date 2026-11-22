#!/usr/bin/env python3
"""Exercise the same contact resources through CardDAV and native webmail."""

import base64
import json
from pathlib import Path
import runpy
import secrets
import sys
import tempfile
from urllib.parse import quote, urlencode
from xml.etree import ElementTree


fixtures = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture, request = fixtures["Fixture"], fixtures["request"]
DAV = {"d": "DAV:"}
NOTE = "Line one, then; line two.\n" + "東京の住所 " * 12
IMPORTED = ("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:external-id\r\nFN:Morgan Lee\r\n"
            "N:Lee;Morgan;;;\r\nitem1.EMAIL;TYPE=WORK;PREF=1:morgan@example.test\r\n"
            "TEL;TYPE=HOME:+12025550175\r\nX-CLIENT;X-ID=\"uri:retained\":Details\r\n"
            "NOTE:Imported\\nfrom desktop\r\nEND:VCARD\r\n").encode()


def run(binary):
    with tempfile.TemporaryDirectory(prefix="mail-webmail-contacts-") as tmp:
        fixture = Fixture(binary, Path(tmp), staging=True)

        def web(session, path, payload=None, *, method=None, expected=200, etag=None):
            headers = dict(session)
            if etag is not None:
                headers["If-Match"] = etag
            location = "/webmail/api/" + path if not path.startswith("/") else path
            code, incoming, raw = request(fixture.webmail + location, payload, headers, method, fixture.tls_context)
            assert code == expected, (method, path, code, raw)
            return incoming, json.loads(raw) if raw else None

        def dav(user, resource="", *, method="GET", data=None, expected=200, etag=None, book="contacts", **extra):
            credentials = base64.b64encode(f"{user}:{fixture.password}".encode()).decode()
            headers = {"Authorization": "Basic " + credentials, "Content-Type": "text/vcard", **extra}
            if etag is not None:
                headers["If-Match"] = etag
            endpoint = fixture.ews_url.rsplit("/EWS/", 1)[0]
            path = f"/addressbooks/{quote(user, safe='')}/{quote(book, safe='')}/{resource}"
            code, incoming, raw = request(endpoint + path, data, headers, method, fixture.tls_context)
            assert code == expected, (method, path, code, raw)
            return incoming, raw

        def sync(user, token=""):
            body = (f'<d:sync-collection xmlns:d="DAV:"><d:sync-token>{token}</d:sync-token>'
                    '<d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>').encode()
            _, raw = dav(user, method="REPORT", data=body, expected=207, Depth="0", **{"Content-Type": "text/xml"})
            doc = ElementTree.fromstring(raw)
            rows = [(entry.findtext("d:href", namespaces=DAV), entry.findtext("d:propstat/d:prop/d:getetag", namespaces=DAV))
                    for entry in doc.findall("d:response", DAV)]
            return doc.findtext("d:sync-token", namespaces=DAV), rows

        def card_path(uid, book="contacts"):
            return "address-book?" + urlencode({"book": book, "uid": uid})

        def cards(session, book="contacts"):
            return {card["uid"]: card for card in web(session, "address-book?" + urlencode({"book": book}))[1]["cards"]}

        with fixture.daemon():
            alice, bob = (fixture.provision(name) for name in ("alice", "bob"))
            owner, other = fixture.login(alice), fixture.login(bob)
            assert web(owner, "address-book")[1] == {"books": ["contacts"], "book": "contacts", "cards": []}
            initial, _ = dav(alice, "old.vcf", method="PUT", data=IMPORTED, expected=201)
            dav(alice, "other-book.vcf", method="PUT", data=IMPORTED, expected=201, book="work")
            assert web(owner, "address-book")[1]["books"] == ["contacts", "work"]
            assert "other-book" in cards(owner, "work") and "other-book" not in cards(owner)
            token, snapshot = sync(alice)
            assert token and any(path.endswith("/old.vcf") and rev == initial["ETag"] for path, rev in snapshot)
            imported = cards(owner)["old"]
            assert imported["card_uid"] == "external-id" and imported["note"] == "Imported\nfrom desktop"
            assert imported["etag"] == initial["ETag"] and imported["emails"] == ["morgan@example.test"]

            edit = dict(kind="contact", name="Morgan Lee", note=NOTE, emails=["morgan@example.test", "morgan.home@example.test"])
            web(owner, card_path("old"), edit, method="PUT", expected=428)
            web(owner, card_path("old"), edit, method="PUT", etag='W/"weak"', expected=400)
            web({**owner, "Origin": "https://outside.example.test"}, card_path("old"), edit,
                method="PUT", etag=imported["etag"], expected=403)
            web(other, card_path("old"), edit, method="PUT", etag=imported["etag"], expected=404)
            web(owner, card_path("old", "work"), edit, method="PUT", etag=imported["etag"], expected=404)
            changed, result = web(owner, card_path("old"), edit, method="PUT", etag=imported["etag"])
            assert changed["ETag"] == result["etag"] != imported["etag"]
            wire, raw = dav(alice, "old.vcf")
            assert wire["ETag"] == changed["ETag"]
            for line in (b"item1.EMAIL;TYPE=WORK;PREF=1:morgan@example.test", b"TEL;TYPE=HOME:+12025550175",
                         b'X-CLIENT;X-ID="uri:retained":Details', b"NOTE:Line one\\, then\\; line two.\\n"):
                assert line in raw, (line, raw)
            assert all(len(line) <= 75 for line in raw.splitlines())
            raw.decode("utf-8")
            assert cards(owner)["old"]["note"] == NOTE
            next_token, changes = sync(alice, token)
            assert next_token != token and any(path.endswith("/old.vcf") and rev == changed["ETag"] for path, rev in changes)
            dav(alice, "old.vcf", method="PUT", data=IMPORTED, etag=imported["etag"], expected=412)
            dav(alice, "old.vcf", method="PUT", data=IMPORTED.replace(b"from desktop", b"updated by CardDAV"),
                etag=wire["ETag"], expected=204)
            web(owner, card_path("old"), edit, method="PUT", etag=wire["ETag"], expected=412)
            assert cards(owner)["old"]["note"] == "Imported\nupdated by CardDAV"

            person = dict(kind="contact", name="Avery Chen", note="Additional reviewer", emails=["avery@example.test"])
            web(owner, "address-book", {**person, "emails": ["avery@example.test", "AVERY@example.test"]}, method="POST", expected=400)
            web(owner, "address-book", person, method="POST", expected=201)
            contact, = (card for card in cards(owner).values() if card["name"] == person["name"])
            suggestions = web(owner, "contacts?q=Avery")[1]
            assert suggestions == [{"address": "avery@example.test", "name": person["name"]}]
            assert web(other, "contacts?q=Avery")[1] == []
            group = dict(kind="group", name="Studio team", note="Working group", members=[contact["uid"], "old"])
            web(other, "address-book", group, method="POST", expected=400)
            web(owner, "address-book", group, method="POST", expected=201)
            team, = (card for card in cards(owner).values() if card["kind"] == "group")
            uri = "urn:uuid:" + contact["uid"]
            assert team["members"] == [uri, "mailto:morgan@example.test"]
            _, raw = dav(alice, team["uid"] + ".vcf")
            assert b"KIND:group\r\n" in raw and ("MEMBER:" + uri).encode() in raw
            assert b"UID:urn:uuid:" in raw

            legacy = ("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:legacy\r\nFN:Legacy group\r\n"
                      "X-ADDRESSBOOKSERVER-KIND:group\r\nX-ADDRESSBOOKSERVER-MEMBER:urn:uuid:external-group\r\n"
                      f"X-ADDRESSBOOKSERVER-MEMBER:{uri}\r\nEND:VCARD\r\n").encode()
            dav(alice, "legacy.vcf", method="PUT", data=legacy, expected=201)
            saved_legacy = cards(owner)["legacy"]
            web(owner, card_path("legacy"), {**group, "name": "Legacy group", "members": ["old"]},
                method="PUT", etag=saved_legacy["etag"])
            _, raw = dav(alice, "legacy.vcf")
            assert b"X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:external-group\r\n" in raw
            assert b"X-ADDRESSBOOKSERVER-MEMBER:mailto:morgan@example.test\r\n" in raw
            assert uri.encode() not in raw

            stale = {**other, "X-Webmail-Account": quote(alice, safe="")}
            saved = web(owner, "drafts", {"subject": "Account-local draft", "text": "Only Alice"}, method="POST")[1]
            assert saved["uid"] > 0
            send_id = secrets.token_hex(16)
            web(owner, "compose", {"subject": "Held mail", "text": "Cancel this", "to": [bob],
                                   "sendId": send_id, "delaySeconds": 30}, method="POST")
            for path in ("address-book", "contacts?q=Avery", "messages?folder=Drafts", "outbox"):
                assert web(stale, path, expected=409)[1]["error"] == "account_changed"
            assert web(other, "messages?folder=Drafts")[1]["items"] == []
            web(stale, card_path("old"), edit, method="PUT", etag=imported["etag"], expected=409)
            web(other, f"outbox/{send_id}", method="DELETE", expected=404)
            web(stale, f"outbox/{send_id}", method="DELETE", expected=409)
            web(stale, "/webmail/auth/logout", {}, method="POST", expected=409)
            assert cards(other) == {}  # The stale tab did not clear or invalidate Bob's session.
            assert web(owner, f"outbox/{send_id}", method="DELETE")[1]["state"] == "cancelled"

        with fixture.daemon():
            owner = fixture.login(alice)
            saved = cards(owner)
            assert saved[team["uid"]]["members"] == team["members"]
            assert saved[team["uid"]]["note"] == group["note"]
            assert saved["old"]["note"] == "Imported\nupdated by CardDAV"
            token, _ = sync(alice)
            web(owner, card_path(team["uid"]), method="DELETE", etag='"stale"', expected=412)
            web(owner, card_path(team["uid"]), method="DELETE", etag=team["etag"], expected=204)
            dav(alice, team["uid"] + ".vcf", expected=404)
            _, changes = sync(alice, token)
            assert any(path.endswith("/" + team["uid"] + ".vcf") and rev is None for path, rev in changes)
    print("Verified native webmail and CardDAV contact edits, groups, notes, sync revisions, restart, and account isolation.")


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve())
