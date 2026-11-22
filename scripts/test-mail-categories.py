#!/usr/bin/env python3
"""Test mail sorting against disposable native SMTP, IMAP and webmail listeners."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import re
import runpy
import sqlite3
import subprocess
import tempfile
from urllib.parse import parse_qs, urlencode, urlsplit


scripts = Path(__file__).resolve().parent
fixture = runpy.run_path(str(scripts / "test-hosted-limits.py"))
routing = runpy.run_path(str(scripts / "test-local-routing.py"))
Fixture = fixture["Fixture"]
request = fixture["request"]
expect_smtp = fixture["expect_smtp"]
eventually = routing["eventually"]


class Search(routing["EventListener"]):
    def do_GET(self):
        url = urlsplit(self.path)
        if not url.path.endswith("/documents/search"):
            return self.send_ok()
        args = parse_qs(url.query)
        terms = dict(re.findall(r"(username|mailbox):=\x60([^\x60]+)\x60", args["filter_by"][0]))
        query = args["q"][0].lower()
        with self.server.events_lock:
            docs = {doc["id"]: doc for _, doc in self.server.events}
        hits = [{"document": doc} for doc in docs.values()
                if all(doc[k] == value for k, value in terms.items()) and query in doc["subject"].lower()]
        data = json.dumps({"hits": hits, "found": len(hits)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_DELETE(self):
        # Leave stale documents in the fixture to test the Maildir join.
        return self.send_ok()


def run(candidate, previous, browser):
    with tempfile.TemporaryDirectory(prefix="mail-categories-") as tmp, routing["listener"]("127.0.0.1", Search) as search:
        root = Path(tmp)
        test = Fixture(previous or candidate, root, staging=True)
        test.env.update(TYPESENSE_API_KEY="category-test", TYPESENSE_HOST="127.0.0.1",
                        TYPESENSE_PORT=str(search.server_port))

        def sql(statement, args=()):
            with closing(sqlite3.connect(root / "smtp.db")) as db, db:
                return db.execute(statement, args).fetchall()

        def api(session, path, payload=None, method=None, expected=200, extra=None):
            status, headers, raw = request(test.webmail + "/webmail/api/" + path, payload,
                                           dict(session, **(extra or {})), method, test.tls_context)
            parsed = json.loads(raw)
            assert status == expected, (path, status, parsed)
            if expected == 200 and isinstance(parsed, dict) and "revision" in parsed and "ETag" in headers:
                assert headers["ETag"] == parsed["revision"]
            return parsed

        def messages(session, folder="INBOX", **params):
            return api(session, "messages?" + urlencode(dict(folder=folder, **params)))

        def subjects(session, folder="INBOX", **params):
            return {item["subject"]: item for item in messages(session, folder, **params)["items"]}

        def indexed(session, query, folder=None):
            params = {"q": query}
            if folder:
                params["folder"] = folder
            return {hit["folder"] for hit in api(session, "search?" + urlencode(params))["items"]}

        def send(recipient, author, subject, *, list_id=False, verified=True, display="Example sender", html=False):
            head = f"From: {display} <{author}>\r\nTo: {recipient}\r\nSubject: {subject}\r\n"
            if list_id:
                head += "List-Id: The digest\r\n <news.example.test>\r\n"
            if html:
                head += "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n"
            body = ('<p>Formatted digest</p><img src="https://tracker.example.test/pixel">'
                    '<style>p::before { content: "fixture style" }</style>'
                    if html else f"Body of {subject}.")
            with test.smtp(author if verified else None) as smtp:
                assert smtp.mail(author)[0] == smtp.rcpt(recipient)[0] == 250
                expect_smtp(smtp.data(f"{head}\r\n{body}\r\n".encode()), 250)

        def detail(session, item):
            return api(session, "messages/ref/" + item["reference"])

        def move(session, item, folder):
            return api(session, "messages/ref/" + item["reference"], {"folder": folder}, "PUT",
                       extra={"If-Match": item["revision"]})

        def rule(session, item, destination, expected=200):
            return api(session, "category-rule", {"destination": destination, "reference": item["reference"]},
                       "PUT", expected, {"If-Match": item["revision"]})

        if previous:
            with test.daemon():
                old = test.provision("old")
                old_author = test.provision("old-author")
                send(old, old_author, "Pre-upgrade digest", list_id=True)
                legacy = subjects(test.login(old))["Pre-upgrade digest"]
            test.binary = candidate

        with test.daemon():
            if previous:
                old_session = test.login(old)
                assert detail(old_session, legacy)["subject"] == "Pre-upgrade digest"
                assert detail(old_session, legacy).get("placement") is None
                assert api(old_session, "category-settings") == {"automatic": False}

            owner = test.provision("owner")
            author = test.provision("digest")
            shop = test.provision("shop")
            other = test.provision("other")
            session = test.login(owner)
            foreign = test.login(other)
            send(owner, author, "Before sorting", list_id=True)
            assert set(subjects(session)) == {"Before sorting"}
            assert not subjects(session, "Newsletters")
            assert api(session, "category-settings") == {"automatic": False}
            api(session, "category-settings", {"automatic": True}, "PUT", 403, {"Origin": "https://other.example"})
            api(session, "category-settings", {"automatic": True}, "PUT")
            assert api(foreign, "category-settings") == {"automatic": False}
            with test.imap(other) as imap:
                assert imap.create("newsletters")[0] == "OK"
                assert imap.append("newsletters", None, None,
                                   b"From: legacy@example.test\r\nSubject: Existing custom folder\r\n\r\nOriginal copy\r\n")[0] == "OK"
            copies = messages(foreign, "*", q="Existing custom folder")["items"]
            assert len(copies) == 1

            send(owner, author, "Weekly Alpha", list_id=True, html=True)
            send(owner, author, "Weekly Beta", list_id=True, display="Updated display name")
            send(owner, shop, "Shop news", list_id=True)
            send(owner, shop, "Your receipt #405", list_id=True)
            send(owner, author, "Ordinary note")
            send(owner, author, "Forged digest", list_id=True, verified=False)
            send(other, author, "Other mailbox digest", list_id=True)
            assert set(subjects(session)) == {"Before sorting", "Ordinary note", "Forged digest"}
            assert set(subjects(foreign)) == {"Other mailbox digest"}
            assert "Other mailbox digest" not in subjects(foreign, "Newsletters")
            assert set(subjects(session, "Receipts")) == {"Your receipt #405"}

            newsletters = subjects(session, "Newsletters")
            alpha = newsletters["Weekly Alpha"]
            assert detail(session, alpha)["placement"] == {
                "original_folder": "Newsletters", "reason": "mailing_list", "verified_author": author, "rule": "automatic",
            }
            receipt = subjects(session, "Receipts")["Your receipt #405"]
            assert detail(session, receipt)["placement"]["reason"] == "receipt_subject"
            assert detail(session, subjects(session)["Forged digest"]).get("placement") is None
            rule(session, subjects(session)["Forged digest"], "receipts", 409)
            rule(foreign, alpha, "receipts", 404)
            api(session, "category-rule", {"reference": alpha["reference"], "destination": "receipts"}, "PUT", 428)
            assert eventually(lambda: indexed(session, "Weekly Alpha"), bool) == {"Newsletters"}
            assert eventually(lambda: indexed(session, "Your receipt #405"), bool) == {"Receipts"}
            assert set(subjects(session, "*", q="Weekly Alpha")) == {"Weekly Alpha"}
            assert not subjects(session, "INBOX", q="Weekly Alpha")
            assert set(subjects(session, "Receipts", q="receipt #405")) == {"Your receipt #405"}
            counts = {row["name"]: (row["total"], row["unread"]) for row in api(session, "folders")}
            assert {key: counts[key] for key in ("INBOX", "Newsletters", "Receipts")} == {
                "INBOX": (3, 3), "Newsletters": (3, 3), "Receipts": (1, 1),
            }

            bundles = messages(session, "Newsletters", bundles="true")
            assert (bundles["total"], bundles["message_total"], bundles["sender_bundles"]) == (2, 3, True)
            assert sorted((group["count"], group["unread"]) for group in bundles["threads"]) == [(1, 1), (2, 2)]
            searched = messages(session, "Newsletters", bundles="true", q="Weekly Alpha")
            assert searched["total"] == searched["message_total"] == 1
            assert searched["threads"][0]["latest"]["subject"] == "Weekly Alpha"
            with test.imap(owner) as imap:
                listings = b"\n".join(imap.list()[1])
                assert b"Newsletters" in listings and b"Receipts" in listings
                assert imap.select("Newsletters") == ("OK", [b"3"])
                assert imap.uid("STORE", str(alpha["uid"]), "+FLAGS.SILENT", "(\\Seen)")[0] == "OK"
                assert imap.select("Receipts") == ("OK", [b"1"])
                assert imap.uid("COPY", str(receipt["uid"]), "Archive")[0] == "OK"
            assert "Your receipt #405" in subjects(session, "Archive")
            assert "Your receipt #405" in subjects(session, "Receipts")
            rule(session, alpha, "receipts", 412)
            alpha = detail(session, alpha)
            assert alpha["flags"]["seen"]
            unread = messages(session, "Newsletters", bundles="true", per_page=2)
            read = messages(session, "Newsletters", bundles="true", per_page=2, page=2)
            assert unread["total"] == 3 and all(group["unread"] for group in unread["threads"])
            group, = read["threads"]
            assert group["unread"] == 0 and group["latest"]["reference"] == alpha["reference"]
            assert next(row for row in api(session, "folders") if row["name"] == "Newsletters")["unread"] == 2

            moved = move(session, alpha, "Receipts")
            assert moved["reference"] == alpha["reference"]
            moved_detail = detail(session, moved)
            assert moved_detail["folder"] == "Receipts" and moved_detail["placement"]["original_folder"] == "Newsletters"
            assert moved_detail["placement"]["rule"] == "automatic"
            eventually(lambda: indexed(session, "Weekly Alpha"), lambda folders: folders == {"Receipts"})
            assert not indexed(session, "Weekly Alpha", "Newsletters")
            send(owner, author, "After one-off move", list_id=True)
            assert "After one-off move" in subjects(session, "Newsletters")

            assert rule(session, moved, "receipts") == {"destination": "receipts"}
            assert detail(session, newsletters["Weekly Beta"])["folder"] == "Newsletters"
            assert detail(session, newsletters["Weekly Beta"])["placement"]["rule"] == "receipts"
            send(owner, author, "Unverified after sender rule", list_id=True, verified=False)
            assert "Unverified after sender rule" in subjects(session)
            forward_config = root / "forwards.json"
            forward_config.write_text(json.dumps({owner: [other]}))
            send(owner, author, "Categorized forward", list_id=True)
            assert "Categorized forward" in subjects(session, "Receipts")
            assert "Categorized forward" in subjects(foreign)
            forward_config.unlink()
            send(owner, author, "Explicit override", list_id=True)
            override = subjects(session, "Receipts")["Explicit override"]
            assert detail(session, override)["placement"]["reason"] == "sender_rule"
            with test.imap(owner) as imap:
                assert imap.select("Receipts")[0] == "OK"
                assert imap.uid("MOVE", str(override["uid"]), "Archive")[0] == "OK"
            archived = detail(session, override)
            assert archived["reference"] == override["reference"] and archived["folder"] == "Archive"
            assert archived["placement"]["original_folder"] == "Receipts"
            print("Verified opt-in, trusted placement, counts, search, sender bundles, read sections, one-off moves, and IMAP.")

            # Interrupt publication with an admitted message and keep the
            # sender rule. Both must survive independently of the delivery journal.
            shelf = root / "mail" / owner / "Receipts"
            saved = shelf.with_suffix(".saved")
            shelf.rename(saved)
            shelf.write_bytes(b"fixture preventing publication")
            send(owner, author, "Pending receipt recovery", list_id=True)
            assert sql("SELECT folder,placement_reason FROM accepted_mail_targets WHERE mailbox=? AND outcome='pending'",
                       (owner,)) == [("Receipts", "sender_rule")]
            shelf.unlink()
            saved.rename(shelf)

        with test.daemon():
            session = test.login(owner)
            assert api(session, "category-settings") == {"automatic": True}
            pending = subjects(session, "Receipts")["Pending receipt recovery"]
            assert detail(session, pending)["placement"]["reason"] == "sender_rule"
            sql("DELETE FROM accepted_mail WHERE complete=1")
            assert detail(session, pending)["placement"]["rule"] == "receipts"
            send(owner, author, "Rule survived restart")
            assert "Rule survived restart" in subjects(session, "Receipts")
            api(session, "category-settings", {"automatic": False}, "PUT")
            send(owner, author, "Rule with sorting off", list_id=True)
            assert "Rule with sorting off" in subjects(session, "Receipts")
            rule(session, pending, "automatic")
            send(owner, author, "After rule cleared", list_id=True)
            assert "After rule cleared" in subjects(session)
            api(session, "category-settings", {"automatic": True}, "PUT")
            rule(session, pending, "inbox")
            send(owner, author, "Explicit inbox override", list_id=True)
            assert detail(session, subjects(session)["Explicit inbox override"])["placement"]["reason"] == "sender_rule"
            api(test.login(shop), "compose", {"to": [owner], "subject": "Your invoice #WEBMAIL", "text": "Paid."}, "POST")
            assert "Your invoice #WEBMAIL" in subjects(session, "Receipts")

            api(session, "sender-review", {"setting": "enable"}, "PUT")
            send(owner, author, "Review beats category rule", list_id=True)
            held, = api(session, "sender-review")["items"]
            assert held["subject"] == "Review beats category rule"
            assert not subjects(session, "*", q=held["subject"])
            api(session, "sender-review/decision", {"reference": held["reference"], "action": "allow",
                "apply_to_sender": True, "rule_revision": held["rule_revision"]}, "POST", extra={"If-Match": held["revision"]})
            released = eventually(lambda: subjects(session), lambda inbox: held["subject"] in inbox)[held["subject"]]
            assert detail(session, released)["placement"]["reason"] == "sender_review"
            rule(session, released, "automatic")
            send(owner, author, "Following approved digest", list_id=True)
            assert "Following approved digest" in subjects(session, "Newsletters")
            print("Verified restart recovery, durable placement and rules, Inbox override, and Sender Review precedence.")

            if browser:
                api(session, "sender-review", {"setting": "disable"}, "PUT")
                api(session, "category-settings", {"automatic": False}, "PUT")
                send(owner, shop, "Your receipt #BROWSER", html=True)
                move(session, subjects(session)["Your receipt #BROWSER"], "Receipts")
                move(session, subjects(session, "Receipts")["Weekly Alpha"], "Newsletters")
                subprocess.run([str(browser), test.webmail, owner, test.password, author], check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--browser", type=Path)
    args = parser.parse_args()
    run(args.binary.resolve(), args.previous.resolve() if args.previous else None,
        args.browser.resolve() if args.browser else None)
