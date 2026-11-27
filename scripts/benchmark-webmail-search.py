#!/usr/bin/env python3
"""Measure native HTTPS first-page search against a seeded mailbox."""

import argparse
from contextlib import ExitStack
from email.utils import formatdate
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import runpy
import tempfile
import time
from typing import NamedTuple
from urllib.parse import urlencode


fixture = runpy.run_path(str(Path(__file__).with_name("test-hosted-limits.py")))
Fixture, request = fixture["Fixture"], fixture["request"]
FIXTURE_VERSION = 1
BASE_TIMESTAMP = 1735689600
PAGE_SIZE = 50
TARGET_MS = 1000
CASES = {
    "rare": {"q": "rare planning memo"},
    "common": {"q": "program update"},
    "absent": {"q": "no results for this phrase"},
    "filtered_conversations": {
        "q": "program update", "from": "team-00@example.test", "conversations": "true",
    },
}


def seed(directory, address, count, seed_value):
    rng = random.Random(seed_value)
    mailbox = directory / "mail" / address
    for folder in ("new", "cur", "Archive"):
        (mailbox / folder).mkdir(parents=True, exist_ok=True)
    hits = dict.fromkeys(CASES, 0)
    for index in range(count):
        timestamp = BASE_TIMESTAMP + 60 * index
        sender = f"team-{rng.randrange(16):02}@example.test"
        team = rng.choice(("Research", "Operations", "Finance", "Design"))
        common = index % 5 == 0
        rare = index % 289 == 0
        hits["rare"] += rare
        hits["common"] += common
        hits["filtered_conversations"] += common and sender == "team-00@example.test"
        body = f"{team} notes for the next meeting. "
        if common:
            body += "Here is the monthly program update. "
        if rare:
            body += "The rare planning memo is ready for review. "
        parent = index - index % 5
        reply = f"In-Reply-To: <perf-{parent}@example.test>\r\n" if index != parent else ""
        folder = "Archive" if index % 10 == 0 else "new" if index % 3 == 0 else "cur"
        flags = ":2,S" if folder != "new" else ""
        name = f"{timestamp * 1000}.{index}.eml{flags}"
        message = (
            f"From: {team} <{sender}>\r\nTo: {address}\r\nSubject: {team} mail {index}\r\n"
            f"Message-ID: <perf-{index}@example.test>\r\n{reply}"
            f"Date: {formatdate(timestamp, usegmt=True)}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n"
        )
        (mailbox / folder / name).write_bytes(message.encode())
    return hits


def measure(test, session, **params):
    query = urlencode(dict(folder="*", page=1, per_page=PAGE_SIZE, personal="true", **params))
    started = time.perf_counter()
    status, headers, data = request(test.webmail + "/webmail/api/messages?" + query,
                                    headers=session, context=test.tls_context, timeout=300)
    elapsed = (time.perf_counter() - started) * 1000
    if status != 200:
        raise RuntimeError(f"Search returned {status}: {data[:500]!r}")
    timing = headers.get("Server-Timing", "")
    server_ms = float(timing.removeprefix("mail-list;dur=")) if timing.startswith("mail-list;dur=") else None
    return json.loads(data), elapsed, server_ms


class SearchMailbox(NamedTuple):
    daemon: Fixture
    session: dict[str, str]
    hits: dict[str, int]
    cold_index_ms: float


def open_mailbox(stack, binary, count, seed_value):
    directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="mail-search-performance-")))
    test = Fixture(binary, directory, staging=True)
    stack.enter_context(test.daemon())
    address = test.provision("search-performance", quota=1024 * 1024 * 1024)
    hits = seed(directory, address, count, seed_value)
    with test.imap(address) as imap:
        for folder in ("INBOX", "Archive"):
            assert imap.select(folder)[0] == "OK"
    session = test.login(address)
    indexed, cold_ms, _ = measure(test, session, q="seed warmup with no matches")
    assert indexed["index"] == {"total": count, "indexed": count, "pending": False}, indexed
    return SearchMailbox(test, session, hits, cold_ms)


def run(binaries, count, seed_value, samples):
    with ExitStack() as stack:
        mailboxes, reports = {}, {}
        for side, binary in binaries.items():
            mailbox = open_mailbox(stack, binary, count, seed_value)
            print(f"{side}: indexed {count} messages in {mailbox.cold_index_ms / 1000:.2f} s", flush=True)
            mailboxes[side] = mailbox
            reports[side] = {"cold_index_ms": round(mailbox.cold_index_ms, 2), "cases": {}}
        expected_index = {"total": count, "indexed": count, "pending": False}
        for name, params in CASES.items():
            latencies = {side: [] for side in mailboxes}
            timings = {side: [] for side in mailboxes}
            key = "threads" if params.get("conversations") == "true" else "items"
            for sample in range(samples + 2):
                # Alternate which daemon answers first, including the warmups.
                order = mailboxes if sample % 2 == 0 else reversed(mailboxes)
                for side in order:
                    mailbox = mailboxes[side]
                    body, elapsed, server_ms = measure(mailbox.daemon, mailbox.session, **params)
                    hits = mailbox.hits[name]
                    assert body["index"] == expected_index, (side, body["index"])
                    assert body["page"] == 1 and body["message_total"] == hits, (side, name, body["message_total"], hits)
                    assert len(body[key]) == min(body["total"], PAGE_SIZE) and body["total"] == hits
                    if sample >= 2:
                        latencies[side].append(elapsed)
                        if server_ms is not None:
                            timings[side].append(server_ms)
            for side, mailbox in mailboxes.items():
                result = {
                    "matches": mailbox.hits[name],
                    "https_p95_ms": percentile(latencies[side]),
                    "server_p95_ms": percentile(timings[side]) if len(timings[side]) == samples else None,
                }
                reports[side]["cases"][name] = result
                print(f"{side} {name}: {result}", flush=True)
        return reports


def percentile(values):
    return round(sorted(values)[math.ceil(0.95 * len(values)) - 1], 2)


def binary_identity(binary, revision):
    with binary.open("rb") as executable:
        digest = hashlib.file_digest(executable, "sha256").hexdigest()
    return {"revision": revision, "binary_sha256": digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--messages", type=int, default=50_000)
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--seed", type=int, default=71)
    parser.add_argument("--revision", default="unspecified")
    parser.add_argument("--output", type=Path, required=True)
    comparison = parser.add_mutually_exclusive_group()
    comparison.add_argument("--baseline-report", type=Path, help="Compare with a separate report from the same environment")
    comparison.add_argument("--baseline-binary", type=Path, help="Alternate requests between this baseline and the candidate")
    parser.add_argument("--baseline-revision", help="Source revision of the paired baseline binary")
    parser.add_argument("--enforce", action="store_true", help="Fail if a warm case exceeds its latency gate")
    args = parser.parse_args()
    if args.messages < 10 or args.samples < 1:
        parser.error("provide at least 10 messages and one sample")
    if args.enforce and (args.messages != 50_000 or args.samples < 20):
        parser.error("the latency gate requires 50,000 messages and at least 20 samples")
    if (args.baseline_binary is None) != (args.baseline_revision is None):
        parser.error("--baseline-binary and --baseline-revision must be used together")

    binary = args.binary.resolve(strict=True)
    environment = {"os": platform.platform(), "cpu_count": os.cpu_count(), "python": platform.python_version()}
    configuration = {"version": FIXTURE_VERSION, "messages": args.messages, "seed": args.seed,
                     "page_size": PAGE_SIZE, "samples": args.samples}
    baseline = json.loads(args.baseline_report.read_text()) if args.baseline_report else None
    if baseline and (baseline["fixture"] != configuration or baseline["environment"] != environment):
        parser.error("the baseline must come from the same fixture and environment")
    scope = {"environment": environment, "fixture": configuration}
    report = {**binary_identity(binary, args.revision), **scope}
    binaries = {"candidate": binary}
    if args.baseline_binary:
        binaries["baseline"] = args.baseline_binary.resolve(strict=True)
        baseline = {**binary_identity(binaries["baseline"], args.baseline_revision), **scope}
    runs = run(binaries, args.messages, args.seed, args.samples)
    report.update(runs["candidate"])
    if args.baseline_binary:
        baseline.update(runs["baseline"])
        report["paired_baseline"] = baseline
    report["baseline_revision"] = baseline["revision"] if baseline else None
    for name, result in report["cases"].items():
        server_p95 = result["server_p95_ms"]
        # Without a timing header HTTPS is an upper bound on server work.
        result["target_met"] = (result["https_p95_ms"] if server_p95 is None else server_p95) <= TARGET_MS
        result["within_baseline"] = None if not baseline else result["https_p95_ms"] <= baseline["cases"][name]["https_p95_ms"] * 1.10
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if args.enforce and any(not case["target_met"] or case["within_baseline"] is False for case in report["cases"].values()):
        raise SystemExit("Warm webmail search exceeded its latency gate. See the benchmark report.")


if __name__ == "__main__":
    main()
