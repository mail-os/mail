//! Lightweight, allocation-free spam scorer.
//!
//! This module is intentionally PURE: every network lookup (DNSBL, reverse
//! DNS) is performed by the SMTP receiver and the results are passed in as
//! `Signals`. That keeps the scoring logic deterministic and unit-testable
//! (`zig build test`) without any DNS dependency.
//!
//! The scorer combines three families of evidence into a single SpamAssassin-
//! style score:
//!   1. Authentication results  — SPF / DKIM / DMARC verdicts.
//!   2. Connection reputation   — DNSBL listings, missing/forged rDNS, HELO.
//!   3. Message structure        — missing headers, shouty/obfuscated subjects,
//!                                 spam phrases, link farms, hidden HTML text,
//!                                 dangerous attachments.
//!
//! The caller turns the resulting score into a disposition:
//!   score >= reject_threshold -> reject at SMTP time (5xx)
//!   score >= junk_threshold   -> deliver into the Junk mailbox
//!   otherwise                  -> deliver to the inbox
//!
//! Authenticated submissions (our own users) are NEVER scored — the receiver
//! only calls this for unauthenticated inbound mail.

const std = @import("std");

/// Generic authentication verdict. Map the protocol-specific SPF/DKIM/DMARC
/// result enums onto this before calling `evaluate`.
pub const Verdict = enum { pass, fail, softfail, neutral, none, temperror, permerror };

/// Evidence gathered by the SMTP receiver. Defaults are the "clean" values so a
/// caller only needs to set the signals it actually computed.
pub const Signals = struct {
    spf: Verdict = .none,
    dkim: Verdict = .none,
    dmarc: Verdict = .none,
    /// Number of DNS blocklists that listed the connecting IP (0 = clean).
    dnsbl_hits: u8 = 0,
    /// Connecting IP has no PTR (reverse DNS) record at all.
    no_ptr: bool = false,
    /// PTR exists but does not forward-confirm (FCrDNS mismatch).
    ptr_not_confirmed: bool = false,
    /// HELO/EHLO argument was an IP literal or otherwise not a FQDN.
    helo_not_fqdn: bool = false,
    /// HELO/EHLO claimed to be *our own* hostname — a classic forgery.
    helo_forges_us: bool = false,
};

pub const Disposition = enum { accept, junk, reject };

pub const Thresholds = struct {
    junk: f32 = 5.0,
    reject: f32 = 12.0,
};

/// Result of scoring. `tests()` returns a comma-separated list of the rule
/// names that fired, suitable for an `X-Spam-Status` header and logging.
pub const Report = struct {
    score: f32 = 0,
    disposition: Disposition = .accept,
    tests_buf: [512]u8 = undefined,
    tests_len: usize = 0,

    pub fn tests(self: *const Report) []const u8 {
        return self.tests_buf[0..self.tests_len];
    }
};

/// Accumulates the firing rule names into a fixed buffer (no allocation).
const TestList = struct {
    buf: [512]u8 = undefined,
    len: usize = 0,

    fn add(self: *TestList, name: []const u8) void {
        // +1 for the trailing comma separator.
        if (self.len + name.len + 1 > self.buf.len) return;
        @memcpy(self.buf[self.len..][0..name.len], name);
        self.len += name.len;
        self.buf[self.len] = ',';
        self.len += 1;
    }

    fn finalize(self: *TestList) []const u8 {
        if (self.len > 0 and self.buf[self.len - 1] == ',') self.len -= 1;
        return self.buf[0..self.len];
    }
};

/// High-confidence spam phrases. Weights are deliberately LOW (and capped)
/// because keyword matching is the most false-positive-prone signal — the
/// robust signals (DNSBL, SPF/DKIM/DMARC, rDNS, header sanity) carry the
/// decision. Matched case-insensitively against subject + start of body.
const spam_phrases = [_][]const u8{
    "viagra",          "cialis",            "sildenafil",        "pharmacy",
    "online casino",   "casino",            "forex",             "bitcoin",
    "crypto investment", "you have won",     "you've won",        "congratulations you",
    "claim your prize", "lottery",          "unclaimed funds",   "inheritance",
    "wire transfer",   "western union",     "hot singles",       "weight loss",
    "work from home",  "make money fast",   "earn extra cash",   "million dollars",
    "risk free",       "100% free",         "act now",           "limited time offer",
    "this is not spam", "cheap meds",        "loan approved",     "refinance",
};

/// URL shorteners frequently used to hide payload links.
const url_shorteners = [_][]const u8{
    "bit.ly", "tinyurl.com", "t.co/", "goo.gl/", "ow.ly/", "is.gd/", "buff.ly/", "rebrand.ly/",
};

/// Attachment name suffixes that are almost always malicious in email.
const dangerous_exts = [_][]const u8{
    ".exe\"", ".scr\"", ".pif\"", ".bat\"", ".cmd\"", ".com\"", ".vbs\"",
    ".js\"",  ".jar\"", ".cpl\"", ".lnk\"", ".iso\"", ".hta\"",
};

/// Score a message. `headers` is the header block (LF-separated lines, no
/// trailing body), `body` is everything after the header/body boundary.
pub fn evaluate(signals: Signals, headers: []const u8, body: []const u8, thresholds: Thresholds) Report {
    var score: f32 = 0;
    var tl: TestList = .{};

    // === 1. Authentication ===
    switch (signals.spf) {
        .fail => {
            score += 3.0;
            tl.add("SPF_FAIL");
        },
        .softfail => {
            score += 1.5;
            tl.add("SPF_SOFTFAIL");
        },
        .permerror => {
            score += 0.8;
            tl.add("SPF_PERMERROR");
        },
        else => {},
    }
    if (signals.dkim == .fail) {
        score += 2.5;
        tl.add("DKIM_FAIL");
    }
    if (signals.dmarc == .fail) {
        score += 3.5;
        tl.add("DMARC_FAIL");
    }
    // Neither SPF nor DKIM asserted a pass: weak on its own, common for bots.
    if (signals.spf != .pass and signals.dkim != .pass) {
        score += 1.0;
        tl.add("NO_AUTH");
    }

    // === 2. Connection reputation ===
    if (signals.dnsbl_hits > 0) {
        // A single listing already pushes a message into Junk; multiple
        // listings (or one listing plus other evidence) reach the reject line.
        const pts = @min(@as(f32, @floatFromInt(signals.dnsbl_hits)) * 6.0, 14.0);
        score += pts;
        tl.add("DNSBL_LISTED");
    }
    if (signals.no_ptr) {
        score += 2.0;
        tl.add("NO_PTR");
    } else if (signals.ptr_not_confirmed) {
        score += 1.0;
        tl.add("PTR_NOT_FCRDNS");
    }
    if (signals.helo_forges_us) {
        score += 3.0;
        tl.add("HELO_FORGES_US");
    } else if (signals.helo_not_fqdn) {
        score += 1.0;
        tl.add("HELO_NOT_FQDN");
    }

    // === 3. Message structure ===
    const subject = headerValue(headers, "Subject");
    if (subject == null or std.mem.trim(u8, subject.?, " \t").len == 0) {
        score += 0.8;
        tl.add("NO_SUBJECT");
    }
    if (!headerPresent(headers, "Message-ID")) {
        score += 1.0;
        tl.add("NO_MSGID");
    }
    if (!headerPresent(headers, "Date")) {
        score += 0.8;
        tl.add("NO_DATE");
    }

    if (subject) |s| {
        if (isMostlyUppercase(s)) {
            score += 1.5;
            tl.add("SUBJ_ALL_CAPS");
        }
        if (highNonAsciiRatio(s)) {
            score += 1.0;
            tl.add("SUBJ_OBFUSCATED");
        }
    }

    // From / Reply-To domain mismatch (only when DMARC didn't already pass).
    if (signals.dmarc != .pass) {
        const from_dom = headerDomain(headers, "From");
        const reply_dom = headerDomain(headers, "Reply-To");
        if (from_dom != null and reply_dom != null and
            !std.ascii.eqlIgnoreCase(from_dom.?, reply_dom.?))
        {
            score += 0.7;
            tl.add("REPLYTO_MISMATCH");
        }
    }

    // Phrase + structural body heuristics (scan subject + start of body).
    const scan_body = body[0..@min(body.len, 8192)];

    var phrase_hits: f32 = 0;
    for (spam_phrases) |phrase| {
        const in_subject = if (subject) |s| std.ascii.indexOfIgnoreCase(s, phrase) != null else false;
        if (in_subject or std.ascii.indexOfIgnoreCase(scan_body, phrase) != null) {
            phrase_hits += 0.6;
        }
    }
    if (phrase_hits > 0) {
        score += @min(phrase_hits, 3.0);
        tl.add("SPAM_PHRASES");
    }

    // Link farm: a wall of URLs is a strong bulk-mail signal.
    const url_count = countOccurrences(scan_body, "http://") + countOccurrences(scan_body, "https://");
    if (url_count >= 20) {
        score += 1.5;
        tl.add("MANY_URLS");
    }
    for (url_shorteners) |sh| {
        if (std.ascii.indexOfIgnoreCase(scan_body, sh) != null) {
            score += 1.0;
            tl.add("URL_SHORTENER");
            break;
        }
    }

    // Hidden HTML text (common in image-spam / cloaking).
    if (containsAnyIgnoreCase(scan_body, &.{ "display:none", "visibility:hidden", "font-size:0", "font-size: 0px" })) {
        score += 1.5;
        tl.add("HTML_HIDDEN_TEXT");
    }

    // Dangerous executable attachment.
    const scan_attach = body[0..@min(body.len, 65536)];
    for (dangerous_exts) |ext| {
        if (std.ascii.indexOfIgnoreCase(scan_attach, ext) != null) {
            score += 2.5;
            tl.add("DANGEROUS_ATTACHMENT");
            break;
        }
    }

    var report = Report{ .score = score };
    if (score >= thresholds.reject) {
        report.disposition = .reject;
    } else if (score >= thresholds.junk) {
        report.disposition = .junk;
    }
    const t = tl.finalize();
    @memcpy(report.tests_buf[0..t.len], t);
    report.tests_len = t.len;
    return report;
}

// --- Header helpers (operate on an LF-separated header block) ---

/// Return the (untrimmed-of-value-but-line-trimmed) value of the first header
/// whose name matches `name` case-insensitively. Does not unfold continuations
/// — sufficient for the heuristics here.
pub fn headerValue(headers: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, headers, '\n');
    while (it.next()) |line| {
        if (line.len < name.len + 1) continue;
        if (!std.ascii.eqlIgnoreCase(line[0..name.len], name)) continue;
        if (line[name.len] != ':') continue;
        return std.mem.trim(u8, line[name.len + 1 ..], " \t\r");
    }
    return null;
}

pub fn headerPresent(headers: []const u8, name: []const u8) bool {
    return headerValue(headers, name) != null;
}

/// Domain portion of an address-bearing header (e.g. From, Reply-To).
fn headerDomain(headers: []const u8, name: []const u8) ?[]const u8 {
    const v = headerValue(headers, name) orelse return null;
    const at = std.mem.lastIndexOfScalar(u8, v, '@') orelse return null;
    var d = v[at + 1 ..];
    var end: usize = 0;
    while (end < d.len and d[end] != '>' and d[end] != ' ' and d[end] != '\t' and
        d[end] != '\r' and d[end] != ';' and d[end] != ',' and d[end] != ')')
    {
        end += 1;
    }
    d = d[0..end];
    return if (d.len == 0) null else d;
}

fn isMostlyUppercase(s: []const u8) bool {
    var letters: usize = 0;
    var upper: usize = 0;
    for (s) |c| {
        if (std.ascii.isAlphabetic(c)) {
            letters += 1;
            if (std.ascii.isUpper(c)) upper += 1;
        }
    }
    // Require a meaningful number of letters so "OK" / "RE: Hi" don't trip it.
    if (letters < 8) return false;
    return upper * 100 >= letters * 80;
}

fn highNonAsciiRatio(s: []const u8) bool {
    if (s.len < 6) return false;
    var non_ascii: usize = 0;
    for (s) |c| {
        if (c >= 0x80) non_ascii += 1;
    }
    return non_ascii * 100 >= s.len * 40;
}

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    if (needle.len == 0) return 0;
    var count: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, i, needle)) |pos| {
        count += 1;
        i = pos + needle.len;
    }
    return count;
}

fn containsAnyIgnoreCase(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |n| {
        if (std.ascii.indexOfIgnoreCase(haystack, n) != null) return true;
    }
    return false;
}

// =========================== tests ===========================

test "clean authenticated-looking mail scores zero and is accepted" {
    const headers =
        "From: Alice <alice@example.com>\n" ++
        "Subject: Lunch tomorrow?\n" ++
        "Date: Mon, 29 Jun 2026 10:00:00 +0000\n" ++
        "Message-ID: <abc@example.com>";
    const body = "Hi Bob, are you free for lunch tomorrow?\n";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expectEqual(@as(f32, 0), r.score);
    try std.testing.expectEqual(Disposition.accept, r.disposition);
}

test "DNSBL listing alone lands in Junk, not rejected" {
    const headers =
        "From: x@spammer.example\n" ++
        "Subject: Hello there friend\n" ++
        "Date: Mon, 29 Jun 2026 10:00:00 +0000\n" ++
        "Message-ID: <z@spammer.example>";
    const r = evaluate(.{ .spf = .pass, .dnsbl_hits = 1 }, headers, "hi\n", .{});
    try std.testing.expectEqual(Disposition.junk, r.disposition);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "DNSBL_LISTED") != null);
}

test "botnet profile (DNSBL + SPF fail + no PTR + no auth) is rejected" {
    const headers = "From: a@b.example\nSubject: hi\nDate: x\nMessage-ID: <1@b>";
    const r = evaluate(.{
        .spf = .fail,
        .dnsbl_hits = 1,
        .no_ptr = true,
    }, headers, "buy now\n", .{});
    try std.testing.expect(r.score >= 12.0);
    try std.testing.expectEqual(Disposition.reject, r.disposition);
}

test "missing headers and shouty subject accumulate score" {
    const headers = "From: x@y.example\nSubject: WIN A FREE IPHONE RIGHT NOW";
    const r = evaluate(.{ .spf = .pass }, headers, "", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "NO_MSGID") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "NO_DATE") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SUBJ_ALL_CAPS") != null);
}

test "spam phrases are capped" {
    const headers = "From: x@y.example\nSubject: hi\nDate: d\nMessage-ID: <1@y>";
    const body = "viagra cialis casino lottery bitcoin forex inheritance wire transfer";
    const r = evaluate(.{ .spf = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SPAM_PHRASES") != null);
    // capped at 3.0, so well under the reject threshold on its own
    try std.testing.expect(r.score <= 3.0 + 0.01);
}

test "dangerous attachment flagged" {
    const headers = "From: x@y.example\nSubject: invoice\nDate: d\nMessage-ID: <1@y>";
    const body = "Content-Disposition: attachment; filename=\"invoice.exe\"\n";
    const r = evaluate(.{ .spf = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "DANGEROUS_ATTACHMENT") != null);
}

test "headerValue is case-insensitive and trims" {
    const headers = "subject:   Hello World  \nFrom: a@b.c";
    const v = headerValue(headers, "Subject").?;
    try std.testing.expectEqualStrings("Hello World", v);
}

test "headerDomain extracts From domain" {
    const headers = "From: Bob <bob@Example.COM>\n";
    const d = headerDomain(headers, "From").?;
    try std.testing.expectEqualStrings("Example.COM", d);
}
