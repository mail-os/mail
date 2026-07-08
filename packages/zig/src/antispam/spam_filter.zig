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
    "viagra",            "cialis",          "sildenafil",      "pharmacy",
    "online casino",     "casino",          "forex",           "bitcoin",
    "crypto investment", "you have won",    "you've won",      "congratulations you",
    "claim your prize",  "lottery",         "unclaimed funds", "inheritance",
    "wire transfer",     "western union",   "hot singles",     "weight loss",
    "work from home",    "make money fast", "earn extra cash", "million dollars",
    "risk free",         "100% free",       "act now",         "limited time offer",
    "this is not spam",  "cheap meds",      "loan approved",   "refinance",
};

/// URL shorteners frequently used to hide payload links.
const url_shorteners = [_][]const u8{
    "bit.ly", "tinyurl.com", "t.co/", "goo.gl/", "ow.ly/", "is.gd/", "buff.ly/", "rebrand.ly/",
};

/// Attachment name suffixes that are almost always malicious in email.
const dangerous_exts = [_][]const u8{
    ".exe", ".scr", ".pif", ".bat", ".cmd", ".com", ".vbs",
    ".js",  ".jar", ".cpl", ".lnk", ".iso", ".hta",
};

/// True if a MIME `name=` / `filename=` parameter declares a file whose
/// extension is in `dangerous_exts`. Only the parameter *value* is examined,
/// so link URLs in the body (e.g. `href="https://example.com"`) cannot
/// false-match a bare extension like ".com". Matching `name=` also covers
/// `filename=` since that string ends in `name=`.
fn hasDangerousAttachment(scan: []const u8) bool {
    var pos: usize = 0;
    while (std.ascii.indexOfIgnoreCasePos(scan, pos, "name=")) |at| {
        var v = at + "name=".len;
        pos = v; // advance past this match for the next iteration
        if (v < scan.len and (scan[v] == '"' or scan[v] == '\'')) v += 1;
        var end = v;
        while (end < scan.len) : (end += 1) {
            const c = scan[end];
            if (c == '"' or c == '\'' or c == ';' or c == '\r' or c == '\n' or c == ' ') break;
        }
        const value = scan[v..end];
        for (dangerous_exts) |ext| {
            if (value.len >= ext.len and
                std.ascii.eqlIgnoreCase(value[value.len - ext.len ..], ext))
                return true;
        }
    }
    return false;
}

/// Unsolicited SEO / web-design outreach — by volume the dominant spam class
/// hitting a published contact address. These are solicitation-specific
/// bigrams (deliberately NOT bare "web"/"seo") so a passing mention in real
/// mail doesn't score; a genuine pitch stacks several. Individually low-weight
/// and capped, like `spam_phrases`.
const seo_phrases = [_][]const u8{
    "search engine optimization", "seo service",             "seo services",         "seo package",
    "seo expert",                 "seo company",             "seo agency",           "1st page of google",
    "first page of google",       "top of google",           "page of google",       "google ranking",
    "search ranking",             "increase your ranking",   "improve your ranking", "rank higher",
    "higher ranking",             "website traffic",         "organic traffic",      "increase traffic",
    "website design",             "web design service",      "website development",  "web development",
    "web developer",              "website redesign",        "redesign of your",     "redesign your website",
    "revamp your website",        "existing website",        "build your website",   "backlink",
    "link building",              "guest post",              "domain authority",     "digital marketing",
    "lead generation",            "se0",
    // App-development pitches, the sibling of the SEO pitch ("interested in
    // building a mobile app?"). Same bigram discipline: no bare "app".
                        "mobile app",           "app development",
    "app developer",              "application development", "build an app",         "building an app",
    "develop an app",             "ios and android",         "android and ios",      "app idea",
};

/// Cold-outreach scaffolding: the opener/closer boilerplate every unsolicited
/// pitch is built from, independent of what is being sold. Each phrase is weak
/// alone (a real correspondent can say "are you interested") so the weight is
/// low and capped — but a pitch stacks four or more, and combined with
/// FREEMAIL_OUTREACH and a solicitation topic it clears the Junk line.
const outreach_phrases = [_][]const u8{
    "just checking",       "are you interested",   "i can send you",                "estimated cost",
    "share the details",   "business development", "looking forward to your reply", "get back to me",
    "quick call",          "schedule a call",      "free consultation",             "no obligation",
    "our services",        "we provide",           "we offer",                      "we specialize",
    "our company",         "dear sir",             "dear madam",                    "greetings of the day",
    "dedicated developer", "hire a developer",     "our portfolio",                 "our team of",
    "years of experience", "cost-effective",       "affordable price",              "best price",
    "special offer",       "reach out to me",
};

/// Contact-harvesting closers: an unsolicited pitch angling to move the
/// conversation to phone/WhatsApp or asking for a "cost/price list". Strong,
/// low-false-positive marker of cold outreach.
const harvest_phrases = [_][]const u8{
    "whatsapp",            "your mobile number", "share your contact",  "share your number",
    "send me your number", "send your contact",  "your contact number", "cost list",
    "price list",          "your whatsapp",
};

/// Free / consumer mail providers. A cold B2B SEO pitch almost always ships
/// from one of these; only ever used as a MULTIPLIER on solicitation content,
/// never on its own (plenty of real people mail from gmail).
const free_providers = [_][]const u8{
    "gmail.com", "googlemail.com", "hotmail.com", "outlook.com", "live.com",
    "yahoo.com", "ymail.com",      "aol.com",     "msn.com",     "gmx.com",
};

/// Consumer brands commonly spoofed in the From display-name (phishing).
/// Kept to distinctive, low-substring-collision names on purpose.
const spoofed_brands = [_][]const u8{
    "netflix", "paypal", "amazon", "microsoft", "coinbase",
    "binance", "fedex",  "norton", "mcafee",    "docusign",
};

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Decode quoted-printable into `out`. `=XX` becomes the byte, `=\n`/`=\r\n`
/// soft line breaks vanish (rejoining phrases QP split across lines), and
/// anything unrecognized passes through verbatim — so non-QP text is
/// unchanged and it is safe to run unconditionally on the scan window.
fn decodeQuotedPrintable(in: []const u8, out: []u8) []const u8 {
    var i: usize = 0;
    var o: usize = 0;
    while (i < in.len and o < out.len) {
        const c = in[i];
        if (c == '=' and i + 1 < in.len) {
            if (in[i + 1] == '\n') {
                i += 2;
                continue;
            }
            if (in[i + 1] == '\r' and i + 2 < in.len and in[i + 2] == '\n') {
                i += 3;
                continue;
            }
            if (i + 2 < in.len) {
                if (hexVal(in[i + 1])) |hi| {
                    if (hexVal(in[i + 2])) |lo| {
                        out[o] = (hi << 4) | lo;
                        o += 1;
                        i += 3;
                        continue;
                    }
                }
            }
        }
        out[o] = c;
        o += 1;
        i += 1;
    }
    return out[0..o];
}

/// Replace a leading HTML entity with its character. Returns null when `s`
/// doesn't start with a known entity.
fn matchEntity(s: []const u8) ?struct { ch: u8, len: usize } {
    const table = [_]struct { name: []const u8, ch: u8 }{
        .{ .name = "&nbsp;", .ch = ' ' },
        .{ .name = "&amp;", .ch = '&' },
        .{ .name = "&lt;", .ch = '<' },
        .{ .name = "&gt;", .ch = '>' },
        .{ .name = "&quot;", .ch = '"' },
        .{ .name = "&#39;", .ch = '\'' },
    };
    for (table) |e| {
        if (std.ascii.startsWithIgnoreCase(s, e.name)) return .{ .ch = e.ch, .len = e.name.len };
    }
    return null;
}

/// Reduce HTML to the text a mail client would render: drop <style>/<script>
/// blocks wholesale, drop tags, decode common entities, and collapse
/// whitespace runs to single spaces. Phrase matching runs on this, so markup
/// (or an entity like "mobile&nbsp;app") can't break up a phrase. Plain text
/// passes through with only whitespace collapsed.
fn stripHtmlText(in: []const u8, out: []u8) []const u8 {
    var i: usize = 0;
    var o: usize = 0;
    var pending_space = false;
    while (i < in.len and o < out.len) {
        var c = in[i];
        if (c == '<') {
            if (std.ascii.startsWithIgnoreCase(in[i..], "<style")) {
                if (std.ascii.indexOfIgnoreCase(in[i..], "</style")) |rel| {
                    const close = i + rel;
                    i = if (std.mem.indexOfScalarPos(u8, in, close, '>')) |gt| gt + 1 else in.len;
                } else i = in.len;
            } else if (std.ascii.startsWithIgnoreCase(in[i..], "<script")) {
                if (std.ascii.indexOfIgnoreCase(in[i..], "</script")) |rel| {
                    const close = i + rel;
                    i = if (std.mem.indexOfScalarPos(u8, in, close, '>')) |gt| gt + 1 else in.len;
                } else i = in.len;
            } else {
                i = if (std.mem.indexOfScalarPos(u8, in, i, '>')) |gt| gt + 1 else in.len;
            }
            pending_space = true;
            continue;
        }
        if (c == '&') {
            if (matchEntity(in[i..])) |e| {
                c = e.ch;
                i += e.len;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
            pending_space = true;
            continue;
        }
        if (pending_space) {
            out[o] = ' ';
            o += 1;
            pending_space = false;
            if (o >= out.len) break;
        }
        out[o] = c;
        o += 1;
    }
    return out[0..o];
}

/// Find a `Content-Transfer-Encoding: base64` MIME part inside the scan
/// window and decode its payload (bounded by `out`). Wrapping the pitch in a
/// base64 text/html part is the oldest filter-evasion trick there is; without
/// this the phrase scan only ever sees boundary noise.
fn decodeBase64Part(window: []const u8, out: []u8) []const u8 {
    const marker = "content-transfer-encoding:";
    var search: usize = 0;
    while (search < window.len) {
        const rel = std.ascii.indexOfIgnoreCase(window[search..], marker) orelse return out[0..0];
        const vstart = search + rel + marker.len;
        const line_end = std.mem.indexOfScalarPos(u8, window, vstart, '\n') orelse window.len;
        if (std.ascii.indexOfIgnoreCase(window[vstart..line_end], "base64") == null) {
            search = line_end;
            continue;
        }
        // Skip the remaining part headers up to the blank line.
        var bp = line_end;
        while (bp < window.len) {
            const le = std.mem.indexOfScalarPos(u8, window, bp + 1, '\n') orelse window.len;
            const line = std.mem.trim(u8, window[bp + 1 .. le], " \t\r");
            bp = le;
            if (line.len == 0) break;
        }
        // Collect base64 payload lines until a boundary ("--...") or garbage.
        var collected: [8192]u8 = undefined;
        var n: usize = 0;
        var p = bp;
        collect: while (p < window.len and n < collected.len) {
            const le = std.mem.indexOfScalarPos(u8, window, p + 1, '\n') orelse window.len;
            const line = std.mem.trim(u8, window[p + 1 .. le], " \t\r");
            p = le;
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "--")) break;
            for (line) |ch| {
                const ok = std.ascii.isAlphanumeric(ch) or ch == '+' or ch == '/' or ch == '=';
                if (!ok) break :collect;
                if (n >= collected.len) break :collect;
                collected[n] = ch;
                n += 1;
            }
        }
        n -= n % 4; // drop a trailing partial quantum (window cut mid-line)
        if (n == 0) return out[0..0];
        const dec_len = std.base64.standard.Decoder.calcSizeForSlice(collected[0..n]) catch return out[0..0];
        if (dec_len > out.len) return out[0..0];
        std.base64.standard.Decoder.decode(out[0..dec_len], collected[0..n]) catch return out[0..0];
        return out[0..dec_len];
    }
    return out[0..0];
}

/// Decode RFC 2047 encoded-words ("=?utf-8?B?...?=" / "=?utf-8?Q?...?=") so
/// subject heuristics see the text the recipient sees. Spam leans on encoded
/// subjects precisely because naive filters skip them. Plain subjects are
/// returned as-is.
fn decodeEncodedWords(s: []const u8, out: []u8) []const u8 {
    if (std.mem.indexOf(u8, s, "=?") == null) return s;
    var i: usize = 0;
    var o: usize = 0;
    while (i < s.len and o < out.len) {
        if (s[i] == '=' and i + 1 < s.len and s[i + 1] == '?') decoded: {
            const q1 = std.mem.indexOfScalarPos(u8, s, i + 2, '?') orelse break :decoded;
            if (q1 + 2 >= s.len or s[q1 + 2] != '?') break :decoded;
            const enc = s[q1 + 1];
            const dend = std.mem.indexOfPos(u8, s, q1 + 3, "?=") orelse break :decoded;
            const data = s[q1 + 3 .. dend];
            if (enc == 'B' or enc == 'b') {
                const dec_len = std.base64.standard.Decoder.calcSizeForSlice(data) catch break :decoded;
                if (o + dec_len > out.len) break :decoded;
                std.base64.standard.Decoder.decode(out[o .. o + dec_len], data) catch break :decoded;
                o += dec_len;
            } else if (enc == 'Q' or enc == 'q') {
                var j: usize = 0;
                while (j < data.len and o < out.len) {
                    if (data[j] == '_') {
                        out[o] = ' ';
                        o += 1;
                        j += 1;
                    } else if (data[j] == '=' and j + 2 < data.len) {
                        const hi = hexVal(data[j + 1]) orelse {
                            out[o] = data[j];
                            o += 1;
                            j += 1;
                            continue;
                        };
                        const lo = hexVal(data[j + 2]) orelse {
                            out[o] = data[j];
                            o += 1;
                            j += 1;
                            continue;
                        };
                        out[o] = (hi << 4) | lo;
                        o += 1;
                        j += 3;
                    } else {
                        out[o] = data[j];
                        o += 1;
                        j += 1;
                    }
                }
            } else break :decoded;
            i = dend + 2;
            continue;
        }
        out[o] = s[i];
        o += 1;
        i += 1;
    }
    return out[0..o];
}

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
    // A failing DKIM signature is only a spam signal when DMARC did not
    // otherwise pass. Large senders (Stripe, Google, SES relays) attach
    // multiple DKIM signatures; it is normal for one (e.g. an ESP's) to fail
    // verification while the aligned signature passes and yields dmarc=pass.
    // Scoring DKIM_FAIL on a dmarc=pass message double-counts against fully
    // authenticated, legitimate mail — the exact false positive that folds
    // Stripe/Google/Hetzner notifications into Junk.
    if (signals.dkim == .fail and signals.dmarc != .pass) {
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
    // Subject heuristics run on the RFC 2047-decoded form — encoded-word
    // subjects otherwise sail past every subject rule.
    var subj_buf: [256]u8 = undefined;
    const subject_raw = headerValue(headers, "Subject");
    const subject: ?[]const u8 = if (subject_raw) |s| decodeEncodedWords(s, &subj_buf) else null;
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
        // Repeated exclamation marks ("Building a new app !!"). Real subjects
        // use at most one.
        if (std.mem.indexOf(u8, s, "!!") != null) {
            score += 0.8;
            tl.add("SUBJ_EXCLAIM");
        }
        // Fabricated reply/forward prefix: cold outreach fakes a threaded
        // subject ("Re: Hi,", "Rw: …", "Fwd: …") to look like an ongoing
        // conversation, but a genuine reply always carries In-Reply-To /
        // References. (Encoded-word subjects are decoded above, so encoded
        // fakes are caught too.)
        const st = std.mem.trim(u8, s, " \t");
        if ((startsWithCI(st, "re:") or startsWithCI(st, "rw:") or
            startsWithCI(st, "fwd:") or startsWithCI(st, "fw:")) and
            !headerPresent(headers, "In-Reply-To") and
            !headerPresent(headers, "References"))
        {
            score += 3.0;
            tl.add("FAKE_REPLY");
        }
    }

    // Bulk-blast addressing: the recipient list was hidden.
    if (headerValue(headers, "To")) |to_v| {
        if (std.ascii.indexOfIgnoreCase(to_v, "undisclosed") != null) {
            score += 1.5;
            tl.add("UNDISCLOSED_RCPTS");
        }
    }

    // Brand spoofing in the From display-name (phishing): the visible name
    // claims a consumer brand the sending domain has nothing to do with
    // (e.g. `"Netflix.com" <l1xwv4u9@aqg.io>`). Independent of DMARC — the
    // display name is never authenticated even when the domain's DMARC passes.
    if (headerValue(headers, "From")) |from_hdr| {
        const disp_end = std.mem.indexOfScalar(u8, from_hdr, '<') orelse from_hdr.len;
        const display = from_hdr[0..disp_end];
        const from_dom = headerDomain(headers, "From");
        for (spoofed_brands) |brand| {
            if (std.ascii.indexOfIgnoreCase(display, brand) != null) {
                const dom_has_brand = if (from_dom) |fd|
                    std.ascii.indexOfIgnoreCase(fd, brand) != null
                else
                    false;
                if (!dom_has_brand) {
                    score += 4.0;
                    tl.add("BRAND_SPOOF");
                }
                break;
            }
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

    // Phrase scans run on a NORMALIZED view of the body, not the raw bytes:
    // quoted-printable is decoded (soft breaks rejoin split phrases), HTML
    // markup/entities are stripped, whitespace is collapsed, and a
    // base64-encoded MIME part is decoded and appended. Raw-byte scans stay
    // raw where the markup itself is the signal (URLs, hidden-text CSS,
    // attachment filenames).
    var qp_buf: [8192]u8 = undefined;
    var text_buf: [8192]u8 = undefined;
    var b64_buf: [6144]u8 = undefined;
    var b64_text_buf: [6144]u8 = undefined;
    const scan_qp = decodeQuotedPrintable(scan_body, &qp_buf);
    const scan_text = stripHtmlText(scan_qp, &text_buf);
    const b64_part = decodeBase64Part(scan_body, &b64_buf);
    const b64_text = if (b64_part.len > 0) stripHtmlText(b64_part, &b64_text_buf) else b64_part;

    const Scan = struct {
        subject: ?[]const u8,
        text: []const u8,
        b64: []const u8,
        fn hit(self: @This(), phrase: []const u8) bool {
            if (self.subject) |s| {
                if (std.ascii.indexOfIgnoreCase(s, phrase) != null) return true;
            }
            if (std.ascii.indexOfIgnoreCase(self.text, phrase) != null) return true;
            return self.b64.len > 0 and std.ascii.indexOfIgnoreCase(self.b64, phrase) != null;
        }
    };
    const scan = Scan{ .subject = subject, .text = scan_text, .b64 = b64_text };

    var phrase_hits: f32 = 0;
    for (spam_phrases) |phrase| {
        if (scan.hit(phrase)) phrase_hits += 0.6;
    }
    if (phrase_hits > 0) {
        score += @min(phrase_hits, 3.0);
        tl.add("SPAM_PHRASES");
    }

    // Unsolicited SEO / web-design / app-development solicitation.
    var seo_hits: f32 = 0;
    for (seo_phrases) |phrase| {
        if (scan.hit(phrase)) seo_hits += 1.2;
    }
    if (seo_hits > 0) {
        // Capped so a legitimate inquiry that happens to use a couple of these
        // bigrams (a real risk on a web-dev company's inbox) stays under the
        // Junk line; only a dense pitch (4+ distinct terms) reaches it alone.
        score += @min(seo_hits, 5.2);
        tl.add("SEO_SOLICITATION");
    }

    // Cold-outreach scaffolding ("just checking", "i can send you",
    // "estimated cost", role signatures, …). Individually meaningless, so the
    // per-phrase weight is low and the total capped — but a pitch stacks them.
    var outreach_count: usize = 0;
    for (outreach_phrases) |phrase| {
        if (scan.hit(phrase)) outreach_count += 1;
    }
    if (outreach_count > 0) {
        score += @min(@as(f32, @floatFromInt(outreach_count)) * 0.8, 4.0);
        tl.add("OUTREACH_PITCH");
    }

    // Contact-harvesting closer (WhatsApp / "cost list" / "your mobile number").
    // Near-unambiguous cold-outreach marker — legitimate correspondence rarely
    // asks an unknown recipient for their WhatsApp or a "cost list".
    var harvest_hit = false;
    for (harvest_phrases) |phrase| {
        if (scan.hit(phrase)) {
            harvest_hit = true;
            break;
        }
    }
    if (harvest_hit) {
        score += 3.0;
        tl.add("CONTACT_HARVEST");
    }

    // A free / consumer-provider sender attached to ANY solicitation content is
    // the textbook cold-outreach shape. A multiplier only — never scored on its
    // own, so a normal person mailing from gmail is unaffected. Outreach
    // scaffolding alone needs 2+ distinct phrases before it counts as
    // solicitation content here.
    if (seo_hits > 0 or harvest_hit or outreach_count >= 2) {
        if (headerDomain(headers, "From")) |fd| {
            for (free_providers) |fp| {
                if (std.ascii.eqlIgnoreCase(fd, fp)) {
                    score += 2.0;
                    tl.add("FREEMAIL_OUTREACH");
                    break;
                }
            }
        }
    }

    // Link farm: a wall of URLs is a strong bulk-mail signal. Scanned on the
    // QP-decoded view so a soft line break can't split "https://" or a
    // shortener host.
    const url_count = countOccurrences(scan_qp, "http://") + countOccurrences(scan_qp, "https://");
    if (url_count >= 20) {
        score += 1.5;
        tl.add("MANY_URLS");
    }
    for (url_shorteners) |sh| {
        if (std.ascii.indexOfIgnoreCase(scan_qp, sh) != null) {
            score += 1.0;
            tl.add("URL_SHORTENER");
            break;
        }
    }

    // Hidden HTML text (common in image-spam / cloaking). QP-decoded view:
    // markup must be intact (not tag-stripped) but soft breaks unsplit.
    if (containsAnyIgnoreCase(scan_qp, &.{ "display:none", "visibility:hidden", "font-size:0", "font-size: 0px" })) {
        score += 1.5;
        tl.add("HTML_HIDDEN_TEXT");
    }

    // Dangerous executable attachment. Inspect only declared MIME filenames
    // (`name=` / `filename=` parameters), never the raw body: a body-wide
    // substring scan matches ordinary links such as href="https://hetzner.com"
    // against ".com", which false-flagged nearly every HTML newsletter.
    const scan_attach = body[0..@min(body.len, 65536)];
    if (hasDangerousAttachment(scan_attach)) {
        score += 2.5;
        tl.add("DANGEROUS_ATTACHMENT");
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

fn startsWithCI(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..needle.len], needle);
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

test "bare-domain link is not a dangerous attachment" {
    const headers = "From: Hetzner <support-cloud@hetzner.com>\nSubject: Invoice\nDate: d\nMessage-ID: <1@hetzner.com>";
    // A newsletter that links to the sender's homepage — the old body-wide
    // scan matched ".com\"" here and false-flagged DANGEROUS_ATTACHMENT.
    const body = "<html><body><a href=\"https://www.hetzner.com\">Home</a> " ++
        "and <a href='https://cloud.hetzner.com/'>Console</a></body></html>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "DANGEROUS_ATTACHMENT") == null);
}

test "dkim fail is not scored when dmarc passes" {
    const headers = "From: Stripe <notifications@stripe.com>\nSubject: Receipt\nDate: d\nMessage-ID: <1@stripe.com>";
    // Real Stripe/SES shape: spf=pass, one DKIM signature fails to verify, but
    // the aligned signature yields dmarc=pass. Must not accrue DKIM_FAIL.
    const r = evaluate(.{ .spf = .pass, .dkim = .fail, .dmarc = .pass }, headers, "hi\n", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "DKIM_FAIL") == null);
    try std.testing.expect(r.score < 5.0);
    try std.testing.expectEqual(Disposition.accept, r.disposition);
}

test "dkim fail still scores when dmarc does not pass" {
    const headers = "From: x@y.example\nSubject: hi\nDate: d\nMessage-ID: <1@y>";
    const r = evaluate(.{ .spf = .neutral, .dkim = .fail, .dmarc = .none }, headers, "hi\n", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "DKIM_FAIL") != null);
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

test "unsolicited SEO pitch from a free provider lands in Junk" {
    const headers =
        "From: Rekha <seo.services@outlook.com>\n" ++
        "Subject: Website Fix\n" ++
        "Date: Mon, 29 Jun 2026 10:00:00 +0000\n" ++
        "Message-ID: <1@outlook.com>";
    const body = "Hello, I am a Web Developer offering website design and website development, " ++
        "including a complete redesign of your existing website. Please share your mobile number.";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SEO_SOLICITATION") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "FREEMAIL_OUTREACH") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "CONTACT_HARVEST") != null);
    try std.testing.expectEqual(Disposition.junk, r.disposition);
}

test "fabricated reply prefix without thread headers is flagged" {
    const headers =
        "From: Lucy <lucy@lexxdigital.com>\n" ++
        "Subject: Re: Hi,\n" ++
        "Date: Mon, 29 Jun 2026 10:00:00 +0000\n" ++
        "Message-ID: <1@lexxdigital.com>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass }, headers, "hi\n", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "FAKE_REPLY") != null);
}

test "genuine reply with In-Reply-To is not a fake reply" {
    const headers =
        "From: Bob <bob@example.com>\n" ++
        "Subject: Re: project update\n" ++
        "In-Reply-To: <prev@example.com>\n" ++
        "Date: Mon, 29 Jun 2026 10:00:00 +0000\n" ++
        "Message-ID: <2@example.com>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, "thanks!\n", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "FAKE_REPLY") == null);
}

test "brand name in display with unrelated domain is brand spoofing" {
    const headers =
        "From: \"Netflix.com\" <l1xwv4u9@aqg.io>\n" ++
        "Subject: Membership will be canceled\n" ++
        "Date: Mon, 29 Jun 2026 10:00:00 +0000\n" ++
        "Message-ID: <1@aqg.io>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass }, headers, "update your payment\n", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "BRAND_SPOOF") != null);
}

test "legit brand mail from its own domain is not brand spoofing" {
    const headers =
        "From: Netflix <info@mailer.netflix.com>\n" ++
        "Subject: New shows this week\n" ++
        "Date: Mon, 29 Jun 2026 10:00:00 +0000\n" ++
        "Message-ID: <1@netflix.com>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, "watch now\n", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "BRAND_SPOOF") == null);
}

test "real-world app-dev cold outreach (QP, outlook freemail) lands in Junk" {
    // Reconstruction of a live miss: scored 1.5 (HTML_HIDDEN_TEXT only)
    // before the outreach/app-dev rules and QP decoding existed.
    const headers =
        "From: Ekta Pandey <ektapandey856@outlook.com>\n" ++
        "To: <info@example.com>\n" ++
        "Subject: Building a new app !!\n" ++
        "Date: Sat, 4 Jul 2026 05:11:19 +0000\n" ++
        "Message-ID: <CH2PR04MB7112@outlook.com>";
    const body =
        "Content-Type: text/plain; charset=\"Windows-1252\"\r\n" ++
        "Content-Transfer-Encoding: quoted-printable\r\n" ++
        "\r\n" ++
        "Hello,\r\n" ++
        "Just checking =97 are you interested in building a mobile app?\r\n" ++
        "If yes, I can send you:\r\n" ++
        "  *   Estimated cost\r\n" ++
        "  *   Timeline\r\n" ++
        "  *   Feature suggestions\r\n" ++
        "Let me know, and I=92ll share the details.\r\n" ++
        "Regards,\r\n" ++
        "Business Development Manager\r\n" ++
        "\r\n" ++
        "<style type=3D\"text/css\" style=3D\"display:none;\"> P {margin-top:0;} </style>\r\n";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "OUTREACH_PITCH") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SEO_SOLICITATION") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "FREEMAIL_OUTREACH") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SUBJ_EXCLAIM") != null);
    try std.testing.expectEqual(Disposition.junk, r.disposition);
}

test "QP soft line break cannot split a phrase" {
    const headers = "From: x@gmail.com\nTo: a@b\nSubject: hi\nDate: d\nMessage-ID: <1@g>";
    const body = "we do mobile app devel=\r\nopment and website des=\nign for you";
    const r = evaluate(.{ .spf = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SEO_SOLICITATION") != null);
}

test "base64-encoded MIME part cannot hide the pitch" {
    // "Are you interested in seo services? I can send you our price list on whatsapp"
    const b64 = "QXJlIHlvdSBpbnRlcmVzdGVkIGluIHNlbyBzZXJ2aWNlcz8gSSBjYW4gc2VuZCB5b3Ugb3VyIHByaWNlIGxpc3Qgb24gd2hhdHNhcHA=";
    const headers = "From: x@gmail.com\nTo: a@b\nSubject: hello\nDate: d\nMessage-ID: <1@g>";
    const body =
        "--boundary42\r\n" ++
        "Content-Type: text/html; charset=utf-8\r\n" ++
        "Content-Transfer-Encoding: base64\r\n" ++
        "\r\n" ++
        b64 ++ "\r\n" ++
        "--boundary42--\r\n";
    const r = evaluate(.{ .spf = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SEO_SOLICITATION") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "CONTACT_HARVEST") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "OUTREACH_PITCH") != null);
}

test "encoded-word subject is decoded before subject heuristics" {
    // =?UTF-8?B?...?= of "WIN A FREE IPHONE RIGHT NOW!!"
    const headers =
        "From: x@promo.example\nTo: a@b\n" ++
        "Subject: =?UTF-8?B?V0lOIEEgRlJFRSBJUEhPTkUgUklHSFQgTk9XISE=?=\n" ++
        "Date: d\nMessage-ID: <1@p>";
    const r = evaluate(.{ .spf = .pass }, headers, "", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SUBJ_ALL_CAPS") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SUBJ_EXCLAIM") != null);
}

test "html entities cannot split a phrase" {
    const headers = "From: x@gmail.com\nTo: a@b\nSubject: hi\nDate: d\nMessage-ID: <1@g>";
    const body = "<div>we offer mobile&nbsp;app development at an affordable&nbsp;price</div>";
    const r = evaluate(.{ .spf = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SEO_SOLICITATION") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "OUTREACH_PITCH") != null);
}

test "undisclosed recipients is flagged" {
    const headers = "From: x@y.example\nTo: undisclosed-recipients:;\nSubject: hi\nDate: d\nMessage-ID: <1@y>";
    const r = evaluate(.{ .spf = .pass }, headers, "hello\n", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "UNDISCLOSED_RCPTS") != null);
}

test "friendly mail using one outreach phrase is not junked" {
    const headers =
        "From: Sam <sam@gmail.com>\nTo: info@example.com\n" ++
        "Subject: coffee next week?\nDate: d\nMessage-ID: <7@g>";
    const body = "Hey! We met at the conference last month — are you interested in grabbing coffee next week?";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expectEqual(Disposition.accept, r.disposition);
}

test "personal testimony from a free provider is not junked" {
    const headers =
        "From: A Witness <witness2024@gmail.com>\nTo: info@example.com\n" ++
        "Subject: my experience\nDate: d\nMessage-ID: <8@g>";
    const body = "Hi, I found your site. I worked there in 2024 and experienced " ++
        "similar treatment. I can share more details if that helps — let me know how.";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expectEqual(Disposition.accept, r.disposition);
    try std.testing.expectEqual(@as(f32, 0), r.score);
}

test "a single website mention from gmail does not junk legit mail" {
    const headers =
        "From: Jamie <jamie@gmail.com>\n" ++
        "Subject: question about your site\n" ++
        "Date: Mon, 29 Jun 2026 10:00:00 +0000\n" ++
        "Message-ID: <9@gmail.com>";
    const body = "Hi, I noticed a broken link on your existing website's contact page. Thought you'd want to know.";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expectEqual(Disposition.accept, r.disposition);
}
