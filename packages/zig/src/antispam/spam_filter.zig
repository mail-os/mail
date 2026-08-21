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
const ascii_compat = @import("ascii-compat");

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
    ".js",  ".jar", ".cpl", ".lnk", ".iso", ".hta", ".msi",
    ".reg", ".ps1", ".wsf", ".chm", ".img",
};

fn hasDangerousSuffix(value: []const u8) bool {
    for (dangerous_exts) |ext| {
        if (value.len >= ext.len and
            std.ascii.eqlIgnoreCase(value[value.len - ext.len ..], ext)) return true;

        // RFC 2231 filenames commonly percent-encode the dot, e.g.
        // filename*=UTF-8''invoice%2Eexe.
        if (value.len >= ext.len + 2 and value[value.len - ext.len - 2] == '%') {
            const hi = hexVal(value[value.len - ext.len - 1]) orelse continue;
            const lo = hexVal(value[value.len - ext.len]) orelse continue;
            if ((hi << 4) | lo == '.' and
                std.ascii.eqlIgnoreCase(value[value.len - ext.len + 1 ..], ext[1..])) return true;
        }
    }
    return false;
}

/// True if a MIME `name=` / `filename=` parameter declares a file whose
/// extension is in `dangerous_exts`. Only the parameter *value* is examined,
/// so link URLs in the body (e.g. `href="https://example.com"`) cannot
/// false-match a bare extension like ".com". Matching `name=` also covers
/// `filename=` since that string ends in `name=`.
fn hasDangerousAttachment(scan: []const u8) bool {
    const markers = [_][]const u8{ "name=", "name*=" };
    for (markers) |marker| {
        var pos: usize = 0;
        while (ascii_compat.indexOfIgnoreCasePos(scan, pos, marker)) |at| {
            var v = at + marker.len;
            pos = v;
            if (v < scan.len and (scan[v] == '"' or scan[v] == '\'')) v += 1;
            var end = v;
            while (end < scan.len) : (end += 1) {
                const c = scan[end];
                if (c == '"' or c == ';' or c == '\r' or c == '\n' or c == ' ') break;
            }
            if (hasDangerousSuffix(scan[v..end])) return true;
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
    "search engine optimization",  "seo service",            "seo services",                 "seo package",
    "seo expert",                  "seo company",            "seo agency",                   "1st page of google",
    "first page of google",        "top of google",          "page of google",               "google ranking",
    "search ranking",              "increase your ranking",  "improve your ranking",         "rank higher",
    "higher ranking",              "website traffic",        "organic traffic",              "increase traffic",
    "website visibility",          "visibility on google",   "optimized for search engines", "improving rankings",
    "website ranking",             "errors at your website", "website errors",               "fix errors",
    "screenshots of these errors", "website design",         "web design service",           "website development",
    "web development",             "web developer",          "website redesign",             "redesign of your",
    "redesign your website",       "revamp your website",    "existing website",             "build your website",
    "backlink",                    "link building",          "guest post",                   "domain authority",
    "digital marketing",           "lead generation",        "se0",
    // App-development pitches, the sibling of the SEO pitch ("interested in
    // building a mobile app?"). Same bigram discipline: no bare "app".
                             "mobile app",
    "app development",             "app developer",          "application development",      "build an app",
    "building an app",             "develop an app",         "ios and android",              "android and ios",
    "app idea",
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

/// A brand that phishing impersonates, plus every domain that legitimately
/// speaks for it. `check_links` marks tokens distinctive enough to be searched
/// for as a *substring* of a link hostname (see `hasBrandLinkMismatch`);
/// short or compound-prone names ("apple" in `pineapple.com`, "ups" in
/// `groups.google.com`, "amazon" in `amazonia.example`) stay out of that scan
/// and are only ever word-matched.
const Brand = struct {
    name: []const u8,
    domains: []const []const u8,
    check_links: bool = true,
};

/// Brands commonly impersonated in the From display-name or Subject. Consumer
/// services, plus the registrar / hosting / DNS brands that "your domain has
/// expired" phishing wears — those lures address the one recipient class that
/// definitely owns a domain, so they are over-represented on a technical inbox.
const impersonated_brands = [_]Brand{
    .{ .name = "netflix", .domains = &.{"netflix.com"} },
    .{ .name = "paypal", .domains = &.{"paypal.com"} },
    .{ .name = "amazon", .domains = &.{ "amazon.com", "amazonses.com", "amazonaws.com" }, .check_links = false },
    .{ .name = "apple", .domains = &.{ "apple.com", "icloud.com" }, .check_links = false },
    .{ .name = "microsoft", .domains = &.{ "microsoft.com", "microsoftonline.com", "office.com" } },
    .{ .name = "coinbase", .domains = &.{"coinbase.com"} },
    .{ .name = "binance", .domains = &.{"binance.com"} },
    .{ .name = "metamask", .domains = &.{"metamask.io"} },
    .{ .name = "fedex", .domains = &.{"fedex.com"} },
    .{ .name = "norton", .domains = &.{"norton.com"} },
    .{ .name = "mcafee", .domains = &.{"mcafee.com"} },
    .{ .name = "docusign", .domains = &.{ "docusign.com", "docusign.net" } },
    .{ .name = "dropbox", .domains = &.{"dropbox.com"} },
    .{ .name = "wetransfer", .domains = &.{"wetransfer.com"} },
    .{ .name = "linkedin", .domains = &.{ "linkedin.com", "licdn.com" } },
    .{ .name = "instagram", .domains = &.{"instagram.com"} },
    .{ .name = "quickbooks", .domains = &.{ "quickbooks.com", "intuit.com" } },
    // Registrars / hosts / DNS — the "domain expired" lure family.
    .{ .name = "porkbun", .domains = &.{"porkbun.com"} },
    .{ .name = "namecheap", .domains = &.{"namecheap.com"} },
    .{ .name = "godaddy", .domains = &.{"godaddy.com"} },
    .{ .name = "cloudflare", .domains = &.{ "cloudflare.com", "notify.cloudflare.com" } },
    .{ .name = "hostgator", .domains = &.{"hostgator.com"} },
    .{ .name = "bluehost", .domains = &.{"bluehost.com"} },
    .{ .name = "dynadot", .domains = &.{"dynadot.com"} },
    .{ .name = "gandi", .domains = &.{ "gandi.net", "gandi.link" }, .check_links = false },
    .{ .name = "squarespace", .domains = &.{"squarespace.com"} },
};

/// Expiry / suspension lures: the message claims something the recipient owns
/// is about to stop working. Half of the `EXPIRY_BRAND_PHISH` conjunction.
const expiry_phrases = [_][]const u8{
    "has expired",        "have expired",          "is expiring",
    "will expire",        "expires on",            "expired on",
    "expiration date",    "expiry date",           "about to expire",
    "has been suspended", "will be suspended",     "will be deactivated",
    "will be terminated", "will be deleted",       "has been locked",
    "no longer active",   "scheduled for removal",
};

/// The other half: the "fix it now" call to action every expiry lure carries.
const restore_cta_phrases = [_][]const u8{
    "renew",               "reactivate",           "restore your",
    "back online",         "update your billing",  "update your payment",
    "verify your account", "confirm your account", "avoid suspension",
    "avoid interruption",  "avoid deactivation",   "reclaim",
};

/// A From display-name is an identity, not a claim. Real senders put their
/// name or brand there and the alarm in the Subject; phishing puts the alarm
/// in the display-name itself ("Your domain has expired" <info@unrelated.cz>)
/// because that is the line every mail client renders largest.
const display_lure_phrases = [_][]const u8{
    "expired",        "expiring",         "suspended",      "suspension",
    "deactivated",    "action required",  "payment failed", "payment declined",
    "security alert", "unusual activity", "account locked", "final notice",
    "past due",       "overdue",          "verify your",    "confirm your",
};

/// Reserved / non-routable TLDs (RFC 2606, RFC 6762, RFC 8375). Mail arriving
/// from the internet can never legitimately carry a From address in one of
/// these — the domain is unresolvable outside a private network, so the
/// address is unreplyable by construction. `.example` is deliberately absent:
/// it is the documentation TLD used by this project's own test fixtures.
const bogus_tlds = [_][]const u8{
    ".local",     ".localdomain", ".localhost", ".lan",  ".home",
    ".home.arpa", ".internal",    ".intranet",  ".corp", ".private",
    ".invalid",   ".test",
};

/// Parcel-fee phishing impersonates a carrier while sending from an unrelated,
/// but often perfectly SPF/DKIM/DMARC-authenticated, compromised domain.  It is
/// important that these are conjunctions: ordinary shipment notices mention a
/// carrier, and ordinary invoices mention payment, but the scam stacks several
/// urgent fee/payment prompts while claiming a carrier identity.
const carriers = [_]struct { brand: []const u8, domain: []const u8 }{
    .{ .brand = "dhl", .domain = "dhl.com" },
    .{ .brand = "fedex", .domain = "fedex.com" },
    .{ .brand = "ups", .domain = "ups.com" },
    .{ .brand = "usps", .domain = "usps.com" },
};
const parcel_phrases = [_][]const u8{
    "shipment held", "shipment release", "customs documentation",
    "customs fee",   "final delivery",   "local facility",
};
const payment_phrases = [_][]const u8{
    "fee required",         "fee must be paid", "amount due",
    "awaiting payment",     "make payment",     "payment information",
    "complete the process", "release fee",
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
        .{ .name = "&#32;", .ch = ' ' },
        .{ .name = "&#x20;", .ch = ' ' },
        .{ .name = "&#X20;", .ch = ' ' },
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
        // Zero-width Unicode characters and their common HTML encodings are
        // invisible in clients but otherwise split phrases such as "pay​ment".
        const zero_width = [_][]const u8{ "\xE2\x80\x8B", "\xE2\x80\x8C", "\xE2\x80\x8D", "&#8203;", "&#x200b;", "&#x200B;" };
        var skipped_zero_width = false;
        for (zero_width) |zw| {
            if (std.mem.startsWith(u8, in[i..], zw)) {
                i += zw.len;
                skipped_zero_width = true;
                break;
            }
        }
        if (skipped_zero_width) continue;
        if (c == '<') {
            if (std.ascii.startsWithIgnoreCase(in[i..], "<style")) {
                if (ascii_compat.indexOfIgnoreCase(in[i..], "</style")) |rel| {
                    const close = i + rel;
                    i = if (std.mem.indexOfScalarPos(u8, in, close, '>')) |gt| gt + 1 else in.len;
                } else i = in.len;
            } else if (std.ascii.startsWithIgnoreCase(in[i..], "<script")) {
                if (ascii_compat.indexOfIgnoreCase(in[i..], "</script")) |rel| {
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
fn decodeBase64Parts(window: []const u8, out: []u8) []const u8 {
    const marker = "content-transfer-encoding:";
    var search: usize = 0;
    var out_len: usize = 0;
    while (search < window.len) {
        const rel = ascii_compat.indexOfIgnoreCase(window[search..], marker) orelse break;
        const vstart = search + rel + marker.len;
        const line_end = std.mem.indexOfScalarPos(u8, window, vstart, '\n') orelse window.len;
        if (ascii_compat.indexOfIgnoreCase(window[vstart..line_end], "base64") == null) {
            search = @min(line_end + 1, window.len);
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
        search = @min(p + 1, window.len);
        n -= n % 4; // drop a trailing partial quantum (window cut mid-line)
        if (n == 0) continue;
        const dec_len = std.base64.standard.Decoder.calcSizeForSlice(collected[0..n]) catch continue;
        if (dec_len > out.len - out_len) break;
        std.base64.standard.Decoder.decode(out[out_len .. out_len + dec_len], collected[0..n]) catch continue;
        out_len += dec_len;
        if (out_len < out.len) {
            out[out_len] = '\n';
            out_len += 1;
        }
    }
    return out[0..out_len];
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
    var subj_raw_buf: [1024]u8 = undefined;
    var subj_buf: [1024]u8 = undefined;
    const subject_raw = headerValueUnfolded(headers, "Subject", &subj_raw_buf);
    const subject: ?[]const u8 = if (subject_raw) |s| decodeEncodedWords(s, &subj_buf) else null;
    var from_raw_buf: [1024]u8 = undefined;
    var from_decoded_buf: [1024]u8 = undefined;
    const from_raw = headerValueUnfolded(headers, "From", &from_raw_buf);
    const from_decoded: ?[]const u8 = if (from_raw) |s| decodeEncodedWords(s, &from_decoded_buf) else null;
    const from_domain = if (from_raw) |s| domainOfHeaderValue(s) else null;
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
        if (ascii_compat.indexOfIgnoreCase(to_v, "undisclosed") != null) {
            score += 1.5;
            tl.add("UNDISCLOSED_RCPTS");
        }
    }

    // Brand spoofing in the From display-name (phishing): the visible name
    // claims a consumer brand the sending domain has nothing to do with
    // (e.g. `"Netflix.com" <l1xwv4u9@aqg.io>`). Independent of DMARC — the
    // display name is never authenticated even when the domain's DMARC passes.
    const display_name: ?[]const u8 = if (from_decoded) |from_hdr| blk: {
        const disp_end = std.mem.indexOfScalar(u8, from_hdr, '<') orelse from_hdr.len;
        break :blk std.mem.trim(u8, from_hdr[0..disp_end], " \t\"'");
    } else null;
    if (display_name) |display| {
        for (impersonated_brands) |brand| {
            // Word-matched: a substring test flags "Pineapple Farms" as Apple.
            if (!containsWordIgnoreCase(display, brand.name)) continue;
            const dom_is_brand = if (from_domain) |fd|
                domainMatchesAny(fd, brand.domains)
            else
                false;
            if (!dom_is_brand) {
                score += 4.0;
                tl.add("BRAND_SPOOF");
            }
            break;
        }
        // The display-name is a warning rather than an identity.
        if (containsAnyIgnoreCase(display, &display_lure_phrases)) {
            score += 3.0;
            tl.add("DISPLAY_NAME_LURE");
        }
    }

    // A From address in a reserved / non-routable TLD cannot have come from a
    // real correspondent: the domain does not exist outside somebody's LAN, so
    // the address can never be replied to. Bulk senders hit this when they
    // blast straight out of a misconfigured appliance.
    if (from_domain) |fd| {
        if (isBogusTld(fd)) {
            score += 4.0;
            tl.add("SENDER_BOGUS_TLD");
        }
    }

    // From / Reply-To domain mismatch (only when DMARC didn't already pass).
    if (signals.dmarc != .pass) {
        var reply_raw_buf: [1024]u8 = undefined;
        const reply_raw = headerValueUnfolded(headers, "Reply-To", &reply_raw_buf);
        const reply_domain = if (reply_raw) |s| domainOfHeaderValue(s) else null;
        if (from_domain != null and reply_domain != null and
            !std.ascii.eqlIgnoreCase(from_domain.?, reply_domain.?))
        {
            score += 0.7;
            tl.add("REPLYTO_MISMATCH");
        }
    }

    // Phrase + structural body heuristics (scan subject + start of body).
    // A larger bounded window prevents trivial padding (large comments/style
    // blocks before the pitch) from pushing content beyond the old 8 KiB scan.
    const scan_body = body[0..@min(body.len, 16384)];

    // Phrase scans run on a NORMALIZED view of the body, not the raw bytes:
    // quoted-printable is decoded (soft breaks rejoin split phrases), HTML
    // markup/entities are stripped, whitespace is collapsed, and a
    // base64-encoded MIME part is decoded and appended. Raw-byte scans stay
    // raw where the markup itself is the signal (URLs, hidden-text CSS,
    // attachment filenames).
    var qp_buf: [16384]u8 = undefined;
    var text_buf: [16384]u8 = undefined;
    var b64_buf: [12288]u8 = undefined;
    var b64_text_buf: [12288]u8 = undefined;
    const scan_qp = decodeQuotedPrintable(scan_body, &qp_buf);
    const scan_text = stripHtmlText(scan_qp, &text_buf);
    const b64_part = decodeBase64Parts(scan_body, &b64_buf);
    const b64_text = if (b64_part.len > 0) stripHtmlText(b64_part, &b64_text_buf) else b64_part;

    const Scan = struct {
        subject: ?[]const u8,
        text: []const u8,
        b64: []const u8,
        fn hit(self: @This(), phrase: []const u8) bool {
            if (self.subject) |s| {
                if (ascii_compat.indexOfIgnoreCase(s, phrase) != null) return true;
            }
            if (ascii_compat.indexOfIgnoreCase(self.text, phrase) != null) return true;
            return self.b64.len > 0 and ascii_compat.indexOfIgnoreCase(self.b64, phrase) != null;
        }
    };
    const scan = Scan{ .subject = subject, .text = scan_text, .b64 = b64_text };

    // Authenticated-domain parcel phishing. DMARC proves only that the sender
    // controls (or compromised) its own domain; it does not make a claim to be
    // DHL/FedEx/UPS/USPS legitimate. Require a carrier/domain mismatch plus a
    // parcel phrase and at least two payment prompts to keep real tracking and
    // invoice messages out of Junk.
    var claimed_carrier: ?@TypeOf(carriers[0]) = null;
    for (carriers) |carrier| {
        if (scanHitWord(scan, carrier.brand)) {
            claimed_carrier = carrier;
            break;
        }
    }
    var parcel_hits: usize = 0;
    for (parcel_phrases) |phrase| {
        if (scan.hit(phrase)) parcel_hits += 1;
    }
    var payment_hits: usize = 0;
    for (payment_phrases) |phrase| {
        if (scan.hit(phrase)) payment_hits += 1;
    }
    if (claimed_carrier) |carrier| {
        const from_matches = if (from_domain) |fd|
            domainIsOrSubdomain(fd, carrier.domain)
        else
            false;
        if (!from_matches and parcel_hits > 0 and payment_hits >= 2) {
            score += 6.0;
            tl.add("CARRIER_PAYMENT_PHISH");
        }
    }

    // Brand impersonation, second angle: the payload link. Scanned on views
    // that still carry markup (`scan_qp`, and the raw base64-decoded part) —
    // `scan_text` has had its tags, and therefore its hrefs, stripped.
    if (hasBrandLinkMismatch(scan_qp) or
        (b64_part.len > 0 and hasBrandLinkMismatch(b64_part)))
    {
        score += 5.0;
        tl.add("BRAND_LINK_MISMATCH");
    }

    // "Your domain has expired — renew now": an expiry/suspension lure wearing
    // a brand the sender demonstrably is not. All three legs are required, and
    // the brand claim must sit in the Subject or the From display-name (an
    // identity position) rather than anywhere in the body — otherwise a
    // newsletter that merely discusses Cloudflare and mentions a renewal would
    // score. A real registrar's own renewal notice is exempt because it sends
    // from the brand's domain.
    var claimed_brand: ?Brand = null;
    for (impersonated_brands) |b| {
        const in_subject = if (subject) |s| containsWordIgnoreCase(s, b.name) else false;
        const in_display = if (display_name) |d| containsWordIgnoreCase(d, b.name) else false;
        if (in_subject or in_display) {
            claimed_brand = b;
            break;
        }
    }
    if (claimed_brand) |b| {
        const from_is_brand = if (from_domain) |fd| domainMatchesAny(fd, b.domains) else false;
        if (!from_is_brand) {
            // The Subject wears the brand as a sender identity ("MetaMask:
            // Action Required", or a bare "Porkbun") while the address behind
            // it belongs to somebody else. Distinct from a passing mention:
            // "Re: your Apple Developer agreement" is a human talking *about*
            // a brand and never matches, because the brand must lead the
            // subject and be followed by a separator or nothing at all.
            if (subject) |s| {
                if (subjectClaimsBrand(s, b.name)) {
                    score += 4.0;
                    tl.add("BRAND_SUBJECT_SPOOF");
                }
            }
            var expiry_hit = false;
            for (expiry_phrases) |p| {
                if (scan.hit(p)) {
                    expiry_hit = true;
                    break;
                }
            }
            var cta_hit = false;
            for (restore_cta_phrases) |p| {
                if (scan.hit(p)) {
                    cta_hit = true;
                    break;
                }
            }
            if (expiry_hit and cta_hit) {
                score += 6.0;
                tl.add("EXPIRY_BRAND_PHISH");
            }
        }
    }

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
        if (from_domain) |fd| {
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
    const url_count = countOccurrencesIgnoreCase(scan_qp, "http://") +
        countOccurrencesIgnoreCase(scan_qp, "https://") +
        countOccurrencesIgnoreCase(b64_part, "http://") +
        countOccurrencesIgnoreCase(b64_part, "https://");
    if (url_count >= 20) {
        score += 1.5;
        tl.add("MANY_URLS");
    }
    for (url_shorteners) |sh| {
        if (ascii_compat.indexOfIgnoreCase(scan_qp, sh) != null) {
            score += 1.0;
            tl.add("URL_SHORTENER");
            break;
        }
    }

    // Hidden HTML text is a cloaking / image-spam signal, but a *single* hidden
    // declaration is ubiquitous in legitimate mail — the inbox-preview
    // "preheader" span, Outlook's `display:none` margin resets, and responsive
    // show/hide blocks. Two guards keep it from nickel-and-diming real
    // newsletters (Stripe, SingleStore, …) into Junk: DMARC-authenticated mail
    // is exempt (an accountable sender), and unauthenticated mail must hide in
    // bulk (cloaking stacks many declarations; a lone preheader does not).
    // QP-decoded view: markup intact (not tag-stripped) but soft breaks unsplit.
    if (signals.dmarc != .pass) {
        const hidden_markers = [_][]const u8{
            "display:none",      "display: none",
            "visibility:hidden", "visibility: hidden",
            "font-size:0",       "font-size: 0",
        };
        var hidden_hits: usize = 0;
        for (hidden_markers) |m| hidden_hits += countOccurrencesIgnoreCase(scan_qp, m);
        if (hidden_hits >= 2) {
            score += 1.5;
            tl.add("HTML_HIDDEN_TEXT");
        }
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

/// Return a header value with RFC 5322 continuation lines unfolded into a
/// caller-owned buffer. This closes a common evasion where a spam phrase is
/// split immediately after `Subject:` onto a whitespace-prefixed line.
fn headerValueUnfolded(headers: []const u8, name: []const u8, out: []u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, headers, '\n');
    var found = false;
    var len: usize = 0;
    while (it.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (!found) {
            if (line.len < name.len + 1 or
                !std.ascii.eqlIgnoreCase(line[0..name.len], name) or
                line[name.len] != ':') continue;
            const value = std.mem.trim(u8, line[name.len + 1 ..], " \t");
            const n = @min(value.len, out.len);
            @memcpy(out[0..n], value[0..n]);
            len = n;
            found = true;
            continue;
        }
        if (line.len == 0 or (line[0] != ' ' and line[0] != '\t')) break;
        const continuation = std.mem.trim(u8, line, " \t");
        if (continuation.len == 0 or len >= out.len) continue;
        if (len > 0) {
            out[len] = ' ';
            len += 1;
        }
        const n = @min(continuation.len, out.len - len);
        @memcpy(out[len .. len + n], continuation[0..n]);
        len += n;
    }
    return if (found) out[0..len] else null;
}

pub fn headerPresent(headers: []const u8, name: []const u8) bool {
    return headerValue(headers, name) != null;
}

/// Domain portion of an address-bearing header (e.g. From, Reply-To).
fn headerDomain(headers: []const u8, name: []const u8) ?[]const u8 {
    const v = headerValue(headers, name) orelse return null;
    return domainOfHeaderValue(v);
}

fn domainOfHeaderValue(v: []const u8) ?[]const u8 {
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

fn domainIsOrSubdomain(domain: []const u8, expected: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(domain, expected)) return true;
    return domain.len > expected.len and
        domain[domain.len - expected.len - 1] == '.' and
        std.ascii.eqlIgnoreCase(domain[domain.len - expected.len ..], expected);
}

/// True when `domain` is one of `list`, or a subdomain of one of them.
fn domainMatchesAny(domain: []const u8, list: []const []const u8) bool {
    for (list) |d| {
        if (domainIsOrSubdomain(domain, d)) return true;
    }
    return false;
}

fn isBogusTld(domain: []const u8) bool {
    for (bogus_tlds) |tld| {
        if (domain.len > tld.len and
            std.ascii.eqlIgnoreCase(domain[domain.len - tld.len ..], tld)) return true;
    }
    return false;
}

/// Extract the host of the http(s) URL whose `://` sits at `at`, or null when
/// the scheme is not http/https. Userinfo and port are stripped.
fn urlHostAt(text: []const u8, at: usize) ?[]const u8 {
    const https = at >= 5 and std.ascii.eqlIgnoreCase(text[at - 5 .. at], "https");
    const http = at >= 4 and std.ascii.eqlIgnoreCase(text[at - 4 .. at], "http");
    if (!https and !http) return null;
    var end = at + 3;
    while (end < text.len) : (end += 1) {
        switch (text[end]) {
            '/', '?', '#', '"', '\'', '<', '>', ' ', '\t', '\r', '\n', ')', ',', ';' => break,
            else => {},
        }
    }
    var host = text[at + 3 .. end];
    if (std.mem.lastIndexOfScalar(u8, host, '@')) |a| host = host[a + 1 ..];
    if (std.mem.indexOfScalar(u8, host, ':')) |c| host = host[0..c];
    return if (host.len == 0) null else host;
}

/// A link whose *hostname* embeds a brand token while its registrable domain
/// belongs to somebody else — `https://sslporkbunvalid.ros-ohrana.ru/` on a
/// message wearing Porkbun's logo. This is the single most reliable phishing
/// tell available without a URL reputation feed, and it is orthogonal to
/// authentication: the sending domain can be perfectly SPF/DKIM/DMARC-aligned
/// (it usually is, being compromised) and the payload link still gives it away.
/// Only the host is inspected, never the path, so `twitter.com/Porkbun` and
/// other legitimate profile links do not match.
fn hasBrandLinkMismatch(text: []const u8) bool {
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, text, i, "://")) |at| {
        i = at + 3;
        const host = urlHostAt(text, at) orelse continue;
        for (impersonated_brands) |b| {
            if (!b.check_links) continue;
            if (ascii_compat.indexOfIgnoreCase(host, b.name) == null) continue;
            if (!domainMatchesAny(host, b.domains)) return true;
        }
    }
    return false;
}

/// True when `subject` presents `brand` as the sender's identity: the brand is
/// the entire subject, or leads it and is followed by a separator. A brand
/// appearing anywhere else in the subject is ordinary correspondence about
/// that brand and deliberately does not match.
fn subjectClaimsBrand(subject: []const u8, brand: []const u8) bool {
    const s = std.mem.trim(u8, subject, " \t");
    if (s.len < brand.len) return false;
    if (!std.ascii.eqlIgnoreCase(s[0..brand.len], brand)) return false;
    const rest = std.mem.trimStart(u8, s[brand.len..], " \t");
    if (rest.len == 0) return true;
    return switch (rest[0]) {
        ':', '-', '|', '\xE2' => true, // ':' '-' '|' and the UTF-8 lead byte of an em/en dash
        else => false,
    };
}

fn isWordByte(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

fn containsWordIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    var pos: usize = 0;
    while (ascii_compat.indexOfIgnoreCasePos(haystack, pos, needle)) |at| {
        const before_ok = at == 0 or !isWordByte(haystack[at - 1]);
        const end = at + needle.len;
        const after_ok = end == haystack.len or !isWordByte(haystack[end]);
        if (before_ok and after_ok) return true;
        pos = at + 1;
    }
    return false;
}

fn scanHitWord(scan: anytype, word: []const u8) bool {
    if (scan.subject) |s| {
        if (containsWordIgnoreCase(s, word)) return true;
    }
    return containsWordIgnoreCase(scan.text, word) or
        (scan.b64.len > 0 and containsWordIgnoreCase(scan.b64, word));
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

fn countOccurrencesIgnoreCase(haystack: []const u8, needle: []const u8) usize {
    if (needle.len == 0) return 0;
    var count: usize = 0;
    var i: usize = 0;
    while (ascii_compat.indexOfIgnoreCasePos(haystack, i, needle)) |pos| {
        count += 1;
        i = pos + needle.len;
    }
    return count;
}

fn containsAnyIgnoreCase(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |n| {
        if (ascii_compat.indexOfIgnoreCase(haystack, n) != null) return true;
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

test "RFC 2231 encoded dangerous attachment is flagged" {
    const headers = "From: x@y.example\nSubject: invoice\nDate: d\nMessage-ID: <1@y>";
    const body = "Content-Disposition: attachment; filename*=UTF-8''invoice%2Eps1\n";
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

test "authenticated newsletter with a preheader is not flagged as hidden text" {
    const headers =
        "From: Stripe <notifications@stripe.com>\n" ++
        "Subject: Your receipt\n" ++
        "Date: Mon, 29 Jun 2026 10:00:00 +0000\n" ++
        "Message-ID: <1@stripe.com>";
    // A single inbox-preview preheader span — the ubiquitous legitimate case.
    const body = "<html><body><span style=\"display:none\">Receipt preview text</span>" ++
        "<p>Thanks for your payment.</p></body></html>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "HTML_HIDDEN_TEXT") == null);
    try std.testing.expectEqual(Disposition.accept, r.disposition);
}

test "bulk hidden text on unauthenticated mail is still flagged" {
    const headers =
        "From: x@spammy.example\nSubject: hi\nDate: d\nMessage-ID: <1@y>";
    // Keyword-stuffing / cloaking stacks many hidden declarations.
    const body = "<div style=\"display:none\">a</div><div style=\"display: none\">b</div>" ++
        "<span style=\"visibility:hidden\">c</span><i style=\"font-size:0\">d</i>";
    const r = evaluate(.{ .spf = .neutral, .dkim = .none, .dmarc = .none }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "HTML_HIDDEN_TEXT") != null);
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

test "real-world organic traffic follow-up lands in Junk" {
    const headers =
        "From: Ronit Roy <ronitroy17906@outlook.com>\n" ++
        "To: info@example.com\n" ++
        "Subject: Gentle Reminder.....\n" ++
        "Date: Mon, 6 Jul 2026 11:17:07 +0000\n" ++
        "Message-ID: <1@outlook.com>";
    const body =
        "Hi, Hope you're doing well. I wanted to follow up and see if you're interested in " ++
        "improving your website's visibility on Google. I can share details along with pricing. " ++
        "Many great websites struggle because they aren't properly optimized for search engines. " ++
        "We fix that - improving rankings, visibility, and conversions through data-driven SEO " ++
        "strategies. Would you like to explore how we can optimize your site? I can send our " ++
        "proposal and pricing.";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SEO_SOLICITATION") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "FREEMAIL_OUTREACH") != null);
    try std.testing.expectEqual(Disposition.junk, r.disposition);
}

test "real-world website ranking error pitch lands in Junk" {
    const headers =
        "From: Jessica <jessica@seopackagesprice.com>\n" ++
        "To: info@example.com\n" ++
        "Subject: Increase Web Reach\n" ++
        "Date: Mon, 6 Jul 2026 14:23:36 +0530\n" ++
        "Message-ID: <1@seopackagesprice.com>";
    const body =
        "Hi info@example.com, Greetings, I noticed some errors at your website ranking. " ++
        "I can help to fix errors for better Google ranking. " ++
        "May I send you screenshots of these errors? Sincerely, Jessica";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SEO_SOLICITATION") != null);
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

test "brand in lookalike sender domain does not bypass spoof detection" {
    const headers =
        "From: PayPal <billing@paypal-security.example>\n" ++
        "Subject: Account notice\nDate: d\nMessage-ID: <1@paypal-security.example>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, "review account", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "BRAND_SPOOF") != null);
}

test "encoded brand in folded From header is still detected" {
    const headers =
        "From: =?UTF-8?B?UGF5UGFs?=\n" ++
        " <billing@unrelated.example>\n" ++
        "Subject: Account notice\nDate: d\nMessage-ID: <1@unrelated.example>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, "review account", .{});
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

test "authenticated parcel payment phishing lands in Junk" {
    const headers =
        "From: Customs Department <random@blueoceancorp.com.vn>\n" ++
        "To: victim@example.com\n" ++
        "Subject: Shipment held - fee required\n" ++
        "Date: Thu, 9 Jul 2026 12:38:39 +0700\n" ++
        "Message-ID: <1@blueoceancorp.com.vn>";
    const body =
        "DHL Express Shipment Release Information. We received the customs documentation. " ++
        "A fee must be paid before final delivery. Total amount due $3.35. " ++
        "Status: Awaiting payment at the local facility. Make payment to complete the process.";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "CARRIER_PAYMENT_PHISH") != null);
    try std.testing.expectEqual(Disposition.junk, r.disposition);
}

test "legitimate carrier tracking notice is not parcel payment phishing" {
    const headers =
        "From: Shop <shipping@trusted-shop.example>\n" ++
        "To: customer@example.com\n" ++
        "Subject: Your order shipped\nDate: d\nMessage-ID: <1@trusted-shop.example>";
    const body = "DHL has your parcel. Track the shipment for the expected final delivery date.";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "CARRIER_PAYMENT_PHISH") == null);
    try std.testing.expectEqual(Disposition.accept, r.disposition);
}

test "legitimate carrier payment mail from carrier domain is not impersonation" {
    const headers =
        "From: DHL <billing@dhl.com>\nTo: customer@example.com\n" ++
        "Subject: Customs fee required\nDate: d\nMessage-ID: <1@dhl.com>";
    const body = "DHL shipment release: customs fee required, amount due, make payment.";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "CARRIER_PAYMENT_PHISH") == null);
    try std.testing.expectEqual(Disposition.accept, r.disposition);
}

test "UPS is matched as a word and not inside groups" {
    const headers =
        "From: Community <hello@community.example>\nTo: a@b\n" ++
        "Subject: Local groups\nDate: d\nMessage-ID: <1@community.example>";
    const body = "Our community groups discussed shipment release and amount due, then make payment.";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "CARRIER_PAYMENT_PHISH") == null);
}

test "folded subject is unfolded before scoring" {
    const headers =
        "From: x@promo.example\nTo: a@b\n" ++
        "Subject: Shipment held -\n\tfee required\n" ++
        "Date: d\nMessage-ID: <1@promo.example>";
    const body = "DHL shipment release, amount due, awaiting payment at the local facility.";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "CARRIER_PAYMENT_PHISH") != null);
}

test "content padded beyond eight KiB is still scanned" {
    const headers =
        "From: x@promo.example\nTo: a@b\nSubject: hello\nDate: d\nMessage-ID: <1@promo.example>";
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(std.testing.allocator);
    try body.appendNTimes(std.testing.allocator, 'x', 9000);
    try body.appendSlice(std.testing.allocator, " DHL shipment release fee required amount due awaiting payment");
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body.items, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "CARRIER_PAYMENT_PHISH") != null);
}

test "uppercase URL schemes count toward link farm" {
    const headers = "From: x@y.example\nSubject: links\nDate: d\nMessage-ID: <1@y>";
    const body = "HTTPS://a.test HTTPS://b.test HTTPS://c.test HTTPS://d.test HTTPS://e.test " ++
        "HTTPS://f.test HTTPS://g.test HTTPS://h.test HTTPS://i.test HTTPS://j.test " ++
        "HTTPS://k.test HTTPS://l.test HTTPS://m.test HTTPS://n.test HTTPS://o.test " ++
        "HTTPS://p.test HTTPS://q.test HTTPS://r.test HTTPS://s.test HTTPS://t.test";
    const r = evaluate(.{ .spf = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "MANY_URLS") != null);
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

test "a benign first base64 part cannot hide spam in a later part" {
    const headers = "From: x@gmail.com\nTo: a@b\nSubject: hello\nDate: d\nMessage-ID: <1@g>";
    const body =
        "--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" ++
        "SGVsbG8sIHRoaXMgaXMgYSBub3JtYWwgYWx0ZXJuYXRpdmUu\r\n" ++
        "--b\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n" ++
        "c2VvIHNlcnZpY2VzIG1vYmlsZSBhcHAgZGV2ZWxvcG1lbnQgcHJpY2UgbGlzdCB3aGF0c2FwcA==\r\n--b--\r\n";
    const r = evaluate(.{ .spf = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SEO_SOLICITATION") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "CONTACT_HARVEST") != null);
}

test "URLs in a base64 MIME part count toward link farm" {
    const headers = "From: x@y.example\nSubject: links\nDate: d\nMessage-ID: <1@y>";
    const body =
        "--b\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n" ++
        "aHR0cHM6Ly9hLnRlc3QgaHR0cHM6Ly9iLnRlc3QgaHR0cHM6Ly9jLnRlc3QgaHR0cHM6Ly9kLnRlc3QgaHR0cHM6Ly9lLnRlc3QgaHR0cHM6Ly9mLnRlc3QgaHR0cHM6Ly9nLnRlc3QgaHR0cHM6Ly9oLnRlc3QgaHR0cHM6Ly9pLnRlc3QgaHR0cHM6Ly9qLnRlc3QgaHR0cHM6Ly9rLnRlc3QgaHR0cHM6Ly9sLnRlc3QgaHR0cHM6Ly9tLnRlc3QgaHR0cHM6Ly9uLnRlc3QgaHR0cHM6Ly9vLnRlc3QgaHR0cHM6Ly9wLnRlc3QgaHR0cHM6Ly9xLnRlc3QgaHR0cHM6Ly9yLnRlc3QgaHR0cHM6Ly9zLnRlc3QgaHR0cHM6Ly90LnRlc3Q=\r\n--b--\r\n";
    const r = evaluate(.{ .spf = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "MANY_URLS") != null);
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

test "numeric HTML entities cannot split a phrase" {
    const headers = "From: x@gmail.com\nTo: a@b\nSubject: hi\nDate: d\nMessage-ID: <1@g>";
    const body = "we offer mobile&#32;app development and seo&#x20;services";
    const r = evaluate(.{ .spf = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SEO_SOLICITATION") != null);
}

test "zero-width Unicode cannot split a phrase" {
    const headers = "From: x@gmail.com\nTo: a@b\nSubject: hi\nDate: d\nMessage-ID: <1@g>";
    const body = "we offer mobile\xE2\x80\x8B app development and seo ser&#8203;vices";
    const r = evaluate(.{ .spf = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SEO_SOLICITATION") != null);
}

test "long subject is not truncated at 512 bytes" {
    var headers: std.ArrayList(u8) = .empty;
    defer headers.deinit(std.testing.allocator);
    try headers.appendSlice(std.testing.allocator, "From: x@y.example\nSubject: ");
    try headers.appendNTimes(std.testing.allocator, 'x', 600);
    try headers.appendSlice(std.testing.allocator, " viagra\nDate: d\nMessage-ID: <1@y>");
    const r = evaluate(.{ .spf = .pass }, headers.items, "", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SPAM_PHRASES") != null);
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

test "authenticated registrar-expiry phishing is rejected" {
    // Real message (2026-08-19): a compromised but fully SPF/DKIM/DMARC-passing
    // domain wearing Porkbun's identity. Every legacy rule scored it 0.0.
    const headers =
        "From: Your domain has expired <info@bebarefoot.cz>\n" ++
        "To: hi@stacksjs.com\n" ++
        "Subject: Porkbun\n" ++
        "Date: Wed, 19 Aug 2026 14:48:01 +0000\n" ++
        "Message-ID: <0@bebarefoot.cz>";
    const body =
        "<p><strong>Your domain has expired</strong></p>" ++
        "<p>The following Porkbun Domain expired on 22.08.2026:<br>" ++
        "Domain Name: stacksjs.com<br>Expiration Date: 22.08.2026<br>" ++
        "To get your domain back online, please visit the " ++
        "<a href=\"https://porkbun.com/panel\">Domains panel</a> of your Porkbun site.</p>" ++
        "<p><a href=\"https://sslporkbunvalid.ros-ohrana.ru/\">RENEW DOMAIN</a></p>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "DISPLAY_NAME_LURE") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "BRAND_LINK_MISMATCH") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "BRAND_SUBJECT_SPOOF") != null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "EXPIRY_BRAND_PHISH") != null);
    try std.testing.expectEqual(Disposition.reject, r.disposition);
}

test "a registrar's own expiry notice is not phishing" {
    const headers =
        "From: Porkbun Support <support@porkbun.com>\n" ++
        "Subject: Porkbun: your domain expires soon\n" ++
        "Date: Wed, 19 Aug 2026 14:48:01 +0000\n" ++
        "Message-ID: <1@porkbun.com>";
    const body =
        "<p>Your domain expires on 22.08.2026. " ++
        "<a href=\"https://porkbun.com/renew\">Renew</a> to keep it online.</p>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expectEqual(Disposition.accept, r.disposition);
    try std.testing.expectEqual(@as(f32, 0), r.score);
}

test "brand in a link path is not a link mismatch" {
    // Legitimate social links ("twitter.com/Porkbun") must not fire the rule —
    // only the hostname is inspected.
    const headers =
        "From: Newsletter <news@example.com>\n" ++
        "Subject: Weekly roundup\nDate: d\nMessage-ID: <2@example.com>";
    const body = "<a href=\"https://twitter.com/Porkbun\">us</a> " ++
        "<a href=\"https://www.facebook.com/PorkbunLLC/\">fb</a>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "BRAND_LINK_MISMATCH") == null);
}

test "brand subdomain of its own domain is not a link mismatch" {
    const headers =
        "From: Cloudflare <noreply@notify.cloudflare.com>\n" ++
        "Subject: [Action required] Verify your email address\nDate: d\nMessage-ID: <3@cloudflare.com>";
    const body = "<a href=\"https://dash.cloudflare.com/verify\">Verify</a>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expectEqual(Disposition.accept, r.disposition);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "BRAND_LINK_MISMATCH") == null);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "BRAND_SPOOF") == null);
}

test "a brand substring inside an unrelated host is not scanned" {
    // "apple" and "amazon" are excluded from the hostname substring scan
    // precisely so `pineapple.example` and `amazonia.example` stay clean.
    const headers =
        "From: Grocer <hi@example.com>\n" ++
        "Subject: Fruit delivery\nDate: d\nMessage-ID: <4@example.com>";
    const body = "<a href=\"https://pineapple-farms.example/order\">order</a>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "BRAND_LINK_MISMATCH") == null);
}

test "brand leading the subject with a separator is an identity claim" {
    const headers =
        "From: \"SUPPORT\" <u9qun8zq@uep.io>\n" ++
        "Subject: MetaMask: Action Required\nDate: d\nMessage-ID: <5@uep.io>";
    const r = evaluate(.{ .spf = .none, .dkim = .none, .dmarc = .none }, headers, "confirm your email\n", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "BRAND_SUBJECT_SPOOF") != null);
}

test "brand mentioned mid-subject is ordinary correspondence" {
    const headers =
        "From: Sam <sam@example.com>\n" ++
        "Subject: Re: your Apple Developer agreement\nDate: d\nMessage-ID: <6@example.com>\n" ++
        "In-Reply-To: <prev@example.com>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, "signed it, thanks\n", .{});
    try std.testing.expectEqual(Disposition.accept, r.disposition);
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "BRAND_SUBJECT_SPOOF") == null);
}

test "display name carrying the alarm instead of an identity is flagged" {
    const headers =
        "From: \"Payment Failed\" <billing@unrelated.example>\n" ++
        "Subject: Notice\nDate: d\nMessage-ID: <7@unrelated.example>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, "see attached\n", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "DISPLAY_NAME_LURE") != null);
}

test "an ordinary display name is not a lure" {
    const headers =
        "From: Turo Support <support@turo.com>\n" ++
        "Subject: Your support call\nDate: d\nMessage-ID: <8@turo.com>\n" ++
        "In-Reply-To: <prev@turo.com>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, "thanks for calling\n", .{});
    try std.testing.expectEqual(@as(f32, 0), r.score);
}

test "sender in a reserved TLD is flagged" {
    const headers =
        "From: Your domain has expired <contact@dcitsaqgvi.local>\n" ++
        "Subject: Notice\nDate: d\nMessage-ID: <9@dcitsaqgvi.local>";
    const r = evaluate(.{ .spf = .temperror, .dkim = .neutral, .dmarc = .temperror }, headers, "hello\n", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SENDER_BOGUS_TLD") != null);
}

test "a real TLD is not a reserved TLD" {
    const headers =
        "From: Alice <alice@localhost-services.com>\n" ++
        "Subject: Hi\nDate: d\nMessage-ID: <10@localhost-services.com>";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, "hello\n", .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "SENDER_BOGUS_TLD") == null);
}

test "base64 body cannot hide a brand link mismatch" {
    const headers =
        "From: Your domain has expired <info@compromised.example>\n" ++
        "Subject: Namecheap\nDate: d\nMessage-ID: <11@compromised.example>\n" ++
        "Content-Type: multipart/alternative; boundary=\"b\"";
    const body =
        "--b\n" ++
        "Content-Type: text/html; charset=\"utf-8\"\n" ++
        "Content-Transfer-Encoding: base64\n" ++
        "\n" ++
        // "<a href=\"https://namecheap-renew.attacker.example/\">renew</a>"
        "PGEgaHJlZj0iaHR0cHM6Ly9uYW1lY2hlYXAtcmVuZXcuYXR0YWNrZXIuZXhhbXBsZS8iPnJlbmV3PC9hPg==\n" ++
        "--b--\n";
    const r = evaluate(.{ .spf = .pass, .dkim = .pass, .dmarc = .pass }, headers, body, .{});
    try std.testing.expect(std.mem.indexOf(u8, r.tests(), "BRAND_LINK_MISMATCH") != null);
}
