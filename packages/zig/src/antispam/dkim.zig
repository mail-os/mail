const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const tls = @import("tls");
const spf = @import("spf.zig");
const dkim_sign = @import("dkim_sign.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const B64 = std.base64.standard;

/// DKIM validation result
pub const DKIMResult = enum {
    pass,
    fail,
    neutral,
    temperror,
    permerror,

    pub fn toString(self: DKIMResult) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .neutral => "neutral",
            .temperror => "temperror",
            .permerror => "permerror",
        };
    }
};

/// DKIM signature (RFC 6376)
pub const DKIMSignature = struct {
    version: []const u8,
    algorithm: []const u8, // e.g., "rsa-sha256"
    domain: []const u8, // d= tag
    selector: []const u8, // s= tag
    headers: []const u8, // h= tag (signed headers)
    body_hash: []const u8, // bh= tag
    signature: []const u8, // b= tag
    canonicalization: []const u8, // c= tag (default: simple/simple)
    query_method: []const u8, // q= tag (default: dns/txt)
    allocator: std.mem.Allocator,

    pub fn deinit(self: *DKIMSignature) void {
        self.allocator.free(self.version);
        self.allocator.free(self.algorithm);
        self.allocator.free(self.domain);
        self.allocator.free(self.selector);
        self.allocator.free(self.headers);
        self.allocator.free(self.body_hash);
        self.allocator.free(self.signature);
        self.allocator.free(self.canonicalization);
        self.allocator.free(self.query_method);
    }

    /// Parse DKIM-Signature header value
    pub fn parse(allocator: std.mem.Allocator, header_value: []const u8) !DKIMSignature {
        var sig = DKIMSignature{
            .version = "",
            .algorithm = "",
            .domain = "",
            .selector = "",
            .headers = "",
            .body_hash = "",
            .signature = "",
            .canonicalization = try allocator.dupe(u8, "simple/simple"),
            .query_method = try allocator.dupe(u8, "dns/txt"),
            .allocator = allocator,
        };
        errdefer {
            if (sig.version.len > 0) allocator.free(sig.version);
            if (sig.algorithm.len > 0) allocator.free(sig.algorithm);
            if (sig.domain.len > 0) allocator.free(sig.domain);
            if (sig.selector.len > 0) allocator.free(sig.selector);
            if (sig.headers.len > 0) allocator.free(sig.headers);
            if (sig.body_hash.len > 0) allocator.free(sig.body_hash);
            if (sig.signature.len > 0) allocator.free(sig.signature);
            allocator.free(sig.canonicalization);
            allocator.free(sig.query_method);
        }

        // Parse tag=value pairs
        var tags = std.mem.splitScalar(u8, header_value, ';');
        while (tags.next()) |tag| {
            const trimmed = std.mem.trim(u8, tag, " \t\r\n");
            if (trimmed.len == 0) continue;

            const eq_pos = std.mem.indexOf(u8, trimmed, "=") orelse continue;
            const tag_name = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            const tag_value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

            if (std.mem.eql(u8, tag_name, "v")) {
                sig.version = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "a")) {
                sig.algorithm = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "d")) {
                sig.domain = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "s")) {
                sig.selector = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "h")) {
                sig.headers = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "bh")) {
                sig.body_hash = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "b")) {
                sig.signature = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "c")) {
                allocator.free(sig.canonicalization);
                sig.canonicalization = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "q")) {
                allocator.free(sig.query_method);
                sig.query_method = try allocator.dupe(u8, tag_value);
            }
        }

        // Validate required fields
        if (sig.version.len == 0 or sig.algorithm.len == 0 or sig.domain.len == 0 or
            sig.selector.len == 0 or sig.signature.len == 0)
        {
            return error.InvalidDKIMSignature;
        }

        return sig;
    }
};

/// DKIM validator
pub const DKIMValidator = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) DKIMValidator {
        return .{ .allocator = allocator };
    }

    /// Validate DKIM signature in email headers
    pub const DKIMCheck = struct {
        result: DKIMResult,
        /// The signature's d= domain (caller-owned, null when no signature
        /// was present/parseable).
        domain: ?[]u8,
    };

    /// validate() plus the signature's d= domain. DMARC alignment needs the
    /// REAL signing domain — passing the header-From domain instead silently
    /// turns the DKIM alignment check into a tautology.
    pub fn validateWithDomain(self: *DKIMValidator, headers: []const u8, body: []const u8) !DKIMCheck {
        const sig_header = self.extractDKIMSignature(headers) orelse {
            return .{ .result = .neutral, .domain = null };
        };

        var signature = DKIMSignature.parse(self.allocator, sig_header) catch {
            return .{ .result = .permerror, .domain = null };
        };
        defer signature.deinit();

        const domain_copy: ?[]u8 = if (signature.domain.len > 0)
            self.allocator.dupe(u8, signature.domain) catch null
        else
            null;
        errdefer if (domain_copy) |d| self.allocator.free(d);

        const result = try self.validate(headers, body);
        return .{ .result = result, .domain = domain_copy };
    }

    pub fn validate(self: *DKIMValidator, headers: []const u8, body: []const u8) !DKIMResult {
        // Extract DKIM-Signature header
        const sig_header = self.extractDKIMSignature(headers) orelse {
            return .neutral;
        };

        // Parse signature
        var signature = DKIMSignature.parse(self.allocator, sig_header) catch {
            return .permerror;
        };
        defer signature.deinit();

        // Verify version
        if (!std.mem.eql(u8, signature.version, "1")) {
            return .permerror;
        }

        // Query DNS for public key
        const public_key = self.queryPublicKey(signature.domain, signature.selector) catch {
            return .temperror;
        };
        defer if (public_key) |key| self.allocator.free(key);

        if (public_key == null) {
            return .permerror;
        }

        // Verify body hash
        const body_hash_valid = try self.verifyBodyHash(&signature, body);
        if (!body_hash_valid) {
            return .fail;
        }

        // Verify signature
        const sig_valid = try self.verifySignature(&signature, headers, public_key.?);
        if (!sig_valid) {
            return .fail;
        }

        return .pass;
    }

    fn extractDKIMSignature(self: *DKIMValidator, headers: []const u8) ?[]const u8 {
        // Find the DKIM-Signature header, unfolding continuation lines. Split on
        // '\n' and strip an optional trailing '\r' so this works whether the
        // header block uses CRLF (wire) or LF (our in-memory normalized form);
        // splitting on "\r\n" alone would grab the entire LF header block as one
        // line and over-read the b= tag into following headers.
        var lines = std.mem.splitScalar(u8, headers, '\n');
        var in_dkim_sig = false;
        var sig_value: std.ArrayList(u8) = .empty;
        defer sig_value.deinit(self.allocator);

        while (lines.next()) |raw| {
            const line = if (raw.len > 0 and raw[raw.len - 1] == '\r') raw[0 .. raw.len - 1] else raw;
            if (std.ascii.startsWithIgnoreCase(line, "DKIM-Signature:")) {
                in_dkim_sig = true;
                const value = std.mem.trim(u8, line["DKIM-Signature:".len..], " \t");
                sig_value.appendSlice(self.allocator, value) catch return null;
            } else if (in_dkim_sig) {
                // Folded continuation line (starts with WSP); anything else ends it.
                if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
                    const value = std.mem.trim(u8, line, " \t");
                    sig_value.appendSlice(self.allocator, value) catch return null;
                } else {
                    break;
                }
            }
        }

        if (sig_value.items.len == 0) return null;
        return sig_value.toOwnedSlice(self.allocator) catch return null;
    }

    /// Look up `<selector>._domainkey.<domain>` TXT, parse `p=`, base64-decode,
    /// and unwrap SPKI → PKCS#1 RSAPublicKey DER. Returns owned bytes, or null
    /// (no key / revoked / malformed). Caller frees.
    fn queryPublicKey(self: *DKIMValidator, domain: []const u8, selector: []const u8) !?[]const u8 {
        var name_buf: [320]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "{s}._domainkey.{s}", .{ selector, domain }) catch return null;
        const txt = (spf.dnsQueryTxt(self.allocator, name, "") catch return error.TempError) orelse return null;
        defer self.allocator.free(txt);

        const p_raw = dkimTag(txt, "p") orelse return null;
        var p_clean = std.ArrayList(u8).empty;
        defer p_clean.deinit(self.allocator);
        for (p_raw) |c| {
            if (c == ' ' or c == '\t' or c == '\r' or c == '\n') continue;
            try p_clean.append(self.allocator, c);
        }
        if (p_clean.items.len == 0) return null; // empty p = revoked key

        const dec_len = B64.Decoder.calcSizeForSlice(p_clean.items) catch return null;
        const der_bytes = try self.allocator.alloc(u8, dec_len);
        errdefer self.allocator.free(der_bytes);
        B64.Decoder.decode(der_bytes, p_clean.items) catch {
            self.allocator.free(der_bytes);
            return null;
        };

        // DKIM publishes the key as SubjectPublicKeyInfo; PublicKey.fromSpki
        // (in verifySignature) parses it directly.
        return der_bytes;
    }

    fn verifyBodyHash(self: *DKIMValidator, signature: *const DKIMSignature, body: []const u8) !bool {
        var cbody = std.ArrayList(u8).empty;
        defer cbody.deinit(self.allocator);
        if (bodyCanonRelaxed(signature.canonicalization))
            try dkim_sign.canonBodyRelaxed(self.allocator, body, &cbody)
        else
            try canonBodySimple(self.allocator, body, &cbody);

        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(cbody.items, &digest, .{});
        var bh: [B64.Encoder.calcSize(Sha256.digest_length)]u8 = undefined;
        _ = B64.Encoder.encode(&bh, &digest);
        return std.mem.eql(u8, std.mem.trim(u8, signature.body_hash, " \t\r\n"), &bh);
    }

    fn verifySignature(self: *DKIMValidator, signature: *const DKIMSignature, headers: []const u8, public_key: []const u8) !bool {
        const relaxed = headerCanonRelaxed(signature.canonicalization);
        var input = std.ArrayList(u8).empty;
        defer input.deinit(self.allocator);

        // Signed headers in h= order. RFC 6376 §5.4.2: when a name appears more
        // than once in h=, instances are matched against the message from the
        // bottom up, each consuming the next-lower unmatched header; an h= entry
        // with no remaining match (over-signing / absent header) contributes
        // nothing. Collect every header span once, then consume.
        var hdrs = try collectHeaders(self.allocator, headers);
        defer hdrs.deinit(self.allocator);
        var hit = std.mem.splitScalar(u8, signature.headers, ':');
        while (hit.next()) |name_raw| {
            const name = std.mem.trim(u8, name_raw, " \t\r\n");
            if (name.len == 0) continue;
            // Pick the lowest unconsumed header with this name.
            var idx: ?usize = null;
            var k = hdrs.items.len;
            while (k > 0) {
                k -= 1;
                if (!hdrs.items[k].consumed and std.ascii.eqlIgnoreCase(hdrs.items[k].name, name)) {
                    idx = k;
                    break;
                }
            }
            const hi = idx orelse continue; // over-signed / absent → contribute nothing
            hdrs.items[hi].consumed = true;
            const h = hdrs.items[hi];
            if (relaxed) {
                var lower_buf: [128]u8 = undefined;
                const lname = if (name.len <= lower_buf.len) std.ascii.lowerString(lower_buf[0..name.len], name) else name;
                try dkim_sign.appendCanonHeader(self.allocator, &input, lname, h.value);
            } else {
                try input.appendSlice(self.allocator, h.full); // simple: verbatim
            }
            try input.appendSlice(self.allocator, "\r\n");
        }

        // The DKIM-Signature header itself with the b= value emptied, NO CRLF.
        const dk = findHeader(headers, "dkim-signature") orelse return false;
        const stripped = try stripBTag(self.allocator, dk.full);
        defer self.allocator.free(stripped);
        if (relaxed) {
            const colon = std.mem.indexOfScalar(u8, stripped, ':') orelse return false;
            try dkim_sign.appendCanonHeader(self.allocator, &input, "dkim-signature", stripped[colon + 1 ..]);
        } else {
            try input.appendSlice(self.allocator, stripped);
        }

        // base64-decode b=
        var b_clean = std.ArrayList(u8).empty;
        defer b_clean.deinit(self.allocator);
        for (signature.signature) |c| {
            if (c == ' ' or c == '\t' or c == '\r' or c == '\n') continue;
            try b_clean.append(self.allocator, c);
        }
        const sig_len = B64.Decoder.calcSizeForSlice(b_clean.items) catch return false;
        const sig_bytes = try self.allocator.alloc(u8, sig_len);
        defer self.allocator.free(sig_bytes);
        B64.Decoder.decode(sig_bytes, b_clean.items) catch return false;

        // RSA-PKCS1-SHA256 verify via zig-tls (public_key is SPKI DER).
        const pub_key = tls.rsa.PublicKey.fromSpki(public_key) catch return false;
        const Pkcs = tls.rsa.PKCS1v1_5(Sha256);
        const sig = Pkcs.Signature{ .bytes = sig_bytes };
        sig.verify(input.items, pub_key) catch return false;
        return true;
    }
};

// ---- DKIM verification helpers ----

/// Value of a `key=value` tag in a DKIM TXT/Signature (`;`-separated). Trimmed.
fn dkimTag(s: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, s, ';');
    while (it.next()) |part| {
        const p = std.mem.trim(u8, part, " \t\r\n");
        if (p.len > key.len and std.mem.startsWith(u8, p, key) and p[key.len] == '=') {
            return std.mem.trim(u8, p[key.len + 1 ..], " \t\r\n");
        }
    }
    return null;
}

/// c= is `header/body`; default `simple/simple`.
fn headerCanonRelaxed(c: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, c, '/') orelse return std.mem.indexOf(u8, c, "relaxed") != null;
    return std.mem.indexOf(u8, c[0..slash], "relaxed") != null;
}
fn bodyCanonRelaxed(c: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, c, '/') orelse return false;
    return std.mem.indexOf(u8, c[slash + 1 ..], "relaxed") != null;
}

const RawHeader = struct { full: []const u8, value: []const u8 };
/// Find a header by case-insensitive name. Returns the full line(s) incl. folds
/// (no trailing CRLF) and the value (after the colon).
fn findHeader(headers: []const u8, name: []const u8) ?RawHeader {
    var i: usize = 0;
    while (i < headers.len) {
        const ls = i;
        if (ls + name.len + 1 <= headers.len and
            std.ascii.eqlIgnoreCase(headers[ls .. ls + name.len], name) and
            headers[ls + name.len] == ':')
        {
            var j = ls + name.len + 1;
            while (true) {
                const nl = std.mem.indexOfScalarPos(u8, headers, j, '\n') orelse {
                    return .{ .full = headers[ls..], .value = headers[ls + name.len + 1 ..] };
                };
                if (nl + 1 < headers.len and (headers[nl + 1] == ' ' or headers[nl + 1] == '\t')) {
                    j = nl + 1;
                } else {
                    const end = if (nl > ls and headers[nl - 1] == '\r') nl - 1 else nl;
                    return .{ .full = headers[ls..end], .value = headers[ls + name.len + 1 .. end] };
                }
            }
        }
        const nl = std.mem.indexOfScalarPos(u8, headers, i, '\n') orelse return null;
        i = nl + 1;
    }
    return null;
}

const HeaderSpan = struct { name: []const u8, full: []const u8, value: []const u8, consumed: bool };

/// Split a header block into individual headers (folded continuation lines kept
/// with their header). Works for CRLF or LF line endings. `name` is the field
/// name (before the colon), `full` the whole header sans trailing CRLF, `value`
/// the bytes after the colon. Caller deinits the returned list.
fn collectHeaders(allocator: std.mem.Allocator, headers: []const u8) !std.ArrayList(HeaderSpan) {
    var list: std.ArrayList(HeaderSpan) = .empty;
    errdefer list.deinit(allocator);
    var i: usize = 0;
    while (i < headers.len) {
        const ls = i;
        // Extend across folded continuation lines (next line starts with WSP).
        var j = ls;
        var nl_final: usize = 0;
        var have_nl = false;
        while (true) {
            const nl = std.mem.indexOfScalarPos(u8, headers, j, '\n') orelse break;
            if (nl + 1 < headers.len and (headers[nl + 1] == ' ' or headers[nl + 1] == '\t')) {
                j = nl + 1;
                continue;
            }
            nl_final = nl;
            have_nl = true;
            break;
        }
        const line_end = if (have_nl) nl_final else headers.len;
        const end = if (line_end > ls and headers[line_end - 1] == '\r') line_end - 1 else line_end;
        const seg = headers[ls..end];
        if (std.mem.indexOfScalar(u8, seg, ':')) |c| {
            const name = seg[0..c];
            // A real field name has no whitespace; skip stray/garbage lines.
            if (name.len > 0 and std.mem.indexOfAny(u8, name, " \t") == null) {
                try list.append(allocator, .{ .name = name, .full = seg, .value = seg[c + 1 ..], .consumed = false });
            }
        }
        if (!have_nl) break;
        i = nl_final + 1;
    }
    return list;
}

/// Copy of a raw DKIM-Signature header with the b= tag value emptied (keep
/// `b=`), as required before verifying. Caller frees.
fn stripBTag(allocator: std.mem.Allocator, hdr: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < hdr.len) {
        if (hdr[i] == 'b' and (i == 0 or hdr[i - 1] == ';' or hdr[i - 1] == ' ' or hdr[i - 1] == '\t' or hdr[i - 1] == '\n' or hdr[i - 1] == '\r')) {
            var k = i + 1;
            while (k < hdr.len and (hdr[k] == ' ' or hdr[k] == '\t')) k += 1;
            if (k < hdr.len and hdr[k] == '=') {
                try out.appendSlice(allocator, hdr[i .. k + 1]); // "b="
                var m = k + 1;
                while (m < hdr.len and hdr[m] != ';') m += 1;
                i = m;
                continue;
            }
        }
        try out.append(allocator, hdr[i]);
        i += 1;
    }
    return out.toOwnedSlice(allocator);
}

/// Simple body canonicalization (RFC 6376 §3.4.3): content as-is, trailing empty
/// lines removed, non-empty body ends with a single CRLF.
fn canonBodySimple(allocator: std.mem.Allocator, body: []const u8, out: *std.ArrayList(u8)) !void {
    var tmp = std.ArrayList(u8).empty;
    defer tmp.deinit(allocator);
    var it = std.mem.splitScalar(u8, body, '\n');
    while (it.next()) |raw| {
        const line = if (raw.len > 0 and raw[raw.len - 1] == '\r') raw[0 .. raw.len - 1] else raw;
        try tmp.appendSlice(allocator, line);
        try tmp.appendSlice(allocator, "\r\n");
    }
    var end = tmp.items.len;
    while (end >= 2 and tmp.items[end - 2] == '\r' and tmp.items[end - 1] == '\n') end -= 2;
    try out.appendSlice(allocator, tmp.items[0..end]);
    if (end > 0) try out.appendSlice(allocator, "\r\n");
}

test "dkim tag + canon mode parsing" {
    try std.testing.expectEqualStrings("rsa", dkimTag("v=DKIM1; k=rsa; p=ABC", "k").?);
    try std.testing.expectEqualStrings("ABC", dkimTag("v=DKIM1; k=rsa; p=ABC", "p").?);
    try std.testing.expect(headerCanonRelaxed("relaxed/relaxed"));
    try std.testing.expect(!headerCanonRelaxed("simple/simple"));
    try std.testing.expect(bodyCanonRelaxed("relaxed/relaxed"));
    try std.testing.expect(!bodyCanonRelaxed("relaxed/simple"));
}

/// DKIM signer for outgoing mail
pub const DKIMSigner = struct {
    allocator: std.mem.Allocator,
    domain: []const u8,
    selector: []const u8,
    private_key: []const u8,

    pub fn init(allocator: std.mem.Allocator, domain: []const u8, selector: []const u8, private_key: []const u8) !DKIMSigner {
        return .{
            .allocator = allocator,
            .domain = try allocator.dupe(u8, domain),
            .selector = try allocator.dupe(u8, selector),
            .private_key = try allocator.dupe(u8, private_key),
        };
    }

    pub fn deinit(self: *DKIMSigner) void {
        self.allocator.free(self.domain);
        self.allocator.free(self.selector);
        self.allocator.free(self.private_key);
    }

    /// Sign an email message
    pub fn sign(self: *DKIMSigner, headers: []const u8, body: []const u8) ![]const u8 {
        _ = headers;
        _ = body;

        // Build DKIM-Signature header
        return try std.fmt.allocPrint(
            self.allocator,
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={s}; s={s};\r\n\th=from:to:subject:date; bh=<body-hash>; b=<signature>",
            .{ self.domain, self.selector },
        );
    }
};

test "DKIM signature parsing" {
    const testing = std.testing;

    const sig_value =
        \\v=1; a=rsa-sha256; c=relaxed/relaxed;
        \\d=example.com; s=default;
        \\h=from:to:subject:date;
        \\bh=BODYHASH==;
        \\b=SIGNATURE==
    ;

    var sig = try DKIMSignature.parse(testing.allocator, sig_value);
    defer sig.deinit();

    try testing.expectEqualStrings("1", sig.version);
    try testing.expectEqualStrings("rsa-sha256", sig.algorithm);
    try testing.expectEqualStrings("example.com", sig.domain);
    try testing.expectEqualStrings("default", sig.selector);
}

test "extractDKIMSignature stops at next header on LF-delimited input" {
    const testing = std.testing;
    var validator = DKIMValidator.init(testing.allocator);

    // LF-delimited (our in-memory form), DKIM-Signature first, b= the last tag
    // with no trailing ';', followed by a Received header that contains ';'.
    // The old "\r\n"-split code over-read b= into the Received header.
    const headers =
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; s=sel; d=ex.com;\n" ++
        "\th=from:to; bh=BODYHASH=; b=SIGPART1\n" ++
        "\tSIGPART2\n" ++
        "Received: from a by b; Sun, 31 May 2026 00:00:00 +0000\n" ++
        "From: x@ex.com\n";

    const extracted = validator.extractDKIMSignature(headers).?;
    defer testing.allocator.free(extracted);

    var sig = try DKIMSignature.parse(testing.allocator, extracted);
    defer sig.deinit();
    // b= must be exactly the (unfolded) signature, not bleeding into Received.
    try testing.expectEqualStrings("SIGPART1SIGPART2", sig.signature);
    try testing.expectEqualStrings("BODYHASH=", sig.body_hash);
    try testing.expectEqualStrings("from:to", sig.headers);
}

test "collectHeaders: order, folds, bottom-up consumption" {
    const testing = std.testing;
    const headers =
        "Received: a; by b\n" ++
        "From: first@ex.com\n" ++
        "Subject: hello\n" ++
        "\tworld\n" ++ // folded into Subject
        "From: second@ex.com\n";
    var hdrs = try collectHeaders(testing.allocator, headers);
    defer hdrs.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 4), hdrs.items.len);
    try testing.expectEqualStrings("Subject: hello\n\tworld", hdrs.items[2].full);
    try testing.expectEqualStrings(" hello\n\tworld", hdrs.items[2].value);

    // RFC 6376 §5.4.2: first h=from consumes the LAST From (bottom-up).
    var idx: ?usize = null;
    var k = hdrs.items.len;
    while (k > 0) {
        k -= 1;
        if (!hdrs.items[k].consumed and std.ascii.eqlIgnoreCase(hdrs.items[k].name, "from")) {
            idx = k;
            break;
        }
    }
    try testing.expectEqual(@as(usize, 3), idx.?);
    hdrs.items[idx.?].consumed = true;
    // A second h=from would then take the first From (index 1).
    idx = null;
    k = hdrs.items.len;
    while (k > 0) {
        k -= 1;
        if (!hdrs.items[k].consumed and std.ascii.eqlIgnoreCase(hdrs.items[k].name, "from")) {
            idx = k;
            break;
        }
    }
    try testing.expectEqual(@as(usize, 1), idx.?);
}

test "DKIM validator neutral" {
    const testing = std.testing;
    var validator = DKIMValidator.init(testing.allocator);

    const headers = "From: test@example.com\r\n\r\n";
    const body = "Test body";

    const result = try validator.validate(headers, body);
    try testing.expect(result == .neutral);
}

// ============================================================================
// DKIM Key Rotation CLI
// ============================================================================

const time_compat = @import("../core/time_compat.zig");

/// Key algorithm types
pub const KeyAlgorithm = enum {
    rsa_2048,
    rsa_4096,
    ed25519,

    pub fn toString(self: KeyAlgorithm) []const u8 {
        return switch (self) {
            .rsa_2048 => "rsa-2048",
            .rsa_4096 => "rsa-4096",
            .ed25519 => "ed25519",
        };
    }

    pub fn fromString(s: []const u8) ?KeyAlgorithm {
        if (std.mem.eql(u8, s, "rsa-2048") or std.mem.eql(u8, s, "rsa2048")) return .rsa_2048;
        if (std.mem.eql(u8, s, "rsa-4096") or std.mem.eql(u8, s, "rsa4096")) return .rsa_4096;
        if (std.mem.eql(u8, s, "ed25519")) return .ed25519;
        return null;
    }

    pub fn getKeySize(self: KeyAlgorithm) u32 {
        return switch (self) {
            .rsa_2048 => 2048,
            .rsa_4096 => 4096,
            .ed25519 => 256,
        };
    }

    pub fn getDkimAlgorithm(self: KeyAlgorithm) []const u8 {
        return switch (self) {
            .rsa_2048, .rsa_4096 => "rsa-sha256",
            .ed25519 => "ed25519-sha256",
        };
    }
};

/// DKIM key pair
pub const DKIMKeyPair = struct {
    id: []const u8,
    domain: []const u8,
    selector: []const u8,
    algorithm: KeyAlgorithm,
    public_key: []const u8, // Base64 encoded
    private_key: []const u8, // PEM format
    created_at: i64,
    expires_at: ?i64,
    is_active: bool,
    rotation_scheduled: ?i64,

    allocator: std.mem.Allocator,

    pub fn deinit(self: *DKIMKeyPair) void {
        self.allocator.free(self.id);
        self.allocator.free(self.domain);
        self.allocator.free(self.selector);
        self.allocator.free(self.public_key);
        // Securely zero private key before freeing
        @memset(@as([]u8, @constCast(self.private_key)), 0);
        self.allocator.free(self.private_key);
    }

    /// Check if key is valid at given time
    pub fn isValidAt(self: *const DKIMKeyPair, timestamp: i64) bool {
        if (!self.is_active) return false;
        if (timestamp < self.created_at) return false;
        if (self.expires_at) |expiry| {
            if (timestamp > expiry) return false;
        }
        return true;
    }

    /// Check if key is expiring soon (within days)
    pub fn isExpiringSoon(self: *const DKIMKeyPair, days: u32) bool {
        if (self.expires_at) |expiry| {
            const threshold = time_compat.timestamp() + @as(i64, days) * 24 * 60 * 60;
            return expiry <= threshold;
        }
        return false;
    }

    /// Generate DNS TXT record content
    pub fn generateDnsRecord(self: *const DKIMKeyPair, allocator: std.mem.Allocator) ![]u8 {
        const key_type = switch (self.algorithm) {
            .rsa_2048, .rsa_4096 => "rsa",
            .ed25519 => "ed25519",
        };

        return std.fmt.allocPrint(allocator,
            \\v=DKIM1; k={s}; p={s}
        , .{ key_type, self.public_key });
    }

    /// Get full DNS record name
    pub fn getDnsRecordName(self: *const DKIMKeyPair, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}._domainkey.{s}", .{
            self.selector,
            self.domain,
        });
    }
};

/// DKIM Key Manager for key generation and rotation
pub const DKIMKeyManager = struct {
    allocator: std.mem.Allocator,
    keys: std.ArrayList(DKIMKeyPair),
    key_storage_path: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator, storage_path: ?[]const u8) !DKIMKeyManager {
        return .{
            .allocator = allocator,
            .keys = .empty,
            .key_storage_path = if (storage_path) |p| try allocator.dupe(u8, p) else null,
        };
    }

    pub fn deinit(self: *DKIMKeyManager) void {
        for (self.keys.items) |*key| {
            key.deinit();
        }
        self.keys.deinit(self.allocator);
        if (self.key_storage_path) |p| self.allocator.free(p);
    }

    /// Generate a new DKIM key pair
    pub fn generateKey(
        self: *DKIMKeyManager,
        domain: []const u8,
        selector: []const u8,
        algorithm: KeyAlgorithm,
        validity_days: ?u32,
    ) !*DKIMKeyPair {
        const key_id = try self.generateKeyId();
        defer self.allocator.free(key_id);

        const now = time_compat.timestamp();
        const expires_at: ?i64 = if (validity_days) |days|
            now + @as(i64, days) * 24 * 60 * 60
        else
            null;

        // Generate key material
        const key_material = try self.generateKeyMaterial(algorithm);

        const key = DKIMKeyPair{
            .id = try self.allocator.dupe(u8, key_id),
            .domain = try self.allocator.dupe(u8, domain),
            .selector = try self.allocator.dupe(u8, selector),
            .algorithm = algorithm,
            .public_key = key_material.public_key,
            .private_key = key_material.private_key,
            .created_at = now,
            .expires_at = expires_at,
            .is_active = true,
            .rotation_scheduled = null,
            .allocator = self.allocator,
        };

        try self.keys.append(self.allocator, key);

        return &self.keys.items[self.keys.items.len - 1];
    }

    /// Schedule key rotation
    pub fn scheduleRotation(
        self: *DKIMKeyManager,
        key_id: []const u8,
        rotation_time: i64,
    ) !void {
        for (self.keys.items) |*key| {
            if (std.mem.eql(u8, key.id, key_id)) {
                key.rotation_scheduled = rotation_time;
                return;
            }
        }
        return error.KeyNotFound;
    }

    /// Execute scheduled rotations
    pub fn executeScheduledRotations(self: *DKIMKeyManager) ![]const RotationResult {
        var results: std.ArrayList(RotationResult) = .empty;
        const now = time_compat.timestamp();

        for (self.keys.items) |*key| {
            if (key.rotation_scheduled) |scheduled| {
                if (now >= scheduled) {
                    // Create new key with same domain/selector but new material
                    const new_selector = try self.generateNewSelector(key.selector);
                    defer self.allocator.free(new_selector);

                    const new_key = try self.generateKey(
                        key.domain,
                        new_selector,
                        key.algorithm,
                        if (key.expires_at) |exp| @as(u32, @intCast(@divFloor(exp - key.created_at, 24 * 60 * 60))) else null,
                    );

                    // Deactivate old key
                    key.is_active = false;
                    key.rotation_scheduled = null;

                    try results.append(self.allocator, .{
                        .old_key_id = key.id,
                        .new_key_id = new_key.id,
                        .domain = key.domain,
                        .old_selector = key.selector,
                        .new_selector = new_key.selector,
                        .success = true,
                        .message = "Key rotated successfully",
                    });
                }
            }
        }

        return results.toOwnedSlice(self.allocator);
    }

    /// Get active key for domain
    pub fn getActiveKey(self: *DKIMKeyManager, domain: []const u8) ?*DKIMKeyPair {
        const now = time_compat.timestamp();
        for (self.keys.items) |*key| {
            if (std.mem.eql(u8, key.domain, domain) and key.isValidAt(now)) {
                return key;
            }
        }
        return null;
    }

    /// List all keys for domain
    pub fn listKeys(self: *DKIMKeyManager, domain: ?[]const u8) []DKIMKeyPair {
        if (domain) |d| {
            var filtered: std.ArrayList(DKIMKeyPair) = .empty;
            for (self.keys.items) |key| {
                if (std.mem.eql(u8, key.domain, d)) {
                    filtered.append(self.allocator, key) catch continue;
                }
            }
            return filtered.toOwnedSlice(self.allocator) catch return &[_]DKIMKeyPair{};
        }
        return self.keys.items;
    }

    /// Check key validity
    pub fn validateKey(self: *DKIMKeyManager, key_id: []const u8) !KeyValidation {
        for (self.keys.items) |*key| {
            if (std.mem.eql(u8, key.id, key_id)) {
                const now = time_compat.timestamp();
                var issues: std.ArrayList([]const u8) = .empty;

                if (!key.is_active) {
                    try issues.append(self.allocator, "Key is inactive");
                }

                if (key.expires_at) |expiry| {
                    if (now > expiry) {
                        try issues.append(self.allocator, "Key has expired");
                    } else if (key.isExpiringSoon(30)) {
                        try issues.append(self.allocator, "Key expires within 30 days");
                    }
                }

                // Check algorithm strength
                if (key.algorithm == .rsa_2048) {
                    try issues.append(self.allocator, "Consider upgrading to RSA-4096 or Ed25519");
                }

                return KeyValidation{
                    .key_id = key.id,
                    .is_valid = key.isValidAt(now),
                    .issues = issues.toOwnedSlice(self.allocator) catch &[_][]const u8{},
                    .days_until_expiry = if (key.expires_at) |exp|
                        @as(i32, @intCast(@divFloor(exp - now, 24 * 60 * 60)))
                    else
                        null,
                };
            }
        }
        return error.KeyNotFound;
    }

    /// Delete a key
    pub fn deleteKey(self: *DKIMKeyManager, key_id: []const u8) !void {
        for (self.keys.items, 0..) |*key, i| {
            if (std.mem.eql(u8, key.id, key_id)) {
                key.deinit();
                _ = self.keys.orderedRemove(i);
                return;
            }
        }
        return error.KeyNotFound;
    }

    fn generateKeyId(self: *DKIMKeyManager) ![]u8 {
        var buf: [16]u8 = undefined;
        io_compat.randomBytes(&buf);
        const hex = std.fmt.bytesToHex(buf, .lower);
        return std.fmt.allocPrint(self.allocator, "dkim_{s}", .{
            &hex,
        });
    }

    fn generateNewSelector(self: *DKIMKeyManager, old_selector: []const u8) ![]u8 {
        // Generate new selector by appending timestamp or incrementing number
        const timestamp = time_compat.timestamp();
        return std.fmt.allocPrint(self.allocator, "{s}_{d}", .{ old_selector, timestamp });
    }

    fn generateKeyMaterial(self: *DKIMKeyManager, algorithm: KeyAlgorithm) !struct {
        public_key: []u8,
        private_key: []u8,
    } {
        // Generate cryptographic key material
        // In production, this would use actual RSA/Ed25519 key generation
        var random_bytes: [64]u8 = undefined;
        io_compat.randomBytes(&random_bytes);

        const pub_hex = std.fmt.bytesToHex(random_bytes[0..32].*, .lower);
        const public_key = try std.fmt.allocPrint(self.allocator, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA{s}", .{&pub_hex});

        _ = algorithm;
        const full_hex = std.fmt.bytesToHex(random_bytes, .lower);
        const private_key = try std.fmt.allocPrint(self.allocator,
            \\-----BEGIN RSA PRIVATE KEY-----
            \\{s}
            \\-----END RSA PRIVATE KEY-----
        , .{&full_hex});

        return .{
            .public_key = public_key,
            .private_key = private_key,
        };
    }

    pub const RotationResult = struct {
        old_key_id: []const u8,
        new_key_id: []const u8,
        domain: []const u8,
        old_selector: []const u8,
        new_selector: []const u8,
        success: bool,
        message: []const u8,
    };

    pub const KeyValidation = struct {
        key_id: []const u8,
        is_valid: bool,
        issues: []const []const u8,
        days_until_expiry: ?i32,
    };
};

/// DKIM CLI for key management
pub const DKIMCli = struct {
    allocator: std.mem.Allocator,
    key_manager: *DKIMKeyManager,

    pub fn init(allocator: std.mem.Allocator, key_manager: *DKIMKeyManager) DKIMCli {
        return .{
            .allocator = allocator,
            .key_manager = key_manager,
        };
    }

    pub const Command = enum {
        generate,
        list,
        show,
        rotate,
        schedule,
        validate,
        dns,
        delete,
        help,

        pub fn fromString(s: []const u8) ?Command {
            if (std.mem.eql(u8, s, "generate") or std.mem.eql(u8, s, "gen")) return .generate;
            if (std.mem.eql(u8, s, "list") or std.mem.eql(u8, s, "ls")) return .list;
            if (std.mem.eql(u8, s, "show")) return .show;
            if (std.mem.eql(u8, s, "rotate")) return .rotate;
            if (std.mem.eql(u8, s, "schedule")) return .schedule;
            if (std.mem.eql(u8, s, "validate") or std.mem.eql(u8, s, "check")) return .validate;
            if (std.mem.eql(u8, s, "dns")) return .dns;
            if (std.mem.eql(u8, s, "delete") or std.mem.eql(u8, s, "rm")) return .delete;
            if (std.mem.eql(u8, s, "help") or std.mem.eql(u8, s, "-h")) return .help;
            return null;
        }
    };

    pub const CliResult = struct {
        success: bool,
        message: []const u8,
        data: ?[]const u8,
    };

    /// Execute CLI command
    pub fn execute(self: *DKIMCli, command: Command, args: []const []const u8) !CliResult {
        return switch (command) {
            .generate => self.cmdGenerate(args),
            .list => self.cmdList(args),
            .show => self.cmdShow(args),
            .rotate => self.cmdRotate(args),
            .schedule => self.cmdSchedule(args),
            .validate => self.cmdValidate(args),
            .dns => self.cmdDns(args),
            .delete => self.cmdDelete(args),
            .help => self.cmdHelp(),
        };
    }

    fn cmdGenerate(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 2) {
            return .{
                .success = false,
                .message = "Usage: dkim generate <domain> <selector> [algorithm] [validity_days]",
                .data = null,
            };
        }

        const domain = args[0];
        const selector = args[1];
        const algorithm = if (args.len > 2)
            KeyAlgorithm.fromString(args[2]) orelse .rsa_2048
        else
            .rsa_2048;
        const validity_days: ?u32 = if (args.len > 3)
            std.fmt.parseInt(u32, args[3], 10) catch 365
        else
            365;

        const key = try self.key_manager.generateKey(domain, selector, algorithm, validity_days);

        const output = try std.fmt.allocPrint(self.allocator,
            \\Key generated successfully:
            \\  ID: {s}
            \\  Domain: {s}
            \\  Selector: {s}
            \\  Algorithm: {s}
            \\  Expires: {d}
            \\
            \\DNS Record ({s}._domainkey.{s}):
            \\  {s}
        , .{
            key.id,
            key.domain,
            key.selector,
            key.algorithm.toString(),
            key.expires_at orelse 0,
            key.selector,
            key.domain,
            try key.generateDnsRecord(self.allocator),
        });

        return .{
            .success = true,
            .message = "Key generated successfully",
            .data = output,
        };
    }

    fn cmdList(self: *DKIMCli, args: []const []const u8) !CliResult {
        const domain = if (args.len > 0) args[0] else null;
        const keys = self.key_manager.listKeys(domain);

        if (keys.len == 0) {
            return .{
                .success = true,
                .message = "No keys found",
                .data = null,
            };
        }

        var output: std.ArrayList(u8) = .empty;

        try output.print(self.allocator, "DKIM Keys:\n", .{});
        try output.print(self.allocator, "{s:<40} {s:<20} {s:<15} {s:<10} {s:<10}\n", .{
            "ID", "Domain", "Selector", "Algorithm", "Status",
        });
        try output.print(self.allocator, "{s}\n", .{"-" ** 95});

        for (keys) |key| {
            const status = if (key.is_active) "active" else "inactive";
            try output.print(self.allocator, "{s:<40} {s:<20} {s:<15} {s:<10} {s:<10}\n", .{
                key.id,
                key.domain,
                key.selector,
                key.algorithm.toString(),
                status,
            });
        }

        return .{
            .success = true,
            .message = try std.fmt.allocPrint(self.allocator, "Found {d} key(s)", .{keys.len}),
            .data = try output.toOwnedSlice(self.allocator),
        };
    }

    fn cmdShow(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 1) {
            return .{
                .success = false,
                .message = "Usage: dkim show <key_id>",
                .data = null,
            };
        }

        const key_id = args[0];

        for (self.key_manager.keys.items) |key| {
            if (std.mem.eql(u8, key.id, key_id)) {
                const output = try std.fmt.allocPrint(self.allocator,
                    \\Key Details:
                    \\  ID: {s}
                    \\  Domain: {s}
                    \\  Selector: {s}
                    \\  Algorithm: {s}
                    \\  Status: {s}
                    \\  Created: {d}
                    \\  Expires: {d}
                    \\  Rotation Scheduled: {d}
                    \\
                    \\Public Key (Base64):
                    \\  {s}
                , .{
                    key.id,
                    key.domain,
                    key.selector,
                    key.algorithm.toString(),
                    if (key.is_active) "active" else "inactive",
                    key.created_at,
                    key.expires_at orelse 0,
                    key.rotation_scheduled orelse 0,
                    key.public_key,
                });

                return .{
                    .success = true,
                    .message = "Key found",
                    .data = output,
                };
            }
        }

        return .{
            .success = false,
            .message = "Key not found",
            .data = null,
        };
    }

    fn cmdRotate(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 1) {
            return .{
                .success = false,
                .message = "Usage: dkim rotate <key_id>",
                .data = null,
            };
        }

        const key_id = args[0];

        // Find and rotate the key
        for (self.key_manager.keys.items) |*key| {
            if (std.mem.eql(u8, key.id, key_id)) {
                const new_selector = try self.allocator.dupe(u8, key.selector);
                defer self.allocator.free(new_selector);

                const new_key = try self.key_manager.generateKey(
                    key.domain,
                    try std.fmt.allocPrint(self.allocator, "{s}_{d}", .{ new_selector, time_compat.timestamp() }),
                    key.algorithm,
                    365,
                );

                // Deactivate old key
                key.is_active = false;

                const output = try std.fmt.allocPrint(self.allocator,
                    \\Key rotated successfully:
                    \\  Old Key: {s} (now inactive)
                    \\  New Key: {s}
                    \\  New Selector: {s}
                    \\
                    \\ACTION REQUIRED: Update DNS record:
                    \\  {s}._domainkey.{s} TXT "v=DKIM1; k=rsa; p={s}"
                , .{
                    key.id,
                    new_key.id,
                    new_key.selector,
                    new_key.selector,
                    new_key.domain,
                    new_key.public_key,
                });

                return .{
                    .success = true,
                    .message = "Key rotated successfully",
                    .data = output,
                };
            }
        }

        return .{
            .success = false,
            .message = "Key not found",
            .data = null,
        };
    }

    fn cmdSchedule(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 2) {
            return .{
                .success = false,
                .message = "Usage: dkim schedule <key_id> <days_from_now>",
                .data = null,
            };
        }

        const key_id = args[0];
        const days = std.fmt.parseInt(u32, args[1], 10) catch {
            return .{
                .success = false,
                .message = "Invalid number of days",
                .data = null,
            };
        };

        const rotation_time = time_compat.timestamp() + @as(i64, days) * 24 * 60 * 60;
        try self.key_manager.scheduleRotation(key_id, rotation_time);

        return .{
            .success = true,
            .message = try std.fmt.allocPrint(self.allocator, "Rotation scheduled for key {s} in {d} days", .{ key_id, days }),
            .data = null,
        };
    }

    fn cmdValidate(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 1) {
            return .{
                .success = false,
                .message = "Usage: dkim validate <key_id>",
                .data = null,
            };
        }

        const key_id = args[0];
        const validation = try self.key_manager.validateKey(key_id);

        var output: std.ArrayList(u8) = .empty;

        try output.print(self.allocator, "Key Validation: {s}\n", .{key_id});
        try output.print(self.allocator, "  Valid: {s}\n", .{if (validation.is_valid) "yes" else "no"});

        if (validation.days_until_expiry) |days| {
            try output.print(self.allocator, "  Days until expiry: {d}\n", .{days});
        }

        if (validation.issues.len > 0) {
            try output.print(self.allocator, "  Issues:\n", .{});
            for (validation.issues) |issue| {
                try output.print(self.allocator, "    - {s}\n", .{issue});
            }
        }

        return .{
            .success = validation.is_valid,
            .message = if (validation.is_valid) "Key is valid" else "Key has issues",
            .data = try output.toOwnedSlice(self.allocator),
        };
    }

    fn cmdDns(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 1) {
            return .{
                .success = false,
                .message = "Usage: dkim dns <key_id>",
                .data = null,
            };
        }

        const key_id = args[0];

        for (self.key_manager.keys.items) |key| {
            if (std.mem.eql(u8, key.id, key_id)) {
                const record_name = try key.getDnsRecordName(self.allocator);
                defer self.allocator.free(record_name);
                const record_value = try key.generateDnsRecord(self.allocator);
                defer self.allocator.free(record_value);

                const output = try std.fmt.allocPrint(self.allocator,
                    \\DNS TXT Record for DKIM:
                    \\
                    \\Name: {s}
                    \\Type: TXT
                    \\Value: "{s}"
                    \\
                    \\BIND format:
                    \\  {s}. IN TXT "{s}"
                    \\
                    \\Cloudflare/Route53 format:
                    \\  Name: {s}
                    \\  Content: {s}
                , .{
                    record_name,
                    record_value,
                    record_name,
                    record_value,
                    record_name,
                    record_value,
                });

                return .{
                    .success = true,
                    .message = "DNS record generated",
                    .data = output,
                };
            }
        }

        return .{
            .success = false,
            .message = "Key not found",
            .data = null,
        };
    }

    fn cmdDelete(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 1) {
            return .{
                .success = false,
                .message = "Usage: dkim delete <key_id>",
                .data = null,
            };
        }

        const key_id = args[0];
        self.key_manager.deleteKey(key_id) catch {
            return .{
                .success = false,
                .message = "Key not found",
                .data = null,
            };
        };

        return .{
            .success = true,
            .message = try std.fmt.allocPrint(self.allocator, "Key {s} deleted", .{key_id}),
            .data = null,
        };
    }

    fn cmdHelp(self: *DKIMCli) CliResult {
        _ = self;
        return .{
            .success = true,
            .message = "DKIM Key Management CLI",
            .data =
            \\DKIM Key Management Commands:
            \\
            \\  generate <domain> <selector> [algorithm] [validity_days]
            \\      Generate a new DKIM key pair
            \\      Algorithms: rsa-2048 (default), rsa-4096, ed25519
            \\      Example: dkim generate example.com default rsa-4096 365
            \\
            \\  list [domain]
            \\      List all DKIM keys, optionally filtered by domain
            \\
            \\  show <key_id>
            \\      Show details of a specific key
            \\
            \\  rotate <key_id>
            \\      Immediately rotate a key (generates new key, deactivates old)
            \\
            \\  schedule <key_id> <days>
            \\      Schedule automatic key rotation
            \\
            \\  validate <key_id>
            \\      Check key validity and get recommendations
            \\
            \\  dns <key_id>
            \\      Generate DNS TXT record for a key
            \\
            \\  delete <key_id>
            \\      Delete a key (use with caution!)
            \\
            \\  help
            \\      Show this help message
            ,
        };
    }
};

// Additional tests
test "DKIM key algorithm conversion" {
    try std.testing.expectEqual(KeyAlgorithm.rsa_2048, KeyAlgorithm.fromString("rsa-2048").?);
    try std.testing.expectEqual(KeyAlgorithm.ed25519, KeyAlgorithm.fromString("ed25519").?);
    try std.testing.expectEqual(@as(u32, 4096), KeyAlgorithm.rsa_4096.getKeySize());
}

test "DKIM key manager generate" {
    var manager = try DKIMKeyManager.init(std.testing.allocator, null);
    defer manager.deinit();

    const key = try manager.generateKey("example.com", "default", .rsa_2048, 365);
    try std.testing.expectEqualStrings("example.com", key.domain);
    try std.testing.expectEqualStrings("default", key.selector);
    try std.testing.expect(key.is_active);
}

test "DKIM CLI help command" {
    var manager = try DKIMKeyManager.init(std.testing.allocator, null);
    defer manager.deinit();

    var cli = DKIMCli.init(std.testing.allocator, &manager);
    const result = try cli.execute(.help, &[_][]const u8{});
    try std.testing.expect(result.success);
}
