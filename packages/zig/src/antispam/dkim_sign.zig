//! Outbound DKIM signing — RFC 6376, `rsa-sha256`, `relaxed/relaxed`.
//!
//! Real signing (not the stub in dkim.zig): reuses zig-tls's RSA PKCS#1 v1.5
//! signer so we don't reimplement modexp. Library feature — any deployment that
//! sets a DKIM key gets signed outbound mail. Configure via env (see main.zig):
//!   DKIM_DOMAIN, DKIM_SELECTOR, DKIM_PRIVATE_KEY (PEM, PKCS#1 "RSA PRIVATE KEY").
//! Publish the public key at `<selector>._domainkey.<domain>` TXT
//!   `v=DKIM1; k=rsa; p=<base64 SPKI/PKCS1 public key>`.
const std = @import("std");
const tls = @import("tls");
const PrivateKey = tls.config.PrivateKey;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Encoder = std.base64.standard.Encoder;

pub const Signer = struct {
    domain: []const u8,
    selector: []const u8,
    key: PrivateKey,

    pub fn initFromPem(domain: []const u8, selector: []const u8, pem: []const u8) !Signer {
        return .{ .domain = domain, .selector = selector, .key = try PrivateKey.parsePem(pem) };
    }

    /// Build a `DKIM-Signature: …\r\n` header for `message` (raw RFC822 headers
    /// + body). Caller owns the result. On any error the caller should send the
    /// message unsigned rather than fail delivery.
    pub fn buildHeader(self: *const Signer, allocator: std.mem.Allocator, message: []const u8, timestamp: i64) ![]u8 {
        const split = splitHeaderBody(message);
        const header_block = message[0..split.header_end];
        const body = message[split.body_start..];

        // --- body hash (relaxed) ---
        var cbody = std.ArrayList(u8).empty;
        defer cbody.deinit(allocator);
        try canonBodyRelaxed(allocator, body, &cbody);
        var bh_raw: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(cbody.items, &bh_raw, .{});
        var bh_b64: [Encoder.calcSize(Sha256.digest_length)]u8 = undefined;
        _ = Encoder.encode(&bh_b64, &bh_raw);

        // --- signed headers (relaxed), in order, only those present ---
        const want = [_][]const u8{ "from", "to", "cc", "subject", "date", "message-id", "mime-version", "content-type" };
        var h_list = std.ArrayList(u8).empty;
        defer h_list.deinit(allocator);
        var signed_canon = std.ArrayList(u8).empty;
        defer signed_canon.deinit(allocator);
        for (want) |name| {
            const val = findHeaderValue(header_block, name) orelse continue;
            if (h_list.items.len > 0) try h_list.append(allocator, ':');
            try h_list.appendSlice(allocator, name);
            try appendCanonHeader(allocator, &signed_canon, name, val);
            try signed_canon.appendSlice(allocator, "\r\n");
        }

        // --- DKIM-Signature header value with empty b= ---
        var sig_val = std.ArrayList(u8).empty;
        defer sig_val.deinit(allocator);
        try sig_val.print(allocator, "v=1; a=rsa-sha256; c=relaxed/relaxed; d={s}; s={s}; t={d}; bh={s}; h={s}; b=", .{
            self.domain, self.selector, timestamp, bh_b64[0..], h_list.items,
        });

        // canonical DKIM-Signature header (relaxed, no trailing CRLF) for signing
        var dkim_canon = std.ArrayList(u8).empty;
        defer dkim_canon.deinit(allocator);
        try appendCanonHeader(allocator, &dkim_canon, "dkim-signature", sig_val.items);

        // --- signing input = signed headers (each + CRLF) + DKIM-Sig (no CRLF) ---
        var input = std.ArrayList(u8).empty;
        defer input.deinit(allocator);
        try input.appendSlice(allocator, signed_canon.items);
        try input.appendSlice(allocator, dkim_canon.items);

        // --- RSA-PKCS1-SHA256 sign (zig-tls) ---
        var out: [544]u8 = undefined; // >= 4096-bit modulus byte length
        const sig = try self.key.key.rsa.signPkcsv1_5(Sha256, input.items, &out);
        const sb_len = Encoder.calcSize(sig.bytes.len);
        const sb = try allocator.alloc(u8, sb_len);
        defer allocator.free(sb);
        _ = Encoder.encode(sb, sig.bytes);

        return std.fmt.allocPrint(allocator, "DKIM-Signature: {s}{s}\r\n", .{ sig_val.items, sb });
    }
};

const Split = struct { header_end: usize, body_start: usize };
fn splitHeaderBody(msg: []const u8) Split {
    if (std.mem.indexOf(u8, msg, "\r\n\r\n")) |i| return .{ .header_end = i + 2, .body_start = i + 4 };
    if (std.mem.indexOf(u8, msg, "\n\n")) |i| return .{ .header_end = i + 1, .body_start = i + 2 };
    return .{ .header_end = msg.len, .body_start = msg.len };
}

/// Find a header's raw value (including folded continuation lines) by
/// case-insensitive name. Returns the bytes after the colon, or null.
fn findHeaderValue(header_block: []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < header_block.len) {
        // start of a header line
        const line_start = i;
        // is this line "name:"? (case-insensitive, must be at column 0)
        if (line_start + name.len + 1 <= header_block.len and
            std.ascii.eqlIgnoreCase(header_block[line_start .. line_start + name.len], name) and
            header_block[line_start + name.len] == ':')
        {
            const vstart = line_start + name.len + 1;
            // extend over continuation lines (next line begins with WSP)
            var j = vstart;
            while (true) {
                const nl = std.mem.indexOfScalarPos(u8, header_block, j, '\n') orelse {
                    return header_block[vstart..];
                };
                // peek next line's first char
                if (nl + 1 < header_block.len and (header_block[nl + 1] == ' ' or header_block[nl + 1] == '\t')) {
                    j = nl + 1; // folded; continue
                } else {
                    return header_block[vstart..nl]; // value up to (not incl) the newline
                }
            }
        }
        // advance to next line
        const nl = std.mem.indexOfScalarPos(u8, header_block, i, '\n') orelse return null;
        i = nl + 1;
    }
    return null;
}

/// Append `name:value` with relaxed value canonicalization (no trailing CRLF).
/// `name` is already lowercase. Relaxed: unfold + collapse WSP (incl CR/LF) to
/// a single space, strip leading/trailing WSP, retain the colon.
pub fn appendCanonHeader(allocator: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, raw_value: []const u8) !void {
    try out.appendSlice(allocator, name);
    try out.append(allocator, ':');
    var started = false; // have we emitted a non-WSP char yet
    var pending_space = false;
    for (raw_value) |c| {
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
            if (started) pending_space = true;
            continue;
        }
        if (pending_space) {
            try out.append(allocator, ' ');
            pending_space = false;
        }
        try out.append(allocator, c);
        started = true;
    }
}

/// Relaxed body canonicalization (RFC 6376 §3.4.4): collapse WSP runs to one
/// space, strip trailing WSP per line, remove trailing empty lines, terminate
/// non-empty body with a single CRLF.
pub fn canonBodyRelaxed(allocator: std.mem.Allocator, body: []const u8, out: *std.ArrayList(u8)) !void {
    var tmp = std.ArrayList(u8).empty;
    defer tmp.deinit(allocator);
    // process line by line (split on \n; strip a trailing \r)
    var it = std.mem.splitScalar(u8, body, '\n');
    while (it.next()) |raw_line| {
        var line = raw_line;
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        // collapse internal WSP, strip trailing WSP
        var pending_space = false;
        var line_out = std.ArrayList(u8).empty;
        defer line_out.deinit(allocator);
        for (line) |c| {
            if (c == ' ' or c == '\t') {
                pending_space = true;
                continue;
            }
            if (pending_space) {
                try line_out.append(allocator, ' ');
                pending_space = false;
            }
            try line_out.append(allocator, c);
        }
        try tmp.appendSlice(allocator, line_out.items);
        try tmp.appendSlice(allocator, "\r\n");
    }
    // remove trailing empty lines: trim all trailing "\r\n" then add one back
    var end = tmp.items.len;
    while (end >= 2 and tmp.items[end - 2] == '\r' and tmp.items[end - 1] == '\n') {
        // is the line before this CRLF empty? trim while the content ends with CRLF CRLF
        // simpler: strip ALL trailing CRLFs, then if any content remains add one CRLF
        end -= 2;
    }
    const content = tmp.items[0..end];
    try out.appendSlice(allocator, content);
    if (content.len > 0) try out.appendSlice(allocator, "\r\n");
}

test "relaxed body canon: trailing empty lines + wsp" {
    const a = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(a);
    try canonBodyRelaxed(a, "Hello   world  \r\n\r\n\r\n", &out);
    try std.testing.expectEqualStrings("Hello world\r\n", out.items);
}

test "relaxed header canon collapses folds + wsp" {
    const a = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(a);
    try appendCanonHeader(a, &out, "subject", "  Hello   World\r\n\tfolded  ");
    try std.testing.expectEqualStrings("subject:Hello World folded", out.items);
}

test "findHeaderValue handles folding + case" {
    const hb = "From: a@b\r\nSubject: hi\r\n there\r\nDate: x\r\n";
    const v = findHeaderValue(hb, "subject").?;
    try std.testing.expectEqualStrings(" hi\r\n there", v);
}
