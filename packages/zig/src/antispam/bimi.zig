const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

// =============================================================================
// BIMI Implementation - Brand Indicators for Message Identification
// =============================================================================
//
// ## Overview
// BIMI (Brand Indicators for Message Identification) allows domain owners to
// associate a brand logo (SVG image) with authenticated email messages. When
// a receiving mail server verifies that a message passes DMARC with a policy
// of quarantine or reject, the server can look up the sender's BIMI record
// and display the associated brand indicator to the recipient.
//
// ## How BIMI Works
// 1. The sender publishes a BIMI DNS TXT record at: default._bimi.<domain>
//    Format: v=BIMI1; l=<url-to-svg>; a=<url-to-vmc>
//
// 2. The receiving server verifies DMARC alignment (must pass with p=quarantine
//    or p=reject).
//
// 3. The server queries the BIMI DNS record for the sender domain.
//
// 4. If a valid record is found, the server fetches the SVG indicator and
//    optionally validates the VMC (Verified Mark Certificate).
//
// 5. The brand logo is displayed to the recipient in supporting mail clients.
//
// ## BIMI DNS Record Tags
//   v= : Version (must be "BIMI1")
//   l= : Location URL pointing to an SVG Tiny PS brand indicator
//   a= : Authority URL pointing to a VMC (Verified Mark Certificate) in PEM format
//
// ## Requirements
// - DMARC must pass with p=quarantine or p=reject
// - SVG must conform to SVG Tiny PS (Portable/Secure) profile
// - VMC (optional but recommended) must be a valid S/MIME certificate
//   issued by a recognized Mark Verifying Authority (MVA)

// =============================================================================
// BIMI Record
// =============================================================================

/// Represents a parsed BIMI DNS TXT record.
/// Format: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
pub const BIMIRecord = struct {
    /// BIMI version string (must be "BIMI1")
    version: []const u8,
    /// Location URL pointing to an SVG Tiny PS brand indicator image
    location: ?[]const u8,
    /// Authority URL pointing to a VMC certificate in PEM format
    authority: ?[]const u8,
    /// The raw, unparsed DNS TXT record value
    raw_record: []const u8,

    allocator: std.mem.Allocator,

    pub fn deinit(self: *BIMIRecord) void {
        self.allocator.free(self.version);
        if (self.location) |loc| self.allocator.free(loc);
        if (self.authority) |auth| self.allocator.free(auth);
        self.allocator.free(self.raw_record);
    }
};

// =============================================================================
// BIMI Result
// =============================================================================

/// The outcome of a BIMI evaluation for a message.
pub const BIMIResult = enum {
    /// BIMI record found and validated; indicator may be displayed
    pass,
    /// No BIMI record published for the domain
    none,
    /// BIMI evaluation failed (invalid record, missing DMARC, etc.)
    fail,
    /// Temporary error during lookup or validation (DNS timeout, etc.)
    temperror,
    /// BIMI record found but the receiver chose not to display it
    declined,

    pub fn toString(self: BIMIResult) []const u8 {
        return switch (self) {
            .pass => "pass",
            .none => "none",
            .fail => "fail",
            .temperror => "temperror",
            .declined => "declined",
        };
    }

    /// Returns true if the result indicates a usable brand indicator.
    pub fn isSuccess(self: BIMIResult) bool {
        return self == .pass;
    }

    /// Returns true if the result represents an error condition.
    pub fn isError(self: BIMIResult) bool {
        return self == .fail or self == .temperror;
    }
};

// =============================================================================
// BIMI Indicator
// =============================================================================

/// Holds fetched BIMI indicator metadata for a domain, including the SVG URL,
/// optional VMC URL, verification status, and DMARC alignment state.
pub const BIMIIndicator = struct {
    /// The domain this indicator belongs to
    domain: []const u8,
    /// URL to the SVG Tiny PS brand indicator image
    svg_url: []const u8,
    /// URL to the VMC certificate (may be empty if not provided)
    vmc_url: ?[]const u8,
    /// Whether the indicator has been verified (VMC validated)
    verified: bool,
    /// Whether the domain's DMARC policy is aligned (p=quarantine or p=reject)
    dmarc_aligned: bool,
    /// Unix timestamp (seconds) when this indicator was fetched
    fetched_at: i64,

    allocator: std.mem.Allocator,

    pub fn deinit(self: *BIMIIndicator) void {
        self.allocator.free(self.domain);
        self.allocator.free(self.svg_url);
        if (self.vmc_url) |vmc| self.allocator.free(vmc);
    }

    /// Returns true if the indicator is both verified and DMARC-aligned,
    /// meaning it is eligible for display.
    pub fn isDisplayable(self: *const BIMIIndicator) bool {
        return self.dmarc_aligned and self.verified;
    }
};

// =============================================================================
// DMARC Result (local enum to avoid circular dependency)
// =============================================================================

/// Simplified DMARC result for BIMI validation purposes.
/// BIMI requires DMARC to pass with an enforcement policy.
pub const DMARCOutcome = enum {
    pass,
    fail,
    none,
    temperror,
    permerror,
};

/// DMARC policy levels relevant to BIMI eligibility.
pub const DMARCPolicyLevel = enum {
    none,
    quarantine,
    reject,

    pub fn fromString(s: []const u8) DMARCPolicyLevel {
        if (std.ascii.eqlIgnoreCase(s, "reject")) return .reject;
        if (std.ascii.eqlIgnoreCase(s, "quarantine")) return .quarantine;
        return .none;
    }

    /// BIMI requires either quarantine or reject.
    pub fn isBIMIEligible(self: DMARCPolicyLevel) bool {
        return self == .quarantine or self == .reject;
    }
};

// =============================================================================
// URL Validation Helpers
// =============================================================================

/// Validates that a URL is a well-formed HTTPS URL pointing to an SVG resource.
/// BIMI requires the indicator to be served over HTTPS and be an SVG file.
pub fn validateSvgUrl(url: []const u8) bool {
    // Must start with https://
    if (!std.mem.startsWith(u8, url, "https://")) return false;

    // Must have content after the scheme
    const after_scheme = url["https://".len..];
    if (after_scheme.len == 0) return false;

    // Extract hostname (everything before the first '/')
    const hostname = if (std.mem.indexOf(u8, after_scheme, "/")) |slash_pos|
        after_scheme[0..slash_pos]
    else
        after_scheme;

    // Must contain a dot in the hostname (valid FQDN)
    if (std.mem.indexOf(u8, hostname, ".") == null) return false;

    // Must end with .svg (case-insensitive check)
    if (url.len < 4) return false;
    const ext = url[url.len - 4 ..];
    if (!std.ascii.eqlIgnoreCase(ext, ".svg")) return false;

    return true;
}

/// Validates that a URL is a well-formed HTTPS URL pointing to a VMC certificate.
/// VMC certificates are typically in PEM format.
pub fn validateVmcUrl(url: []const u8) bool {
    // Must start with https://
    if (!std.mem.startsWith(u8, url, "https://")) return false;

    // Must have content after the scheme
    const after_scheme = url["https://".len..];
    if (after_scheme.len == 0) return false;

    // Extract hostname (everything before the first '/')
    const hostname = if (std.mem.indexOf(u8, after_scheme, "/")) |slash_pos|
        after_scheme[0..slash_pos]
    else
        after_scheme;

    // Must contain a dot in the hostname (valid FQDN)
    if (std.mem.indexOf(u8, hostname, ".") == null) return false;

    // Must end with .pem (case-insensitive check)
    if (url.len < 4) return false;
    const ext = url[url.len - 4 ..];
    if (!std.ascii.eqlIgnoreCase(ext, ".pem")) return false;

    return true;
}

// =============================================================================
// BIMI Validator
// =============================================================================

/// Core BIMI validator that performs DNS lookups, parses BIMI records, and
/// evaluates BIMI eligibility based on DMARC alignment.
pub const BIMIValidator = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BIMIValidator {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *BIMIValidator) void {
        // No owned resources to free; the allocator is borrowed.
        _ = self;
    }

    /// Look up the BIMI DNS TXT record for the given domain.
    /// Queries: default._bimi.<domain>
    ///
    /// In production this would perform an actual DNS TXT query.
    /// Currently stubbed to return null (no record found).
    pub fn lookupBIMI(self: *BIMIValidator, domain: []const u8) !?[]const u8 {
        _ = self;
        _ = domain;
        // Stub: In production, query DNS for TXT record at:
        //   default._bimi.<domain>
        // and return the TXT record value.
        return null;
    }

    /// Parse a BIMI DNS TXT record value into a BIMIRecord struct.
    /// Expected format: "v=BIMI1; l=<svg-url>; a=<vmc-url>"
    ///
    /// The version tag (v=BIMI1) is required. The location (l=) and
    /// authority (a=) tags are optional but at least the location
    /// should be present for a usable record.
    pub fn parseBIMIRecord(self: *BIMIValidator, txt_value: []const u8) !BIMIRecord {
        var record = BIMIRecord{
            .version = &.{},
            .location = null,
            .authority = null,
            .raw_record = try self.allocator.dupe(u8, txt_value),
            .allocator = self.allocator,
        };
        errdefer {
            if (record.version.len > 0) self.allocator.free(record.version);
            if (record.location) |loc| self.allocator.free(loc);
            if (record.authority) |auth| self.allocator.free(auth);
            self.allocator.free(record.raw_record);
        }

        // Parse semicolon-delimited tag=value pairs
        var tags = std.mem.splitScalar(u8, txt_value, ';');
        while (tags.next()) |tag| {
            const trimmed = std.mem.trim(u8, tag, " \t\r\n");
            if (trimmed.len == 0) continue;

            const eq_pos = std.mem.indexOf(u8, trimmed, "=") orelse continue;
            const tag_name = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            const tag_value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

            if (std.mem.eql(u8, tag_name, "v")) {
                record.version = try self.allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "l")) {
                if (tag_value.len > 0) {
                    record.location = try self.allocator.dupe(u8, tag_value);
                }
            } else if (std.mem.eql(u8, tag_name, "a")) {
                if (tag_value.len > 0) {
                    record.authority = try self.allocator.dupe(u8, tag_value);
                }
            }
        }

        // The version tag is mandatory and must be "BIMI1"
        if (record.version.len == 0 or !std.mem.eql(u8, record.version, "BIMI1")) {
            return error.InvalidBIMIRecord;
        }

        return record;
    }

    /// Validate BIMI eligibility for a domain given its DMARC evaluation outcome.
    ///
    /// BIMI requires:
    /// 1. DMARC must pass
    /// 2. DMARC policy must be quarantine or reject (not none)
    /// 3. A valid BIMI DNS record must exist
    /// 4. The BIMI record must contain a location URL
    pub fn validateBIMI(
        self: *BIMIValidator,
        domain: []const u8,
        dmarc_result: DMARCOutcome,
        dmarc_policy: DMARCPolicyLevel,
    ) !BIMIResult {
        // Step 1: DMARC must pass
        if (dmarc_result != .pass) {
            return .fail;
        }

        // Step 2: DMARC policy must be quarantine or reject
        if (!dmarc_policy.isBIMIEligible()) {
            return .fail;
        }

        // Step 3: Look up the BIMI record
        const txt_value = self.lookupBIMI(domain) catch {
            return .temperror;
        };

        if (txt_value == null) {
            return .none;
        }

        // Step 4: Parse and validate the BIMI record
        var record = self.parseBIMIRecord(txt_value.?) catch {
            return .fail;
        };
        defer record.deinit();

        // Step 5: Record must have a location URL
        if (record.location == null) {
            return .fail;
        }

        // Step 6: Validate the SVG URL format
        if (!validateSvgUrl(record.location.?)) {
            return .fail;
        }

        // Step 7: If authority is present, validate its URL format
        if (record.authority) |auth| {
            if (!validateVmcUrl(auth)) {
                return .declined;
            }
        }

        return .pass;
    }

    /// Fetch the SVG brand indicator from the given URL.
    ///
    /// In production this would perform an HTTPS GET request to retrieve the
    /// SVG image data. Currently stubbed to return null.
    pub fn fetchIndicator(self: *BIMIValidator, url: []const u8) !?[]const u8 {
        _ = self;
        _ = url;
        // Stub: In production, perform an HTTPS GET request to the URL
        // and return the SVG content as bytes.
        // Validate that the response Content-Type is image/svg+xml.
        return null;
    }

    /// Build a full BIMIIndicator by looking up and validating the BIMI record
    /// for a domain, given its DMARC evaluation results.
    pub fn buildIndicator(
        self: *BIMIValidator,
        domain: []const u8,
        dmarc_result: DMARCOutcome,
        dmarc_policy: DMARCPolicyLevel,
    ) !?BIMIIndicator {
        const bimi_result = try self.validateBIMI(domain, dmarc_result, dmarc_policy);
        if (bimi_result != .pass) return null;

        const txt_value = (try self.lookupBIMI(domain)) orelse return null;
        var record = try self.parseBIMIRecord(txt_value);
        defer record.deinit();

        const svg_url = record.location orelse return null;

        const has_vmc = record.authority != null;

        return BIMIIndicator{
            .domain = try self.allocator.dupe(u8, domain),
            .svg_url = try self.allocator.dupe(u8, svg_url),
            .vmc_url = if (record.authority) |auth|
                try self.allocator.dupe(u8, auth)
            else
                null,
            .verified = has_vmc,
            .dmarc_aligned = true,
            .fetched_at = time_compat.timestamp(),
            .allocator = self.allocator,
        };
    }
};

// =============================================================================
// BIMI Policy
// =============================================================================

/// Represents a cached BIMI policy for a domain, including the selector used,
/// the resolved BIMI record, and TTL metadata.
pub const BIMIPolicy = struct {
    /// The domain this policy applies to
    domain: []const u8,
    /// The BIMI selector (typically "default")
    selector: []const u8,
    /// The parsed BIMI record, if one was found
    record: ?BIMIRecord,
    /// Unix timestamp (seconds) when this policy was last checked
    last_checked: i64,
    /// How long (in seconds) to cache this policy before re-querying DNS
    cache_ttl: i64,

    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        domain: []const u8,
        selector: []const u8,
        record: ?BIMIRecord,
        cache_ttl: i64,
    ) !BIMIPolicy {
        return .{
            .domain = try allocator.dupe(u8, domain),
            .selector = try allocator.dupe(u8, selector),
            .record = record,
            .last_checked = time_compat.timestamp(),
            .cache_ttl = cache_ttl,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BIMIPolicy) void {
        self.allocator.free(self.domain);
        self.allocator.free(self.selector);
        if (self.record) |*rec| {
            var mutable_rec = rec.*;
            mutable_rec.deinit();
        }
    }

    /// Returns the full DNS query name for this BIMI policy.
    /// Format: <selector>._bimi.<domain>
    pub fn getDnsName(self: *const BIMIPolicy, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}._bimi.{s}", .{
            self.selector,
            self.domain,
        });
    }

    /// Returns true if the policy has expired based on its TTL.
    pub fn isExpired(self: *const BIMIPolicy) bool {
        const now = time_compat.timestamp();
        return (now - self.last_checked) >= self.cache_ttl;
    }
};

// =============================================================================
// BIMI Policy Cache
// =============================================================================

/// A simple in-memory cache for BIMI policies keyed by domain name.
/// Supports get, put, removal, and TTL-based expiration checks.
pub const BIMIPolicyCache = struct {
    entries: std.StringHashMap(BIMIPolicy),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BIMIPolicyCache {
        return .{
            .entries = std.StringHashMap(BIMIPolicy).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BIMIPolicyCache) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var policy = entry.value_ptr.*;
            policy.deinit();
        }
        self.entries.deinit();
    }

    /// Retrieve a cached policy for the given domain.
    /// Returns null if no entry exists.
    pub fn get(self: *BIMIPolicyCache, domain: []const u8) ?*BIMIPolicy {
        return self.entries.getPtr(domain);
    }

    /// Insert or update a policy in the cache.
    /// The cache takes ownership of a duped copy of the domain key.
    pub fn put(self: *BIMIPolicyCache, policy: BIMIPolicy) !void {
        const key = try self.allocator.dupe(u8, policy.domain);
        errdefer self.allocator.free(key);

        // If an entry already exists, clean it up first
        if (self.entries.fetchRemove(policy.domain)) |existing| {
            self.allocator.free(existing.key);
            var old_policy = existing.value;
            old_policy.deinit();
        }

        try self.entries.put(key, policy);
    }

    /// Check whether the cached entry for a domain has expired.
    /// Returns true if the entry does not exist or its TTL has elapsed.
    pub fn isExpired(self: *BIMIPolicyCache, domain: []const u8) bool {
        const policy = self.get(domain) orelse return true;
        return policy.isExpired();
    }

    /// Remove a cached entry for the given domain and free its resources.
    pub fn remove(self: *BIMIPolicyCache, domain: []const u8) void {
        if (self.entries.fetchRemove(domain)) |existing| {
            self.allocator.free(existing.key);
            var old_policy = existing.value;
            old_policy.deinit();
        }
    }

    /// Return the number of entries currently in the cache.
    pub fn count(self: *const BIMIPolicyCache) u32 {
        return self.entries.count();
    }
};

// =============================================================================
// Tests
// =============================================================================

test "BIMI record parsing - valid record with location and authority" {
    const testing = std.testing;
    var validator = BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const txt = "v=BIMI1; l=https://example.com/brand/logo.svg; a=https://example.com/certs/vmc.pem";
    var record = try validator.parseBIMIRecord(txt);
    defer record.deinit();

    try testing.expectEqualStrings("BIMI1", record.version);
    try testing.expectEqualStrings("https://example.com/brand/logo.svg", record.location.?);
    try testing.expectEqualStrings("https://example.com/certs/vmc.pem", record.authority.?);
    try testing.expectEqualStrings(txt, record.raw_record);
}

test "BIMI record parsing - valid record with location only" {
    const testing = std.testing;
    var validator = BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const txt = "v=BIMI1; l=https://brand.example.org/icon.svg";
    var record = try validator.parseBIMIRecord(txt);
    defer record.deinit();

    try testing.expectEqualStrings("BIMI1", record.version);
    try testing.expectEqualStrings("https://brand.example.org/icon.svg", record.location.?);
    try testing.expect(record.authority == null);
}

test "BIMI record parsing - missing version tag" {
    const testing = std.testing;
    var validator = BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const txt = "l=https://example.com/logo.svg; a=https://example.com/vmc.pem";
    const result = validator.parseBIMIRecord(txt);
    try testing.expectError(error.InvalidBIMIRecord, result);
}

test "BIMI record parsing - wrong version" {
    const testing = std.testing;
    var validator = BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const txt = "v=BIMI2; l=https://example.com/logo.svg";
    const result = validator.parseBIMIRecord(txt);
    try testing.expectError(error.InvalidBIMIRecord, result);
}

test "BIMI record parsing - empty location value" {
    const testing = std.testing;
    var validator = BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const txt = "v=BIMI1; l=; a=";
    var record = try validator.parseBIMIRecord(txt);
    defer record.deinit();

    try testing.expectEqualStrings("BIMI1", record.version);
    try testing.expect(record.location == null);
    try testing.expect(record.authority == null);
}

test "BIMI record parsing - extra whitespace" {
    const testing = std.testing;
    var validator = BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const txt = "  v = BIMI1 ;  l = https://example.com/logo.svg ;  a = https://example.com/vmc.pem  ";
    var record = try validator.parseBIMIRecord(txt);
    defer record.deinit();

    try testing.expectEqualStrings("BIMI1", record.version);
    try testing.expectEqualStrings("https://example.com/logo.svg", record.location.?);
    try testing.expectEqualStrings("https://example.com/vmc.pem", record.authority.?);
}

test "BIMI validation - DMARC not passing" {
    const testing = std.testing;
    var validator = BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const result = try validator.validateBIMI("example.com", .fail, .reject);
    try testing.expect(result == .fail);
}

test "BIMI validation - DMARC policy none is ineligible" {
    const testing = std.testing;
    var validator = BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const result = try validator.validateBIMI("example.com", .pass, .none);
    try testing.expect(result == .fail);
}

test "BIMI validation - DMARC pass with quarantine returns none (no DNS record)" {
    const testing = std.testing;
    var validator = BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    // The stub lookupBIMI returns null, so we expect .none
    const result = try validator.validateBIMI("example.com", .pass, .quarantine);
    try testing.expect(result == .none);
}

test "BIMI validation - DMARC pass with reject returns none (no DNS record)" {
    const testing = std.testing;
    var validator = BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const result = try validator.validateBIMI("example.com", .pass, .reject);
    try testing.expect(result == .none);
}

test "BIMIResult toString" {
    const testing = std.testing;

    try testing.expectEqualStrings("pass", BIMIResult.pass.toString());
    try testing.expectEqualStrings("none", BIMIResult.none.toString());
    try testing.expectEqualStrings("fail", BIMIResult.fail.toString());
    try testing.expectEqualStrings("temperror", BIMIResult.temperror.toString());
    try testing.expectEqualStrings("declined", BIMIResult.declined.toString());
}

test "BIMIResult isSuccess and isError" {
    const testing = std.testing;

    try testing.expect(BIMIResult.pass.isSuccess());
    try testing.expect(!BIMIResult.fail.isSuccess());
    try testing.expect(!BIMIResult.none.isSuccess());

    try testing.expect(BIMIResult.fail.isError());
    try testing.expect(BIMIResult.temperror.isError());
    try testing.expect(!BIMIResult.pass.isError());
    try testing.expect(!BIMIResult.none.isError());
    try testing.expect(!BIMIResult.declined.isError());
}

test "DMARCPolicyLevel BIMI eligibility" {
    const testing = std.testing;

    try testing.expect(!DMARCPolicyLevel.none.isBIMIEligible());
    try testing.expect(DMARCPolicyLevel.quarantine.isBIMIEligible());
    try testing.expect(DMARCPolicyLevel.reject.isBIMIEligible());
}

test "DMARCPolicyLevel fromString" {
    const testing = std.testing;

    try testing.expect(DMARCPolicyLevel.fromString("reject") == .reject);
    try testing.expect(DMARCPolicyLevel.fromString("REJECT") == .reject);
    try testing.expect(DMARCPolicyLevel.fromString("quarantine") == .quarantine);
    try testing.expect(DMARCPolicyLevel.fromString("Quarantine") == .quarantine);
    try testing.expect(DMARCPolicyLevel.fromString("none") == .none);
    try testing.expect(DMARCPolicyLevel.fromString("unknown") == .none);
}

test "SVG URL validation" {
    const testing = std.testing;

    // Valid SVG URLs
    try testing.expect(validateSvgUrl("https://example.com/logo.svg"));
    try testing.expect(validateSvgUrl("https://brand.example.org/assets/icon.svg"));
    try testing.expect(validateSvgUrl("https://cdn.example.com/path/to/image.SVG"));

    // Invalid: not HTTPS
    try testing.expect(!validateSvgUrl("http://example.com/logo.svg"));

    // Invalid: no extension
    try testing.expect(!validateSvgUrl("https://example.com/logo"));

    // Invalid: wrong extension
    try testing.expect(!validateSvgUrl("https://example.com/logo.png"));

    // Invalid: empty after scheme
    try testing.expect(!validateSvgUrl("https://"));

    // Invalid: no hostname dot
    try testing.expect(!validateSvgUrl("https://localhost/logo.svg"));

    // Invalid: completely empty
    try testing.expect(!validateSvgUrl(""));
}

test "VMC URL validation" {
    const testing = std.testing;

    // Valid VMC URLs
    try testing.expect(validateVmcUrl("https://example.com/cert.pem"));
    try testing.expect(validateVmcUrl("https://certs.example.org/vmc/chain.pem"));
    try testing.expect(validateVmcUrl("https://ca.example.com/certificates/mark.PEM"));

    // Invalid: not HTTPS
    try testing.expect(!validateVmcUrl("http://example.com/cert.pem"));

    // Invalid: wrong extension
    try testing.expect(!validateVmcUrl("https://example.com/cert.crt"));

    // Invalid: no extension
    try testing.expect(!validateVmcUrl("https://example.com/cert"));

    // Invalid: empty
    try testing.expect(!validateVmcUrl(""));

    // Invalid: no hostname dot
    try testing.expect(!validateVmcUrl("https://localhost/cert.pem"));
}

test "BIMIPolicy init and DNS name" {
    const testing = std.testing;

    const policy = try BIMIPolicy.init(
        testing.allocator,
        "example.com",
        "default",
        null,
        3600,
    );
    var policy_mut = policy;
    defer policy_mut.deinit();

    try testing.expectEqualStrings("example.com", policy.domain);
    try testing.expectEqualStrings("default", policy.selector);
    try testing.expect(policy.record == null);
    try testing.expectEqual(@as(i64, 3600), policy.cache_ttl);

    const dns_name = try policy.getDnsName(testing.allocator);
    defer testing.allocator.free(dns_name);
    try testing.expectEqualStrings("default._bimi.example.com", dns_name);
}

test "BIMIPolicy expiration" {
    const testing = std.testing;

    // Create a policy with TTL of 0 so it is immediately expired
    const policy = try BIMIPolicy.init(
        testing.allocator,
        "example.com",
        "default",
        null,
        0,
    );
    var policy_mut = policy;
    defer policy_mut.deinit();

    try testing.expect(policy.isExpired());
}

test "BIMIPolicyCache put and get" {
    const testing = std.testing;

    var cache = BIMIPolicyCache.init(testing.allocator);
    defer cache.deinit();

    const policy = try BIMIPolicy.init(
        testing.allocator,
        "example.com",
        "default",
        null,
        3600,
    );
    // Note: cache takes ownership, so we must not defer deinit here

    try cache.put(policy);

    try testing.expectEqual(@as(u32, 1), cache.count());

    const retrieved = cache.get("example.com");
    try testing.expect(retrieved != null);
    try testing.expectEqualStrings("example.com", retrieved.?.domain);
    try testing.expectEqualStrings("default", retrieved.?.selector);
}

test "BIMIPolicyCache get nonexistent" {
    const testing = std.testing;

    var cache = BIMIPolicyCache.init(testing.allocator);
    defer cache.deinit();

    const retrieved = cache.get("nonexistent.com");
    try testing.expect(retrieved == null);
}

test "BIMIPolicyCache isExpired with no entry" {
    const testing = std.testing;

    var cache = BIMIPolicyCache.init(testing.allocator);
    defer cache.deinit();

    // Non-existent entry should be considered expired
    try testing.expect(cache.isExpired("nonexistent.com"));
}

test "BIMIPolicyCache remove" {
    const testing = std.testing;

    var cache = BIMIPolicyCache.init(testing.allocator);
    defer cache.deinit();

    const policy = try BIMIPolicy.init(
        testing.allocator,
        "example.com",
        "default",
        null,
        3600,
    );

    try cache.put(policy);
    try testing.expectEqual(@as(u32, 1), cache.count());

    cache.remove("example.com");
    try testing.expectEqual(@as(u32, 0), cache.count());
    try testing.expect(cache.get("example.com") == null);
}

test "BIMIPolicyCache replace existing entry" {
    const testing = std.testing;

    var cache = BIMIPolicyCache.init(testing.allocator);
    defer cache.deinit();

    const policy1 = try BIMIPolicy.init(
        testing.allocator,
        "example.com",
        "default",
        null,
        3600,
    );

    try cache.put(policy1);

    // Replace with a different selector
    const policy2 = try BIMIPolicy.init(
        testing.allocator,
        "example.com",
        "brand2024",
        null,
        7200,
    );

    try cache.put(policy2);

    try testing.expectEqual(@as(u32, 1), cache.count());

    const retrieved = cache.get("example.com");
    try testing.expect(retrieved != null);
    try testing.expectEqualStrings("brand2024", retrieved.?.selector);
    try testing.expectEqual(@as(i64, 7200), retrieved.?.cache_ttl);
}

test "BIMIIndicator isDisplayable" {
    const testing = std.testing;

    var indicator = BIMIIndicator{
        .domain = try testing.allocator.dupe(u8, "example.com"),
        .svg_url = try testing.allocator.dupe(u8, "https://example.com/logo.svg"),
        .vmc_url = try testing.allocator.dupe(u8, "https://example.com/vmc.pem"),
        .verified = true,
        .dmarc_aligned = true,
        .fetched_at = time_compat.timestamp(),
        .allocator = testing.allocator,
    };
    defer indicator.deinit();

    try testing.expect(indicator.isDisplayable());

    // Not displayable if not verified
    indicator.verified = false;
    try testing.expect(!indicator.isDisplayable());

    // Not displayable if DMARC not aligned
    indicator.verified = true;
    indicator.dmarc_aligned = false;
    try testing.expect(!indicator.isDisplayable());
}

test "BIMIValidator lookupBIMI returns null (stubbed)" {
    const testing = std.testing;
    var validator = BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const result = try validator.lookupBIMI("example.com");
    try testing.expect(result == null);
}

test "BIMIValidator fetchIndicator returns null (stubbed)" {
    const testing = std.testing;
    var validator = BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const result = try validator.fetchIndicator("https://example.com/logo.svg");
    try testing.expect(result == null);
}
