const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

// =============================================================================
// DANE/TLSA Implementation - RFC 6698 / RFC 7672
// =============================================================================
//
// ## Overview
// DNS-Based Authentication of Named Entities (DANE) uses TLSA DNS records to
// associate TLS server certificates or public keys with the domain name where
// they are found. This enables domain owners to specify which TLS credentials
// a connecting client should expect, providing a stronger chain of trust than
// traditional CA-based PKI alone.
//
// RFC 7672 extends DANE specifically for SMTP, defining how MTAs should
// look up and validate TLSA records for mail delivery.
//
// ## TLSA Record Format (RFC 6698 Section 2)
// TLSA records are published at: _port._tcp.hostname
// Format: <usage> <selector> <matching_type> <certificate_association_data>
//
// Example DNS record:
//   _25._tcp.mail.example.com. IN TLSA 3 1 1 <sha256-hash-hex>
//
// ## Certificate Usage Values
//   0 - CA Constraint (PKIX-TA): Match against a CA certificate in the chain
//   1 - Service Certificate Constraint (PKIX-EE): Match against the end entity
//       certificate, also requiring PKIX validation
//   2 - Trust Anchor Assertion (DANE-TA): Match against a trust anchor; chain
//       must build to this anchor, no PKIX required
//   3 - Domain-Issued Certificate (DANE-EE): Match against the end entity
//       certificate directly; no PKIX required
//
// ## Selector Values
//   0 - Full certificate (DER-encoded)
//   1 - SubjectPublicKeyInfo (DER-encoded)
//
// ## Matching Type Values
//   0 - Exact match (no hash)
//   1 - SHA-256 hash
//   2 - SHA-512 hash
//
// ## SMTP-specific Behavior (RFC 7672)
// - TLSA records are looked up for the MX host, not the recipient domain
// - Usage 3 (DANE-EE) is recommended for SMTP as it avoids PKIX complexity
// - If DNSSEC-validated TLSA records exist, TLS is mandatory (no fallback)
// - If no TLSA records exist (or DNSSEC fails), opportunistic TLS is used
//
// ## Security Considerations
// - DANE relies on DNSSEC for integrity; without DNSSEC, TLSA records
//   are advisory only
// - Implementations must handle DNS timeouts gracefully (return temperror)
// - Cache TLSA records respecting DNS TTL values
// - Usage 3 (DANE-EE) does not require hostname verification, since the
//   certificate itself is pinned via the TLSA record
// =============================================================================

/// TLSA certificate usage field (RFC 6698 Section 2.1.1)
pub const TLSAUsage = enum(u8) {
    /// PKIX-TA: CA constraint. The certificate presented must pass PKIX
    /// validation and must chain to a trust anchor matching the TLSA record.
    CA_CONSTRAINT = 0,

    /// PKIX-EE: Service certificate constraint. The end-entity certificate
    /// must match the TLSA record and pass PKIX validation.
    SERVICE_CERT_CONSTRAINT = 1,

    /// DANE-TA: Trust anchor assertion. The certificate chain must include
    /// a certificate matching the TLSA record. No PKIX validation required.
    TRUST_ANCHOR_ASSERTION = 2,

    /// DANE-EE: Domain-issued certificate. The end-entity certificate must
    /// match the TLSA record directly. No PKIX or chain validation required.
    /// This is the recommended usage for SMTP (RFC 7672 Section 3.1).
    DOMAIN_ISSUED_CERT = 3,

    pub fn toString(self: TLSAUsage) []const u8 {
        return switch (self) {
            .CA_CONSTRAINT => "PKIX-TA (CA Constraint)",
            .SERVICE_CERT_CONSTRAINT => "PKIX-EE (Service Certificate Constraint)",
            .TRUST_ANCHOR_ASSERTION => "DANE-TA (Trust Anchor Assertion)",
            .DOMAIN_ISSUED_CERT => "DANE-EE (Domain-Issued Certificate)",
        };
    }

    pub fn fromInt(value: u8) ?TLSAUsage {
        return switch (value) {
            0 => .CA_CONSTRAINT,
            1 => .SERVICE_CERT_CONSTRAINT,
            2 => .TRUST_ANCHOR_ASSERTION,
            3 => .DOMAIN_ISSUED_CERT,
            else => null,
        };
    }

    /// Whether this usage type requires PKIX (traditional CA) validation
    /// in addition to TLSA matching.
    pub fn requiresPKIX(self: TLSAUsage) bool {
        return switch (self) {
            .CA_CONSTRAINT, .SERVICE_CERT_CONSTRAINT => true,
            .TRUST_ANCHOR_ASSERTION, .DOMAIN_ISSUED_CERT => false,
        };
    }

    /// Whether this usage type matches against the end-entity certificate
    /// (as opposed to a CA or trust anchor in the chain).
    pub fn isEndEntity(self: TLSAUsage) bool {
        return switch (self) {
            .SERVICE_CERT_CONSTRAINT, .DOMAIN_ISSUED_CERT => true,
            .CA_CONSTRAINT, .TRUST_ANCHOR_ASSERTION => false,
        };
    }
};

/// TLSA selector field (RFC 6698 Section 2.1.2)
pub const TLSASelector = enum(u8) {
    /// Match against the full DER-encoded certificate.
    FULL_CERT = 0,

    /// Match against the DER-encoded SubjectPublicKeyInfo structure.
    /// This is often preferred because it remains stable across certificate
    /// renewal if the same key pair is reused.
    SUBJECT_PUBLIC_KEY_INFO = 1,

    pub fn toString(self: TLSASelector) []const u8 {
        return switch (self) {
            .FULL_CERT => "Full Certificate",
            .SUBJECT_PUBLIC_KEY_INFO => "SubjectPublicKeyInfo",
        };
    }

    pub fn fromInt(value: u8) ?TLSASelector {
        return switch (value) {
            0 => .FULL_CERT,
            1 => .SUBJECT_PUBLIC_KEY_INFO,
            else => null,
        };
    }
};

/// TLSA matching type field (RFC 6698 Section 2.1.3)
pub const TLSAMatchingType = enum(u8) {
    /// No hash used; exact match on the full data.
    EXACT = 0,

    /// SHA-256 hash of the selected content.
    SHA256 = 1,

    /// SHA-512 hash of the selected content.
    SHA512 = 2,

    pub fn toString(self: TLSAMatchingType) []const u8 {
        return switch (self) {
            .EXACT => "Exact Match",
            .SHA256 => "SHA-256",
            .SHA512 => "SHA-512",
        };
    }

    pub fn fromInt(value: u8) ?TLSAMatchingType {
        return switch (value) {
            0 => .EXACT,
            1 => .SHA256,
            2 => .SHA512,
            else => null,
        };
    }

    /// Return the expected hash length in bytes for this matching type.
    /// Returns null for EXACT since the length depends on the input.
    pub fn hashLength(self: TLSAMatchingType) ?usize {
        return switch (self) {
            .EXACT => null,
            .SHA256 => 32,
            .SHA512 => 64,
        };
    }
};

/// A parsed TLSA DNS record (RFC 6698 Section 2)
pub const TLSARecord = struct {
    /// Certificate usage field (0-3)
    usage: TLSAUsage,

    /// Selector field: what part of the certificate to match (0-1)
    selector: TLSASelector,

    /// Matching type: how to compare the data (0-2)
    matching_type: TLSAMatchingType,

    /// Certificate association data (hex-encoded hash or raw certificate bytes)
    certificate_data: []const u8,

    /// Whether this record was validated via DNSSEC
    dnssec_validated: bool,

    allocator: std.mem.Allocator,

    pub fn deinit(self: *TLSARecord) void {
        self.allocator.free(self.certificate_data);
    }

    /// Parse a TLSA record from its textual representation.
    /// Expected format: "<usage> <selector> <matching_type> <hex-data>"
    /// Example: "3 1 1 a]0b9c2f..."
    pub fn parse(allocator: std.mem.Allocator, record_text: []const u8) !TLSARecord {
        const trimmed = std.mem.trim(u8, record_text, " \t\r\n");
        if (trimmed.len == 0) return error.InvalidTLSARecord;

        var parts = std.mem.splitScalar(u8, trimmed, ' ');

        // Parse usage field
        const usage_str = parts.next() orelse return error.InvalidTLSARecord;
        const usage_int = std.fmt.parseInt(u8, usage_str, 10) catch return error.InvalidTLSARecord;
        const usage = TLSAUsage.fromInt(usage_int) orelse return error.InvalidTLSARecord;

        // Parse selector field
        const selector_str = parts.next() orelse return error.InvalidTLSARecord;
        const selector_int = std.fmt.parseInt(u8, selector_str, 10) catch return error.InvalidTLSARecord;
        const selector = TLSASelector.fromInt(selector_int) orelse return error.InvalidTLSARecord;

        // Parse matching type field
        const matching_str = parts.next() orelse return error.InvalidTLSARecord;
        const matching_int = std.fmt.parseInt(u8, matching_str, 10) catch return error.InvalidTLSARecord;
        const matching_type = TLSAMatchingType.fromInt(matching_int) orelse return error.InvalidTLSARecord;

        // Remaining content is the certificate association data (hex encoded)
        // Collect all remaining parts (data may contain spaces)
        var data_buf: std.ArrayList(u8) = .empty;
        defer data_buf.deinit(allocator);

        while (parts.next()) |part| {
            const part_trimmed = std.mem.trim(u8, part, " \t");
            if (part_trimmed.len == 0) continue;
            try data_buf.appendSlice(allocator, part_trimmed);
        }

        if (data_buf.items.len == 0) return error.InvalidTLSARecord;

        // Validate hex data
        for (data_buf.items) |c| {
            if (!std.ascii.isHex(c)) return error.InvalidTLSARecord;
        }

        // Validate data length against matching type
        if (matching_type.hashLength()) |expected_len| {
            // Hex-encoded, so expected byte count * 2
            if (data_buf.items.len != expected_len * 2) return error.InvalidTLSARecord;
        }

        const certificate_data = try allocator.dupe(u8, data_buf.items);

        return TLSARecord{
            .usage = usage,
            .selector = selector,
            .matching_type = matching_type,
            .certificate_data = certificate_data,
            .dnssec_validated = false,
            .allocator = allocator,
        };
    }

    /// Format the TLSA record as a DNS presentation string.
    pub fn format(self: *const TLSARecord, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{d} {d} {d} {s}", .{
            @intFromEnum(self.usage),
            @intFromEnum(self.selector),
            @intFromEnum(self.matching_type),
            self.certificate_data,
        });
    }

    /// Format the full DNS name for this TLSA record.
    pub fn dnsName(allocator: std.mem.Allocator, domain: []const u8, port: u16) ![]u8 {
        return std.fmt.allocPrint(allocator, "_{d}._tcp.{s}", .{ port, domain });
    }
};

/// DANE validation result
pub const DANEResult = enum {
    /// Certificate matched a TLSA record successfully.
    pass,

    /// Certificate did not match any TLSA record.
    fail,

    /// Temporary error during validation (DNS timeout, etc.).
    temperror,

    /// Permanent error in TLSA records or configuration.
    permerror,

    /// No TLSA records found for the domain (DANE is not configured).
    no_tlsa,

    pub fn toString(self: DANEResult) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .temperror => "temperror",
            .permerror => "permerror",
            .no_tlsa => "no_tlsa",
        };
    }

    /// Whether the result indicates that mail delivery should proceed.
    /// For DANE, even a failure might not block delivery depending on policy.
    pub fn shouldProceed(self: DANEResult) bool {
        return switch (self) {
            .pass, .no_tlsa => true,
            .fail, .permerror => false,
            .temperror => true, // Fail-open for temporary errors per RFC 7672
        };
    }

    /// Whether the result indicates that TLS is required for this connection.
    /// When DANE records are found (pass or fail), TLS is mandatory.
    pub fn requiresTLS(self: DANEResult) bool {
        return switch (self) {
            .pass, .fail, .permerror => true,
            .no_tlsa, .temperror => false,
        };
    }
};

/// DANE policy for a specific domain, containing cached TLSA records.
pub const DANEPolicy = struct {
    /// The domain this policy applies to (e.g., "mail.example.com").
    domain: []const u8,

    /// The TLSA records associated with this domain/port combination.
    records: std.ArrayList(TLSARecord),

    /// Unix timestamp when the records were last fetched from DNS.
    last_checked: i64,

    /// Cache TTL in seconds (derived from DNS TTL).
    cache_ttl: u32,

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, domain: []const u8, cache_ttl: u32) !DANEPolicy {
        return .{
            .domain = try allocator.dupe(u8, domain),
            .records = .{},
            .last_checked = time_compat.timestamp(),
            .cache_ttl = cache_ttl,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DANEPolicy) void {
        for (self.records.items) |*record| {
            record.deinit();
        }
        self.records.deinit(self.allocator);
        self.allocator.free(self.domain);
    }

    /// Add a TLSA record to this policy.
    pub fn addRecord(self: *DANEPolicy, record: TLSARecord) !void {
        try self.records.append(self.allocator, record);
    }

    /// Check whether this policy has expired based on its TTL.
    pub fn isExpired(self: *const DANEPolicy) bool {
        const now = time_compat.timestamp();
        return (now - self.last_checked) >= @as(i64, self.cache_ttl);
    }

    /// Check whether this policy has expired relative to a given timestamp.
    pub fn isExpiredAt(self: *const DANEPolicy, timestamp: i64) bool {
        return (timestamp - self.last_checked) >= @as(i64, self.cache_ttl);
    }

    /// Refresh the last_checked timestamp.
    pub fn refresh(self: *DANEPolicy) void {
        self.last_checked = time_compat.timestamp();
    }

    /// Return the number of TLSA records in this policy.
    pub fn recordCount(self: *const DANEPolicy) usize {
        return self.records.items.len;
    }

    /// Check whether any records require PKIX validation.
    pub fn requiresPKIX(self: *const DANEPolicy) bool {
        for (self.records.items) |record| {
            if (record.usage.requiresPKIX()) return true;
        }
        return false;
    }
};

/// Cache for DANE policies, keyed by domain name.
pub const DANEPolicyCache = struct {
    policies: std.StringHashMap(DANEPolicy),
    allocator: std.mem.Allocator,
    max_entries: usize,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) DANEPolicyCache {
        return .{
            .policies = std.StringHashMap(DANEPolicy).init(allocator),
            .allocator = allocator,
            .max_entries = max_entries,
        };
    }

    pub fn deinit(self: *DANEPolicyCache) void {
        var it = self.policies.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.policies.deinit();
    }

    /// Retrieve a cached policy for the given domain.
    /// Returns null if no policy is cached or if the cached policy has expired.
    pub fn get(self: *DANEPolicyCache, domain: []const u8) ?*DANEPolicy {
        const policy = self.policies.getPtr(domain) orelse return null;
        if (policy.isExpired()) {
            return null;
        }
        return policy;
    }

    /// Store a policy in the cache. If the cache is full, evict the oldest entry.
    pub fn put(self: *DANEPolicyCache, policy: DANEPolicy) !void {
        // Evict expired entries if we are at capacity
        if (self.policies.count() >= self.max_entries) {
            self.evictExpired();
        }

        // If still at capacity after eviction, remove the oldest entry
        if (self.policies.count() >= self.max_entries) {
            self.evictOldest();
        }

        const key = try self.allocator.dupe(u8, policy.domain);
        errdefer self.allocator.free(key);

        // If a policy already exists for this domain, clean it up
        if (self.policies.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            var old_policy = removed.value;
            old_policy.deinit();
        }

        try self.policies.put(key, policy);
    }

    /// Check whether a cached policy for the given domain has expired.
    pub fn isExpired(self: *DANEPolicyCache, domain: []const u8) bool {
        const policy = self.policies.getPtr(domain) orelse return true;
        return policy.isExpired();
    }

    /// Remove a specific domain from the cache.
    pub fn remove(self: *DANEPolicyCache, domain: []const u8) void {
        if (self.policies.fetchRemove(domain)) |removed| {
            self.allocator.free(removed.key);
            var policy = removed.value;
            policy.deinit();
        }
    }

    /// Remove all expired entries from the cache.
    pub fn evictExpired(self: *DANEPolicyCache) void {
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.policies.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.policies.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
                var policy = removed.value;
                policy.deinit();
            }
        }
    }

    /// Remove the oldest entry (by last_checked timestamp) from the cache.
    fn evictOldest(self: *DANEPolicyCache) void {
        var oldest_key: ?[]const u8 = null;
        var oldest_time: i64 = std.math.maxInt(i64);

        var it = self.policies.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.last_checked < oldest_time) {
                oldest_time = entry.value_ptr.last_checked;
                oldest_key = entry.key_ptr.*;
            }
        }

        if (oldest_key) |key| {
            if (self.policies.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
                var policy = removed.value;
                policy.deinit();
            }
        }
    }

    /// Return the number of cached policies.
    pub fn count(self: *const DANEPolicyCache) usize {
        return self.policies.count();
    }
};

/// DANE/TLSA validator for SMTP connections (RFC 7672)
pub const DANEValidator = struct {
    allocator: std.mem.Allocator,
    cache: DANEPolicyCache,
    dns_timeout_ms: u32,

    pub fn init(allocator: std.mem.Allocator) DANEValidator {
        return .{
            .allocator = allocator,
            .cache = DANEPolicyCache.init(allocator, 1024),
            .dns_timeout_ms = 5000,
        };
    }

    pub fn deinit(self: *DANEValidator) void {
        self.cache.deinit();
    }

    /// Look up TLSA records for a given domain and port.
    /// Queries DNS for _port._tcp.domain TLSA records.
    ///
    /// In production, this would perform actual DNS queries via the system
    /// resolver or a dedicated DNS library, requiring DNSSEC validation.
    /// This implementation provides a stubbed DNS layer consistent with
    /// the existing DKIM/SPF pattern in this codebase.
    pub fn lookupTLSA(self: *DANEValidator, domain: []const u8, port: u16) !?[]TLSARecord {
        // Check cache first
        if (self.cache.get(domain)) |policy| {
            if (policy.records.items.len > 0) {
                // Return a copy of cached records
                var records = try self.allocator.alloc(TLSARecord, policy.records.items.len);
                for (policy.records.items, 0..) |record, i| {
                    records[i] = TLSARecord{
                        .usage = record.usage,
                        .selector = record.selector,
                        .matching_type = record.matching_type,
                        .certificate_data = try self.allocator.dupe(u8, record.certificate_data),
                        .dnssec_validated = record.dnssec_validated,
                        .allocator = self.allocator,
                    };
                }
                return records;
            }
        }

        // Construct the TLSA query name: _port._tcp.domain
        const query_name = try TLSARecord.dnsName(self.allocator, domain, port);
        defer self.allocator.free(query_name);

        // In production, this would perform an actual DNSSEC-validated
        // DNS query for TLSA records at the constructed name.
        //
        // The query flow would be:
        // 1. Resolve _port._tcp.domain for TLSA records
        // 2. Verify DNSSEC signatures on the response
        // 3. Parse each TLSA RR into a TLSARecord struct
        // 4. Cache the results with the DNS TTL
        //
        // For now, we return null to indicate no TLSA records found,
        // matching the stub pattern used in DKIM's queryPublicKey and
        // SPF's querySPFRecord.

        return null;
    }

    /// Validate a certificate against a set of TLSA records.
    ///
    /// This implements the core DANE validation logic per RFC 6698 Section 2.2:
    /// - For each TLSA record, extract the appropriate data from the certificate
    ///   (based on the selector field), compute the hash (based on the matching
    ///   type), and compare against the certificate_data in the record.
    /// - The certificate passes if it matches ANY of the provided TLSA records.
    pub fn validateCertificate(
        self: *DANEValidator,
        cert_data: []const u8,
        tlsa_records: []const TLSARecord,
    ) DANEResult {
        if (tlsa_records.len == 0) {
            return .no_tlsa;
        }

        if (cert_data.len == 0) {
            return .permerror;
        }

        var had_match_attempt = false;

        for (tlsa_records) |record| {
            had_match_attempt = true;

            // Select the appropriate data from the certificate based on the
            // selector field.
            const selected_data = self.selectCertificateData(cert_data, record.selector);

            // Compute the comparison value based on the matching type.
            const match_result = self.matchData(selected_data, record.matching_type, record.certificate_data);

            if (match_result) {
                return .pass;
            }
        }

        if (!had_match_attempt) {
            return .permerror;
        }

        return .fail;
    }

    /// Select the relevant portion of the certificate based on the TLSA selector.
    ///
    /// For FULL_CERT (0): return the entire DER-encoded certificate.
    /// For SUBJECT_PUBLIC_KEY_INFO (1): extract and return the SubjectPublicKeyInfo
    /// structure from the certificate.
    ///
    /// In a full implementation, SUBJECT_PUBLIC_KEY_INFO extraction would require
    /// ASN.1/DER parsing of the X.509 certificate to locate the
    /// SubjectPublicKeyInfo field within the TBSCertificate structure.
    fn selectCertificateData(self: *DANEValidator, cert_data: []const u8, selector: TLSASelector) []const u8 {
        _ = self;
        return switch (selector) {
            .FULL_CERT => cert_data,
            .SUBJECT_PUBLIC_KEY_INFO => {
                // In production, this would parse the X.509 DER structure to
                // extract the SubjectPublicKeyInfo. The SPKI is located at a
                // specific offset within TBSCertificate:
                //
                //   Certificate ::= SEQUENCE {
                //       tbsCertificate       TBSCertificate,
                //       signatureAlgorithm   AlgorithmIdentifier,
                //       signatureValue       BIT STRING
                //   }
                //
                //   TBSCertificate ::= SEQUENCE {
                //       version         [0]  EXPLICIT INTEGER DEFAULT v1,
                //       serialNumber         CertificateSerialNumber,
                //       signature            AlgorithmIdentifier,
                //       issuer               Name,
                //       validity             Validity,
                //       subject              Name,
                //       subjectPubKeyInfo    SubjectPublicKeyInfo,  <-- this
                //       ...
                //   }
                //
                // For now, return the full certificate data as a placeholder.
                // A real implementation would use proper ASN.1 parsing or
                // delegate to OpenSSL/BoringSSL via C interop.
                return cert_data;
            },
        };
    }

    /// Compare selected certificate data against a TLSA record's certificate_data
    /// using the specified matching type.
    ///
    /// Returns true if the data matches.
    fn matchData(
        self: *DANEValidator,
        selected_data: []const u8,
        matching_type: TLSAMatchingType,
        expected_hex: []const u8,
    ) bool {
        return switch (matching_type) {
            .EXACT => {
                // Convert selected_data to hex and compare
                const hex = self.bytesToHex(selected_data) catch return false;
                defer self.allocator.free(hex);
                return std.ascii.eqlIgnoreCase(hex, expected_hex);
            },
            .SHA256 => {
                const hash = self.computeSHA256Hash(selected_data);
                const hex = self.bytesToHex(&hash) catch return false;
                defer self.allocator.free(hex);
                return std.ascii.eqlIgnoreCase(hex, expected_hex);
            },
            .SHA512 => {
                const hash = self.computeSHA512Hash(selected_data);
                const hex = self.bytesToHex(&hash) catch return false;
                defer self.allocator.free(hex);
                return std.ascii.eqlIgnoreCase(hex, expected_hex);
            },
        };
    }

    /// Compute SHA-256 hash of the provided data.
    /// Used for TLSA matching_type 1.
    pub fn computeSHA256Hash(self: *DANEValidator, data: []const u8) [32]u8 {
        _ = self;
        var out: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
        return out;
    }

    /// Compute SHA-512 hash of the provided data.
    /// Used for TLSA matching_type 2.
    pub fn computeSHA512Hash(self: *DANEValidator, data: []const u8) [64]u8 {
        _ = self;
        var out: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(data, &out, .{});
        return out;
    }

    /// Convert a byte slice to a lowercase hex string.
    fn bytesToHex(self: *DANEValidator, data: []const u8) ![]u8 {
        const hex = try self.allocator.alloc(u8, data.len * 2);
        for (data, 0..) |byte, i| {
            const hi: u4 = @intCast(byte >> 4);
            const lo: u4 = @intCast(byte & 0x0f);
            hex[i * 2] = std.fmt.digitToChar(hi, .lower);
            hex[i * 2 + 1] = std.fmt.digitToChar(lo, .lower);
        }
        return hex;
    }

    /// Perform a full DANE validation for an SMTP connection.
    ///
    /// This is the main entry point for SMTP DANE validation (RFC 7672):
    /// 1. Look up TLSA records for the MX host
    /// 2. If no records found, return no_tlsa (opportunistic TLS)
    /// 3. If records found, validate the presented certificate
    /// 4. Cache the result
    pub fn validateSMTP(
        self: *DANEValidator,
        mx_host: []const u8,
        port: u16,
        cert_data: []const u8,
    ) !DANEResult {
        // Look up TLSA records
        const records_opt = try self.lookupTLSA(mx_host, port);

        if (records_opt == null) {
            return .no_tlsa;
        }

        const records = records_opt.?;
        defer {
            for (records) |*record| {
                var r = record.*;
                r.deinit();
            }
            self.allocator.free(records);
        }

        if (records.len == 0) {
            return .no_tlsa;
        }

        // Validate the certificate against the TLSA records
        return self.validateCertificate(cert_data, records);
    }

    /// Generate a TLSA record for publishing in DNS.
    ///
    /// Given a certificate, selector, matching type, and usage, produce the
    /// TLSA record data that should be published in DNS for this certificate.
    pub fn generateTLSARecord(
        self: *DANEValidator,
        cert_data: []const u8,
        usage: TLSAUsage,
        selector: TLSASelector,
        matching_type: TLSAMatchingType,
    ) !TLSARecord {
        // Select the appropriate data
        const selected = self.selectCertificateData(cert_data, selector);

        // Compute the certificate association data
        const cert_assoc_data = switch (matching_type) {
            .EXACT => try self.bytesToHex(selected),
            .SHA256 => blk: {
                const hash = self.computeSHA256Hash(selected);
                break :blk try self.bytesToHex(&hash);
            },
            .SHA512 => blk: {
                const hash = self.computeSHA512Hash(selected);
                break :blk try self.bytesToHex(&hash);
            },
        };

        return TLSARecord{
            .usage = usage,
            .selector = selector,
            .matching_type = matching_type,
            .certificate_data = cert_assoc_data,
            .dnssec_validated = false,
            .allocator = self.allocator,
        };
    }
};

// =============================================================================
// Tests
// =============================================================================

test "TLSAUsage enum properties" {
    const testing = std.testing;

    // Usage 0: CA_CONSTRAINT
    try testing.expect(TLSAUsage.CA_CONSTRAINT.requiresPKIX());
    try testing.expect(!TLSAUsage.CA_CONSTRAINT.isEndEntity());
    try testing.expectEqualStrings("PKIX-TA (CA Constraint)", TLSAUsage.CA_CONSTRAINT.toString());

    // Usage 1: SERVICE_CERT_CONSTRAINT
    try testing.expect(TLSAUsage.SERVICE_CERT_CONSTRAINT.requiresPKIX());
    try testing.expect(TLSAUsage.SERVICE_CERT_CONSTRAINT.isEndEntity());

    // Usage 2: TRUST_ANCHOR_ASSERTION
    try testing.expect(!TLSAUsage.TRUST_ANCHOR_ASSERTION.requiresPKIX());
    try testing.expect(!TLSAUsage.TRUST_ANCHOR_ASSERTION.isEndEntity());

    // Usage 3: DOMAIN_ISSUED_CERT
    try testing.expect(!TLSAUsage.DOMAIN_ISSUED_CERT.requiresPKIX());
    try testing.expect(TLSAUsage.DOMAIN_ISSUED_CERT.isEndEntity());
    try testing.expectEqualStrings("DANE-EE (Domain-Issued Certificate)", TLSAUsage.DOMAIN_ISSUED_CERT.toString());

    // fromInt
    try testing.expectEqual(TLSAUsage.CA_CONSTRAINT, TLSAUsage.fromInt(0).?);
    try testing.expectEqual(TLSAUsage.DOMAIN_ISSUED_CERT, TLSAUsage.fromInt(3).?);
    try testing.expect(TLSAUsage.fromInt(4) == null);
    try testing.expect(TLSAUsage.fromInt(255) == null);
}

test "TLSASelector enum properties" {
    const testing = std.testing;

    try testing.expectEqualStrings("Full Certificate", TLSASelector.FULL_CERT.toString());
    try testing.expectEqualStrings("SubjectPublicKeyInfo", TLSASelector.SUBJECT_PUBLIC_KEY_INFO.toString());

    try testing.expectEqual(TLSASelector.FULL_CERT, TLSASelector.fromInt(0).?);
    try testing.expectEqual(TLSASelector.SUBJECT_PUBLIC_KEY_INFO, TLSASelector.fromInt(1).?);
    try testing.expect(TLSASelector.fromInt(2) == null);
}

test "TLSAMatchingType enum properties" {
    const testing = std.testing;

    try testing.expectEqualStrings("Exact Match", TLSAMatchingType.EXACT.toString());
    try testing.expectEqualStrings("SHA-256", TLSAMatchingType.SHA256.toString());
    try testing.expectEqualStrings("SHA-512", TLSAMatchingType.SHA512.toString());

    try testing.expectEqual(TLSAMatchingType.EXACT, TLSAMatchingType.fromInt(0).?);
    try testing.expectEqual(TLSAMatchingType.SHA256, TLSAMatchingType.fromInt(1).?);
    try testing.expectEqual(TLSAMatchingType.SHA512, TLSAMatchingType.fromInt(2).?);
    try testing.expect(TLSAMatchingType.fromInt(3) == null);

    // Hash lengths
    try testing.expect(TLSAMatchingType.EXACT.hashLength() == null);
    try testing.expectEqual(@as(usize, 32), TLSAMatchingType.SHA256.hashLength().?);
    try testing.expectEqual(@as(usize, 64), TLSAMatchingType.SHA512.hashLength().?);
}

test "TLSA record parsing - valid DANE-EE SHA-256" {
    const testing = std.testing;

    // Typical DANE-EE record: usage=3, selector=1 (SPKI), matching=1 (SHA-256)
    const record_text = "3 1 1 " ++ "a]0b9c2f3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b";
    // Fix: use valid hex characters
    const valid_record_text = "3 1 1 " ++ "a00b9c2f3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b";
    var record = try TLSARecord.parse(testing.allocator, valid_record_text);
    defer record.deinit();

    try testing.expectEqual(TLSAUsage.DOMAIN_ISSUED_CERT, record.usage);
    try testing.expectEqual(TLSASelector.SUBJECT_PUBLIC_KEY_INFO, record.selector);
    try testing.expectEqual(TLSAMatchingType.SHA256, record.matching_type);
    try testing.expect(record.certificate_data.len == 64); // 32 bytes hex-encoded
    try testing.expect(!record.dnssec_validated);
    _ = record_text;
}

test "TLSA record parsing - valid PKIX-TA SHA-512" {
    const testing = std.testing;

    // 128 hex characters = 64 bytes = SHA-512
    const hex_data = "a00b9c2f3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b" ++
        "1122334455667788990011223344556677889900aabbccddeeff0011223344aabb";
    const record_text = "0 0 2 " ++ hex_data;

    var record = try TLSARecord.parse(testing.allocator, record_text);
    defer record.deinit();

    try testing.expectEqual(TLSAUsage.CA_CONSTRAINT, record.usage);
    try testing.expectEqual(TLSASelector.FULL_CERT, record.selector);
    try testing.expectEqual(TLSAMatchingType.SHA512, record.matching_type);
    try testing.expect(record.certificate_data.len == 128); // 64 bytes hex-encoded
}

test "TLSA record parsing - invalid records" {
    const testing = std.testing;

    // Empty record
    try testing.expectError(error.InvalidTLSARecord, TLSARecord.parse(testing.allocator, ""));

    // Missing fields
    try testing.expectError(error.InvalidTLSARecord, TLSARecord.parse(testing.allocator, "3"));
    try testing.expectError(error.InvalidTLSARecord, TLSARecord.parse(testing.allocator, "3 1"));
    try testing.expectError(error.InvalidTLSARecord, TLSARecord.parse(testing.allocator, "3 1 1"));

    // Invalid usage value
    try testing.expectError(error.InvalidTLSARecord, TLSARecord.parse(
        testing.allocator,
        "4 1 1 a00b9c2f3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
    ));

    // Invalid selector value
    try testing.expectError(error.InvalidTLSARecord, TLSARecord.parse(
        testing.allocator,
        "3 2 1 a00b9c2f3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
    ));

    // Invalid matching type
    try testing.expectError(error.InvalidTLSARecord, TLSARecord.parse(
        testing.allocator,
        "3 1 3 a00b9c2f3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
    ));

    // Invalid hex characters
    try testing.expectError(error.InvalidTLSARecord, TLSARecord.parse(
        testing.allocator,
        "3 1 1 zzzzzzzz3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
    ));

    // Wrong hash length for SHA-256 (should be exactly 64 hex chars)
    try testing.expectError(error.InvalidTLSARecord, TLSARecord.parse(
        testing.allocator,
        "3 1 1 a00b9c2f",
    ));
}

test "TLSA record format" {
    const testing = std.testing;

    const record_text = "3 1 1 a00b9c2f3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b";
    var record = try TLSARecord.parse(testing.allocator, record_text);
    defer record.deinit();

    const formatted = try record.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expectEqualStrings(record_text, formatted);
}

test "TLSA DNS name construction" {
    const testing = std.testing;

    const name_25 = try TLSARecord.dnsName(testing.allocator, "mail.example.com", 25);
    defer testing.allocator.free(name_25);
    try testing.expectEqualStrings("_25._tcp.mail.example.com", name_25);

    const name_465 = try TLSARecord.dnsName(testing.allocator, "smtp.example.org", 465);
    defer testing.allocator.free(name_465);
    try testing.expectEqualStrings("_465._tcp.smtp.example.org", name_465);

    const name_587 = try TLSARecord.dnsName(testing.allocator, "submission.example.com", 587);
    defer testing.allocator.free(name_587);
    try testing.expectEqualStrings("_587._tcp.submission.example.com", name_587);
}

test "DANEResult enum properties" {
    const testing = std.testing;

    // toString
    try testing.expectEqualStrings("pass", DANEResult.pass.toString());
    try testing.expectEqualStrings("fail", DANEResult.fail.toString());
    try testing.expectEqualStrings("temperror", DANEResult.temperror.toString());
    try testing.expectEqualStrings("permerror", DANEResult.permerror.toString());
    try testing.expectEqualStrings("no_tlsa", DANEResult.no_tlsa.toString());

    // shouldProceed
    try testing.expect(DANEResult.pass.shouldProceed());
    try testing.expect(!DANEResult.fail.shouldProceed());
    try testing.expect(DANEResult.temperror.shouldProceed()); // fail-open
    try testing.expect(!DANEResult.permerror.shouldProceed());
    try testing.expect(DANEResult.no_tlsa.shouldProceed());

    // requiresTLS
    try testing.expect(DANEResult.pass.requiresTLS());
    try testing.expect(DANEResult.fail.requiresTLS());
    try testing.expect(!DANEResult.temperror.requiresTLS());
    try testing.expect(DANEResult.permerror.requiresTLS());
    try testing.expect(!DANEResult.no_tlsa.requiresTLS());
}

test "DANEPolicy creation and expiration" {
    const testing = std.testing;

    var policy = try DANEPolicy.init(testing.allocator, "mail.example.com", 3600);
    defer policy.deinit();

    try testing.expectEqualStrings("mail.example.com", policy.domain);
    try testing.expectEqual(@as(u32, 3600), policy.cache_ttl);
    try testing.expectEqual(@as(usize, 0), policy.recordCount());
    try testing.expect(!policy.requiresPKIX());

    // Should not be expired immediately
    try testing.expect(!policy.isExpired());

    // Test with a past timestamp
    try testing.expect(!policy.isExpiredAt(policy.last_checked + 3599));
    try testing.expect(policy.isExpiredAt(policy.last_checked + 3600));
    try testing.expect(policy.isExpiredAt(policy.last_checked + 7200));
}

test "DANEPolicy add records" {
    const testing = std.testing;

    var policy = try DANEPolicy.init(testing.allocator, "mail.example.com", 3600);
    defer policy.deinit();

    // Add a DANE-EE record
    const record_text = "3 1 1 a00b9c2f3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b";
    const record = try TLSARecord.parse(testing.allocator, record_text);
    // Don't defer deinit -- policy takes ownership
    try policy.addRecord(record);

    try testing.expectEqual(@as(usize, 1), policy.recordCount());
    try testing.expect(!policy.requiresPKIX());

    // Add a PKIX-EE record
    const pkix_record_text = "1 0 1 b11c9d3f4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0c";
    const pkix_record = try TLSARecord.parse(testing.allocator, pkix_record_text);
    try policy.addRecord(pkix_record);

    try testing.expectEqual(@as(usize, 2), policy.recordCount());
    try testing.expect(policy.requiresPKIX()); // Now true because of usage=1
}

test "DANEPolicyCache basic operations" {
    const testing = std.testing;

    var cache = DANEPolicyCache.init(testing.allocator, 100);
    defer cache.deinit();

    try testing.expectEqual(@as(usize, 0), cache.count());

    // Create and cache a policy
    var policy = try DANEPolicy.init(testing.allocator, "mail.example.com", 3600);

    const record_text = "3 1 1 a00b9c2f3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b";
    const record = try TLSARecord.parse(testing.allocator, record_text);
    try policy.addRecord(record);

    try cache.put(policy);
    try testing.expectEqual(@as(usize, 1), cache.count());

    // Retrieve the cached policy
    const cached = cache.get("mail.example.com");
    try testing.expect(cached != null);
    try testing.expectEqualStrings("mail.example.com", cached.?.domain);
    try testing.expectEqual(@as(usize, 1), cached.?.recordCount());

    // Non-existent domain
    try testing.expect(cache.get("nonexistent.example.com") == null);
}

test "DANEPolicyCache expiration" {
    const testing = std.testing;

    var cache = DANEPolicyCache.init(testing.allocator, 100);
    defer cache.deinit();

    // isExpired returns true for non-existent entries
    try testing.expect(cache.isExpired("nonexistent.example.com"));

    // Create a policy with 1-second TTL
    var policy = try DANEPolicy.init(testing.allocator, "short-ttl.example.com", 1);
    // Set last_checked far in the past to force expiration
    policy.last_checked = time_compat.timestamp() - 100;
    try cache.put(policy);

    // Should be expired
    try testing.expect(cache.isExpired("short-ttl.example.com"));
    try testing.expect(cache.get("short-ttl.example.com") == null);
}

test "DANEPolicyCache remove" {
    const testing = std.testing;

    var cache = DANEPolicyCache.init(testing.allocator, 100);
    defer cache.deinit();

    const policy = try DANEPolicy.init(testing.allocator, "remove-me.example.com", 3600);
    try cache.put(policy);
    try testing.expectEqual(@as(usize, 1), cache.count());

    cache.remove("remove-me.example.com");
    try testing.expectEqual(@as(usize, 0), cache.count());
    try testing.expect(cache.get("remove-me.example.com") == null);

    // Removing non-existent entry is a no-op
    cache.remove("nonexistent.example.com");
    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "DANEPolicyCache capacity eviction" {
    const testing = std.testing;

    // Create a cache with max 3 entries
    var cache = DANEPolicyCache.init(testing.allocator, 3);
    defer cache.deinit();

    var p1 = try DANEPolicy.init(testing.allocator, "first.example.com", 3600);
    p1.last_checked = 1000;
    try cache.put(p1);

    var p2 = try DANEPolicy.init(testing.allocator, "second.example.com", 3600);
    p2.last_checked = 2000;
    try cache.put(p2);

    var p3 = try DANEPolicy.init(testing.allocator, "third.example.com", 3600);
    p3.last_checked = 3000;
    try cache.put(p3);

    try testing.expectEqual(@as(usize, 3), cache.count());

    // Adding a 4th entry should evict the oldest (first.example.com with ts=1000)
    var p4 = try DANEPolicy.init(testing.allocator, "fourth.example.com", 3600);
    p4.last_checked = 4000;
    try cache.put(p4);

    // Should still be at max capacity
    try testing.expect(cache.count() <= 3);
}

test "DANEValidator init and deinit" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    try testing.expectEqual(@as(u32, 5000), validator.dns_timeout_ms);
}

test "DANEValidator SHA-256 hash computation" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    // Hash of empty string should be the well-known SHA-256 empty hash
    const empty_hash = validator.computeSHA256Hash("");
    const empty_hex = try validator.bytesToHex(&empty_hash);
    defer testing.allocator.free(empty_hex);
    try testing.expectEqualStrings(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        empty_hex,
    );

    // Hash of "hello"
    const hello_hash = validator.computeSHA256Hash("hello");
    const hello_hex = try validator.bytesToHex(&hello_hash);
    defer testing.allocator.free(hello_hex);
    try testing.expectEqualStrings(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        hello_hex,
    );
}

test "DANEValidator SHA-512 hash computation" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    // Hash of empty string
    const empty_hash = validator.computeSHA512Hash("");
    const empty_hex = try validator.bytesToHex(&empty_hash);
    defer testing.allocator.free(empty_hex);
    try testing.expectEqualStrings(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" ++
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        empty_hex,
    );

    // Hash of "hello"
    const hello_hash = validator.computeSHA512Hash("hello");
    const hello_hex = try validator.bytesToHex(&hello_hash);
    defer testing.allocator.free(hello_hex);
    try testing.expectEqualStrings(
        "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7" ++
            "2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
        hello_hex,
    );
}

test "DANEValidator certificate validation - pass with SHA-256" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    // Create a fake certificate (just some bytes)
    const cert_data = "this is fake certificate data for testing";

    // Compute the SHA-256 hash so we can create a matching TLSA record
    const hash = validator.computeSHA256Hash(cert_data);
    const hash_hex = try validator.bytesToHex(&hash);
    defer testing.allocator.free(hash_hex);

    // Build the TLSA record text
    const record_text = try std.fmt.allocPrint(testing.allocator, "3 0 1 {s}", .{hash_hex});
    defer testing.allocator.free(record_text);

    var record = try TLSARecord.parse(testing.allocator, record_text);
    defer record.deinit();

    const records = [_]TLSARecord{record};
    const result = validator.validateCertificate(cert_data, &records);
    try testing.expectEqual(DANEResult.pass, result);
}

test "DANEValidator certificate validation - pass with SHA-512" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const cert_data = "another fake certificate for SHA-512 testing";

    // Compute the SHA-512 hash
    const hash = validator.computeSHA512Hash(cert_data);
    const hash_hex = try validator.bytesToHex(&hash);
    defer testing.allocator.free(hash_hex);

    // Build the TLSA record text: usage=3, selector=0, matching=2 (SHA-512)
    const record_text = try std.fmt.allocPrint(testing.allocator, "3 0 2 {s}", .{hash_hex});
    defer testing.allocator.free(record_text);

    var record = try TLSARecord.parse(testing.allocator, record_text);
    defer record.deinit();

    const records = [_]TLSARecord{record};
    const result = validator.validateCertificate(cert_data, &records);
    try testing.expectEqual(DANEResult.pass, result);
}

test "DANEValidator certificate validation - pass with exact match" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const cert_data = "exact match certificate bytes";

    // Convert to hex for the TLSA record (matching_type=0 means exact)
    const cert_hex = try validator.bytesToHex(cert_data);
    defer testing.allocator.free(cert_hex);

    // For exact matching, we need to construct the record manually since
    // the data length won't match a hash length
    const tlsa_record = TLSARecord{
        .usage = .DOMAIN_ISSUED_CERT,
        .selector = .FULL_CERT,
        .matching_type = .EXACT,
        .certificate_data = cert_hex,
        .dnssec_validated = false,
        .allocator = testing.allocator,
    };

    const records = [_]TLSARecord{tlsa_record};
    const result = validator.validateCertificate(cert_data, &records);
    try testing.expectEqual(DANEResult.pass, result);
}

test "DANEValidator certificate validation - fail on mismatch" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const cert_data = "the real certificate data";

    // Create a TLSA record with a hash that does NOT match the certificate
    const wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    const record_text = try std.fmt.allocPrint(testing.allocator, "3 0 1 {s}", .{wrong_hash});
    defer testing.allocator.free(record_text);

    var record = try TLSARecord.parse(testing.allocator, record_text);
    defer record.deinit();

    const records = [_]TLSARecord{record};
    const result = validator.validateCertificate(cert_data, &records);
    try testing.expectEqual(DANEResult.fail, result);
}

test "DANEValidator certificate validation - no TLSA records" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const cert_data = "any certificate";
    const empty_records = [_]TLSARecord{};

    const result = validator.validateCertificate(cert_data, &empty_records);
    try testing.expectEqual(DANEResult.no_tlsa, result);
}

test "DANEValidator certificate validation - empty cert data" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    const record_text = try std.fmt.allocPrint(testing.allocator, "3 0 1 {s}", .{wrong_hash});
    defer testing.allocator.free(record_text);

    var record = try TLSARecord.parse(testing.allocator, record_text);
    defer record.deinit();

    const records = [_]TLSARecord{record};
    const result = validator.validateCertificate("", &records);
    try testing.expectEqual(DANEResult.permerror, result);
}

test "DANEValidator certificate validation - multiple records, one match" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const cert_data = "certificate data to validate";

    // Compute the correct hash
    const correct_hash = validator.computeSHA256Hash(cert_data);
    const correct_hex = try validator.bytesToHex(&correct_hash);
    defer testing.allocator.free(correct_hex);

    // First record: wrong hash
    const wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    const wrong_text = try std.fmt.allocPrint(testing.allocator, "3 0 1 {s}", .{wrong_hash});
    defer testing.allocator.free(wrong_text);
    var wrong_record = try TLSARecord.parse(testing.allocator, wrong_text);
    defer wrong_record.deinit();

    // Second record: correct hash
    const correct_text = try std.fmt.allocPrint(testing.allocator, "3 0 1 {s}", .{correct_hex});
    defer testing.allocator.free(correct_text);
    var correct_record = try TLSARecord.parse(testing.allocator, correct_text);
    defer correct_record.deinit();

    // Should pass because at least one record matches
    const records = [_]TLSARecord{ wrong_record, correct_record };
    const result = validator.validateCertificate(cert_data, &records);
    try testing.expectEqual(DANEResult.pass, result);
}

test "DANEValidator SMTP validation with no TLSA records" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    // lookupTLSA is stubbed to return null, so this should return no_tlsa
    const result = try validator.validateSMTP("mail.example.com", 25, "cert data");
    try testing.expectEqual(DANEResult.no_tlsa, result);
}

test "DANEValidator generate TLSA record" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const cert_data = "certificate data for record generation";

    // Generate a DANE-EE SHA-256 TLSA record
    var record = try validator.generateTLSARecord(
        cert_data,
        .DOMAIN_ISSUED_CERT,
        .FULL_CERT,
        .SHA256,
    );
    defer record.deinit();

    try testing.expectEqual(TLSAUsage.DOMAIN_ISSUED_CERT, record.usage);
    try testing.expectEqual(TLSASelector.FULL_CERT, record.selector);
    try testing.expectEqual(TLSAMatchingType.SHA256, record.matching_type);
    try testing.expect(record.certificate_data.len == 64); // SHA-256 hex

    // Verify the generated record would validate the same certificate
    const records = [_]TLSARecord{record};
    const result = validator.validateCertificate(cert_data, &records);
    try testing.expectEqual(DANEResult.pass, result);
}

test "DANEValidator generate and validate SHA-512 TLSA record" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const cert_data = "certificate for SHA-512 generation test";

    var record = try validator.generateTLSARecord(
        cert_data,
        .TRUST_ANCHOR_ASSERTION,
        .SUBJECT_PUBLIC_KEY_INFO,
        .SHA512,
    );
    defer record.deinit();

    try testing.expectEqual(TLSAUsage.TRUST_ANCHOR_ASSERTION, record.usage);
    try testing.expectEqual(TLSASelector.SUBJECT_PUBLIC_KEY_INFO, record.selector);
    try testing.expectEqual(TLSAMatchingType.SHA512, record.matching_type);
    try testing.expect(record.certificate_data.len == 128); // SHA-512 hex

    // Validate
    const records = [_]TLSARecord{record};
    const result = validator.validateCertificate(cert_data, &records);
    try testing.expectEqual(DANEResult.pass, result);
}

test "DANEValidator bytesToHex" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    // Known byte sequence
    const bytes = [_]u8{ 0x00, 0xFF, 0xAB, 0x12, 0xCD };
    const hex = try validator.bytesToHex(&bytes);
    defer testing.allocator.free(hex);
    try testing.expectEqualStrings("00ffab12cd", hex);

    // Empty input
    const empty_hex = try validator.bytesToHex("");
    defer testing.allocator.free(empty_hex);
    try testing.expectEqualStrings("", empty_hex);

    // Single byte
    const single = [_]u8{0x42};
    const single_hex = try validator.bytesToHex(&single);
    defer testing.allocator.free(single_hex);
    try testing.expectEqualStrings("42", single_hex);
}

test "DANEPolicyCache replace existing entry" {
    const testing = std.testing;

    var cache = DANEPolicyCache.init(testing.allocator, 100);
    defer cache.deinit();

    // Insert first policy
    const policy1 = try DANEPolicy.init(testing.allocator, "mail.example.com", 3600);
    try cache.put(policy1);
    try testing.expectEqual(@as(usize, 1), cache.count());

    // Insert replacement policy for same domain
    const policy2 = try DANEPolicy.init(testing.allocator, "mail.example.com", 7200);
    try cache.put(policy2);
    try testing.expectEqual(@as(usize, 1), cache.count());

    // Verify the new TTL is present
    const cached = cache.get("mail.example.com");
    try testing.expect(cached != null);
    try testing.expectEqual(@as(u32, 7200), cached.?.cache_ttl);
}

test "DANEPolicyCache evict expired entries" {
    const testing = std.testing;

    var cache = DANEPolicyCache.init(testing.allocator, 100);
    defer cache.deinit();

    // Insert an expired policy
    var expired = try DANEPolicy.init(testing.allocator, "expired.example.com", 1);
    expired.last_checked = time_compat.timestamp() - 100;
    try cache.put(expired);

    // Insert a valid policy
    const valid = try DANEPolicy.init(testing.allocator, "valid.example.com", 3600);
    try cache.put(valid);

    try testing.expectEqual(@as(usize, 2), cache.count());

    cache.evictExpired();

    try testing.expectEqual(@as(usize, 1), cache.count());
    try testing.expect(cache.get("valid.example.com") != null);
    try testing.expect(cache.get("expired.example.com") == null);
}

test "All TLSA usage values are covered" {
    const testing = std.testing;

    // Ensure all 4 usage values are parseable and round-trip correctly
    const usages = [_]u8{ 0, 1, 2, 3 };
    const expected = [_]TLSAUsage{
        .CA_CONSTRAINT,
        .SERVICE_CERT_CONSTRAINT,
        .TRUST_ANCHOR_ASSERTION,
        .DOMAIN_ISSUED_CERT,
    };

    for (usages, expected) |val, exp| {
        const parsed = TLSAUsage.fromInt(val);
        try testing.expect(parsed != null);
        try testing.expectEqual(exp, parsed.?);
        try testing.expectEqual(val, @intFromEnum(parsed.?));
    }
}

test "DANEValidator case-insensitive hex matching" {
    const testing = std.testing;

    var validator = DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const cert_data = "test certificate for case insensitive check";
    const hash = validator.computeSHA256Hash(cert_data);
    const hash_hex_lower = try validator.bytesToHex(&hash);
    defer testing.allocator.free(hash_hex_lower);

    // Convert to uppercase for the TLSA record
    const hash_hex_upper = try testing.allocator.alloc(u8, hash_hex_lower.len);
    defer testing.allocator.free(hash_hex_upper);
    for (hash_hex_lower, 0..) |c, i| {
        hash_hex_upper[i] = std.ascii.toUpper(c);
    }

    // Create a TLSA record with uppercase hex
    const record = TLSARecord{
        .usage = .DOMAIN_ISSUED_CERT,
        .selector = .FULL_CERT,
        .matching_type = .SHA256,
        .certificate_data = hash_hex_upper,
        .dnssec_validated = false,
        .allocator = testing.allocator,
    };

    const records = [_]TLSARecord{record};
    const result = validator.validateCertificate(cert_data, &records);
    try testing.expectEqual(DANEResult.pass, result);
}
