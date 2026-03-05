const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const spf = @import("spf.zig");
const dkim = @import("dkim.zig");

/// DMARC policy
pub const DMARCPolicy = enum {
    none,
    quarantine,
    reject,

    pub fn toString(self: DMARCPolicy) []const u8 {
        return switch (self) {
            .none => "none",
            .quarantine => "quarantine",
            .reject => "reject",
        };
    }

    pub fn fromString(s: []const u8) DMARCPolicy {
        if (std.ascii.eqlIgnoreCase(s, "reject")) return .reject;
        if (std.ascii.eqlIgnoreCase(s, "quarantine")) return .quarantine;
        return .none;
    }
};

/// DMARC alignment mode
pub const AlignmentMode = enum {
    relaxed,
    strict,

    pub fn fromString(s: []const u8) AlignmentMode {
        if (std.ascii.eqlIgnoreCase(s, "s")) return .strict;
        return .relaxed;
    }
};

/// DMARC record
pub const DMARCRecord = struct {
    version: []const u8,
    policy: DMARCPolicy,
    subdomain_policy: DMARCPolicy,
    percentage: u8, // 0-100
    dkim_alignment: AlignmentMode,
    spf_alignment: AlignmentMode,
    report_format: []const u8,
    report_interval: u32,
    aggregate_report_uri: ?[]const u8,
    forensic_report_uri: ?[]const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *DMARCRecord) void {
        self.allocator.free(self.version);
        self.allocator.free(self.report_format);
        if (self.aggregate_report_uri) |uri| self.allocator.free(uri);
        if (self.forensic_report_uri) |uri| self.allocator.free(uri);
    }

    /// Parse DMARC record from DNS TXT
    /// Format: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    pub fn parse(allocator: std.mem.Allocator, record: []const u8) !DMARCRecord {
        var dmarc = DMARCRecord{
            .version = "",
            .policy = .none,
            .subdomain_policy = .none,
            .percentage = 100,
            .dkim_alignment = .relaxed,
            .spf_alignment = .relaxed,
            .report_format = try allocator.dupe(u8, "afrf"),
            .report_interval = 86400, // 24 hours
            .aggregate_report_uri = null,
            .forensic_report_uri = null,
            .allocator = allocator,
        };
        errdefer {
            if (dmarc.version.len > 0) allocator.free(dmarc.version);
            allocator.free(dmarc.report_format);
            if (dmarc.aggregate_report_uri) |uri| allocator.free(uri);
            if (dmarc.forensic_report_uri) |uri| allocator.free(uri);
        }

        // Parse tag=value pairs
        var tags = std.mem.splitScalar(u8, record, ';');
        while (tags.next()) |tag| {
            const trimmed = std.mem.trim(u8, tag, " \t\r\n");
            if (trimmed.len == 0) continue;

            const eq_pos = std.mem.indexOf(u8, trimmed, "=") orelse continue;
            const tag_name = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            const tag_value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

            if (std.mem.eql(u8, tag_name, "v")) {
                dmarc.version = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "p")) {
                dmarc.policy = DMARCPolicy.fromString(tag_value);
            } else if (std.mem.eql(u8, tag_name, "sp")) {
                dmarc.subdomain_policy = DMARCPolicy.fromString(tag_value);
            } else if (std.mem.eql(u8, tag_name, "pct")) {
                dmarc.percentage = std.fmt.parseInt(u8, tag_value, 10) catch 100;
            } else if (std.mem.eql(u8, tag_name, "adkim")) {
                dmarc.dkim_alignment = AlignmentMode.fromString(tag_value);
            } else if (std.mem.eql(u8, tag_name, "aspf")) {
                dmarc.spf_alignment = AlignmentMode.fromString(tag_value);
            } else if (std.mem.eql(u8, tag_name, "rua")) {
                dmarc.aggregate_report_uri = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "ruf")) {
                dmarc.forensic_report_uri = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "rf")) {
                allocator.free(dmarc.report_format);
                dmarc.report_format = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "ri")) {
                dmarc.report_interval = std.fmt.parseInt(u32, tag_value, 10) catch 86400;
            }
        }

        // Validate required fields
        if (dmarc.version.len == 0 or !std.mem.eql(u8, dmarc.version, "DMARC1")) {
            return error.InvalidDMARCRecord;
        }

        return dmarc;
    }
};

/// DMARC validation result
pub const DMARCResult = enum {
    pass,
    fail,
    none,
    temperror,
    permerror,

    pub fn toString(self: DMARCResult) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .none => "none",
            .temperror => "temperror",
            .permerror => "permerror",
        };
    }

    pub fn shouldAccept(self: DMARCResult, policy: DMARCPolicy) bool {
        return switch (self) {
            .pass, .none => true,
            .fail => policy == .none,
            .temperror, .permerror => true, // Don't reject on errors
        };
    }
};

/// DMARC validator (RFC 7489)
pub const DMARCValidator = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) DMARCValidator {
        return .{ .allocator = allocator };
    }

    /// Validate DMARC policy
    pub fn validate(
        self: *DMARCValidator,
        from_domain: []const u8,
        spf_result: spf.SPFResult,
        spf_domain: []const u8,
        dkim_result: dkim.DKIMResult,
        dkim_domain: []const u8,
    ) !DMARCResult {
        // Query DMARC record for domain
        const dmarc_record = self.queryDMARCRecord(from_domain) catch {
            return .none;
        };
        defer if (dmarc_record) |*record| {
            var rec = record.*;
            rec.deinit();
        };

        if (dmarc_record == null) {
            return .none;
        }

        const record = dmarc_record.?;

        // Check identifier alignment
        const spf_aligned = self.checkAlignment(from_domain, spf_domain, record.spf_alignment);
        const dkim_aligned = self.checkAlignment(from_domain, dkim_domain, record.dkim_alignment);

        // DMARC passes if either SPF or DKIM passes AND is aligned
        const spf_pass = spf_result == .pass and spf_aligned;
        const dkim_pass = dkim_result == .pass and dkim_aligned;

        if (spf_pass or dkim_pass) {
            return .pass;
        }

        return .fail;
    }

    fn queryDMARCRecord(self: *DMARCValidator, domain: []const u8) !?DMARCRecord {
        // In production, query DNS TXT record at: _dmarc.domain
        _ = self;
        _ = domain;

        // For now, return null (no record found)
        // A real implementation would use DNS lookups
        return null;
    }

    fn checkAlignment(self: *DMARCValidator, from_domain: []const u8, auth_domain: []const u8, mode: AlignmentMode) bool {
        _ = self;

        switch (mode) {
            .strict => {
                // Strict: domains must match exactly
                return std.ascii.eqlIgnoreCase(from_domain, auth_domain);
            },
            .relaxed => {
                // Relaxed: organizational domains must match
                // e.g., mail.example.com and example.com both match
                const from_org = self.getOrganizationalDomain(from_domain);
                const auth_org = self.getOrganizationalDomain(auth_domain);
                return std.ascii.eqlIgnoreCase(from_org, auth_org);
            },
        }
    }

    fn getOrganizationalDomain(self: *DMARCValidator, domain: []const u8) []const u8 {
        _ = self;
        // Simple implementation: take last two labels
        // Real implementation would use Public Suffix List
        var parts = std.mem.splitBackwardsScalar(u8, domain, '.');
        const tld = parts.next() orelse return domain;
        const sld = parts.next() orelse return domain;

        const start = domain.len - tld.len - sld.len - 1;
        return domain[start..];
    }
};

/// DMARC aggregate report generator
pub const DMARCAggregateReport = struct {
    allocator: std.mem.Allocator,
    report_id: []const u8,
    org_name: []const u8,
    email: []const u8,
    begin_timestamp: i64,
    end_timestamp: i64,
    records: std.ArrayList(ReportRecord),

    pub const ReportRecord = struct {
        source_ip: []const u8,
        count: u32,
        disposition: DMARCPolicy,
        dkim_result: dkim.DKIMResult,
        spf_result: spf.SPFResult,
        header_from: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator, org_name: []const u8, email: []const u8) !DMARCAggregateReport {
        const report_id = try std.fmt.allocPrint(allocator, "{d}", .{time_compat.timestamp()});
        return .{
            .allocator = allocator,
            .report_id = report_id,
            .org_name = try allocator.dupe(u8, org_name),
            .email = try allocator.dupe(u8, email),
            .begin_timestamp = time_compat.timestamp(),
            .end_timestamp = time_compat.timestamp() + 86400,
            .records = std.ArrayList(ReportRecord).init(allocator),
        };
    }

    pub fn deinit(self: *DMARCAggregateReport) void {
        self.allocator.free(self.report_id);
        self.allocator.free(self.org_name);
        self.allocator.free(self.email);
        self.records.deinit();
    }

    pub fn toXML(self: *DMARCAggregateReport) ![]const u8 {
        var xml = std.ArrayList(u8).init(self.allocator);
        defer xml.deinit();

        const writer = xml.writer();

        try writer.print(
            \\<?xml version="1.0"?>
            \\<feedback>
            \\  <report_metadata>
            \\    <org_name>{s}</org_name>
            \\    <email>{s}</email>
            \\    <report_id>{s}</report_id>
            \\    <date_range>
            \\      <begin>{d}</begin>
            \\      <end>{d}</end>
            \\    </date_range>
            \\  </report_metadata>
            \\  <policy_published>
            \\    <domain>example.com</domain>
            \\    <p>reject</p>
            \\  </policy_published>
            \\</feedback>
            \\
        ,
            .{ self.org_name, self.email, self.report_id, self.begin_timestamp, self.end_timestamp },
        );

        return try xml.toOwnedSlice();
    }
};

test "DMARC record parsing" {
    const testing = std.testing;

    const record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100";
    var dmarc = try DMARCRecord.parse(testing.allocator, record);
    defer dmarc.deinit();

    try testing.expectEqualStrings("DMARC1", dmarc.version);
    try testing.expect(dmarc.policy == .reject);
    try testing.expectEqual(@as(u8, 100), dmarc.percentage);
}

test "DMARC alignment checking" {
    const testing = std.testing;
    var validator = DMARCValidator.init(testing.allocator);

    // Strict alignment
    try testing.expect(validator.checkAlignment("example.com", "example.com", .strict));
    try testing.expect(!validator.checkAlignment("mail.example.com", "example.com", .strict));

    // Relaxed alignment
    try testing.expect(validator.checkAlignment("mail.example.com", "example.com", .relaxed));
    try testing.expect(validator.checkAlignment("example.com", "mail.example.com", .relaxed));
}
