const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// TLS failure types per RFC 8460 Section 4.3
pub const TLSFailureType = enum {
    starttls_not_supported,
    certificate_invalid,
    certificate_expired,
    certificate_hostname_mismatch,
    policy_mismatch,
    sts_policy_invalid,
    dane_required,
    other,

    pub fn toString(self: TLSFailureType) []const u8 {
        return switch (self) {
            .starttls_not_supported => "starttls-not-supported",
            .certificate_invalid => "certificate-invalid",
            .certificate_expired => "certificate-expired",
            .certificate_hostname_mismatch => "certificate-hostname-mismatch",
            .policy_mismatch => "policy-mismatch",
            .sts_policy_invalid => "sts-policy-invalid",
            .dane_required => "dane-required",
            .other => "other",
        };
    }

    pub fn fromString(str: []const u8) !TLSFailureType {
        if (std.mem.eql(u8, str, "starttls-not-supported")) return .starttls_not_supported;
        if (std.mem.eql(u8, str, "certificate-invalid")) return .certificate_invalid;
        if (std.mem.eql(u8, str, "certificate-expired")) return .certificate_expired;
        if (std.mem.eql(u8, str, "certificate-hostname-mismatch")) return .certificate_hostname_mismatch;
        if (std.mem.eql(u8, str, "policy-mismatch")) return .policy_mismatch;
        if (std.mem.eql(u8, str, "sts-policy-invalid")) return .sts_policy_invalid;
        if (std.mem.eql(u8, str, "dane-required")) return .dane_required;
        if (std.mem.eql(u8, str, "other")) return .other;
        return error.InvalidFailureType;
    }
};

/// Result types per RFC 8460 Section 4.3
pub const ResultType = enum {
    starttls_not_supported,
    certificate_host_mismatch,
    certificate_expired,
    certificate_not_trusted,
    validation_failure,
    tlsa_invalid,
    dnssec_invalid,
    dane_required,
    sts_policy_fetch_error,
    sts_policy_invalid,
    sts_webpki_invalid,
    negotiation_failure,

    pub fn toString(self: ResultType) []const u8 {
        return switch (self) {
            .starttls_not_supported => "starttls-not-supported",
            .certificate_host_mismatch => "certificate-host-mismatch",
            .certificate_expired => "certificate-expired",
            .certificate_not_trusted => "certificate-not-trusted",
            .validation_failure => "validation-failure",
            .tlsa_invalid => "tlsa-invalid",
            .dnssec_invalid => "dnssec-invalid",
            .dane_required => "dane-required",
            .sts_policy_fetch_error => "sts-policy-fetch-error",
            .sts_policy_invalid => "sts-policy-invalid",
            .sts_webpki_invalid => "sts-webpki-invalid",
            .negotiation_failure => "negotiation-failure",
        };
    }
};

/// Policy types per RFC 8460 Section 4.2
pub const PolicyType = enum {
    tlsa,
    sts,
    no_policy_found,

    pub fn toString(self: PolicyType) []const u8 {
        return switch (self) {
            .tlsa => "tlsa",
            .sts => "sts",
            .no_policy_found => "no-policy-found",
        };
    }

    pub fn fromString(str: []const u8) !PolicyType {
        if (std.mem.eql(u8, str, "tlsa")) return .tlsa;
        if (std.mem.eql(u8, str, "sts")) return .sts;
        if (std.mem.eql(u8, str, "no-policy-found")) return .no_policy_found;
        return error.InvalidPolicyType;
    }
};

/// TLS-RPT DNS record (v=TLSRPTv1) per RFC 8460 Section 3
pub const TLSRPTRecord = struct {
    version: []const u8,
    rua: []const []const u8,
    allocator: std.mem.Allocator,

    /// Parse a TLS-RPT DNS TXT record string.
    /// Expected format: "v=TLSRPTv1; rua=mailto:reports@example.com,https://..."
    pub fn parse(allocator: std.mem.Allocator, record_text: []const u8) !TLSRPTRecord {
        var version: ?[]const u8 = null;
        var rua_list: std.ArrayList([]const u8) = .{};
        errdefer {
            for (rua_list.items) |uri| allocator.free(uri);
            rua_list.deinit(allocator);
        }
        errdefer if (version) |v| allocator.free(v);

        var pairs = std.mem.splitSequence(u8, record_text, ";");
        while (pairs.next()) |raw_pair| {
            const pair = std.mem.trim(u8, raw_pair, " \t\r\n");
            if (pair.len == 0) continue;

            if (std.mem.startsWith(u8, pair, "v=")) {
                const val = pair[2..];
                if (!std.mem.eql(u8, val, "TLSRPTv1")) {
                    return error.UnsupportedVersion;
                }
                version = try allocator.dupe(u8, val);
            } else if (std.mem.startsWith(u8, pair, "rua=")) {
                const val = pair[4..];
                var uris = std.mem.splitScalar(u8, val, ',');
                while (uris.next()) |raw_uri| {
                    const uri = std.mem.trim(u8, raw_uri, " \t");
                    if (uri.len > 0) {
                        try rua_list.append(allocator, try allocator.dupe(u8, uri));
                    }
                }
            }
        }

        if (version == null) return error.MissingVersion;
        if (rua_list.items.len == 0) {
            allocator.free(version.?);
            version = null;
            return error.MissingReportingURI;
        }

        return TLSRPTRecord{
            .version = version.?,
            .rua = try rua_list.toOwnedSlice(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TLSRPTRecord) void {
        self.allocator.free(self.version);
        for (self.rua) |uri| self.allocator.free(uri);
        self.allocator.free(self.rua);
    }
};

/// TLS report policy containing version and reporting configuration per RFC 8460 Section 3
pub const TLSReportPolicy = struct {
    version: []const u8,
    rua: []const []const u8,
    max_age: u64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, rua_uris: []const []const u8, max_age: u64) !TLSReportPolicy {
        var rua = try allocator.alloc([]const u8, rua_uris.len);
        errdefer allocator.free(rua);
        var initialized: usize = 0;
        errdefer for (rua[0..initialized]) |uri| allocator.free(uri);

        for (rua_uris, 0..) |uri, i| {
            rua[i] = try allocator.dupe(u8, uri);
            initialized = i + 1;
        }

        return TLSReportPolicy{
            .version = try allocator.dupe(u8, "TLSRPTv1"),
            .rua = rua,
            .max_age = max_age,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TLSReportPolicy) void {
        self.allocator.free(self.version);
        for (self.rua) |uri| self.allocator.free(uri);
        self.allocator.free(self.rua);
    }
};

/// Individual TLS failure entry per RFC 8460 Section 4.3
pub const TLSFailureReport = struct {
    result_type: ResultType,
    sending_mta: []const u8,
    receiving_mx: []const u8,
    policy_type: PolicyType,
    policy_string: []const []const u8,
    failure_reason: []const u8,
    failed_session_count: u64,
    additional_info: []const u8,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        result_type: ResultType,
        sending_mta: []const u8,
        receiving_mx: []const u8,
        policy_type: PolicyType,
        policy_strings: []const []const u8,
        failure_reason: []const u8,
        failed_session_count: u64,
        additional_info: []const u8,
    ) !TLSFailureReport {
        var ps = try allocator.alloc([]const u8, policy_strings.len);
        errdefer allocator.free(ps);
        var ps_init: usize = 0;
        errdefer for (ps[0..ps_init]) |s| allocator.free(s);

        for (policy_strings, 0..) |s, i| {
            ps[i] = try allocator.dupe(u8, s);
            ps_init = i + 1;
        }

        return TLSFailureReport{
            .result_type = result_type,
            .sending_mta = try allocator.dupe(u8, sending_mta),
            .receiving_mx = try allocator.dupe(u8, receiving_mx),
            .policy_type = policy_type,
            .policy_string = ps,
            .failure_reason = try allocator.dupe(u8, failure_reason),
            .failed_session_count = failed_session_count,
            .additional_info = try allocator.dupe(u8, additional_info),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TLSFailureReport) void {
        self.allocator.free(self.sending_mta);
        self.allocator.free(self.receiving_mx);
        for (self.policy_string) |s| self.allocator.free(s);
        self.allocator.free(self.policy_string);
        self.allocator.free(self.failure_reason);
        self.allocator.free(self.additional_info);
    }
};

/// Date range for a TLS-RPT report
pub const DateRange = struct {
    start_datetime: i64,
    end_datetime: i64,
};

/// Per-policy summary within a TLS-RPT aggregate report (RFC 8460 Section 4.2)
pub const PolicySummary = struct {
    policy_type: PolicyType,
    policy_string: []const []const u8,
    policy_domain: []const u8,
    mx_host: []const u8,
    total_successful_session_count: u64,
    total_failure_session_count: u64,
    failure_details: []const TLSFailureReport,
    allocator: std.mem.Allocator,
};

/// Full TLS-RPT aggregate report per RFC 8460 Section 4
pub const TLSReport = struct {
    organization_name: []const u8,
    date_range: DateRange,
    contact_info: []const u8,
    report_id: []const u8,
    policies: []const PolicySummary,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *TLSReport) void {
        self.allocator.free(self.organization_name);
        self.allocator.free(self.contact_info);
        self.allocator.free(self.report_id);
        self.allocator.free(self.policies);
    }
};

/// Internal tracking record for domain+mx pair statistics
const DomainMXStats = struct {
    successful_sessions: u64,
    failed_sessions: u64,
    failures: std.ArrayList(FailureRecord),

    fn deinitStats(self: *DomainMXStats, allocator: std.mem.Allocator) void {
        for (self.failures.items) |*f| f.deinitRecord(allocator);
        self.failures.deinit(allocator);
    }
};

/// Individual recorded failure
const FailureRecord = struct {
    failure_type: TLSFailureType,
    result_type: ResultType,
    detail: []const u8,
    timestamp: i64,
    count: u64,

    fn deinitRecord(self: *FailureRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.detail);
    }
};

/// Composite key for the domain stats map: "domain\0mx"
const StatsKey = struct {
    buf: []const u8,

    fn make(allocator: std.mem.Allocator, domain_name: []const u8, mx_host: []const u8) !StatsKey {
        const buf = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ domain_name, mx_host });
        return .{ .buf = buf };
    }

    fn getDomain(self: StatsKey) []const u8 {
        if (std.mem.indexOfScalar(u8, self.buf, 0)) |idx| return self.buf[0..idx];
        return self.buf;
    }

    fn getMx(self: StatsKey) []const u8 {
        if (std.mem.indexOfScalar(u8, self.buf, 0)) |idx| return self.buf[idx + 1 ..];
        return "";
    }

    fn free(self: StatsKey, allocator: std.mem.Allocator) void {
        allocator.free(self.buf);
    }
};

/// Aggregate statistics returned by getStats()
pub const AggregateStats = struct {
    total_domains: usize,
    total_successful_sessions: u64,
    total_failed_sessions: u64,
    total_failure_records: u64,
};

/// Thread-safe TLS-RPT report aggregator.
/// Tracks successful and failed TLS connections per domain and MX host,
/// and generates RFC 8460 compliant JSON reports.
pub const TLSReportAggregator = struct {
    allocator: std.mem.Allocator,
    mutex: mutex_compat.Mutex,
    domain_stats: std.StringHashMap(DomainMXStats),
    tracked_domains: std.StringHashMap(void),
    organization_name: []const u8,
    contact_info: []const u8,
    period_start: i64,

    pub fn init(allocator: std.mem.Allocator) TLSReportAggregator {
        return .{
            .allocator = allocator,
            .mutex = .{},
            .domain_stats = std.StringHashMap(DomainMXStats).init(allocator),
            .tracked_domains = std.StringHashMap(void).init(allocator),
            .organization_name = "Mail Server",
            .contact_info = "postmaster",
            .period_start = time_compat.timestamp(),
        };
    }

    pub fn deinit(self: *TLSReportAggregator) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.domain_stats.iterator();
        while (it.next()) |entry| {
            var stats = entry.value_ptr;
            stats.deinitStats(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.domain_stats.deinit();

        var domain_it = self.tracked_domains.iterator();
        while (domain_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.tracked_domains.deinit();
    }

    /// Set the organization name used in generated reports.
    pub fn setOrganizationName(self: *TLSReportAggregator, name: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.organization_name = name;
    }

    /// Set the contact info used in generated reports.
    pub fn setContactInfo(self: *TLSReportAggregator, info: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.contact_info = info;
    }

    /// Record a successful TLS connection to the given domain and MX host.
    pub fn recordSuccess(self: *TLSReportAggregator, domain_name: []const u8, mx_host: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = try StatsKey.make(self.allocator, domain_name, mx_host);
        errdefer key.free(self.allocator);

        const result = try self.domain_stats.getOrPut(key.buf);
        if (!result.found_existing) {
            result.value_ptr.* = .{
                .successful_sessions = 0,
                .failed_sessions = 0,
                .failures = .{},
            };
        } else {
            key.free(self.allocator);
        }
        result.value_ptr.successful_sessions += 1;

        if (!self.tracked_domains.contains(domain_name)) {
            const d = try self.allocator.dupe(u8, domain_name);
            try self.tracked_domains.put(d, {});
        }
    }

    /// Record a TLS failure for the given domain and MX host.
    pub fn recordFailure(
        self: *TLSReportAggregator,
        domain_name: []const u8,
        mx_host: []const u8,
        failure_type: TLSFailureType,
        detail: []const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = try StatsKey.make(self.allocator, domain_name, mx_host);
        errdefer key.free(self.allocator);

        const result = try self.domain_stats.getOrPut(key.buf);
        if (!result.found_existing) {
            result.value_ptr.* = .{
                .successful_sessions = 0,
                .failed_sessions = 0,
                .failures = .{},
            };
        } else {
            key.free(self.allocator);
        }

        result.value_ptr.failed_sessions += 1;
        const result_type = mapFailureToResult(failure_type);

        // Coalesce identical failure type+detail
        for (result.value_ptr.failures.items) |*existing| {
            if (existing.result_type == result_type and std.mem.eql(u8, existing.detail, detail)) {
                existing.count += 1;
                // Track domain
                if (!self.tracked_domains.contains(domain_name)) {
                    const d = try self.allocator.dupe(u8, domain_name);
                    try self.tracked_domains.put(d, {});
                }
                return;
            }
        }

        try result.value_ptr.failures.append(self.allocator, .{
            .failure_type = failure_type,
            .result_type = result_type,
            .detail = try self.allocator.dupe(u8, detail),
            .timestamp = time_compat.timestamp(),
            .count = 1,
        });

        if (!self.tracked_domains.contains(domain_name)) {
            const d = try self.allocator.dupe(u8, domain_name);
            try self.tracked_domains.put(d, {});
        }
    }

    /// Generate a JSON TLS-RPT report for a specific domain per RFC 8460.
    /// The caller owns the returned memory.
    pub fn generateReport(self: *TLSReportAggregator, domain_name: []const u8) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();
        const report_id = try std.fmt.allocPrint(self.allocator, "{d}-{s}", .{ now, domain_name });
        defer self.allocator.free(report_id);

        var json: std.ArrayList(u8) = .{};
        defer json.deinit(self.allocator);

        try json.appendSlice(self.allocator, "{\n");
        try json.appendSlice(self.allocator, "  \"organization-name\": \"");
        try appendJsonEscaped(&json, self.allocator, self.organization_name);
        try json.appendSlice(self.allocator, "\",\n");

        try json.print(self.allocator, "  \"date-range\": {{\n    \"start-datetime\": \"{d}\",\n    \"end-datetime\": \"{d}\"\n  }},\n", .{
            self.period_start,
            now,
        });

        try json.appendSlice(self.allocator, "  \"contact-info\": \"");
        try appendJsonEscaped(&json, self.allocator, self.contact_info);
        try json.appendSlice(self.allocator, "\",\n");

        try json.appendSlice(self.allocator, "  \"report-id\": \"");
        try appendJsonEscaped(&json, self.allocator, report_id);
        try json.appendSlice(self.allocator, "\",\n");

        try json.appendSlice(self.allocator, "  \"policies\": [\n");

        var policy_count: usize = 0;
        var it = self.domain_stats.iterator();
        while (it.next()) |entry| {
            const skey = StatsKey{ .buf = entry.key_ptr.* };
            const entry_domain = skey.getDomain();
            if (!std.mem.eql(u8, entry_domain, domain_name)) continue;

            const stats = entry.value_ptr;
            const mx = skey.getMx();

            if (policy_count > 0) try json.appendSlice(self.allocator, ",\n");

            try json.appendSlice(self.allocator, "    {\n");
            try json.appendSlice(self.allocator, "      \"policy\": {\n");
            try json.appendSlice(self.allocator, "        \"policy-type\": \"no-policy-found\",\n");
            try json.appendSlice(self.allocator, "        \"policy-string\": [],\n");
            try json.appendSlice(self.allocator, "        \"policy-domain\": \"");
            try appendJsonEscaped(&json, self.allocator, domain_name);
            try json.appendSlice(self.allocator, "\",\n");
            try json.appendSlice(self.allocator, "        \"mx-host\": \"");
            try appendJsonEscaped(&json, self.allocator, mx);
            try json.appendSlice(self.allocator, "\"\n");
            try json.appendSlice(self.allocator, "      },\n");

            try json.appendSlice(self.allocator, "      \"summary\": {\n");
            try json.print(self.allocator, "        \"total-successful-session-count\": {d},\n", .{stats.successful_sessions});
            try json.print(self.allocator, "        \"total-failure-session-count\": {d}\n", .{stats.failed_sessions});
            try json.appendSlice(self.allocator, "      }");

            if (stats.failures.items.len > 0) {
                try json.appendSlice(self.allocator, ",\n      \"failure-details\": [\n");
                for (stats.failures.items, 0..) |failure, fi| {
                    if (fi > 0) try json.appendSlice(self.allocator, ",\n");
                    try json.appendSlice(self.allocator, "        {\n");
                    try json.appendSlice(self.allocator, "          \"result-type\": \"");
                    try appendJsonEscaped(&json, self.allocator, failure.result_type.toString());
                    try json.appendSlice(self.allocator, "\",\n");
                    try json.appendSlice(self.allocator, "          \"sending-mta-domain\": \"");
                    try appendJsonEscaped(&json, self.allocator, self.organization_name);
                    try json.appendSlice(self.allocator, "\",\n");
                    try json.appendSlice(self.allocator, "          \"receiving-mx-hostname\": \"");
                    try appendJsonEscaped(&json, self.allocator, mx);
                    try json.appendSlice(self.allocator, "\",\n");
                    try json.print(self.allocator, "          \"failed-session-count\": {d},\n", .{failure.count});
                    try json.appendSlice(self.allocator, "          \"failure-reason-code\": \"");
                    try appendJsonEscaped(&json, self.allocator, failure.detail);
                    try json.appendSlice(self.allocator, "\"\n");
                    try json.appendSlice(self.allocator, "        }");
                }
                try json.appendSlice(self.allocator, "\n      ]\n");
            } else {
                try json.appendSlice(self.allocator, "\n");
            }

            try json.appendSlice(self.allocator, "    }");
            policy_count += 1;
        }

        if (policy_count == 0) {
            try json.appendSlice(self.allocator, "    {\n");
            try json.appendSlice(self.allocator, "      \"policy\": {\n");
            try json.appendSlice(self.allocator, "        \"policy-type\": \"no-policy-found\",\n");
            try json.appendSlice(self.allocator, "        \"policy-string\": [],\n");
            try json.appendSlice(self.allocator, "        \"policy-domain\": \"");
            try appendJsonEscaped(&json, self.allocator, domain_name);
            try json.appendSlice(self.allocator, "\",\n");
            try json.appendSlice(self.allocator, "        \"mx-host\": \"\"\n");
            try json.appendSlice(self.allocator, "      },\n");
            try json.appendSlice(self.allocator, "      \"summary\": {\n");
            try json.appendSlice(self.allocator, "        \"total-successful-session-count\": 0,\n");
            try json.appendSlice(self.allocator, "        \"total-failure-session-count\": 0\n");
            try json.appendSlice(self.allocator, "      }\n");
            try json.appendSlice(self.allocator, "    }");
        }

        try json.appendSlice(self.allocator, "\n  ]\n}");

        return try json.toOwnedSlice(self.allocator);
    }

    /// Return aggregate statistics across all tracked domains.
    pub fn getStats(self: *TLSReportAggregator) AggregateStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        var stats = AggregateStats{
            .total_domains = self.tracked_domains.count(),
            .total_successful_sessions = 0,
            .total_failed_sessions = 0,
            .total_failure_records = 0,
        };

        var it = self.domain_stats.iterator();
        while (it.next()) |entry| {
            stats.total_successful_sessions += entry.value_ptr.successful_sessions;
            stats.total_failed_sessions += entry.value_ptr.failed_sessions;
            stats.total_failure_records += entry.value_ptr.failures.items.len;
        }

        return stats;
    }

    /// Reset the aggregator, clearing all tracked data and starting a new period.
    pub fn reset(self: *TLSReportAggregator) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.domain_stats.iterator();
        while (it.next()) |entry| {
            var s = entry.value_ptr;
            s.deinitStats(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.domain_stats.clearAndFree();

        var domain_it = self.tracked_domains.iterator();
        while (domain_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.tracked_domains.clearAndFree();

        self.period_start = time_compat.timestamp();
    }

    fn mapFailureToResult(ft: TLSFailureType) ResultType {
        return switch (ft) {
            .starttls_not_supported => .starttls_not_supported,
            .certificate_invalid => .certificate_not_trusted,
            .certificate_expired => .certificate_expired,
            .certificate_hostname_mismatch => .certificate_host_mismatch,
            .policy_mismatch => .validation_failure,
            .sts_policy_invalid => .sts_policy_invalid,
            .dane_required => .dane_required,
            .other => .negotiation_failure,
        };
    }
};

/// JSON report generator that produces RFC 8460 compliant output.
/// Formats TLSReport data structures into JSON.
pub const TLSReportGenerator = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) TLSReportGenerator {
        return .{ .allocator = allocator };
    }

    /// Generate a complete TLS-RPT JSON report from a TLSReport struct.
    /// The caller owns the returned memory.
    pub fn formatReport(self: *TLSReportGenerator, report: *const TLSReport) ![]const u8 {
        var json: std.ArrayList(u8) = .{};
        defer json.deinit(self.allocator);

        try json.appendSlice(self.allocator, "{\n");
        try json.appendSlice(self.allocator, "  \"organization-name\": \"");
        try appendJsonEscaped(&json, self.allocator, report.organization_name);
        try json.appendSlice(self.allocator, "\",\n");

        try json.print(self.allocator, "  \"date-range\": {{\n    \"start-datetime\": \"{d}\",\n    \"end-datetime\": \"{d}\"\n  }},\n", .{
            report.date_range.start_datetime,
            report.date_range.end_datetime,
        });

        try json.appendSlice(self.allocator, "  \"contact-info\": \"");
        try appendJsonEscaped(&json, self.allocator, report.contact_info);
        try json.appendSlice(self.allocator, "\",\n");

        try json.appendSlice(self.allocator, "  \"report-id\": \"");
        try appendJsonEscaped(&json, self.allocator, report.report_id);
        try json.appendSlice(self.allocator, "\",\n");

        try json.appendSlice(self.allocator, "  \"policies\": [\n");

        for (report.policies, 0..) |policy, pi| {
            if (pi > 0) try json.appendSlice(self.allocator, ",\n");

            try json.appendSlice(self.allocator, "    {\n");
            try json.appendSlice(self.allocator, "      \"policy\": {\n");
            try json.appendSlice(self.allocator, "        \"policy-type\": \"");
            try appendJsonEscaped(&json, self.allocator, policy.policy_type.toString());
            try json.appendSlice(self.allocator, "\",\n");

            try json.appendSlice(self.allocator, "        \"policy-string\": [");
            for (policy.policy_string, 0..) |ps, psi| {
                if (psi > 0) try json.appendSlice(self.allocator, ", ");
                try json.appendSlice(self.allocator, "\"");
                try appendJsonEscaped(&json, self.allocator, ps);
                try json.appendSlice(self.allocator, "\"");
            }
            try json.appendSlice(self.allocator, "],\n");

            try json.appendSlice(self.allocator, "        \"policy-domain\": \"");
            try appendJsonEscaped(&json, self.allocator, policy.policy_domain);
            try json.appendSlice(self.allocator, "\",\n");
            try json.appendSlice(self.allocator, "        \"mx-host\": \"");
            try appendJsonEscaped(&json, self.allocator, policy.mx_host);
            try json.appendSlice(self.allocator, "\"\n");
            try json.appendSlice(self.allocator, "      },\n");

            try json.appendSlice(self.allocator, "      \"summary\": {\n");
            try json.print(self.allocator, "        \"total-successful-session-count\": {d},\n", .{policy.total_successful_session_count});
            try json.print(self.allocator, "        \"total-failure-session-count\": {d}\n", .{policy.total_failure_session_count});
            try json.appendSlice(self.allocator, "      }");

            if (policy.failure_details.len > 0) {
                try json.appendSlice(self.allocator, ",\n      \"failure-details\": [\n");
                for (policy.failure_details, 0..) |fd, fi| {
                    if (fi > 0) try json.appendSlice(self.allocator, ",\n");
                    try json.appendSlice(self.allocator, "        {\n");
                    try json.appendSlice(self.allocator, "          \"result-type\": \"");
                    try appendJsonEscaped(&json, self.allocator, fd.result_type.toString());
                    try json.appendSlice(self.allocator, "\",\n");
                    try json.appendSlice(self.allocator, "          \"sending-mta-domain\": \"");
                    try appendJsonEscaped(&json, self.allocator, fd.sending_mta);
                    try json.appendSlice(self.allocator, "\",\n");
                    try json.appendSlice(self.allocator, "          \"receiving-mx-hostname\": \"");
                    try appendJsonEscaped(&json, self.allocator, fd.receiving_mx);
                    try json.appendSlice(self.allocator, "\",\n");
                    try json.print(self.allocator, "          \"failed-session-count\": {d},\n", .{fd.failed_session_count});
                    try json.appendSlice(self.allocator, "          \"failure-reason-code\": \"");
                    try appendJsonEscaped(&json, self.allocator, fd.failure_reason);
                    try json.appendSlice(self.allocator, "\"\n");
                    try json.appendSlice(self.allocator, "        }");
                }
                try json.appendSlice(self.allocator, "\n      ]\n");
            } else {
                try json.appendSlice(self.allocator, "\n");
            }

            try json.appendSlice(self.allocator, "    }");
        }

        try json.appendSlice(self.allocator, "\n  ]\n}");

        return try json.toOwnedSlice(self.allocator);
    }
};

/// Append a JSON-escaped version of `s` to the list.
fn appendJsonEscaped(list: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            '\n' => try list.appendSlice(allocator, "\\n"),
            '\r' => try list.appendSlice(allocator, "\\r"),
            '\t' => try list.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    var buf: [6]u8 = undefined;
                    const hex = "0123456789abcdef";
                    buf[0] = '\\';
                    buf[1] = 'u';
                    buf[2] = '0';
                    buf[3] = '0';
                    buf[4] = hex[c >> 4];
                    buf[5] = hex[c & 0x0f];
                    try list.appendSlice(allocator, &buf);
                } else {
                    try list.append(allocator, c);
                }
            },
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "TLSFailureType toString and fromString" {
    const testing = std.testing;

    try testing.expectEqualStrings("starttls-not-supported", TLSFailureType.starttls_not_supported.toString());
    try testing.expectEqualStrings("certificate-invalid", TLSFailureType.certificate_invalid.toString());
    try testing.expectEqualStrings("certificate-expired", TLSFailureType.certificate_expired.toString());
    try testing.expectEqualStrings("certificate-hostname-mismatch", TLSFailureType.certificate_hostname_mismatch.toString());
    try testing.expectEqualStrings("dane-required", TLSFailureType.dane_required.toString());
    try testing.expectEqualStrings("other", TLSFailureType.other.toString());

    try testing.expectEqual(TLSFailureType.starttls_not_supported, try TLSFailureType.fromString("starttls-not-supported"));
    try testing.expectEqual(TLSFailureType.certificate_expired, try TLSFailureType.fromString("certificate-expired"));
    try testing.expectEqual(TLSFailureType.other, try TLSFailureType.fromString("other"));

    try testing.expectError(error.InvalidFailureType, TLSFailureType.fromString("unknown-type"));
}

test "TLSRPTRecord parse valid record" {
    const testing = std.testing;

    var record = try TLSRPTRecord.parse(testing.allocator, "v=TLSRPTv1; rua=mailto:reports@example.com");
    defer record.deinit();

    try testing.expectEqualStrings("TLSRPTv1", record.version);
    try testing.expectEqual(@as(usize, 1), record.rua.len);
    try testing.expectEqualStrings("mailto:reports@example.com", record.rua[0]);
}

test "TLSRPTRecord parse multiple URIs" {
    const testing = std.testing;

    var record = try TLSRPTRecord.parse(
        testing.allocator,
        "v=TLSRPTv1; rua=mailto:tls@example.com,https://report.example.com/submit",
    );
    defer record.deinit();

    try testing.expectEqualStrings("TLSRPTv1", record.version);
    try testing.expectEqual(@as(usize, 2), record.rua.len);
    try testing.expectEqualStrings("mailto:tls@example.com", record.rua[0]);
    try testing.expectEqualStrings("https://report.example.com/submit", record.rua[1]);
}

test "TLSRPTRecord parse with extra whitespace" {
    const testing = std.testing;

    var record = try TLSRPTRecord.parse(testing.allocator, "  v=TLSRPTv1 ;  rua=mailto:reports@example.com  ");
    defer record.deinit();

    try testing.expectEqualStrings("TLSRPTv1", record.version);
    try testing.expectEqual(@as(usize, 1), record.rua.len);
}

test "TLSRPTRecord parse missing version" {
    const testing = std.testing;
    try testing.expectError(error.MissingVersion, TLSRPTRecord.parse(testing.allocator, "rua=mailto:reports@example.com"));
}

test "TLSRPTRecord parse unsupported version" {
    const testing = std.testing;
    try testing.expectError(error.UnsupportedVersion, TLSRPTRecord.parse(testing.allocator, "v=TLSRPTv2; rua=mailto:reports@example.com"));
}

test "TLSRPTRecord parse missing rua" {
    const testing = std.testing;
    try testing.expectError(error.MissingReportingURI, TLSRPTRecord.parse(testing.allocator, "v=TLSRPTv1"));
}

test "TLSReportPolicy init and deinit" {
    const testing = std.testing;

    const uris = [_][]const u8{ "mailto:reports@example.com", "https://report.example.com/submit" };
    var policy = try TLSReportPolicy.init(testing.allocator, &uris, 86400);
    defer policy.deinit();

    try testing.expectEqualStrings("TLSRPTv1", policy.version);
    try testing.expectEqual(@as(usize, 2), policy.rua.len);
    try testing.expectEqualStrings("mailto:reports@example.com", policy.rua[0]);
    try testing.expectEqualStrings("https://report.example.com/submit", policy.rua[1]);
    try testing.expectEqual(@as(u64, 86400), policy.max_age);
}

test "TLSFailureReport init and deinit" {
    const testing = std.testing;

    const policy_strings = [_][]const u8{ "version: STSv1", "mode: enforce" };
    var report = try TLSFailureReport.init(
        testing.allocator,
        .certificate_expired,
        "mail.sender.com",
        "mx.receiver.com",
        .sts,
        &policy_strings,
        "Certificate expired on 2025-01-01",
        3,
        "https://example.com/info",
    );
    defer report.deinit();

    try testing.expectEqualStrings("certificate-expired", report.result_type.toString());
    try testing.expectEqualStrings("mail.sender.com", report.sending_mta);
    try testing.expectEqualStrings("mx.receiver.com", report.receiving_mx);
    try testing.expectEqualStrings("sts", report.policy_type.toString());
    try testing.expectEqual(@as(usize, 2), report.policy_string.len);
    try testing.expectEqualStrings("version: STSv1", report.policy_string[0]);
    try testing.expectEqualStrings("Certificate expired on 2025-01-01", report.failure_reason);
    try testing.expectEqual(@as(u64, 3), report.failed_session_count);
    try testing.expectEqualStrings("https://example.com/info", report.additional_info);
}

test "TLSReportAggregator recordSuccess and getStats" {
    const testing = std.testing;

    var agg = TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordSuccess("example.com", "mx1.example.com");
    try agg.recordSuccess("example.com", "mx1.example.com");
    try agg.recordSuccess("example.com", "mx2.example.com");
    try agg.recordSuccess("other.com", "mx.other.com");

    const stats = agg.getStats();

    try testing.expectEqual(@as(usize, 2), stats.total_domains);
    try testing.expectEqual(@as(u64, 4), stats.total_successful_sessions);
    try testing.expectEqual(@as(u64, 0), stats.total_failed_sessions);
    try testing.expectEqual(@as(u64, 0), stats.total_failure_records);
}

test "TLSReportAggregator recordFailure and getStats" {
    const testing = std.testing;

    var agg = TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordFailure("example.com", "mx1.example.com", .certificate_expired, "cert expired 2025-01-01");
    try agg.recordFailure("example.com", "mx1.example.com", .certificate_expired, "cert expired 2025-01-01");
    try agg.recordFailure("example.com", "mx1.example.com", .starttls_not_supported, "no STARTTLS");

    const stats = agg.getStats();

    try testing.expectEqual(@as(usize, 1), stats.total_domains);
    try testing.expectEqual(@as(u64, 0), stats.total_successful_sessions);
    try testing.expectEqual(@as(u64, 3), stats.total_failed_sessions);
    try testing.expectEqual(@as(u64, 2), stats.total_failure_records);
}

test "TLSReportAggregator mixed success and failure" {
    const testing = std.testing;

    var agg = TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordSuccess("example.com", "mx1.example.com");
    try agg.recordSuccess("example.com", "mx1.example.com");
    try agg.recordFailure("example.com", "mx1.example.com", .certificate_hostname_mismatch, "hostname mismatch");
    try agg.recordSuccess("example.com", "mx2.example.com");

    const stats = agg.getStats();

    try testing.expectEqual(@as(usize, 1), stats.total_domains);
    try testing.expectEqual(@as(u64, 3), stats.total_successful_sessions);
    try testing.expectEqual(@as(u64, 1), stats.total_failed_sessions);
    try testing.expectEqual(@as(u64, 1), stats.total_failure_records);
}

test "TLSReportAggregator generateReport basic structure" {
    const testing = std.testing;

    var agg = TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordSuccess("example.com", "mx1.example.com");
    try agg.recordFailure("example.com", "mx1.example.com", .certificate_expired, "cert expired");

    const report = try agg.generateReport("example.com");
    defer testing.allocator.free(report);

    try testing.expect(std.mem.indexOf(u8, report, "\"organization-name\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"date-range\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"start-datetime\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"end-datetime\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"contact-info\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"report-id\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"policies\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"policy-type\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"policy-domain\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-successful-session-count\": 1") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-failure-session-count\": 1") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"failure-details\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"certificate-expired\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"failure-reason-code\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "cert expired") != null);
}

test "TLSReportAggregator generateReport for unknown domain" {
    const testing = std.testing;

    var agg = TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    const report = try agg.generateReport("unknown.com");
    defer testing.allocator.free(report);

    try testing.expect(std.mem.indexOf(u8, report, "\"organization-name\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"policies\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-successful-session-count\": 0") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-failure-session-count\": 0") != null);
}

test "TLSReportAggregator generateReport no failures section when all success" {
    const testing = std.testing;

    var agg = TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordSuccess("clean.com", "mx.clean.com");
    try agg.recordSuccess("clean.com", "mx.clean.com");

    const report = try agg.generateReport("clean.com");
    defer testing.allocator.free(report);

    try testing.expect(std.mem.indexOf(u8, report, "\"total-successful-session-count\": 2") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-failure-session-count\": 0") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"failure-details\"") == null);
}

test "TLSReportAggregator reset" {
    const testing = std.testing;

    var agg = TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordSuccess("example.com", "mx.example.com");
    try agg.recordFailure("example.com", "mx.example.com", .other, "test");

    var stats = agg.getStats();
    try testing.expectEqual(@as(usize, 1), stats.total_domains);
    try testing.expectEqual(@as(u64, 1), stats.total_successful_sessions);

    agg.reset();

    stats = agg.getStats();
    try testing.expectEqual(@as(usize, 0), stats.total_domains);
    try testing.expectEqual(@as(u64, 0), stats.total_successful_sessions);
    try testing.expectEqual(@as(u64, 0), stats.total_failed_sessions);
}

test "TLSReportGenerator formatReport" {
    const testing = std.testing;

    const policy_strings = [_][]const u8{"version: STSv1"};
    var failure = try TLSFailureReport.init(
        testing.allocator,
        .certificate_expired,
        "mail.sender.com",
        "mx.receiver.com",
        .sts,
        &policy_strings,
        "Certificate expired",
        5,
        "",
    );
    defer failure.deinit();

    const failures = [_]TLSFailureReport{failure};
    const ps = [_][]const u8{"version: STSv1"};
    const policies = [_]PolicySummary{.{
        .policy_type = .sts,
        .policy_string = &ps,
        .policy_domain = "receiver.com",
        .mx_host = "mx.receiver.com",
        .total_successful_session_count = 100,
        .total_failure_session_count = 5,
        .failure_details = &failures,
        .allocator = testing.allocator,
    }};

    var report = TLSReport{
        .organization_name = "Example Org",
        .date_range = .{ .start_datetime = 1700000000, .end_datetime = 1700086400 },
        .contact_info = "postmaster@example.com",
        .report_id = "report-001",
        .policies = &policies,
        .allocator = testing.allocator,
    };
    _ = &report;

    var gen = TLSReportGenerator.init(testing.allocator);
    const json = try gen.formatReport(&report);
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"organization-name\": \"Example Org\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"start-datetime\": \"1700000000\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"end-datetime\": \"1700086400\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"contact-info\": \"postmaster@example.com\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"report-id\": \"report-001\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"policy-type\": \"sts\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"policy-domain\": \"receiver.com\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"mx-host\": \"mx.receiver.com\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"total-successful-session-count\": 100") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"total-failure-session-count\": 5") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"certificate-expired\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"Certificate expired\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"failed-session-count\": 5") != null);
}

test "TLSReportGenerator formatReport multiple policies" {
    const testing = std.testing;

    const ps1 = [_][]const u8{"version: STSv1"};
    const ps2 = [_][]const u8{};
    const no_failures = [_]TLSFailureReport{};

    const policies = [_]PolicySummary{
        .{
            .policy_type = .sts,
            .policy_string = &ps1,
            .policy_domain = "alpha.com",
            .mx_host = "mx.alpha.com",
            .total_successful_session_count = 50,
            .total_failure_session_count = 0,
            .failure_details = &no_failures,
            .allocator = testing.allocator,
        },
        .{
            .policy_type = .no_policy_found,
            .policy_string = &ps2,
            .policy_domain = "beta.com",
            .mx_host = "mx.beta.com",
            .total_successful_session_count = 10,
            .total_failure_session_count = 2,
            .failure_details = &no_failures,
            .allocator = testing.allocator,
        },
    };

    var report = TLSReport{
        .organization_name = "Multi Org",
        .date_range = .{ .start_datetime = 1700000000, .end_datetime = 1700086400 },
        .contact_info = "admin@multi.com",
        .report_id = "multi-report-001",
        .policies = &policies,
        .allocator = testing.allocator,
    };
    _ = &report;

    var gen = TLSReportGenerator.init(testing.allocator);
    const json = try gen.formatReport(&report);
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"alpha.com\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"beta.com\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"total-successful-session-count\": 50") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"total-successful-session-count\": 10") != null);
}

test "appendJsonEscaped handles special characters" {
    const testing = std.testing;

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(testing.allocator);

    try appendJsonEscaped(&buf, testing.allocator, "hello \"world\"");
    try testing.expectEqualStrings("hello \\\"world\\\"", buf.items);

    buf.clearRetainingCapacity();
    try appendJsonEscaped(&buf, testing.allocator, "line1\nline2");
    try testing.expectEqualStrings("line1\\nline2", buf.items);

    buf.clearRetainingCapacity();
    try appendJsonEscaped(&buf, testing.allocator, "back\\slash");
    try testing.expectEqualStrings("back\\\\slash", buf.items);

    buf.clearRetainingCapacity();
    try appendJsonEscaped(&buf, testing.allocator, "tab\there");
    try testing.expectEqualStrings("tab\\there", buf.items);
}

test "PolicyType toString and fromString" {
    const testing = std.testing;

    try testing.expectEqualStrings("tlsa", PolicyType.tlsa.toString());
    try testing.expectEqualStrings("sts", PolicyType.sts.toString());
    try testing.expectEqualStrings("no-policy-found", PolicyType.no_policy_found.toString());

    try testing.expectEqual(PolicyType.tlsa, try PolicyType.fromString("tlsa"));
    try testing.expectEqual(PolicyType.sts, try PolicyType.fromString("sts"));
    try testing.expectEqual(PolicyType.no_policy_found, try PolicyType.fromString("no-policy-found"));

    try testing.expectError(error.InvalidPolicyType, PolicyType.fromString("invalid"));
}

test "ResultType toString covers all variants" {
    const testing = std.testing;

    try testing.expectEqualStrings("starttls-not-supported", ResultType.starttls_not_supported.toString());
    try testing.expectEqualStrings("certificate-host-mismatch", ResultType.certificate_host_mismatch.toString());
    try testing.expectEqualStrings("certificate-expired", ResultType.certificate_expired.toString());
    try testing.expectEqualStrings("certificate-not-trusted", ResultType.certificate_not_trusted.toString());
    try testing.expectEqualStrings("validation-failure", ResultType.validation_failure.toString());
    try testing.expectEqualStrings("tlsa-invalid", ResultType.tlsa_invalid.toString());
    try testing.expectEqualStrings("dnssec-invalid", ResultType.dnssec_invalid.toString());
    try testing.expectEqualStrings("dane-required", ResultType.dane_required.toString());
    try testing.expectEqualStrings("sts-policy-fetch-error", ResultType.sts_policy_fetch_error.toString());
    try testing.expectEqualStrings("sts-policy-invalid", ResultType.sts_policy_invalid.toString());
    try testing.expectEqualStrings("sts-webpki-invalid", ResultType.sts_webpki_invalid.toString());
    try testing.expectEqualStrings("negotiation-failure", ResultType.negotiation_failure.toString());
}

test "TLSReportAggregator failure coalescing" {
    const testing = std.testing;

    var agg = TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordFailure("example.com", "mx.example.com", .certificate_expired, "expired cert");
    try agg.recordFailure("example.com", "mx.example.com", .certificate_expired, "expired cert");
    try agg.recordFailure("example.com", "mx.example.com", .certificate_expired, "expired cert");

    const stats = agg.getStats();
    try testing.expectEqual(@as(u64, 3), stats.total_failed_sessions);
    try testing.expectEqual(@as(u64, 1), stats.total_failure_records);

    try agg.recordFailure("example.com", "mx.example.com", .certificate_expired, "different cert");
    const stats2 = agg.getStats();
    try testing.expectEqual(@as(u64, 2), stats2.total_failure_records);
}

test "TLSReportAggregator multiple domains isolation" {
    const testing = std.testing;

    var agg = TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordSuccess("alpha.com", "mx.alpha.com");
    try agg.recordSuccess("alpha.com", "mx.alpha.com");
    try agg.recordFailure("beta.com", "mx.beta.com", .starttls_not_supported, "no STARTTLS");

    const report_alpha = try agg.generateReport("alpha.com");
    defer testing.allocator.free(report_alpha);

    try testing.expect(std.mem.indexOf(u8, report_alpha, "\"total-successful-session-count\": 2") != null);
    try testing.expect(std.mem.indexOf(u8, report_alpha, "\"failure-details\"") == null);

    const report_beta = try agg.generateReport("beta.com");
    defer testing.allocator.free(report_beta);

    try testing.expect(std.mem.indexOf(u8, report_beta, "\"total-failure-session-count\": 1") != null);
    try testing.expect(std.mem.indexOf(u8, report_beta, "\"starttls-not-supported\"") != null);
}

test "StatsKey domain and mx extraction" {
    const testing = std.testing;

    const key = try StatsKey.make(testing.allocator, "example.com", "mx1.example.com");
    defer key.free(testing.allocator);

    try testing.expectEqualStrings("example.com", key.getDomain());
    try testing.expectEqualStrings("mx1.example.com", key.getMx());
}

test "TLSReportAggregator setOrganizationName and setContactInfo" {
    const testing = std.testing;

    var agg = TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    agg.setOrganizationName("My Mail Corp");
    agg.setContactInfo("admin@mymail.com");

    try agg.recordSuccess("example.com", "mx.example.com");

    const report = try agg.generateReport("example.com");
    defer testing.allocator.free(report);

    try testing.expect(std.mem.indexOf(u8, report, "\"organization-name\": \"My Mail Corp\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"contact-info\": \"admin@mymail.com\"") != null);
}
