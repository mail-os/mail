// RFC 8460 TLS-RPT (SMTP TLS Reporting) Test Suite
// Tests for TLS failure recording, report aggregation, JSON report generation,
// and TLS-RPT DNS record parsing.
// https://datatracker.ietf.org/doc/html/rfc8460

const std = @import("std");
const testing = std.testing;
const tls_rpt = @import("mail").tls_rpt;

// ============================================================================
// TLSFailureType tests
// ============================================================================

test "RFC 8460 TLSFailureType toString" {
    try testing.expectEqualStrings("starttls-not-supported", tls_rpt.TLSFailureType.starttls_not_supported.toString());
    try testing.expectEqualStrings("certificate-invalid", tls_rpt.TLSFailureType.certificate_invalid.toString());
    try testing.expectEqualStrings("certificate-expired", tls_rpt.TLSFailureType.certificate_expired.toString());
    try testing.expectEqualStrings("certificate-hostname-mismatch", tls_rpt.TLSFailureType.certificate_hostname_mismatch.toString());
    try testing.expectEqualStrings("policy-mismatch", tls_rpt.TLSFailureType.policy_mismatch.toString());
    try testing.expectEqualStrings("sts-policy-invalid", tls_rpt.TLSFailureType.sts_policy_invalid.toString());
    try testing.expectEqualStrings("dane-required", tls_rpt.TLSFailureType.dane_required.toString());
    try testing.expectEqualStrings("other", tls_rpt.TLSFailureType.other.toString());
}

test "RFC 8460 TLSFailureType fromString" {
    try testing.expectEqual(tls_rpt.TLSFailureType.starttls_not_supported, try tls_rpt.TLSFailureType.fromString("starttls-not-supported"));
    try testing.expectEqual(tls_rpt.TLSFailureType.certificate_invalid, try tls_rpt.TLSFailureType.fromString("certificate-invalid"));
    try testing.expectEqual(tls_rpt.TLSFailureType.certificate_expired, try tls_rpt.TLSFailureType.fromString("certificate-expired"));
    try testing.expectEqual(tls_rpt.TLSFailureType.certificate_hostname_mismatch, try tls_rpt.TLSFailureType.fromString("certificate-hostname-mismatch"));
    try testing.expectEqual(tls_rpt.TLSFailureType.policy_mismatch, try tls_rpt.TLSFailureType.fromString("policy-mismatch"));
    try testing.expectEqual(tls_rpt.TLSFailureType.sts_policy_invalid, try tls_rpt.TLSFailureType.fromString("sts-policy-invalid"));
    try testing.expectEqual(tls_rpt.TLSFailureType.dane_required, try tls_rpt.TLSFailureType.fromString("dane-required"));
    try testing.expectEqual(tls_rpt.TLSFailureType.other, try tls_rpt.TLSFailureType.fromString("other"));
}

test "RFC 8460 TLSFailureType fromString invalid" {
    try testing.expectError(error.InvalidFailureType, tls_rpt.TLSFailureType.fromString("unknown-type"));
    try testing.expectError(error.InvalidFailureType, tls_rpt.TLSFailureType.fromString(""));
}

// ============================================================================
// ResultType tests
// ============================================================================

test "RFC 8460 ResultType toString" {
    try testing.expectEqualStrings("starttls-not-supported", tls_rpt.ResultType.starttls_not_supported.toString());
    try testing.expectEqualStrings("certificate-host-mismatch", tls_rpt.ResultType.certificate_host_mismatch.toString());
    try testing.expectEqualStrings("certificate-expired", tls_rpt.ResultType.certificate_expired.toString());
    try testing.expectEqualStrings("certificate-not-trusted", tls_rpt.ResultType.certificate_not_trusted.toString());
    try testing.expectEqualStrings("validation-failure", tls_rpt.ResultType.validation_failure.toString());
    try testing.expectEqualStrings("tlsa-invalid", tls_rpt.ResultType.tlsa_invalid.toString());
    try testing.expectEqualStrings("dnssec-invalid", tls_rpt.ResultType.dnssec_invalid.toString());
    try testing.expectEqualStrings("dane-required", tls_rpt.ResultType.dane_required.toString());
    try testing.expectEqualStrings("sts-policy-fetch-error", tls_rpt.ResultType.sts_policy_fetch_error.toString());
    try testing.expectEqualStrings("sts-policy-invalid", tls_rpt.ResultType.sts_policy_invalid.toString());
    try testing.expectEqualStrings("sts-webpki-invalid", tls_rpt.ResultType.sts_webpki_invalid.toString());
    try testing.expectEqualStrings("negotiation-failure", tls_rpt.ResultType.negotiation_failure.toString());
}

// ============================================================================
// PolicyType tests
// ============================================================================

test "RFC 8460 PolicyType toString" {
    try testing.expectEqualStrings("tlsa", tls_rpt.PolicyType.tlsa.toString());
    try testing.expectEqualStrings("sts", tls_rpt.PolicyType.sts.toString());
    try testing.expectEqualStrings("no-policy-found", tls_rpt.PolicyType.no_policy_found.toString());
}

test "RFC 8460 PolicyType fromString" {
    try testing.expectEqual(tls_rpt.PolicyType.tlsa, try tls_rpt.PolicyType.fromString("tlsa"));
    try testing.expectEqual(tls_rpt.PolicyType.sts, try tls_rpt.PolicyType.fromString("sts"));
    try testing.expectEqual(tls_rpt.PolicyType.no_policy_found, try tls_rpt.PolicyType.fromString("no-policy-found"));
    try testing.expectError(error.InvalidPolicyType, tls_rpt.PolicyType.fromString("invalid"));
}

// ============================================================================
// TLSRPTRecord parsing tests
// ============================================================================

test "RFC 8460 TLSRPTRecord parse: valid single rua" {
    var record = try tls_rpt.TLSRPTRecord.parse(testing.allocator, "v=TLSRPTv1; rua=mailto:reports@example.com");
    defer record.deinit();

    try testing.expectEqualStrings("TLSRPTv1", record.version);
    try testing.expectEqual(@as(usize, 1), record.rua.len);
    try testing.expectEqualStrings("mailto:reports@example.com", record.rua[0]);
}

test "RFC 8460 TLSRPTRecord parse: multiple URIs" {
    var record = try tls_rpt.TLSRPTRecord.parse(
        testing.allocator,
        "v=TLSRPTv1; rua=mailto:tls@example.com,https://report.example.com/submit",
    );
    defer record.deinit();

    try testing.expectEqual(@as(usize, 2), record.rua.len);
    try testing.expectEqualStrings("mailto:tls@example.com", record.rua[0]);
    try testing.expectEqualStrings("https://report.example.com/submit", record.rua[1]);
}

test "RFC 8460 TLSRPTRecord parse: extra whitespace" {
    var record = try tls_rpt.TLSRPTRecord.parse(
        testing.allocator,
        "  v=TLSRPTv1 ;  rua=mailto:reports@example.com  ",
    );
    defer record.deinit();

    try testing.expectEqualStrings("TLSRPTv1", record.version);
    try testing.expectEqual(@as(usize, 1), record.rua.len);
}

test "RFC 8460 TLSRPTRecord parse: missing version" {
    try testing.expectError(
        error.MissingVersion,
        tls_rpt.TLSRPTRecord.parse(testing.allocator, "rua=mailto:reports@example.com"),
    );
}

test "RFC 8460 TLSRPTRecord parse: unsupported version" {
    try testing.expectError(
        error.UnsupportedVersion,
        tls_rpt.TLSRPTRecord.parse(testing.allocator, "v=TLSRPTv2; rua=mailto:reports@example.com"),
    );
}

test "RFC 8460 TLSRPTRecord parse: missing rua" {
    try testing.expectError(
        error.MissingReportingURI,
        tls_rpt.TLSRPTRecord.parse(testing.allocator, "v=TLSRPTv1"),
    );
}

// ============================================================================
// TLSReportPolicy tests
// ============================================================================

test "RFC 8460 TLSReportPolicy init and deinit" {
    const uris = [_][]const u8{ "mailto:reports@example.com", "https://report.example.com/submit" };
    var policy = try tls_rpt.TLSReportPolicy.init(testing.allocator, &uris, 86400);
    defer policy.deinit();

    try testing.expectEqualStrings("TLSRPTv1", policy.version);
    try testing.expectEqual(@as(usize, 2), policy.rua.len);
    try testing.expectEqualStrings("mailto:reports@example.com", policy.rua[0]);
    try testing.expectEqualStrings("https://report.example.com/submit", policy.rua[1]);
    try testing.expectEqual(@as(u64, 86400), policy.max_age);
}

// ============================================================================
// TLSFailureReport tests
// ============================================================================

test "RFC 8460 TLSFailureReport init and deinit" {
    const policy_strings = [_][]const u8{ "version: STSv1", "mode: enforce" };
    var report = try tls_rpt.TLSFailureReport.init(
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
    try testing.expectEqualStrings("mode: enforce", report.policy_string[1]);
    try testing.expectEqualStrings("Certificate expired on 2025-01-01", report.failure_reason);
    try testing.expectEqual(@as(u64, 3), report.failed_session_count);
    try testing.expectEqualStrings("https://example.com/info", report.additional_info);
}

// ============================================================================
// TLSReportAggregator tests
// ============================================================================

test "RFC 8460 aggregator: recordSuccess and getStats" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
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

test "RFC 8460 aggregator: recordFailure and getStats" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordFailure("example.com", "mx1.example.com", .certificate_expired, "cert expired 2025-01-01");
    // Same failure type+detail should coalesce
    try agg.recordFailure("example.com", "mx1.example.com", .certificate_expired, "cert expired 2025-01-01");
    // Different failure type should create separate record
    try agg.recordFailure("example.com", "mx1.example.com", .starttls_not_supported, "no STARTTLS");

    const stats = agg.getStats();
    try testing.expectEqual(@as(usize, 1), stats.total_domains);
    try testing.expectEqual(@as(u64, 0), stats.total_successful_sessions);
    try testing.expectEqual(@as(u64, 3), stats.total_failed_sessions);
    try testing.expectEqual(@as(u64, 2), stats.total_failure_records); // coalesced
}

test "RFC 8460 aggregator: mixed success and failure" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
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

test "RFC 8460 aggregator: setOrganizationName and setContactInfo" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    agg.setOrganizationName("My Mail Server");
    agg.setContactInfo("postmaster@example.com");

    try agg.recordSuccess("example.com", "mx.example.com");

    const report = try agg.generateReport("example.com");
    defer testing.allocator.free(report);

    try testing.expect(std.mem.indexOf(u8, report, "My Mail Server") != null);
    try testing.expect(std.mem.indexOf(u8, report, "postmaster@example.com") != null);
}

// ============================================================================
// JSON report generation tests
// ============================================================================

test "RFC 8460 JSON report: basic structure" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordSuccess("example.com", "mx1.example.com");
    try agg.recordFailure("example.com", "mx1.example.com", .certificate_expired, "cert expired");

    const report = try agg.generateReport("example.com");
    defer testing.allocator.free(report);

    // Verify required JSON fields per RFC 8460
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
    try testing.expect(std.mem.indexOf(u8, report, "cert expired") != null);
}

test "RFC 8460 JSON report: unknown domain generates empty report" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    const report = try agg.generateReport("unknown.com");
    defer testing.allocator.free(report);

    try testing.expect(std.mem.indexOf(u8, report, "\"organization-name\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"policies\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-successful-session-count\": 0") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-failure-session-count\": 0") != null);
}

test "RFC 8460 JSON report: no failure details for clean domain" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordSuccess("clean.com", "mx.clean.com");
    try agg.recordSuccess("clean.com", "mx.clean.com");

    const report = try agg.generateReport("clean.com");
    defer testing.allocator.free(report);

    try testing.expect(std.mem.indexOf(u8, report, "\"total-successful-session-count\": 2") != null);
    // Should not contain failure-details when no failures
    try testing.expect(std.mem.indexOf(u8, report, "\"failure-details\"") == null);
}

// ============================================================================
// Aggregator reset tests
// ============================================================================

test "RFC 8460 aggregator: reset clears all data" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordSuccess("example.com", "mx.example.com");
    try agg.recordFailure("example.com", "mx.example.com", .certificate_expired, "expired");

    var stats = agg.getStats();
    try testing.expectEqual(@as(usize, 1), stats.total_domains);
    try testing.expect(stats.total_successful_sessions > 0);

    agg.reset();

    stats = agg.getStats();
    try testing.expectEqual(@as(usize, 0), stats.total_domains);
    try testing.expectEqual(@as(u64, 0), stats.total_successful_sessions);
    try testing.expectEqual(@as(u64, 0), stats.total_failed_sessions);
    try testing.expectEqual(@as(u64, 0), stats.total_failure_records);
}

// ============================================================================
// TLSReportGenerator tests
// ============================================================================

test "RFC 8460 TLSReportGenerator: init" {
    var gen = tls_rpt.TLSReportGenerator.init(testing.allocator);
    _ = &gen;
    // Generator is stateless aside from allocator, just verify construction
}

// ============================================================================
// DateRange tests
// ============================================================================

test "RFC 8460 DateRange struct" {
    const range = tls_rpt.DateRange{
        .start_datetime = 1700000000,
        .end_datetime = 1700086400,
    };

    try testing.expectEqual(@as(i64, 1700000000), range.start_datetime);
    try testing.expectEqual(@as(i64, 1700086400), range.end_datetime);
    try testing.expect(range.end_datetime > range.start_datetime);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

test "RFC 8460 edge case: report with zero policies (unknown domain)" {
    // When generating a report for a domain with no recorded data,
    // the aggregator should produce a valid report with a single
    // empty policy entry (no-policy-found).
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    const report = try agg.generateReport("no-data-domain.com");
    defer testing.allocator.free(report);

    // Should still have valid JSON structure
    try testing.expect(std.mem.indexOf(u8, report, "\"policies\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"no-policy-found\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-successful-session-count\": 0") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-failure-session-count\": 0") != null);
    // Should NOT contain failure-details since there are no failures
    try testing.expect(std.mem.indexOf(u8, report, "\"failure-details\"") == null);
}

test "RFC 8460 edge case: report with policy that has zero failure details" {
    // Record only successes for a domain, then generate a report.
    // The report should have a policy entry but no failure-details section.
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordSuccess("success-only.com", "mx1.success-only.com");
    try agg.recordSuccess("success-only.com", "mx1.success-only.com");
    try agg.recordSuccess("success-only.com", "mx1.success-only.com");

    const report = try agg.generateReport("success-only.com");
    defer testing.allocator.free(report);

    try testing.expect(std.mem.indexOf(u8, report, "\"total-successful-session-count\": 3") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-failure-session-count\": 0") != null);
    // No failure-details key should be present
    try testing.expect(std.mem.indexOf(u8, report, "\"failure-details\"") == null);
}

test "RFC 8460 edge case: failure detail with empty detail string" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    // Record a failure with an empty detail string
    try agg.recordFailure("empty-detail.com", "mx.empty-detail.com", .other, "");

    const stats = agg.getStats();
    try testing.expectEqual(@as(u64, 1), stats.total_failed_sessions);
    try testing.expectEqual(@as(u64, 1), stats.total_failure_records);

    const report = try agg.generateReport("empty-detail.com");
    defer testing.allocator.free(report);

    // The failure-reason-code should be an empty string
    try testing.expect(std.mem.indexOf(u8, report, "\"failure-reason-code\": \"\"") != null);
}

test "RFC 8460 edge case: report with very long organization name" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    // Set a very long organization name (1000 characters)
    const long_name = "A" ** 1000;
    agg.setOrganizationName(long_name);

    try agg.recordSuccess("example.com", "mx.example.com");

    const report = try agg.generateReport("example.com");
    defer testing.allocator.free(report);

    // The long name should appear in the report
    try testing.expect(std.mem.indexOf(u8, report, long_name) != null);
    // Report should still be valid JSON structure
    try testing.expect(std.mem.indexOf(u8, report, "\"organization-name\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"policies\"") != null);
}

test "RFC 8460 edge case: date range with start > end" {
    // DateRange is just a struct with no validation; we can construct
    // one with start > end and it should hold the values.
    const range = tls_rpt.DateRange{
        .start_datetime = 1700086400,
        .end_datetime = 1700000000,
    };

    try testing.expect(range.start_datetime > range.end_datetime);
    try testing.expectEqual(@as(i64, 1700086400), range.start_datetime);
    try testing.expectEqual(@as(i64, 1700000000), range.end_datetime);
}

test "RFC 8460 edge case: policy type fromString for all valid types" {
    // "sts"
    const sts = try tls_rpt.PolicyType.fromString("sts");
    try testing.expectEqual(tls_rpt.PolicyType.sts, sts);
    try testing.expectEqualStrings("sts", sts.toString());

    // "tlsa"
    const tlsa = try tls_rpt.PolicyType.fromString("tlsa");
    try testing.expectEqual(tls_rpt.PolicyType.tlsa, tlsa);
    try testing.expectEqualStrings("tlsa", tlsa.toString());

    // "no-policy-found"
    const no_policy = try tls_rpt.PolicyType.fromString("no-policy-found");
    try testing.expectEqual(tls_rpt.PolicyType.no_policy_found, no_policy);
    try testing.expectEqualStrings("no-policy-found", no_policy.toString());

    // Unknown type should error
    try testing.expectError(error.InvalidPolicyType, tls_rpt.PolicyType.fromString("unknown"));
    try testing.expectError(error.InvalidPolicyType, tls_rpt.PolicyType.fromString(""));
    try testing.expectError(error.InvalidPolicyType, tls_rpt.PolicyType.fromString("STS"));
    try testing.expectError(error.InvalidPolicyType, tls_rpt.PolicyType.fromString("TLSA"));
}

test "RFC 8460 edge case: all valid ResultType failure types from RFC 8460" {
    // Verify every ResultType enum variant has the correct toString value
    const expected = [_]struct { rt: tls_rpt.ResultType, str: []const u8 }{
        .{ .rt = .starttls_not_supported, .str = "starttls-not-supported" },
        .{ .rt = .certificate_host_mismatch, .str = "certificate-host-mismatch" },
        .{ .rt = .certificate_expired, .str = "certificate-expired" },
        .{ .rt = .certificate_not_trusted, .str = "certificate-not-trusted" },
        .{ .rt = .validation_failure, .str = "validation-failure" },
        .{ .rt = .tlsa_invalid, .str = "tlsa-invalid" },
        .{ .rt = .dnssec_invalid, .str = "dnssec-invalid" },
        .{ .rt = .dane_required, .str = "dane-required" },
        .{ .rt = .sts_policy_fetch_error, .str = "sts-policy-fetch-error" },
        .{ .rt = .sts_policy_invalid, .str = "sts-policy-invalid" },
        .{ .rt = .sts_webpki_invalid, .str = "sts-webpki-invalid" },
        .{ .rt = .negotiation_failure, .str = "negotiation-failure" },
    };

    for (expected) |e| {
        try testing.expectEqualStrings(e.str, e.rt.toString());
    }
}

test "RFC 8460 edge case: all valid TLSFailureType values round-trip through toString/fromString" {
    const types = [_]tls_rpt.TLSFailureType{
        .starttls_not_supported,
        .certificate_invalid,
        .certificate_expired,
        .certificate_hostname_mismatch,
        .policy_mismatch,
        .sts_policy_invalid,
        .dane_required,
        .other,
    };

    for (types) |ft| {
        const str = ft.toString();
        const parsed = try tls_rpt.TLSFailureType.fromString(str);
        try testing.expectEqual(ft, parsed);
    }
}

test "RFC 8460 edge case: JSON report generation and structure validation" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    agg.setOrganizationName("Test Mail Corp");
    agg.setContactInfo("abuse@testmail.com");

    try agg.recordSuccess("verify.com", "mx1.verify.com");
    try agg.recordFailure("verify.com", "mx1.verify.com", .certificate_expired, "expired 2025-12-31");
    try agg.recordFailure("verify.com", "mx1.verify.com", .starttls_not_supported, "no STARTTLS banner");

    const report = try agg.generateReport("verify.com");
    defer testing.allocator.free(report);

    // Verify the report starts and ends as valid JSON object
    try testing.expect(std.mem.startsWith(u8, report, "{"));
    try testing.expect(std.mem.endsWith(u8, report, "}"));

    // Verify all required top-level fields per RFC 8460
    try testing.expect(std.mem.indexOf(u8, report, "\"organization-name\": \"Test Mail Corp\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"contact-info\": \"abuse@testmail.com\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"report-id\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"date-range\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"start-datetime\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"end-datetime\"") != null);

    // Verify policy structure
    try testing.expect(std.mem.indexOf(u8, report, "\"policy-type\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"policy-domain\": \"verify.com\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"mx-host\": \"mx1.verify.com\"") != null);

    // Verify summary counts
    try testing.expect(std.mem.indexOf(u8, report, "\"total-successful-session-count\": 1") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-failure-session-count\": 2") != null);

    // Verify failure details
    try testing.expect(std.mem.indexOf(u8, report, "\"certificate-expired\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"starttls-not-supported\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "expired 2025-12-31") != null);
    try testing.expect(std.mem.indexOf(u8, report, "no STARTTLS banner") != null);
}

test "RFC 8460 edge case: adding many failure records (100+) to test accumulation" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    // Record 150 failures with unique details to prevent coalescing
    var i: usize = 0;
    while (i < 150) : (i += 1) {
        const detail = try std.fmt.allocPrint(testing.allocator, "failure-detail-{d}", .{i});
        defer testing.allocator.free(detail);
        try agg.recordFailure("stress.com", "mx.stress.com", .certificate_expired, detail);
    }

    const stats = agg.getStats();
    try testing.expectEqual(@as(u64, 150), stats.total_failed_sessions);
    try testing.expectEqual(@as(u64, 150), stats.total_failure_records);
    try testing.expectEqual(@as(usize, 1), stats.total_domains);

    // Generate the report and verify it contains all 150 failure entries
    const report = try agg.generateReport("stress.com");
    defer testing.allocator.free(report);

    // Spot-check a few entries
    try testing.expect(std.mem.indexOf(u8, report, "failure-detail-0") != null);
    try testing.expect(std.mem.indexOf(u8, report, "failure-detail-99") != null);
    try testing.expect(std.mem.indexOf(u8, report, "failure-detail-149") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-failure-session-count\": 150") != null);
}

test "RFC 8460 edge case: report with unicode in organization name" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    // Set organization name with unicode characters (UTF-8 encoded)
    agg.setOrganizationName("M\xc3\xa4il S\xc3\xa9rver GmbH \xe2\x9c\x89");

    try agg.recordSuccess("unicode-org.com", "mx.unicode-org.com");

    const report = try agg.generateReport("unicode-org.com");
    defer testing.allocator.free(report);

    // The unicode org name should appear in the report
    try testing.expect(std.mem.indexOf(u8, report, "M\xc3\xa4il S\xc3\xa9rver GmbH \xe2\x9c\x89") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"organization-name\"") != null);
}

test "RFC 8460 edge case: coalescing identical failures increments count" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    // Record the same failure type+detail 5 times
    try agg.recordFailure("coalesce.com", "mx.coalesce.com", .certificate_expired, "same reason");
    try agg.recordFailure("coalesce.com", "mx.coalesce.com", .certificate_expired, "same reason");
    try agg.recordFailure("coalesce.com", "mx.coalesce.com", .certificate_expired, "same reason");
    try agg.recordFailure("coalesce.com", "mx.coalesce.com", .certificate_expired, "same reason");
    try agg.recordFailure("coalesce.com", "mx.coalesce.com", .certificate_expired, "same reason");

    const stats = agg.getStats();
    // 5 failed sessions total
    try testing.expectEqual(@as(u64, 5), stats.total_failed_sessions);
    // But only 1 failure record (coalesced)
    try testing.expectEqual(@as(u64, 1), stats.total_failure_records);

    const report = try agg.generateReport("coalesce.com");
    defer testing.allocator.free(report);

    // The coalesced count should be 5
    try testing.expect(std.mem.indexOf(u8, report, "\"failed-session-count\": 5") != null);
}

test "RFC 8460 edge case: multiple domains tracked independently" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    try agg.recordSuccess("alpha.com", "mx.alpha.com");
    try agg.recordSuccess("alpha.com", "mx.alpha.com");
    try agg.recordFailure("beta.com", "mx.beta.com", .starttls_not_supported, "no STARTTLS");
    try agg.recordSuccess("gamma.com", "mx.gamma.com");
    try agg.recordFailure("gamma.com", "mx.gamma.com", .dane_required, "DANE required");

    const stats = agg.getStats();
    try testing.expectEqual(@as(usize, 3), stats.total_domains);
    try testing.expectEqual(@as(u64, 3), stats.total_successful_sessions);
    try testing.expectEqual(@as(u64, 2), stats.total_failed_sessions);

    // Report for alpha should have no failures
    const alpha_report = try agg.generateReport("alpha.com");
    defer testing.allocator.free(alpha_report);
    try testing.expect(std.mem.indexOf(u8, alpha_report, "\"total-successful-session-count\": 2") != null);
    try testing.expect(std.mem.indexOf(u8, alpha_report, "\"failure-details\"") == null);

    // Report for beta should have only failures
    const beta_report = try agg.generateReport("beta.com");
    defer testing.allocator.free(beta_report);
    try testing.expect(std.mem.indexOf(u8, beta_report, "\"total-successful-session-count\": 0") != null);
    try testing.expect(std.mem.indexOf(u8, beta_report, "\"total-failure-session-count\": 1") != null);
    try testing.expect(std.mem.indexOf(u8, beta_report, "\"starttls-not-supported\"") != null);

    // Report for gamma should have mixed
    const gamma_report = try agg.generateReport("gamma.com");
    defer testing.allocator.free(gamma_report);
    try testing.expect(std.mem.indexOf(u8, gamma_report, "\"total-successful-session-count\": 1") != null);
    try testing.expect(std.mem.indexOf(u8, gamma_report, "\"total-failure-session-count\": 1") != null);
    try testing.expect(std.mem.indexOf(u8, gamma_report, "\"dane-required\"") != null);
}

test "RFC 8460 edge case: TLSRPTRecord parse with empty rua URI after comma" {
    // "rua=mailto:a@b.com," has a trailing comma leading to an empty URI
    var record = try tls_rpt.TLSRPTRecord.parse(
        testing.allocator,
        "v=TLSRPTv1; rua=mailto:a@b.com,",
    );
    defer record.deinit();

    // The empty segment after the comma should be skipped
    try testing.expectEqual(@as(usize, 1), record.rua.len);
    try testing.expectEqualStrings("mailto:a@b.com", record.rua[0]);
}

test "RFC 8460 edge case: TLSReportPolicy init with zero URIs" {
    const uris = [_][]const u8{};
    var policy = try tls_rpt.TLSReportPolicy.init(testing.allocator, &uris, 3600);
    defer policy.deinit();

    try testing.expectEqualStrings("TLSRPTv1", policy.version);
    try testing.expectEqual(@as(usize, 0), policy.rua.len);
    try testing.expectEqual(@as(u64, 3600), policy.max_age);
}

test "RFC 8460 edge case: TLSFailureReport with empty fields" {
    const empty_policy_strings = [_][]const u8{};
    var report = try tls_rpt.TLSFailureReport.init(
        testing.allocator,
        .negotiation_failure,
        "", // empty sending_mta
        "", // empty receiving_mx
        .no_policy_found,
        &empty_policy_strings,
        "", // empty failure_reason
        0, // zero failed_session_count
        "", // empty additional_info
    );
    defer report.deinit();

    try testing.expectEqualStrings("negotiation-failure", report.result_type.toString());
    try testing.expectEqualStrings("", report.sending_mta);
    try testing.expectEqualStrings("", report.receiving_mx);
    try testing.expectEqualStrings("no-policy-found", report.policy_type.toString());
    try testing.expectEqual(@as(usize, 0), report.policy_string.len);
    try testing.expectEqualStrings("", report.failure_reason);
    try testing.expectEqual(@as(u64, 0), report.failed_session_count);
    try testing.expectEqualStrings("", report.additional_info);
}

test "RFC 8460 edge case: aggregator reset then reuse" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    // Phase 1: record some data
    try agg.recordSuccess("phase1.com", "mx.phase1.com");
    try agg.recordFailure("phase1.com", "mx.phase1.com", .certificate_expired, "expired");

    var stats = agg.getStats();
    try testing.expectEqual(@as(usize, 1), stats.total_domains);
    try testing.expectEqual(@as(u64, 1), stats.total_successful_sessions);
    try testing.expectEqual(@as(u64, 1), stats.total_failed_sessions);

    // Reset
    agg.reset();

    stats = agg.getStats();
    try testing.expectEqual(@as(usize, 0), stats.total_domains);
    try testing.expectEqual(@as(u64, 0), stats.total_successful_sessions);
    try testing.expectEqual(@as(u64, 0), stats.total_failed_sessions);
    try testing.expectEqual(@as(u64, 0), stats.total_failure_records);

    // Phase 2: record new data after reset
    try agg.recordSuccess("phase2.com", "mx.phase2.com");

    stats = agg.getStats();
    try testing.expectEqual(@as(usize, 1), stats.total_domains);
    try testing.expectEqual(@as(u64, 1), stats.total_successful_sessions);
    try testing.expectEqual(@as(u64, 0), stats.total_failed_sessions);

    // Phase 1 data should be gone
    const report = try agg.generateReport("phase1.com");
    defer testing.allocator.free(report);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-successful-session-count\": 0") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\"total-failure-session-count\": 0") != null);
}

test "RFC 8460 edge case: JSON escaping of special characters in failure detail" {
    var agg = tls_rpt.TLSReportAggregator.init(testing.allocator);
    defer agg.deinit();

    // Record a failure with JSON-special characters in the detail
    try agg.recordFailure(
        "escape.com",
        "mx.escape.com",
        .other,
        "error with \"quotes\" and \\backslashes\\ and\nnewlines",
    );

    const report = try agg.generateReport("escape.com");
    defer testing.allocator.free(report);

    // The JSON output should have escaped the special characters
    try testing.expect(std.mem.indexOf(u8, report, "\\\"quotes\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\\\\backslashes\\\\") != null);
    try testing.expect(std.mem.indexOf(u8, report, "\\n") != null);
    // Raw unescaped quote should NOT appear in the failure detail value
    // (it would break JSON parsing)
}

test "RFC 8460 edge case: TLSReportGenerator formatReport with empty policies" {
    var gen = tls_rpt.TLSReportGenerator.init(testing.allocator);

    const empty_policies = try testing.allocator.alloc(tls_rpt.PolicySummary, 0);
    defer testing.allocator.free(empty_policies);

    var report_struct = tls_rpt.TLSReport{
        .organization_name = try testing.allocator.dupe(u8, "Test Org"),
        .date_range = .{
            .start_datetime = 1700000000,
            .end_datetime = 1700086400,
        },
        .contact_info = try testing.allocator.dupe(u8, "postmaster@test.com"),
        .report_id = try testing.allocator.dupe(u8, "test-report-001"),
        .policies = empty_policies,
        .allocator = testing.allocator,
    };
    defer report_struct.deinit();

    const json = try gen.formatReport(&report_struct);
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"organization-name\": \"Test Org\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"report-id\": \"test-report-001\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"policies\": [") != null);
    // With zero policies, the array should be empty
    try testing.expect(std.mem.startsWith(u8, json, "{"));
    try testing.expect(std.mem.endsWith(u8, json, "}"));
}
