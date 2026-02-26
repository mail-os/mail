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
