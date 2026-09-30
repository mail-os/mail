const std = @import("std");
const email_validator = @import("email_validator");

/// Fuzzing harness for SMTP protocol parsing
/// This file contains fuzz targets for testing protocol robustness against malformed input
///
/// Usage:
///   zig build-exe tests/fuzz_smtp_protocol.zig -fsanitize=fuzzer
///   ./fuzz_smtp_protocol corpus_dir/
///
/// Or with AFL:
///   afl-fuzz -i corpus_in -o corpus_out -- ./fuzz_smtp_protocol @@

/// Fuzz target for SMTP command parsing
export fn LLVMFuzzerTestOneInput(data_ptr: [*]const u8, size: usize) callconv(.C) c_int {
    const data = data_ptr[0..size];

    // Skip empty inputs
    if (size == 0) return 0;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test SMTP command parsing with fuzzy input
    fuzzSmtpCommand(allocator, data) catch {};

    // Test email address validation with fuzzy input
    fuzzEmailValidation(data) catch {};

    // Test MAIL FROM parsing
    fuzzMailFrom(allocator, data) catch {};

    // Test RCPT TO parsing
    fuzzRcptTo(allocator, data) catch {};

    return 0;
}

/// Fuzz SMTP command parsing
fn fuzzSmtpCommand(allocator: std.mem.Allocator, data: []const u8) !void {
    _ = allocator;

    // Try to parse as SMTP command
    // This should handle any malformed input gracefully
    if (std.mem.indexOf(u8, data, "\r\n")) |_| {
        var lines = std.mem.split(u8, data, "\r\n");
        while (lines.next()) |line| {
            if (line.len == 0) continue;

            // Extract command (first word)
            var parts = std.mem.split(u8, line, " ");
            const cmd = parts.next() orelse continue;

            // Validate command doesn't crash on weird input
            _ = std.ascii.eqlIgnoreCase(cmd, "HELO");
            _ = std.ascii.eqlIgnoreCase(cmd, "EHLO");
            _ = std.ascii.eqlIgnoreCase(cmd, "MAIL");
            _ = std.ascii.eqlIgnoreCase(cmd, "RCPT");
            _ = std.ascii.eqlIgnoreCase(cmd, "DATA");
            _ = std.ascii.eqlIgnoreCase(cmd, "QUIT");
        }
    }
}

/// Fuzz email address validation
fn fuzzEmailValidation(data: []const u8) !void {
    // Try to validate as email address
    // Should handle malformed emails gracefully
    _ = email_validator.validateEmail(data);
}

/// Fuzz MAIL FROM parsing
fn fuzzMailFrom(allocator: std.mem.Allocator, data: []const u8) !void {
    // Try to parse MAIL FROM with various malformed inputs
    if (std.mem.startsWith(u8, data, "MAIL FROM:")) {
        const rest = data[10..];

        // Extract email from angle brackets
        if (std.mem.indexOf(u8, rest, "<")) |start| {
            if (std.mem.indexOf(u8, rest[start..], ">")) |end_offset| {
                const email = rest[start + 1 .. start + end_offset];

                // Validate extracted email
                _ = email_validator.validateEmail(email);

                // Test normalization
                const normalized = email_validator.normalizeEmail(allocator, email) catch return;
                defer allocator.free(normalized);
            }
        }
    }
}

/// Fuzz RCPT TO parsing
fn fuzzRcptTo(allocator: std.mem.Allocator, data: []const u8) !void {
    // Try to parse RCPT TO with various malformed inputs
    if (std.mem.startsWith(u8, data, "RCPT TO:")) {
        const rest = data[8..];

        // Extract email from angle brackets
        if (std.mem.indexOf(u8, rest, "<")) |start| {
            if (std.mem.indexOf(u8, rest[start..], ">")) |end_offset| {
                const email = rest[start + 1 .. start + end_offset];

                // Validate extracted email
                _ = email_validator.validateEmail(email);

                // Test domain extraction
                const domain = email_validator.extractDomain(email) catch return;
                _ = domain;
            }
        }
    }
}

// Unit tests for fuzz harness (verify it compiles and runs)
test "fuzz harness smoke test" {
    const testing = std.testing;

    // Test with valid SMTP commands
    const valid_commands =
        \\HELO example.com
        \\MAIL FROM:<sender@example.com>
        \\RCPT TO:<recipient@example.com>
        \\DATA
        \\QUIT
    ;

    try fuzzSmtpCommand(testing.allocator, valid_commands);

    // Test with malformed input (should not crash)
    const malformed =
        \\HELO
        \\MAIL FROM:<
        \\RCPT TO:invalid
        \\\x00\x01\xFF
    ;

    try fuzzSmtpCommand(testing.allocator, malformed);
}

test "fuzz email validation" {
    // Valid emails should pass
    try fuzzEmailValidation("user@example.com");

    // Invalid emails should not crash
    try fuzzEmailValidation("");
    try fuzzEmailValidation("@");
    try fuzzEmailValidation("user@@example.com");
    try fuzzEmailValidation("user@");
    try fuzzEmailValidation("@example.com");
    try fuzzEmailValidation("\x00\xFF");
}

test "fuzz MAIL FROM parsing" {
    const testing = std.testing;

    // Valid MAIL FROM
    try fuzzMailFrom(testing.allocator, "MAIL FROM:<user@example.com>");

    // Malformed MAIL FROM (should not crash)
    try fuzzMailFrom(testing.allocator, "MAIL FROM:");
    try fuzzMailFrom(testing.allocator, "MAIL FROM:<");
    try fuzzMailFrom(testing.allocator, "MAIL FROM:<user@>");
    try fuzzMailFrom(testing.allocator, "MAIL FROM:<@example.com>");
}

test "fuzz RCPT TO parsing" {
    const testing = std.testing;

    // Valid RCPT TO
    try fuzzRcptTo(testing.allocator, "RCPT TO:<user@example.com>");

    // Malformed RCPT TO (should not crash)
    try fuzzRcptTo(testing.allocator, "RCPT TO:");
    try fuzzRcptTo(testing.allocator, "RCPT TO:<");
    try fuzzRcptTo(testing.allocator, "RCPT TO:<user@>");
}
