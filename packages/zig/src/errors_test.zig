const std = @import("std");
const testing = std.testing;
const errors = @import("core/errors.zig");

test "error info - message too large" {
    const err_info = errors.getErrorInfo(errors.SmtpError.MessageTooLarge);
    try testing.expectEqual(@as(u16, 552), err_info.code);
    try testing.expect(std.mem.indexOf(u8, err_info.message, "size") != null);
}

test "error info - too many recipients" {
    const err_info = errors.getErrorInfo(errors.SmtpError.TooManyRecipients);
    try testing.expectEqual(@as(u16, 452), err_info.code);
    try testing.expect(std.mem.indexOf(u8, err_info.message, "recipients") != null);
}

test "error info - rate limit exceeded" {
    const err_info = errors.getErrorInfo(errors.SmtpError.RateLimitExceeded);
    try testing.expectEqual(@as(u16, 450), err_info.code);
    try testing.expect(std.mem.indexOf(u8, err_info.message, "Rate limit") != null);
}

test "error info - invalid command" {
    const err_info = errors.getErrorInfo(errors.SmtpError.InvalidCommand);
    try testing.expectEqual(@as(u16, 500), err_info.code);
    try testing.expect(std.mem.indexOf(u8, err_info.message, "Syntax error") != null);
}

test "error info - invalid sequence" {
    const err_info = errors.getErrorInfo(errors.SmtpError.InvalidSequence);
    try testing.expectEqual(@as(u16, 503), err_info.code);
    try testing.expect(std.mem.indexOf(u8, err_info.message, "sequence") != null);
}

test "error info - authentication failed" {
    const err_info = errors.getErrorInfo(errors.SmtpError.AuthenticationFailed);
    try testing.expectEqual(@as(u16, 535), err_info.code);
    try testing.expect(std.mem.indexOf(u8, err_info.message, "Authentication") != null);
}

test "error info - invalid recipient" {
    const err_info = errors.getErrorInfo(errors.SmtpError.InvalidRecipient);
    try testing.expectEqual(@as(u16, 550), err_info.code);
    try testing.expect(std.mem.indexOf(u8, err_info.message, "address") != null);
}

test "error info - storage failure" {
    const err_info = errors.getErrorInfo(errors.SmtpError.StorageFailure);
    try testing.expect(err_info.code >= 400);
    try testing.expect(err_info.code < 500);
    try testing.expect(std.mem.indexOf(u8, err_info.message, "storage") != null or std.mem.indexOf(u8, err_info.message, "Storage") != null);
}

test "error codes are valid SMTP codes" {
    // Test that all error codes are valid SMTP response codes
    const test_errors = [_]anyerror{
        errors.SmtpError.InvalidCommand,
        errors.SmtpError.InvalidSequence,
        errors.SmtpError.MessageTooLarge,
        errors.SmtpError.TooManyRecipients,
        errors.SmtpError.RateLimitExceeded,
        errors.SmtpError.AuthenticationFailed,
        errors.SmtpError.InvalidRecipient,
        errors.SmtpError.StorageFailure,
    };

    for (test_errors) |err| {
        const info = errors.getErrorInfo(err);
        // SMTP codes should be 3 digits: 2xx, 3xx, 4xx, 5xx
        try testing.expect(info.code >= 200);
        try testing.expect(info.code < 600);
        try testing.expect(info.message.len > 0);
    }
}
