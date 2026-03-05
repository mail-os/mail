const std = @import("std");

/// SMTP-specific errors
pub const SmtpError = error{
    // Protocol errors
    InvalidCommand,
    InvalidSequence,
    SyntaxError,
    ParameterError,

    // Authentication errors
    AuthenticationFailed,
    AuthenticationRequired,

    // Message errors
    MessageTooLarge,
    TooManyRecipients,
    InvalidEmailAddress,
    InvalidSender,
    InvalidRecipient,

    // Connection errors
    ConnectionTimeout,
    ConnectionClosed,
    TooManyConnections,
    RateLimitExceeded,

    // TLS errors
    TlsNotAvailable,
    TlsRequired,

    // Server errors
    TemporaryFailure,
    PermanentFailure,
    ServiceUnavailable,

    // Storage errors
    StorageFailure,
    DiskFull,
};

/// Combined error set for the entire SMTP server
pub const ServerError = SmtpError || std.mem.Allocator.Error || std.Io.File.OpenError || std.Io.File.WritePositionalError || error{
    EndOfStream,
    LineTooLong,
    OutOfMemory,
    AccessDenied,
    FileNotFound,
    InvalidFormat,
};

/// Error information for logging and responses
pub const ErrorInfo = struct {
    code: u16,
    message: []const u8,
    log_level: enum { debug, info, warn, err, critical },
};

/// Get SMTP response code and message for an error
pub fn getErrorInfo(err: anyerror) ErrorInfo {
    return switch (err) {
        // Syntax errors (500-series)
        SmtpError.InvalidCommand => .{ .code = 500, .message = "Syntax error, command unrecognized", .log_level = .debug },
        SmtpError.SyntaxError => .{ .code = 501, .message = "Syntax error in parameters or arguments", .log_level = .debug },
        SmtpError.ParameterError => .{ .code = 501, .message = "Invalid parameter", .log_level = .debug },

        // Sequence errors
        SmtpError.InvalidSequence => .{ .code = 503, .message = "Bad sequence of commands", .log_level = .debug },
        SmtpError.AuthenticationRequired => .{ .code = 530, .message = "Authentication required", .log_level = .info },

        // Authentication errors
        SmtpError.AuthenticationFailed => .{ .code = 535, .message = "Authentication failed", .log_level = .warn },

        // Message errors
        SmtpError.MessageTooLarge => .{ .code = 552, .message = "Message size exceeds maximum allowed", .log_level = .info },
        SmtpError.TooManyRecipients => .{ .code = 452, .message = "Too many recipients", .log_level = .info },
        SmtpError.InvalidEmailAddress => .{ .code = 553, .message = "Invalid email address", .log_level = .debug },
        SmtpError.InvalidSender => .{ .code = 553, .message = "Invalid sender address", .log_level = .debug },
        SmtpError.InvalidRecipient => .{ .code = 550, .message = "Invalid recipient address", .log_level = .debug },

        // Connection errors
        SmtpError.ConnectionTimeout => .{ .code = 421, .message = "Connection timeout", .log_level = .info },
        SmtpError.ConnectionClosed => .{ .code = 421, .message = "Connection closed", .log_level = .info },
        SmtpError.TooManyConnections => .{ .code = 421, .message = "Too many connections, try again later", .log_level = .warn },
        SmtpError.RateLimitExceeded => .{ .code = 450, .message = "Rate limit exceeded, try again later", .log_level = .warn },

        // TLS errors
        SmtpError.TlsNotAvailable => .{ .code = 454, .message = "TLS not available", .log_level = .debug },
        SmtpError.TlsRequired => .{ .code = 530, .message = "Must issue STARTTLS first", .log_level = .info },

        // Storage errors
        SmtpError.StorageFailure => .{ .code = 452, .message = "Insufficient system storage", .log_level = .err },
        SmtpError.DiskFull => .{ .code = 452, .message = "Insufficient system storage", .log_level = .critical },

        // Server errors
        SmtpError.TemporaryFailure => .{ .code = 451, .message = "Requested action aborted: local error in processing", .log_level = .err },
        SmtpError.PermanentFailure => .{ .code = 554, .message = "Transaction failed", .log_level = .err },
        SmtpError.ServiceUnavailable => .{ .code = 421, .message = "Service not available", .log_level = .critical },

        // Generic errors
        error.OutOfMemory => .{ .code = 451, .message = "Insufficient system resources", .log_level = .critical },
        error.AccessDenied => .{ .code = 550, .message = "Access denied", .log_level = .warn },
        error.EndOfStream => .{ .code = 451, .message = "Connection lost", .log_level = .info },

        else => .{ .code = 451, .message = "Internal server error", .log_level = .err },
    };
}

/// Format error for SMTP response
pub fn formatSmtpError(err: anyerror, buf: []u8) ![]const u8 {
    const info = getErrorInfo(err);
    return std.fmt.bufPrint(buf, "{d} {s}\r\n", .{ info.code, info.message });
}

/// Check if error is temporary (client should retry)
pub fn isTemporary(err: anyerror) bool {
    const info = getErrorInfo(err);
    return info.code >= 400 and info.code < 500;
}

/// Check if error is permanent (client should not retry)
pub fn isPermanent(err: anyerror) bool {
    const info = getErrorInfo(err);
    return info.code >= 500 and info.code < 600;
}
