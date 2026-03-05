const std = @import("std");

/// Global constants for SMTP server
/// This module centralizes all magic numbers and buffer sizes used throughout the codebase
/// to improve maintainability and consistency.
/// Buffer sizes for I/O operations
pub const BufferSizes = struct {
    /// Small buffer for short strings (e.g., status codes, short messages)
    pub const SMALL = 256;

    /// Medium buffer for commands and responses
    pub const MEDIUM = 1024;

    /// Large buffer for reading email data
    pub const LARGE = 8192;

    /// Extra large buffer for message content
    pub const XLARGE = 65536;

    /// Maximum size for temporary buffers
    pub const MAX = 1024 * 1024; // 1MB
};

/// SMTP Protocol Limits (RFC 5321)
pub const SMTPLimits = struct {
    /// Maximum length of a command line
    pub const MAX_COMMAND_LENGTH = 512;

    /// Maximum length of a reply line
    pub const MAX_REPLY_LENGTH = 512;

    /// Maximum length of a path (e.g., MAIL FROM, RCPT TO)
    pub const MAX_PATH_LENGTH = 256;

    /// Maximum number of recipients per message
    pub const MAX_RECIPIENTS = 100;

    /// Maximum message size (default: 10MB)
    pub const MAX_MESSAGE_SIZE = 10 * 1024 * 1024;

    /// Maximum length of a domain name
    pub const MAX_DOMAIN_LENGTH = 255;

    /// Maximum length of a local part (before @)
    pub const MAX_LOCAL_PART_LENGTH = 64;

    /// Maximum length of complete email address
    pub const MAX_EMAIL_LENGTH = 320;
};

/// RFC 5322 Email Message Limits
pub const EmailLimits = struct {
    /// Maximum line length in message (hard limit)
    pub const MAX_LINE_LENGTH = 998;

    /// Recommended line length
    pub const RECOMMENDED_LINE_LENGTH = 78;

    /// Maximum header line length
    pub const MAX_HEADER_LENGTH = 998;

    /// Maximum number of headers
    pub const MAX_HEADERS = 100;
};

/// MIME Limits (RFC 2046)
pub const MIMELimits = struct {
    /// Maximum MIME nesting depth
    pub const MAX_DEPTH = 10;

    /// Maximum boundary string length
    pub const MAX_BOUNDARY_LENGTH = 70;

    /// Maximum number of MIME parts
    pub const MAX_PARTS = 100;

    /// Maximum attachment size (default: 25MB)
    pub const MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024;
};

/// Connection and Rate Limiting
pub const ConnectionLimits = struct {
    /// Maximum concurrent connections
    pub const MAX_CONNECTIONS = 1000;

    /// Maximum connections per IP
    pub const MAX_PER_IP = 10;

    /// Connection timeout (seconds)
    pub const TIMEOUT_SECONDS = 300;

    /// Command timeout (seconds)
    pub const COMMAND_TIMEOUT = 60;

    /// DATA command timeout (seconds)
    pub const DATA_TIMEOUT = 600;

    /// Rate limit window (seconds)
    pub const RATE_LIMIT_WINDOW = 60;

    /// Maximum requests per window
    pub const MAX_REQUESTS_PER_WINDOW = 100;
};

/// Database Limits
pub const DatabaseLimits = struct {
    /// Maximum query length
    pub const MAX_QUERY_LENGTH = 4096;

    /// Maximum number of parameters
    pub const MAX_PARAMETERS = 50;

    /// Connection pool size
    pub const POOL_SIZE = 10;

    /// Maximum idle connections
    pub const MAX_IDLE = 5;
};

/// Queue Limits
pub const QueueLimits = struct {
    /// Maximum queue size
    pub const MAX_SIZE = 10000;

    /// Maximum retry attempts
    pub const MAX_RETRIES = 5;

    /// Initial retry delay (seconds)
    pub const INITIAL_RETRY_DELAY = 60;

    /// Maximum retry delay (seconds)
    pub const MAX_RETRY_DELAY = 86400; // 24 hours
};

/// Storage Limits
pub const StorageLimits = struct {
    /// Maximum number of messages per folder
    pub const MAX_MESSAGES_PER_FOLDER = 10000;

    /// Maximum folder name length
    pub const MAX_FOLDER_NAME = 255;

    /// Maximum storage quota per user (default: 1GB)
    pub const DEFAULT_QUOTA = 1024 * 1024 * 1024;
};

/// TLS/Security Limits
pub const SecurityLimits = struct {
    /// Minimum TLS version
    pub const MIN_TLS_VERSION = "1.2";

    /// Certificate expiry warning (days)
    pub const CERT_EXPIRY_WARNING_DAYS = 30;

    /// Maximum password length
    pub const MAX_PASSWORD_LENGTH = 128;

    /// Minimum password length
    pub const MIN_PASSWORD_LENGTH = 8;

    /// Maximum authentication failures before ban
    pub const MAX_AUTH_FAILURES = 5;
};

/// Logging and Monitoring
pub const LoggingLimits = struct {
    /// Maximum log line length
    pub const MAX_LOG_LINE = 8192;

    /// Maximum log file size (bytes)
    pub const MAX_LOG_FILE_SIZE = 100 * 1024 * 1024; // 100MB

    /// Maximum number of log files
    pub const MAX_LOG_FILES = 10;
};

/// API Limits
pub const APILimits = struct {
    /// Maximum JSON payload size
    pub const MAX_JSON_SIZE = 1024 * 1024; // 1MB

    /// Maximum API request rate per minute
    pub const MAX_REQUESTS_PER_MINUTE = 60;

    /// Maximum response size
    pub const MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10MB
};

/// Cluster Limits
pub const ClusterLimits = struct {
    /// Maximum number of cluster nodes
    pub const MAX_NODES = 100;

    /// Heartbeat interval (seconds)
    pub const HEARTBEAT_INTERVAL = 5;

    /// Node timeout (seconds)
    pub const NODE_TIMEOUT = 30;

    /// Maximum message queue size
    pub const MAX_MESSAGE_QUEUE = 1000;
};

/// Utility functions for working with limits
pub const Utils = struct {
    /// Check if a size is within a limit
    pub fn isWithinLimit(size: usize, limit: usize) bool {
        return size <= limit;
    }

    /// Calculate percentage of limit used
    pub fn percentageUsed(used: usize, limit: usize) f64 {
        if (limit == 0) return 100.0;
        return @as(f64, @floatFromInt(used)) / @as(f64, @floatFromInt(limit)) * 100.0;
    }

    /// Check if size is approaching limit (>80%)
    pub fn isApproachingLimit(used: usize, limit: usize) bool {
        return percentageUsed(used, limit) > 80.0;
    }

    /// Get remaining capacity
    pub fn remainingCapacity(used: usize, limit: usize) usize {
        if (used >= limit) return 0;
        return limit - used;
    }
};

// Tests
test "buffer size constants" {
    const testing = std.testing;

    try testing.expect(BufferSizes.SMALL < BufferSizes.MEDIUM);
    try testing.expect(BufferSizes.MEDIUM < BufferSizes.LARGE);
    try testing.expect(BufferSizes.LARGE < BufferSizes.XLARGE);
    try testing.expect(BufferSizes.XLARGE < BufferSizes.MAX);
}

test "SMTP limits" {
    const testing = std.testing;

    try testing.expect(SMTPLimits.MAX_COMMAND_LENGTH == 512);
    try testing.expect(SMTPLimits.MAX_EMAIL_LENGTH == 320);
    try testing.expect(SMTPLimits.MAX_LOCAL_PART_LENGTH == 64);
    try testing.expect(SMTPLimits.MAX_DOMAIN_LENGTH == 255);
}

test "utility functions" {
    const testing = std.testing;

    try testing.expect(Utils.isWithinLimit(50, 100));
    try testing.expect(!Utils.isWithinLimit(150, 100));

    const pct = Utils.percentageUsed(50, 100);
    try testing.expectApproxEqAbs(50.0, pct, 0.01);

    try testing.expect(!Utils.isApproachingLimit(70, 100));
    try testing.expect(Utils.isApproachingLimit(85, 100));

    try testing.expectEqual(@as(usize, 30), Utils.remainingCapacity(70, 100));
    try testing.expectEqual(@as(usize, 0), Utils.remainingCapacity(150, 100));
}
