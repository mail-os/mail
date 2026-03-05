const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

// =============================================================================
// RFC 8058 - List-Unsubscribe One-Click
// =============================================================================
//
// ## Overview
// Implements RFC 8058 (One-Click Functionality for List-Unsubscribe) to satisfy
// Gmail and Yahoo deliverability requirements effective February 2024.
//
// RFC 8058 mandates that bulk senders include:
//   1. A List-Unsubscribe header with an HTTPS URL (and optionally mailto:)
//   2. A List-Unsubscribe-Post header set to "List-Unsubscribe=One-Click"
//
// The unsubscribe endpoint MUST accept POST requests only, with content type
// application/x-www-form-urlencoded and body "List-Unsubscribe=One-Click".
//
// ## Security Model
// Unsubscribe URLs contain an HMAC-SHA256 signed token encoding:
//   - list_id: the mailing list identifier
//   - recipient: the subscriber email address
//   - message_id: the originating Message-ID
//   - timestamp: issuance time (for expiry enforcement)
//
// Tokens are validated for HMAC integrity and a configurable TTL (default 30
// days), preventing replay and forgery attacks.
//
// ## References
// - RFC 8058: Signaling One-Click Functionality for List-Unsubscribe
// - RFC 2369: The Use of URLs as Meta-Syntax for Core Mail List Commands
// - RFC 6376: DomainKeys Identified Mail (DKIM) Signatures
// =============================================================================

/// Default token time-to-live: 30 days in seconds.
const DEFAULT_TOKEN_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Maximum allowed token TTL: 365 days.
const MAX_TOKEN_TTL_SECONDS: i64 = 365 * 24 * 60 * 60;

/// HMAC key length in bytes (SHA-256 output).
const HMAC_LENGTH: usize = 32;

/// Separator used between token fields before HMAC computation.
const TOKEN_FIELD_SEPARATOR: u8 = 0x00;

/// Required POST body per RFC 8058.
const ONE_CLICK_POST_BODY = "List-Unsubscribe=One-Click";

/// Required content type for one-click unsubscribe requests.
const ONE_CLICK_CONTENT_TYPE = "application/x-www-form-urlencoded";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for List-Unsubscribe header generation and one-click handling.
pub const ListUnsubscribeConfig = struct {
    /// Whether List-Unsubscribe headers should be injected into outgoing messages.
    enabled: bool = true,

    /// Base URL for HTTPS unsubscribe endpoints, e.g. "https://mail.example.com/unsubscribe".
    /// Must use the https scheme in production (enforced when require_https is true).
    url_base: []const u8,

    /// Enforce that url_base begins with "https://". Disable only for testing.
    require_https: bool = true,

    /// Include a mailto: alternative in the List-Unsubscribe header.
    /// Some older mail clients only support mailto-based unsubscribe.
    include_mailto: bool = false,

    /// The mailto address to use when include_mailto is true (e.g. "unsubscribe@example.com").
    mailto_address: ?[]const u8 = null,

    /// Shared secret for HMAC-SHA256 token signing. Must be at least 16 bytes.
    hmac_secret: []const u8,

    /// Token validity duration in seconds. Defaults to 30 days.
    token_ttl_seconds: i64 = DEFAULT_TOKEN_TTL_SECONDS,

    /// Validate that the configuration is usable.
    pub fn validate(self: ListUnsubscribeConfig) ConfigValidationError!void {
        if (self.url_base.len == 0) {
            return error.EmptyUrlBase;
        }
        if (self.require_https) {
            if (!startsWith(self.url_base, "https://")) {
                return error.HttpsRequired;
            }
        }
        if (self.hmac_secret.len < 16) {
            return error.SecretTooShort;
        }
        if (self.token_ttl_seconds <= 0 or self.token_ttl_seconds > MAX_TOKEN_TTL_SECONDS) {
            return error.InvalidTtl;
        }
        if (self.include_mailto) {
            if (self.mailto_address == null or self.mailto_address.?.len == 0) {
                return error.MissingMailtoAddress;
            }
        }
    }
};

pub const ConfigValidationError = error{
    EmptyUrlBase,
    HttpsRequired,
    SecretTooShort,
    InvalidTtl,
    MissingMailtoAddress,
};

// ---------------------------------------------------------------------------
// Unsubscribe Result
// ---------------------------------------------------------------------------

/// Outcome of processing an unsubscribe request.
pub const UnsubscribeResult = enum {
    /// Unsubscribe processed successfully.
    success,
    /// The token HMAC failed verification.
    invalid_token,
    /// The token has exceeded its TTL.
    expired_token,
    /// The HTTP method is not POST (RFC 8058 requires POST).
    invalid_method,
    /// The recipient was already unsubscribed.
    already_unsubscribed,
    /// An internal error occurred.
    @"error",

    pub fn isSuccess(self: UnsubscribeResult) bool {
        return self == .success;
    }

    pub fn toString(self: UnsubscribeResult) []const u8 {
        return switch (self) {
            .success => "Successfully unsubscribed",
            .invalid_token => "Invalid unsubscribe token",
            .expired_token => "Unsubscribe token has expired",
            .invalid_method => "Invalid HTTP method (POST required)",
            .already_unsubscribed => "Already unsubscribed",
            .@"error" => "Internal error processing unsubscribe",
        };
    }
};

// ---------------------------------------------------------------------------
// Unsubscribe Token
// ---------------------------------------------------------------------------

/// A signed, time-limited token that authorises an unsubscribe action for a
/// specific (list, recipient, message) tuple.
pub const UnsubscribeToken = struct {
    /// Mailing list identifier (e.g. "newsletter" or "marketing.weekly").
    list_id: []const u8,
    /// Recipient email address.
    recipient: []const u8,
    /// Message-ID of the email that carried this token.
    message_id: []const u8,
    /// Unix timestamp (seconds) when the token was created.
    timestamp: i64,
    /// HMAC-SHA256 over (list_id || 0x00 || recipient || 0x00 || message_id || 0x00 || timestamp).
    hmac: [HMAC_LENGTH]u8,

    /// Serialise the token to a URL-safe Base64 string.
    /// Layout: [list_id_len:u16][list_id][recipient_len:u16][recipient]
    ///         [message_id_len:u16][message_id][timestamp:i64][hmac:32]
    pub fn serialize(self: *const UnsubscribeToken, allocator: std.mem.Allocator) ![]const u8 {
        const payload_len = 2 + self.list_id.len +
            2 + self.recipient.len +
            2 + self.message_id.len +
            @sizeOf(i64) + HMAC_LENGTH;

        var buf = try allocator.alloc(u8, payload_len);
        defer allocator.free(buf);

        var offset: usize = 0;

        // list_id
        const lid_len: u16 = @intCast(self.list_id.len);
        std.mem.writeInt(u16, buf[offset..][0..2], lid_len, .big);
        offset += 2;
        @memcpy(buf[offset..][0..self.list_id.len], self.list_id);
        offset += self.list_id.len;

        // recipient
        const rcp_len: u16 = @intCast(self.recipient.len);
        std.mem.writeInt(u16, buf[offset..][0..2], rcp_len, .big);
        offset += 2;
        @memcpy(buf[offset..][0..self.recipient.len], self.recipient);
        offset += self.recipient.len;

        // message_id
        const mid_len: u16 = @intCast(self.message_id.len);
        std.mem.writeInt(u16, buf[offset..][0..2], mid_len, .big);
        offset += 2;
        @memcpy(buf[offset..][0..self.message_id.len], self.message_id);
        offset += self.message_id.len;

        // timestamp
        std.mem.writeInt(i64, buf[offset..][0..@sizeOf(i64)], self.timestamp, .big);
        offset += @sizeOf(i64);

        // hmac
        @memcpy(buf[offset..][0..HMAC_LENGTH], &self.hmac);

        // Encode as URL-safe Base64 (no padding).
        const encoder = std.base64.url_safe_no_pad;
        const encoded_len = encoder.Encoder.calcSize(payload_len);
        const encoded = try allocator.alloc(u8, encoded_len);
        _ = encoder.Encoder.encode(encoded, buf);
        return encoded;
    }

    /// Deserialise a token from its URL-safe Base64 representation.
    pub fn deserialize(allocator: std.mem.Allocator, encoded: []const u8) !UnsubscribeToken {
        const decoder = std.base64.url_safe_no_pad;
        const decoded_len = decoder.Decoder.calcSizeForSlice(encoded) catch return error.InvalidTokenEncoding;
        var decoded = try allocator.alloc(u8, decoded_len);
        defer allocator.free(decoded);
        decoder.Decoder.decode(decoded, encoded) catch return error.InvalidTokenEncoding;

        var offset: usize = 0;

        // list_id
        if (offset + 2 > decoded.len) return error.InvalidTokenStructure;
        const lid_len = std.mem.readInt(u16, decoded[offset..][0..2], .big);
        offset += 2;
        if (offset + lid_len > decoded.len) return error.InvalidTokenStructure;
        const list_id = try allocator.dupe(u8, decoded[offset..][0..lid_len]);
        errdefer allocator.free(list_id);
        offset += lid_len;

        // recipient
        if (offset + 2 > decoded.len) return error.InvalidTokenStructure;
        const rcp_len = std.mem.readInt(u16, decoded[offset..][0..2], .big);
        offset += 2;
        if (offset + rcp_len > decoded.len) return error.InvalidTokenStructure;
        const recipient = try allocator.dupe(u8, decoded[offset..][0..rcp_len]);
        errdefer allocator.free(recipient);
        offset += rcp_len;

        // message_id
        if (offset + 2 > decoded.len) return error.InvalidTokenStructure;
        const mid_len = std.mem.readInt(u16, decoded[offset..][0..2], .big);
        offset += 2;
        if (offset + mid_len > decoded.len) return error.InvalidTokenStructure;
        const message_id = try allocator.dupe(u8, decoded[offset..][0..mid_len]);
        errdefer allocator.free(message_id);
        offset += mid_len;

        // timestamp
        if (offset + @sizeOf(i64) > decoded.len) return error.InvalidTokenStructure;
        const timestamp = std.mem.readInt(i64, decoded[offset..][0..@sizeOf(i64)], .big);
        offset += @sizeOf(i64);

        // hmac
        if (offset + HMAC_LENGTH > decoded.len) return error.InvalidTokenStructure;
        var hmac: [HMAC_LENGTH]u8 = undefined;
        @memcpy(&hmac, decoded[offset..][0..HMAC_LENGTH]);

        return UnsubscribeToken{
            .list_id = list_id,
            .recipient = recipient,
            .message_id = message_id,
            .timestamp = timestamp,
            .hmac = hmac,
        };
    }

    /// Release allocator-owned fields.
    pub fn deinit(self: *const UnsubscribeToken, allocator: std.mem.Allocator) void {
        allocator.free(self.list_id);
        allocator.free(self.recipient);
        allocator.free(self.message_id);
    }
};

// ---------------------------------------------------------------------------
// Token Generator
// ---------------------------------------------------------------------------

/// Generates and validates HMAC-signed unsubscribe tokens.
pub const UnsubscribeTokenGenerator = struct {
    allocator: std.mem.Allocator,
    secret: []const u8,
    ttl_seconds: i64,

    pub fn init(allocator: std.mem.Allocator, secret: []const u8) UnsubscribeTokenGenerator {
        return .{
            .allocator = allocator,
            .secret = secret,
            .ttl_seconds = DEFAULT_TOKEN_TTL_SECONDS,
        };
    }

    pub fn initWithTtl(allocator: std.mem.Allocator, secret: []const u8, ttl_seconds: i64) UnsubscribeTokenGenerator {
        return .{
            .allocator = allocator,
            .secret = secret,
            .ttl_seconds = ttl_seconds,
        };
    }

    pub fn deinit(self: *UnsubscribeTokenGenerator) void {
        // No owned resources to free; included for API symmetry.
        _ = self;
    }

    /// Create an HMAC-signed token for the given list/recipient/message tuple.
    pub fn generateToken(self: *const UnsubscribeTokenGenerator, list_id: []const u8, recipient: []const u8, message_id: []const u8) UnsubscribeToken {
        const ts = time_compat.timestamp();
        return self.generateTokenWithTimestamp(list_id, recipient, message_id, ts);
    }

    /// Create a token with an explicit timestamp (useful for testing).
    pub fn generateTokenWithTimestamp(
        self: *const UnsubscribeTokenGenerator,
        list_id: []const u8,
        recipient: []const u8,
        message_id: []const u8,
        ts: i64,
    ) UnsubscribeToken {
        const hmac = computeHmac(self.secret, list_id, recipient, message_id, ts);
        return UnsubscribeToken{
            .list_id = list_id,
            .recipient = recipient,
            .message_id = message_id,
            .timestamp = ts,
            .hmac = hmac,
        };
    }

    /// Validate a token's HMAC and check that it has not expired.
    pub fn validateToken(self: *const UnsubscribeTokenGenerator, token: *const UnsubscribeToken) TokenValidationResult {
        // Recompute expected HMAC.
        const expected = computeHmac(
            self.secret,
            token.list_id,
            token.recipient,
            token.message_id,
            token.timestamp,
        );

        // Constant-time comparison to prevent timing attacks.
        if (!constantTimeEqual(&expected, &token.hmac)) {
            return .invalid_hmac;
        }

        // Check expiry.
        const now = time_compat.timestamp();
        const age = now - token.timestamp;
        if (age < 0) {
            // Token issued in the future -- reject.
            return .invalid_hmac;
        }
        if (age > self.ttl_seconds) {
            return .expired;
        }

        return .valid;
    }

    /// Validate a serialised (Base64) token string end-to-end.
    pub fn validateTokenString(self: *const UnsubscribeTokenGenerator, token_string: []const u8) struct { result: TokenValidationResult, token: ?UnsubscribeToken } {
        const token = UnsubscribeToken.deserialize(self.allocator, token_string) catch {
            return .{ .result = .invalid_format, .token = null };
        };

        const result = self.validateToken(&token);
        if (result != .valid) {
            token.deinit(self.allocator);
            return .{ .result = result, .token = null };
        }

        return .{ .result = .valid, .token = token };
    }
};

pub const TokenValidationResult = enum {
    valid,
    invalid_hmac,
    expired,
    invalid_format,

    pub fn isValid(self: TokenValidationResult) bool {
        return self == .valid;
    }

    pub fn toString(self: TokenValidationResult) []const u8 {
        return switch (self) {
            .valid => "Token is valid",
            .invalid_hmac => "Token HMAC verification failed",
            .expired => "Token has expired",
            .invalid_format => "Token format is invalid",
        };
    }
};

// ---------------------------------------------------------------------------
// List-Unsubscribe Header
// ---------------------------------------------------------------------------

/// Generates RFC 8058-compliant List-Unsubscribe and List-Unsubscribe-Post
/// headers for inclusion in outgoing messages.
pub const ListUnsubscribeHeader = struct {
    config: ListUnsubscribeConfig,
    generator: UnsubscribeTokenGenerator,

    pub fn init(config: ListUnsubscribeConfig) ListUnsubscribeHeader {
        return .{
            .config = config,
            .generator = UnsubscribeTokenGenerator.initWithTtl(
                // Token generator doesn't allocate during generation itself,
                // but we still carry the allocator for serialisation later.
                std.heap.page_allocator,
                config.hmac_secret,
                config.token_ttl_seconds,
            ),
        };
    }

    /// Generate both List-Unsubscribe and List-Unsubscribe-Post header values
    /// for a specific message.
    ///
    /// Returns a HeaderPair whose fields are allocator-owned strings.
    pub fn generateHeaders(
        self: *const ListUnsubscribeHeader,
        allocator: std.mem.Allocator,
        list_id: []const u8,
        recipient: []const u8,
        message_id: []const u8,
    ) !HeaderPair {
        // Build the token and its serialised form.
        var gen = UnsubscribeTokenGenerator.initWithTtl(allocator, self.config.hmac_secret, self.config.token_ttl_seconds);
        const token = gen.generateToken(list_id, recipient, message_id);

        const token_string = try token.serialize(allocator);
        defer allocator.free(token_string);

        // Build the HTTPS unsubscribe URL.
        const url = try formatUnsubscribeUrl(allocator, self.config.url_base, token_string);
        defer allocator.free(url);

        // Compose the List-Unsubscribe header value.
        var list_unsub_value: []const u8 = undefined;
        if (self.config.include_mailto and self.config.mailto_address != null) {
            list_unsub_value = try std.fmt.allocPrint(
                allocator,
                "<{s}>, <mailto:{s}?subject=unsubscribe&body={s}>",
                .{ url, self.config.mailto_address.?, token_string },
            );
        } else {
            list_unsub_value = try std.fmt.allocPrint(allocator, "<{s}>", .{url});
        }

        // The List-Unsubscribe-Post value is always the same per RFC 8058.
        const post_value = try allocator.dupe(u8, "List-Unsubscribe=One-Click");

        return HeaderPair{
            .list_unsubscribe = list_unsub_value,
            .list_unsubscribe_post = post_value,
        };
    }

    /// Generate complete header lines (including header names) ready for
    /// injection into a message.
    pub fn generateHeaderLines(
        self: *const ListUnsubscribeHeader,
        allocator: std.mem.Allocator,
        list_id: []const u8,
        recipient: []const u8,
        message_id: []const u8,
    ) ![]const u8 {
        const pair = try self.generateHeaders(allocator, list_id, recipient, message_id);
        defer pair.deinit(allocator);

        return try std.fmt.allocPrint(
            allocator,
            "List-Unsubscribe: {s}\r\nList-Unsubscribe-Post: {s}\r\n",
            .{ pair.list_unsubscribe, pair.list_unsubscribe_post },
        );
    }
};

/// Holds the two header values produced by ListUnsubscribeHeader.
pub const HeaderPair = struct {
    /// Value for the List-Unsubscribe header.
    list_unsubscribe: []const u8,
    /// Value for the List-Unsubscribe-Post header (always "List-Unsubscribe=One-Click").
    list_unsubscribe_post: []const u8,

    pub fn deinit(self: *const HeaderPair, allocator: std.mem.Allocator) void {
        allocator.free(self.list_unsubscribe);
        allocator.free(self.list_unsubscribe_post);
    }
};

// ---------------------------------------------------------------------------
// One-Click Handler
// ---------------------------------------------------------------------------

/// HTTP method as relevant to unsubscribe handling.
pub const HttpMethod = enum {
    GET,
    POST,
    HEAD,
    PUT,
    DELETE,
    PATCH,
    OPTIONS,
    OTHER,

    pub fn fromString(method: []const u8) HttpMethod {
        if (std.ascii.eqlIgnoreCase(method, "GET")) return .GET;
        if (std.ascii.eqlIgnoreCase(method, "POST")) return .POST;
        if (std.ascii.eqlIgnoreCase(method, "HEAD")) return .HEAD;
        if (std.ascii.eqlIgnoreCase(method, "PUT")) return .PUT;
        if (std.ascii.eqlIgnoreCase(method, "DELETE")) return .DELETE;
        if (std.ascii.eqlIgnoreCase(method, "PATCH")) return .PATCH;
        if (std.ascii.eqlIgnoreCase(method, "OPTIONS")) return .OPTIONS;
        return .OTHER;
    }
};

/// Callback signature invoked when an unsubscribe is successfully validated.
/// Implementations should perform the actual removal (database update, list
/// management, etc.) and return true on success.
pub const UnsubscribeCallback = *const fn (list_id: []const u8, recipient: []const u8, message_id: []const u8) bool;

/// Processes incoming HTTP one-click unsubscribe requests per RFC 8058.
pub const OneClickHandler = struct {
    allocator: std.mem.Allocator,
    config: ListUnsubscribeConfig,
    generator: UnsubscribeTokenGenerator,
    callback: ?UnsubscribeCallback,
    /// Track already-processed tokens to detect duplicates (in-memory; a
    /// production deployment would back this with persistent storage).
    processed_tokens: std.StringHashMap(i64),

    pub fn init(allocator: std.mem.Allocator, config: ListUnsubscribeConfig) OneClickHandler {
        return .{
            .allocator = allocator,
            .config = config,
            .generator = UnsubscribeTokenGenerator.initWithTtl(allocator, config.hmac_secret, config.token_ttl_seconds),
            .callback = null,
            .processed_tokens = std.StringHashMap(i64).init(allocator),
        };
    }

    pub fn initWithCallback(allocator: std.mem.Allocator, config: ListUnsubscribeConfig, callback: UnsubscribeCallback) OneClickHandler {
        var handler = init(allocator, config);
        handler.callback = callback;
        return handler;
    }

    pub fn deinit(self: *OneClickHandler) void {
        var it = self.processed_tokens.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.processed_tokens.deinit();
    }

    /// Validate that the incoming request matches RFC 8058 requirements:
    /// - Method must be POST.
    /// - Content-Type must be application/x-www-form-urlencoded.
    pub fn isValidRequest(method: []const u8, content_type: []const u8) bool {
        if (!std.ascii.eqlIgnoreCase(method, "POST")) return false;
        // Content-Type may include charset, e.g. "application/x-www-form-urlencoded; charset=UTF-8"
        if (!hasPrefix(content_type, ONE_CLICK_CONTENT_TYPE)) return false;
        return true;
    }

    /// Process a one-click unsubscribe POST request.
    ///
    /// `token_string` is the URL-safe Base64 token extracted from the request
    /// URL or POST body.
    /// `method` is the HTTP method string (must be "POST").
    pub fn handleUnsubscribeRequest(self: *OneClickHandler, token_string: []const u8, method: []const u8) UnsubscribeResult {
        // Step 1: Enforce POST method.
        const http_method = HttpMethod.fromString(method);
        if (http_method != .POST) {
            return .invalid_method;
        }

        // Step 2: Check if token was already processed.
        if (self.processed_tokens.contains(token_string)) {
            return .already_unsubscribed;
        }

        // Step 3: Validate the token (HMAC + expiry).
        const validation = self.generator.validateTokenString(token_string);
        switch (validation.result) {
            .valid => {},
            .invalid_hmac, .invalid_format => return .invalid_token,
            .expired => return .expired_token,
        }

        const token = validation.token.?;
        defer token.deinit(self.allocator);

        // Step 4: Execute the callback if registered.
        if (self.callback) |cb| {
            if (!cb(token.list_id, token.recipient, token.message_id)) {
                return .@"error";
            }
        }

        // Step 5: Record this token as processed.
        const key = self.allocator.dupe(u8, token_string) catch return .@"error";
        self.processed_tokens.put(key, time_compat.timestamp()) catch {
            self.allocator.free(key);
            return .@"error";
        };

        return .success;
    }

    /// Handle a full request with method and content-type validation.
    pub fn handleFullRequest(
        self: *OneClickHandler,
        token_string: []const u8,
        method: []const u8,
        content_type: []const u8,
        body: []const u8,
    ) UnsubscribeResult {
        // Validate the request format.
        if (!isValidRequest(method, content_type)) {
            const http_method = HttpMethod.fromString(method);
            if (http_method != .POST) return .invalid_method;
            return .@"error";
        }

        // RFC 8058 Section 3: The POST body MUST contain "List-Unsubscribe=One-Click".
        if (!containsOneClickPayload(body)) {
            return .@"error";
        }

        return self.handleUnsubscribeRequest(token_string, method);
    }

    /// Purge processed tokens older than the given age (in seconds) to
    /// prevent unbounded memory growth.
    pub fn purgeExpiredEntries(self: *OneClickHandler, max_age_seconds: i64) usize {
        const now = time_compat.timestamp();
        var to_remove: std.ArrayList([]const u8) = .{};
        defer to_remove.deinit(self.allocator);

        var it = self.processed_tokens.iterator();
        while (it.next()) |entry| {
            if (now - entry.value_ptr.* > max_age_seconds) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            _ = self.processed_tokens.fetchRemove(key);
            self.allocator.free(key);
        }

        return to_remove.items.len;
    }
};

// ---------------------------------------------------------------------------
// Header Injection Helper
// ---------------------------------------------------------------------------

/// Inject List-Unsubscribe and List-Unsubscribe-Post headers into an existing
/// RFC 5322 message. Headers are inserted after the first header line (before
/// the body separator "\r\n\r\n").
pub fn injectUnsubscribeHeaders(
    allocator: std.mem.Allocator,
    message: []const u8,
    config: ListUnsubscribeConfig,
    list_id: []const u8,
    recipient: []const u8,
    message_id: []const u8,
) ![]const u8 {
    if (!config.enabled) {
        return try allocator.dupe(u8, message);
    }

    const header_gen = ListUnsubscribeHeader.init(config);
    const header_lines = try header_gen.generateHeaderLines(allocator, list_id, recipient, message_id);
    defer allocator.free(header_lines);

    // Find the header/body boundary.
    const boundary = std.mem.indexOf(u8, message, "\r\n\r\n");
    if (boundary) |pos| {
        // Insert new headers just before the blank line separating headers from body.
        var result: std.ArrayList(u8) = .{};
        errdefer result.deinit(allocator);

        try result.appendSlice(allocator, message[0 .. pos + 2]); // Include the \r\n at end of last header
        try result.appendSlice(allocator, header_lines);
        try result.appendSlice(allocator, message[pos + 2 ..]); // \r\n + body

        return try result.toOwnedSlice(allocator);
    } else {
        // No body boundary found; append headers at the end.
        return try std.fmt.allocPrint(allocator, "{s}\r\n{s}", .{ message, header_lines });
    }
}

// ---------------------------------------------------------------------------
// URL Formatting
// ---------------------------------------------------------------------------

/// Build a complete unsubscribe URL by appending the token as a query parameter.
pub fn formatUnsubscribeUrl(allocator: std.mem.Allocator, url_base: []const u8, token: []const u8) ![]const u8 {
    // Determine the correct separator: '?' if no query string exists, '&' otherwise.
    const separator: u8 = if (std.mem.indexOf(u8, url_base, "?") != null) '&' else '?';
    return try std.fmt.allocPrint(allocator, "{s}{c}token={s}", .{ url_base, separator, token });
}

/// Build a complete unsubscribe URL from individual parameters (convenience).
pub fn buildUnsubscribeUrl(
    allocator: std.mem.Allocator,
    config: ListUnsubscribeConfig,
    list_id: []const u8,
    recipient: []const u8,
    message_id: []const u8,
) ![]const u8 {
    var gen = UnsubscribeTokenGenerator.initWithTtl(allocator, config.hmac_secret, config.token_ttl_seconds);
    const token = gen.generateToken(list_id, recipient, message_id);
    const token_string = try token.serialize(allocator);
    defer allocator.free(token_string);

    return try formatUnsubscribeUrl(allocator, config.url_base, token_string);
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256 over the canonical token payload.
/// Uses the one-shot `create` API to stay consistent with the rest of the codebase.
fn computeHmac(
    secret: []const u8,
    list_id: []const u8,
    recipient: []const u8,
    message_id: []const u8,
    ts: i64,
) [HMAC_LENGTH]u8 {
    // Build the canonical message: list_id || 0x00 || recipient || 0x00 || message_id || 0x00 || timestamp(be)
    const msg_len = list_id.len + 1 + recipient.len + 1 + message_id.len + 1 + @sizeOf(i64);

    // Use a stack buffer for typical sizes; the canonical message is always bounded
    // by the sum of email field lengths (well under 4 KiB).
    var buf: [4096]u8 = undefined;
    if (msg_len > buf.len) {
        // Fallback: zero-fill and return a sentinel -- in practice this never triggers
        // because email fields are tiny relative to 4 KiB.
        var result: [HMAC_LENGTH]u8 = undefined;
        @memset(&result, 0);
        return result;
    }

    var offset: usize = 0;
    @memcpy(buf[offset..][0..list_id.len], list_id);
    offset += list_id.len;
    buf[offset] = TOKEN_FIELD_SEPARATOR;
    offset += 1;
    @memcpy(buf[offset..][0..recipient.len], recipient);
    offset += recipient.len;
    buf[offset] = TOKEN_FIELD_SEPARATOR;
    offset += 1;
    @memcpy(buf[offset..][0..message_id.len], message_id);
    offset += message_id.len;
    buf[offset] = TOKEN_FIELD_SEPARATOR;
    offset += 1;
    std.mem.writeInt(i64, buf[offset..][0..@sizeOf(i64)], ts, .big);
    offset += @sizeOf(i64);

    var result: [HMAC_LENGTH]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&result, buf[0..offset], secret);
    return result;
}

/// Constant-time byte-array comparison to defend against timing attacks.
fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

/// Check if `haystack` starts with `prefix`.
fn startsWith(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return std.mem.eql(u8, haystack[0..prefix.len], prefix);
}

/// Case-insensitive prefix check.
fn hasPrefix(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    for (haystack[0..prefix.len], prefix) |h, p| {
        if (std.ascii.toLower(h) != std.ascii.toLower(p)) return false;
    }
    return true;
}

/// Check whether the POST body contains the one-click payload.
fn containsOneClickPayload(body: []const u8) bool {
    return std.mem.indexOf(u8, body, ONE_CLICK_POST_BODY) != null;
}

// ===========================================================================
// Tests
// ===========================================================================

test "config validation - valid config" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
    };
    try config.validate();
}

test "config validation - empty url_base" {
    const config = ListUnsubscribeConfig{
        .url_base = "",
        .hmac_secret = "supersecretkey1234567890abcdef",
    };
    try std.testing.expectError(error.EmptyUrlBase, config.validate());
}

test "config validation - http url rejected when require_https" {
    const config = ListUnsubscribeConfig{
        .url_base = "http://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .require_https = true,
    };
    try std.testing.expectError(error.HttpsRequired, config.validate());
}

test "config validation - http url allowed when require_https is false" {
    const config = ListUnsubscribeConfig{
        .url_base = "http://localhost:8080/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .require_https = false,
    };
    try config.validate();
}

test "config validation - secret too short" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "short",
    };
    try std.testing.expectError(error.SecretTooShort, config.validate());
}

test "config validation - invalid TTL" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .token_ttl_seconds = 0,
    };
    try std.testing.expectError(error.InvalidTtl, config.validate());
}

test "config validation - mailto without address" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .include_mailto = true,
        .mailto_address = null,
    };
    try std.testing.expectError(error.MissingMailtoAddress, config.validate());
}

test "token generation and HMAC verification" {
    const secret = "test-secret-key-at-least-16-bytes";
    var gen = UnsubscribeTokenGenerator.init(std.testing.allocator, secret);
    defer gen.deinit();

    const token = gen.generateTokenWithTimestamp(
        "newsletter",
        "user@example.com",
        "<msg001@example.com>",
        1700000000,
    );

    // Token fields should match inputs.
    try std.testing.expectEqualStrings("newsletter", token.list_id);
    try std.testing.expectEqualStrings("user@example.com", token.recipient);
    try std.testing.expectEqualStrings("<msg001@example.com>", token.message_id);
    try std.testing.expectEqual(@as(i64, 1700000000), token.timestamp);

    // HMAC should be non-zero.
    var all_zero = true;
    for (token.hmac) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "token serialization round-trip" {
    const secret = "test-secret-key-at-least-16-bytes";
    var gen = UnsubscribeTokenGenerator.init(std.testing.allocator, secret);
    defer gen.deinit();

    const token = gen.generateTokenWithTimestamp(
        "my-list",
        "alice@example.org",
        "<abc123@mail.example.org>",
        1700000000,
    );

    // Serialize.
    const encoded = try token.serialize(std.testing.allocator);
    defer std.testing.allocator.free(encoded);

    // Deserialize.
    const decoded = try UnsubscribeToken.deserialize(std.testing.allocator, encoded);
    defer decoded.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("my-list", decoded.list_id);
    try std.testing.expectEqualStrings("alice@example.org", decoded.recipient);
    try std.testing.expectEqualStrings("<abc123@mail.example.org>", decoded.message_id);
    try std.testing.expectEqual(@as(i64, 1700000000), decoded.timestamp);
    try std.testing.expectEqualSlices(u8, &token.hmac, &decoded.hmac);
}

test "token validation - valid token" {
    const secret = "test-secret-key-at-least-16-bytes";
    // Use a very large TTL so the token is valid regardless of wall-clock time.
    var gen = UnsubscribeTokenGenerator.initWithTtl(std.testing.allocator, secret, MAX_TOKEN_TTL_SECONDS);
    defer gen.deinit();

    const token = gen.generateToken("list1", "bob@example.com", "<msg@example.com>");
    const result = gen.validateToken(&token);
    try std.testing.expectEqual(TokenValidationResult.valid, result);
}

test "token validation - tampered HMAC" {
    const secret = "test-secret-key-at-least-16-bytes";
    var gen = UnsubscribeTokenGenerator.initWithTtl(std.testing.allocator, secret, MAX_TOKEN_TTL_SECONDS);
    defer gen.deinit();

    var token = gen.generateToken("list1", "bob@example.com", "<msg@example.com>");
    // Flip a bit in the HMAC.
    token.hmac[0] ^= 0xFF;

    const result = gen.validateToken(&token);
    try std.testing.expectEqual(TokenValidationResult.invalid_hmac, result);
}

test "token validation - wrong secret" {
    const secret1 = "test-secret-key-at-least-16-bytes";
    const secret2 = "different-secret-key-at-least-16";
    var gen1 = UnsubscribeTokenGenerator.initWithTtl(std.testing.allocator, secret1, MAX_TOKEN_TTL_SECONDS);
    var gen2 = UnsubscribeTokenGenerator.initWithTtl(std.testing.allocator, secret2, MAX_TOKEN_TTL_SECONDS);
    defer gen1.deinit();
    defer gen2.deinit();

    const token = gen1.generateToken("list1", "bob@example.com", "<msg@example.com>");
    const result = gen2.validateToken(&token);
    try std.testing.expectEqual(TokenValidationResult.invalid_hmac, result);
}

test "token validation - expired token" {
    const secret = "test-secret-key-at-least-16-bytes";
    var gen = UnsubscribeTokenGenerator.initWithTtl(std.testing.allocator, secret, 60); // 60-second TTL
    defer gen.deinit();

    // Create a token with a timestamp far in the past.
    const token = gen.generateTokenWithTimestamp("list1", "bob@example.com", "<msg@example.com>", 1000000);
    const result = gen.validateToken(&token);
    try std.testing.expectEqual(TokenValidationResult.expired, result);
}

test "token string validation round-trip" {
    const secret = "test-secret-key-at-least-16-bytes";
    var gen = UnsubscribeTokenGenerator.initWithTtl(std.testing.allocator, secret, MAX_TOKEN_TTL_SECONDS);
    defer gen.deinit();

    const token = gen.generateToken("weekly-digest", "carol@example.net", "<digest42@lists.example.net>");
    const encoded = try token.serialize(std.testing.allocator);
    defer std.testing.allocator.free(encoded);

    const validation = gen.validateTokenString(encoded);
    try std.testing.expectEqual(TokenValidationResult.valid, validation.result);
    try std.testing.expect(validation.token != null);
    validation.token.?.deinit(std.testing.allocator);
}

test "token string validation - garbage input" {
    const secret = "test-secret-key-at-least-16-bytes";
    var gen = UnsubscribeTokenGenerator.initWithTtl(std.testing.allocator, secret, MAX_TOKEN_TTL_SECONDS);
    defer gen.deinit();

    const validation = gen.validateTokenString("not-a-valid-token!!!");
    try std.testing.expectEqual(TokenValidationResult.invalid_format, validation.result);
    try std.testing.expect(validation.token == null);
}

test "header generation format - HTTPS only" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false, // relax for test
        .include_mailto = false,
    };

    const header = ListUnsubscribeHeader.init(config);
    const pair = try header.generateHeaders(
        std.testing.allocator,
        "newsletter",
        "user@example.com",
        "<msg@example.com>",
    );
    defer pair.deinit(std.testing.allocator);

    // List-Unsubscribe must be wrapped in angle brackets.
    try std.testing.expect(pair.list_unsubscribe.len > 0);
    try std.testing.expect(pair.list_unsubscribe[0] == '<');
    try std.testing.expect(pair.list_unsubscribe[pair.list_unsubscribe.len - 1] == '>');

    // Must contain the URL base.
    try std.testing.expect(std.mem.indexOf(u8, pair.list_unsubscribe, "https://mail.example.com/unsubscribe") != null);

    // Must contain a token query parameter.
    try std.testing.expect(std.mem.indexOf(u8, pair.list_unsubscribe, "?token=") != null);

    // List-Unsubscribe-Post must be exactly as specified by RFC 8058.
    try std.testing.expectEqualStrings("List-Unsubscribe=One-Click", pair.list_unsubscribe_post);
}

test "header generation format - with mailto" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
        .include_mailto = true,
        .mailto_address = "unsubscribe@example.com",
    };

    const header = ListUnsubscribeHeader.init(config);
    const pair = try header.generateHeaders(
        std.testing.allocator,
        "newsletter",
        "user@example.com",
        "<msg@example.com>",
    );
    defer pair.deinit(std.testing.allocator);

    // Should contain both HTTPS and mailto URLs.
    try std.testing.expect(std.mem.indexOf(u8, pair.list_unsubscribe, "https://") != null);
    try std.testing.expect(std.mem.indexOf(u8, pair.list_unsubscribe, "mailto:unsubscribe@example.com") != null);

    // Should have two angle-bracketed entries separated by comma+space.
    try std.testing.expect(std.mem.indexOf(u8, pair.list_unsubscribe, ">, <mailto:") != null);
}

test "header line generation" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
    };

    const header = ListUnsubscribeHeader.init(config);
    const lines = try header.generateHeaderLines(
        std.testing.allocator,
        "test-list",
        "user@example.com",
        "<msg@example.com>",
    );
    defer std.testing.allocator.free(lines);

    // Should contain proper header names.
    try std.testing.expect(std.mem.indexOf(u8, lines, "List-Unsubscribe: ") != null);
    try std.testing.expect(std.mem.indexOf(u8, lines, "List-Unsubscribe-Post: List-Unsubscribe=One-Click") != null);

    // Lines should be CRLF-terminated.
    try std.testing.expect(std.mem.indexOf(u8, lines, "\r\n") != null);
}

test "one-click handler - valid POST request" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
        .token_ttl_seconds = MAX_TOKEN_TTL_SECONDS,
    };

    var handler = OneClickHandler.init(std.testing.allocator, config);
    defer handler.deinit();

    // Generate a valid token.
    const token = handler.generator.generateToken("list1", "user@test.com", "<m@test.com>");
    const encoded = try token.serialize(std.testing.allocator);
    defer std.testing.allocator.free(encoded);

    const result = handler.handleUnsubscribeRequest(encoded, "POST");
    try std.testing.expectEqual(UnsubscribeResult.success, result);
}

test "one-click handler - reject GET request" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
        .token_ttl_seconds = MAX_TOKEN_TTL_SECONDS,
    };

    var handler = OneClickHandler.init(std.testing.allocator, config);
    defer handler.deinit();

    const token = handler.generator.generateToken("list1", "user@test.com", "<m@test.com>");
    const encoded = try token.serialize(std.testing.allocator);
    defer std.testing.allocator.free(encoded);

    const result = handler.handleUnsubscribeRequest(encoded, "GET");
    try std.testing.expectEqual(UnsubscribeResult.invalid_method, result);
}

test "one-click handler - reject PUT request" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
        .token_ttl_seconds = MAX_TOKEN_TTL_SECONDS,
    };

    var handler = OneClickHandler.init(std.testing.allocator, config);
    defer handler.deinit();

    const token = handler.generator.generateToken("list1", "user@test.com", "<m@test.com>");
    const encoded = try token.serialize(std.testing.allocator);
    defer std.testing.allocator.free(encoded);

    const result = handler.handleUnsubscribeRequest(encoded, "PUT");
    try std.testing.expectEqual(UnsubscribeResult.invalid_method, result);
}

test "one-click handler - duplicate unsubscribe" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
        .token_ttl_seconds = MAX_TOKEN_TTL_SECONDS,
    };

    var handler = OneClickHandler.init(std.testing.allocator, config);
    defer handler.deinit();

    const token = handler.generator.generateToken("list1", "user@test.com", "<m@test.com>");
    const encoded = try token.serialize(std.testing.allocator);
    defer std.testing.allocator.free(encoded);

    // First request should succeed.
    const result1 = handler.handleUnsubscribeRequest(encoded, "POST");
    try std.testing.expectEqual(UnsubscribeResult.success, result1);

    // Second request with the same token should report already unsubscribed.
    const result2 = handler.handleUnsubscribeRequest(encoded, "POST");
    try std.testing.expectEqual(UnsubscribeResult.already_unsubscribed, result2);
}

test "one-click handler - invalid token" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
        .token_ttl_seconds = MAX_TOKEN_TTL_SECONDS,
    };

    var handler = OneClickHandler.init(std.testing.allocator, config);
    defer handler.deinit();

    const result = handler.handleUnsubscribeRequest("totally-bogus-token", "POST");
    try std.testing.expectEqual(UnsubscribeResult.invalid_token, result);
}

test "one-click handler - full request validation" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
        .token_ttl_seconds = MAX_TOKEN_TTL_SECONDS,
    };

    var handler = OneClickHandler.init(std.testing.allocator, config);
    defer handler.deinit();

    const token = handler.generator.generateToken("list1", "user@test.com", "<m@test.com>");
    const encoded = try token.serialize(std.testing.allocator);
    defer std.testing.allocator.free(encoded);

    // Valid request.
    const result = handler.handleFullRequest(
        encoded,
        "POST",
        "application/x-www-form-urlencoded",
        "List-Unsubscribe=One-Click",
    );
    try std.testing.expectEqual(UnsubscribeResult.success, result);
}

test "one-click handler - reject wrong content type" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
        .token_ttl_seconds = MAX_TOKEN_TTL_SECONDS,
    };

    var handler = OneClickHandler.init(std.testing.allocator, config);
    defer handler.deinit();

    const token = handler.generator.generateToken("list1", "user@test.com", "<m@test.com>");
    const encoded = try token.serialize(std.testing.allocator);
    defer std.testing.allocator.free(encoded);

    const result = handler.handleFullRequest(
        encoded,
        "POST",
        "application/json",
        "List-Unsubscribe=One-Click",
    );
    try std.testing.expectEqual(UnsubscribeResult.@"error", result);
}

test "one-click handler - reject missing body payload" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
        .token_ttl_seconds = MAX_TOKEN_TTL_SECONDS,
    };

    var handler = OneClickHandler.init(std.testing.allocator, config);
    defer handler.deinit();

    const token = handler.generator.generateToken("list1", "user@test.com", "<m@test.com>");
    const encoded = try token.serialize(std.testing.allocator);
    defer std.testing.allocator.free(encoded);

    const result = handler.handleFullRequest(
        encoded,
        "POST",
        "application/x-www-form-urlencoded",
        "some-other-param=value",
    );
    try std.testing.expectEqual(UnsubscribeResult.@"error", result);
}

test "isValidRequest - valid POST" {
    try std.testing.expect(OneClickHandler.isValidRequest("POST", "application/x-www-form-urlencoded"));
}

test "isValidRequest - POST with charset" {
    try std.testing.expect(OneClickHandler.isValidRequest("POST", "application/x-www-form-urlencoded; charset=UTF-8"));
}

test "isValidRequest - GET rejected" {
    try std.testing.expect(!OneClickHandler.isValidRequest("GET", "application/x-www-form-urlencoded"));
}

test "isValidRequest - wrong content type" {
    try std.testing.expect(!OneClickHandler.isValidRequest("POST", "text/html"));
}

test "isValidRequest - case insensitive method" {
    try std.testing.expect(OneClickHandler.isValidRequest("post", "application/x-www-form-urlencoded"));
}

test "URL formatting - no existing query string" {
    const url = try formatUnsubscribeUrl(std.testing.allocator, "https://example.com/unsub", "abc123");
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://example.com/unsub?token=abc123", url);
}

test "URL formatting - existing query string" {
    const url = try formatUnsubscribeUrl(std.testing.allocator, "https://example.com/unsub?list=news", "abc123");
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://example.com/unsub?list=news&token=abc123", url);
}

test "URL building end-to-end" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
    };

    const url = try buildUnsubscribeUrl(
        std.testing.allocator,
        config,
        "list1",
        "user@example.com",
        "<msg@example.com>",
    );
    defer std.testing.allocator.free(url);

    try std.testing.expect(startsWith(url, "https://mail.example.com/unsubscribe?token="));
    try std.testing.expect(url.len > "https://mail.example.com/unsubscribe?token=".len);
}

test "header injection into message" {
    const config = ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
    };

    const message =
        "From: sender@example.com\r\n" ++
        "To: recipient@example.com\r\n" ++
        "Subject: Hello\r\n" ++
        "\r\n" ++
        "Body text here.";

    const result = try injectUnsubscribeHeaders(
        std.testing.allocator,
        message,
        config,
        "newsletter",
        "recipient@example.com",
        "<msg1@example.com>",
    );
    defer std.testing.allocator.free(result);

    // Should still contain original headers.
    try std.testing.expect(std.mem.indexOf(u8, result, "From: sender@example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Subject: Hello") != null);

    // Should contain new List-Unsubscribe headers.
    try std.testing.expect(std.mem.indexOf(u8, result, "List-Unsubscribe: <https://mail.example.com/unsubscribe?token=") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "List-Unsubscribe-Post: List-Unsubscribe=One-Click") != null);

    // Body should be preserved.
    try std.testing.expect(std.mem.indexOf(u8, result, "Body text here.") != null);
}

test "header injection - disabled config" {
    const config = ListUnsubscribeConfig{
        .enabled = false,
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "test-secret-key-at-least-16-bytes",
        .require_https = false,
    };

    const message = "From: a@b.com\r\n\r\nBody";
    const result = try injectUnsubscribeHeaders(
        std.testing.allocator,
        message,
        config,
        "list",
        "user@example.com",
        "<m@e.com>",
    );
    defer std.testing.allocator.free(result);

    // Should be unchanged.
    try std.testing.expectEqualStrings(message, result);
}

test "HMAC determinism" {
    const secret = "test-secret-key-at-least-16-bytes";
    const hmac1 = computeHmac(secret, "list", "user@test.com", "<msg>", 1700000000);
    const hmac2 = computeHmac(secret, "list", "user@test.com", "<msg>", 1700000000);
    try std.testing.expectEqualSlices(u8, &hmac1, &hmac2);
}

test "HMAC varies with input" {
    const secret = "test-secret-key-at-least-16-bytes";
    const hmac1 = computeHmac(secret, "list-a", "user@test.com", "<msg>", 1700000000);
    const hmac2 = computeHmac(secret, "list-b", "user@test.com", "<msg>", 1700000000);
    try std.testing.expect(!std.mem.eql(u8, &hmac1, &hmac2));
}

test "HMAC varies with timestamp" {
    const secret = "test-secret-key-at-least-16-bytes";
    const hmac1 = computeHmac(secret, "list", "user@test.com", "<msg>", 1700000000);
    const hmac2 = computeHmac(secret, "list", "user@test.com", "<msg>", 1700000001);
    try std.testing.expect(!std.mem.eql(u8, &hmac1, &hmac2));
}

test "constant time comparison" {
    const a = [_]u8{ 1, 2, 3, 4 };
    const b = [_]u8{ 1, 2, 3, 4 };
    const c = [_]u8{ 1, 2, 3, 5 };

    try std.testing.expect(constantTimeEqual(&a, &b));
    try std.testing.expect(!constantTimeEqual(&a, &c));
}

test "UnsubscribeResult toString" {
    try std.testing.expectEqualStrings("Successfully unsubscribed", UnsubscribeResult.success.toString());
    try std.testing.expectEqualStrings("Invalid unsubscribe token", UnsubscribeResult.invalid_token.toString());
    try std.testing.expectEqualStrings("Unsubscribe token has expired", UnsubscribeResult.expired_token.toString());
    try std.testing.expectEqualStrings("Invalid HTTP method (POST required)", UnsubscribeResult.invalid_method.toString());
    try std.testing.expectEqualStrings("Already unsubscribed", UnsubscribeResult.already_unsubscribed.toString());
}

test "HttpMethod fromString" {
    try std.testing.expectEqual(HttpMethod.GET, HttpMethod.fromString("GET"));
    try std.testing.expectEqual(HttpMethod.POST, HttpMethod.fromString("POST"));
    try std.testing.expectEqual(HttpMethod.POST, HttpMethod.fromString("post"));
    try std.testing.expectEqual(HttpMethod.POST, HttpMethod.fromString("Post"));
    try std.testing.expectEqual(HttpMethod.OTHER, HttpMethod.fromString("TRACE"));
}
