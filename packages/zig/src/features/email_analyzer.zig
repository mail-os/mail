const std = @import("std");
const Allocator = std.mem.Allocator;

/// Email Analysis Features
/// - Link checking
/// - Spam scoring
/// - Header analysis
/// - Content validation

// ============================================================================
// Link Checker
// ============================================================================

pub const LinkStatus = struct {
    url: []const u8,
    status_code: u16,
    is_broken: bool,
    error_message: ?[]const u8 = null,
};

pub const LinkCheckResult = struct {
    total_links: usize,
    working_links: usize,
    broken_links: usize,
    links: std.ArrayList(LinkStatus),

    pub fn deinit(self: *LinkCheckResult, allocator: Allocator) void {
        for (self.links.items) |link| {
            allocator.free(link.url);
            if (link.error_message) |msg| {
                allocator.free(msg);
            }
        }
        self.links.deinit(allocator);
    }
};

pub fn checkLinks(allocator: Allocator, html_content: []const u8) !LinkCheckResult {
    var result = LinkCheckResult{
        .total_links = 0,
        .working_links = 0,
        .broken_links = 0,
        .links = std.ArrayList(LinkStatus){},
    };

    // Extract all links from HTML
    var links = try extractLinks(allocator, html_content);
    defer {
        for (links.items) |link| {
            allocator.free(link);
        }
        links.deinit(allocator);
    }

    result.total_links = links.items.len;

    // Check each link
    for (links.items) |url| {
        const status = try checkLink(allocator, url);
        try result.links.append(allocator, status);

        if (status.is_broken) {
            result.broken_links += 1;
        } else {
            result.working_links += 1;
        }
    }

    return result;
}

fn extractLinks(allocator: Allocator, html: []const u8) !std.ArrayList([]const u8) {
    var links = std.ArrayList([]const u8){};

    // Simple link extraction (href="...")
    var i: usize = 0;
    while (i < html.len) : (i += 1) {
        if (std.mem.startsWith(u8, html[i..], "href=\"")) {
            const start = i + 6;
            const end = std.mem.indexOfScalarPos(u8, html, start, '"') orelse continue;
            const url = html[start..end];

            // Skip anchors, mailto, tel, etc.
            if (std.mem.startsWith(u8, url, "http://") or std.mem.startsWith(u8, url, "https://")) {
                const url_copy = try allocator.dupe(u8, url);
                try links.append(allocator, url_copy);
            }

            i = end;
        }
    }

    return links;
}

fn checkLink(allocator: Allocator, url: []const u8) !LinkStatus {
    // In a real implementation, make HTTP request
    // For now, simulate link checking
    _ = allocator;

    // Simulate: most links work, some are broken
    const hash = simpleHash(url);
    const is_broken = (hash % 10) == 0; // 10% failure rate

    return LinkStatus{
        .url = url,
        .status_code = if (is_broken) 404 else 200,
        .is_broken = is_broken,
        .error_message = if (is_broken) "Not Found" else null,
    };
}

// ============================================================================
// Spam Analyzer
// ============================================================================

pub const SpamRule = struct {
    name: []const u8,
    score: f64,
    description: []const u8,
    triggered: bool,
};

pub const SpamReport = struct {
    total_score: f64,
    threshold: f64,
    is_spam: bool,
    rules: std.ArrayList(SpamRule),

    pub fn deinit(self: *SpamReport, allocator: Allocator) void {
        for (self.rules.items) |rule| {
            allocator.free(rule.description);
        }
        self.rules.deinit(allocator);
    }
};

pub fn analyzeSpam(allocator: Allocator, email_content: []const u8, headers: []const u8) !SpamReport {
    var report = SpamReport{
        .total_score = 0.0,
        .threshold = 5.0, // SpamAssassin default
        .is_spam = false,
        .rules = std.ArrayList(SpamRule){},
    };

    // Check various spam indicators
    try checkSpamWords(allocator, &report, email_content);
    try checkHeaders(allocator, &report, headers);
    try checkHtml(allocator, &report, email_content);
    try checkSpamLinks(allocator, &report, email_content);

    // Determine if spam
    report.is_spam = report.total_score >= report.threshold;

    return report;
}

fn checkSpamWords(allocator: Allocator, report: *SpamReport, content: []const u8) !void {
    const spam_words = [_]struct { word: []const u8, score: f64 }{
        .{ .word = "viagra", .score = 2.5 },
        .{ .word = "casino", .score = 2.0 },
        .{ .word = "free money", .score = 3.0 },
        .{ .word = "winner", .score = 1.5 },
        .{ .word = "click here", .score = 1.0 },
        .{ .word = "limited time", .score = 1.2 },
        .{ .word = "act now", .score = 1.5 },
        .{ .word = "congratulations", .score = 1.0 },
    };

    const lower_content = try std.ascii.allocLowerString(allocator, content);
    defer allocator.free(lower_content);

    for (spam_words) |spam_word| {
        if (std.mem.indexOf(u8, lower_content, spam_word.word)) |_| {
            report.total_score += spam_word.score;
            try report.rules.append(allocator, SpamRule{
                .name = "SPAM_WORD",
                .score = spam_word.score,
                .description = try std.fmt.allocPrint(allocator, "Contains spam word: {s}", .{spam_word.word}),
                .triggered = true,
            });
        }
    }
}

fn checkHeaders(allocator: Allocator, report: *SpamReport, headers: []const u8) !void {
    // Check for missing or suspicious headers
    if (std.mem.indexOf(u8, headers, "From:") == null) {
        report.total_score += 1.0;
        try report.rules.append(allocator, SpamRule{
            .name = "MISSING_FROM",
            .score = 1.0,
            .description = "Missing From header",
            .triggered = true,
        });
    }

    if (std.mem.indexOf(u8, headers, "Date:") == null) {
        report.total_score += 0.5;
        try report.rules.append(allocator, SpamRule{
            .name = "MISSING_DATE",
            .score = 0.5,
            .description = "Missing Date header",
            .triggered = true,
        });
    }

    // Check for suspicious From addresses
    if (std.mem.indexOf(u8, headers, "@suspicious.com") != null) {
        report.total_score += 2.0;
        try report.rules.append(allocator, SpamRule{
            .name = "SUSPICIOUS_FROM",
            .score = 2.0,
            .description = "From address in suspicious domain",
            .triggered = true,
        });
    }
}

fn checkHtml(allocator: Allocator, report: *SpamReport, content: []const u8) !void {
    // Check HTML patterns
    if (std.mem.indexOf(u8, content, "<html") != null) {
        // Count images vs. text ratio
        const img_count = countOccurrences(content, "<img");
        const text_len = content.len - (img_count * 20); // Approximate

        if (img_count > 5 and text_len < 100) {
            report.total_score += 1.5;
            try report.rules.append(allocator, SpamRule{
                .name = "IMAGE_ONLY",
                .score = 1.5,
                .description = "Email is mostly images with little text",
                .triggered = true,
            });
        }
    }

    // Check for excessive capitalization
    var caps_count: usize = 0;
    for (content) |c| {
        if (std.ascii.isUpper(c)) caps_count += 1;
    }

    const caps_ratio = @as(f64, @floatFromInt(caps_count)) / @as(f64, @floatFromInt(content.len));
    if (caps_ratio > 0.3) {
        report.total_score += 1.0;
        try report.rules.append(allocator, SpamRule{
            .name = "EXCESSIVE_CAPS",
            .score = 1.0,
            .description = "Excessive use of capital letters",
            .triggered = true,
        });
    }
}

fn checkSpamLinks(allocator: Allocator, report: *SpamReport, content: []const u8) !void {
    // Count links
    const link_count = countOccurrences(content, "href=");

    if (link_count > 20) {
        report.total_score += 1.0;
        try report.rules.append(allocator, SpamRule{
            .name = "EXCESSIVE_LINKS",
            .score = 1.0,
            .description = try std.fmt.allocPrint(allocator, "Contains {d} links", .{link_count}),
            .triggered = true,
        });
    }

    // Check for shortened URLs
    const short_urls = [_][]const u8{ "bit.ly", "tinyurl.com", "goo.gl", "t.co" };
    for (short_urls) |short_url| {
        if (std.mem.indexOf(u8, content, short_url)) |_| {
            report.total_score += 0.8;
            try report.rules.append(allocator, SpamRule{
                .name = "SHORTENED_URL",
                .score = 0.8,
                .description = try std.fmt.allocPrint(allocator, "Contains shortened URL: {s}", .{short_url}),
                .triggered = true,
            });
            break;
        }
    }
}

// ============================================================================
// Header Analyzer
// ============================================================================

pub const HeaderAnalysis = struct {
    has_spf: bool,
    has_dkim: bool,
    has_dmarc: bool,
    sender_ip: ?[]const u8,
    received_hops: usize,
    warnings: std.ArrayList([]const u8),

    pub fn deinit(self: *HeaderAnalysis, allocator: Allocator) void {
        for (self.warnings.items) |warning| {
            allocator.free(warning);
        }
        self.warnings.deinit(allocator);
    }
};

pub fn analyzeHeaders(allocator: Allocator, headers: []const u8) !HeaderAnalysis {
    var analysis = HeaderAnalysis{
        .has_spf = false,
        .has_dkim = false,
        .has_dmarc = false,
        .sender_ip = null,
        .received_hops = 0,
        .warnings = std.ArrayList([]const u8){},
    };

    // Check for authentication headers
    if (std.mem.indexOf(u8, headers, "SPF=pass") != null or
        std.mem.indexOf(u8, headers, "spf=pass") != null)
    {
        analysis.has_spf = true;
    }

    if (std.mem.indexOf(u8, headers, "DKIM-Signature:") != null) {
        analysis.has_dkim = true;
    }

    if (std.mem.indexOf(u8, headers, "DMARC=pass") != null) {
        analysis.has_dmarc = true;
    }

    // Count Received headers (mail hops)
    analysis.received_hops = countOccurrences(headers, "Received:");

    // Add warnings for missing authentication
    if (!analysis.has_spf) {
        try analysis.warnings.append(allocator, try allocator.dupe(u8, "Missing SPF authentication"));
    }

    if (!analysis.has_dkim) {
        try analysis.warnings.append(allocator, try allocator.dupe(u8, "Missing DKIM signature"));
    }

    if (!analysis.has_dmarc) {
        try analysis.warnings.append(allocator, try allocator.dupe(u8, "Missing DMARC policy"));
    }

    if (analysis.received_hops > 5) {
        const warning = try std.fmt.allocPrint(
            allocator,
            "Excessive mail hops ({d} servers)",
            .{analysis.received_hops},
        );
        try analysis.warnings.append(allocator, warning);
    }

    return analysis;
}

// ============================================================================
// Helper Functions
// ============================================================================

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    var count: usize = 0;
    var pos: usize = 0;

    while (pos < haystack.len) {
        if (std.mem.indexOf(u8, haystack[pos..], needle)) |found_pos| {
            count += 1;
            pos += found_pos + needle.len;
        } else {
            break;
        }
    }

    return count;
}

fn simpleHash(s: []const u8) u32 {
    var hash: u32 = 0;
    for (s) |c| {
        hash = hash *% 31 +% c;
    }
    return hash;
}

// ============================================================================
// Tests
// ============================================================================

test "link extraction" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const html =
        \\<html>
        \\<a href="https://example.com">Link 1</a>
        \\<a href="http://test.com">Link 2</a>
        \\<a href="#anchor">Anchor</a>
        \\</html>
    ;

    var links = try extractLinks(allocator, html);
    defer {
        for (links.items) |link| {
            allocator.free(link);
        }
        links.deinit(allocator);
    }

    try testing.expectEqual(@as(usize, 2), links.items.len);
}

test "spam word detection" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var report = SpamReport{
        .total_score = 0.0,
        .threshold = 5.0,
        .is_spam = false,
        .rules = std.ArrayList(SpamRule){},
    };
    defer report.deinit(allocator);

    const content = "Buy viagra now! Click here for free money!";
    try checkSpamWords(allocator, &report, content);

    try testing.expect(report.total_score > 0.0);
    try testing.expect(report.rules.items.len > 0);
}

test "header analysis" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const headers =
        \\From: sender@example.com
        \\Date: Mon, 24 Oct 2025 10:00:00 +0000
        \\Received: from server1
        \\Received: from server2
        \\SPF=pass
    ;

    var analysis = try analyzeHeaders(allocator, headers);
    defer analysis.deinit(allocator);

    try testing.expect(analysis.has_spf);
    try testing.expectEqual(@as(usize, 2), analysis.received_hops);
}
