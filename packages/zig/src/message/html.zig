const std = @import("std");

/// HTML email utilities
pub const HTMLEmail = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) HTMLEmail {
        return .{ .allocator = allocator };
    }

    /// Convert plain text to HTML
    pub fn textToHTML(self: *HTMLEmail, text: []const u8) ![]const u8 {
        var html = std.ArrayList(u8).init(self.allocator);
        defer html.deinit();

        try html.appendSlice("<!DOCTYPE html>\n");
        try html.appendSlice("<html>\n<head>\n");
        try html.appendSlice("<meta charset=\"UTF-8\">\n");
        try html.appendSlice("<style>\n");
        try html.appendSlice("body { font-family: Arial, sans-serif; line-height: 1.6; }\n");
        try html.appendSlice("</style>\n");
        try html.appendSlice("</head>\n<body>\n<pre>\n");

        // Escape HTML and preserve formatting
        try self.escapeHTML(text, &html);

        try html.appendSlice("\n</pre>\n</body>\n</html>");

        return try html.toOwnedSlice();
    }

    /// Create multipart alternative email (plain text + HTML)
    pub fn createMultipartAlternative(
        self: *HTMLEmail,
        plain_text: []const u8,
        html_content: []const u8,
        boundary: []const u8,
    ) ![]const u8 {
        var message = std.ArrayList(u8).init(self.allocator);
        defer message.deinit();

        // Plain text part
        try std.fmt.format(message.writer(), "--{s}\r\n", .{boundary});
        try message.appendSlice("Content-Type: text/plain; charset=UTF-8\r\n");
        try message.appendSlice("Content-Transfer-Encoding: 8bit\r\n\r\n");
        try message.appendSlice(plain_text);
        try message.appendSlice("\r\n\r\n");

        // HTML part
        try std.fmt.format(message.writer(), "--{s}\r\n", .{boundary});
        try message.appendSlice("Content-Type: text/html; charset=UTF-8\r\n");
        try message.appendSlice("Content-Transfer-Encoding: 8bit\r\n\r\n");
        try message.appendSlice(html_content);
        try message.appendSlice("\r\n\r\n");

        // End boundary
        try std.fmt.format(message.writer(), "--{s}--\r\n", .{boundary});

        return try message.toOwnedSlice();
    }

    /// Strip HTML tags from content (convert HTML to plain text)
    pub fn stripHTML(self: *HTMLEmail, html: []const u8) ![]const u8 {
        var text = std.ArrayList(u8).init(self.allocator);
        defer text.deinit();

        var in_tag = false;
        var in_script = false;
        var in_style = false;

        var i: usize = 0;
        while (i < html.len) {
            if (html[i] == '<') {
                in_tag = true;

                // Check for script/style tags
                if (i + 7 < html.len and std.mem.eql(u8, html[i .. i + 7], "<script")) {
                    in_script = true;
                } else if (i + 6 < html.len and std.mem.eql(u8, html[i .. i + 6], "<style")) {
                    in_style = true;
                } else if (i + 9 < html.len and std.mem.eql(u8, html[i .. i + 9], "</script>")) {
                    in_script = false;
                    i += 8;
                } else if (i + 8 < html.len and std.mem.eql(u8, html[i .. i + 8], "</style>")) {
                    in_style = false;
                    i += 7;
                }

                // Handle <br> tags - convert to newline
                if (i + 4 < html.len and std.ascii.eqlIgnoreCase(html[i .. i + 4], "<br>")) {
                    try text.append('\n');
                } else if (i + 5 < html.len and std.ascii.eqlIgnoreCase(html[i .. i + 5], "<br/>")) {
                    try text.append('\n');
                } else if (i + 6 < html.len and std.ascii.eqlIgnoreCase(html[i .. i + 6], "<br />")) {
                    try text.append('\n');
                }

                // Handle paragraph tags
                if (i + 3 < html.len and std.ascii.eqlIgnoreCase(html[i .. i + 3], "<p>")) {
                    try text.append('\n');
                } else if (i + 4 < html.len and std.ascii.eqlIgnoreCase(html[i .. i + 4], "</p>")) {
                    try text.append('\n');
                }

                i += 1;
            } else if (html[i] == '>') {
                in_tag = false;
                i += 1;
            } else if (!in_tag and !in_script and !in_style) {
                try text.append(html[i]);
                i += 1;
            } else {
                i += 1;
            }
        }

        // Decode HTML entities
        return try self.decodeHTMLEntities(text.items);
    }

    /// Escape HTML special characters
    fn escapeHTML(self: *HTMLEmail, text: []const u8, output: *std.ArrayList(u8)) !void {
        _ = self;
        for (text) |c| {
            switch (c) {
                '<' => try output.appendSlice("&lt;"),
                '>' => try output.appendSlice("&gt;"),
                '&' => try output.appendSlice("&amp;"),
                '"' => try output.appendSlice("&quot;"),
                '\'' => try output.appendSlice("&#39;"),
                else => try output.append(c),
            }
        }
    }

    /// Decode common HTML entities
    fn decodeHTMLEntities(self: *HTMLEmail, text: []const u8) ![]const u8 {
        var decoded = std.ArrayList(u8).init(self.allocator);
        defer decoded.deinit();

        var i: usize = 0;
        while (i < text.len) {
            if (text[i] == '&') {
                // Try to decode entity
                if (i + 4 < text.len and std.mem.eql(u8, text[i .. i + 4], "&lt;")) {
                    try decoded.append('<');
                    i += 4;
                } else if (i + 4 < text.len and std.mem.eql(u8, text[i .. i + 4], "&gt;")) {
                    try decoded.append('>');
                    i += 4;
                } else if (i + 5 < text.len and std.mem.eql(u8, text[i .. i + 5], "&amp;")) {
                    try decoded.append('&');
                    i += 5;
                } else if (i + 6 < text.len and std.mem.eql(u8, text[i .. i + 6], "&quot;")) {
                    try decoded.append('"');
                    i += 6;
                } else if (i + 6 < text.len and std.mem.eql(u8, text[i .. i + 6], "&nbsp;")) {
                    try decoded.append(' ');
                    i += 6;
                } else if (i + 5 < text.len and std.mem.eql(u8, text[i .. i + 5], "&#39;")) {
                    try decoded.append('\'');
                    i += 5;
                } else {
                    try decoded.append(text[i]);
                    i += 1;
                }
            } else {
                try decoded.append(text[i]);
                i += 1;
            }
        }

        return try decoded.toOwnedSlice();
    }

    /// Sanitize HTML (remove dangerous tags and attributes)
    pub fn sanitizeHTML(self: *HTMLEmail, html: []const u8) ![]const u8 {
        var sanitized = std.ArrayList(u8).init(self.allocator);
        defer sanitized.deinit();

        // List of dangerous tags to remove
        const dangerous_tags = [_][]const u8{
            "<script", "</script>",
            "<iframe", "</iframe>",
            "<object", "</object>",
            "<embed",  "</embed>",
            "<applet", "</applet>",
        };

        var safe_html = try self.allocator.dupe(u8, html);
        defer self.allocator.free(safe_html);

        // Remove dangerous tags
        for (dangerous_tags) |tag| {
            const tag_lower = try self.allocator.dupe(u8, tag);
            defer self.allocator.free(tag_lower);

            // Simple removal (case-insensitive)
            var result = std.ArrayList(u8).init(self.allocator);
            defer result.deinit();

            var i: usize = 0;
            while (i < safe_html.len) {
                var found = false;
                if (i + tag.len <= safe_html.len) {
                    if (std.ascii.eqlIgnoreCase(safe_html[i .. i + tag.len], tag)) {
                        // Skip this tag
                        while (i < safe_html.len and safe_html[i] != '>') {
                            i += 1;
                        }
                        if (i < safe_html.len) i += 1;
                        found = true;
                    }
                }

                if (!found) {
                    try result.append(safe_html[i]);
                    i += 1;
                }
            }

            self.allocator.free(safe_html);
            safe_html = try result.toOwnedSlice();
        }

        return safe_html;
    }

    /// Validate HTML structure (basic validation)
    pub fn isValidHTML(self: *HTMLEmail, html: []const u8) bool {
        _ = self;

        // Check for basic HTML structure
        const has_html = std.mem.indexOf(u8, html, "<html") != null or std.mem.indexOf(u8, html, "<HTML") != null;
        const has_body = std.mem.indexOf(u8, html, "<body") != null or std.mem.indexOf(u8, html, "<BODY") != null;

        // Count opening and closing tags
        var open_count: usize = 0;
        var close_count: usize = 0;

        for (html) |c| {
            if (c == '<') open_count += 1;
            if (c == '>') close_count += 1;
        }

        return (has_html or has_body) and (open_count == close_count);
    }
};

test "text to HTML conversion" {
    const testing = std.testing;
    var html_email = HTMLEmail.init(testing.allocator);

    const text = "Hello, World!\nThis is a test.";
    const html = try html_email.textToHTML(text);
    defer testing.allocator.free(html);

    try testing.expect(std.mem.indexOf(u8, html, "<!DOCTYPE html>") != null);
    try testing.expect(std.mem.indexOf(u8, html, "<pre>") != null);
    try testing.expect(std.mem.indexOf(u8, html, "Hello, World!") != null);
}

test "HTML stripping" {
    const testing = std.testing;
    var html_email = HTMLEmail.init(testing.allocator);

    const html = "<html><body><p>Hello, <b>World</b>!</p></body></html>";
    const text = try html_email.stripHTML(html);
    defer testing.allocator.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "Hello") != null);
    try testing.expect(std.mem.indexOf(u8, text, "World") != null);
    try testing.expect(std.mem.indexOf(u8, text, "<b>") == null);
}

test "HTML entity decoding" {
    const testing = std.testing;
    var html_email = HTMLEmail.init(testing.allocator);

    const text = "Hello &amp; &lt;World&gt;";
    const decoded = try html_email.decodeHTMLEntities(text);
    defer testing.allocator.free(decoded);

    try testing.expectEqualStrings("Hello & <World>", decoded);
}

test "HTML sanitization" {
    const testing = std.testing;
    var html_email = HTMLEmail.init(testing.allocator);

    const html = "<p>Safe content</p><script>alert('xss')</script>";
    const sanitized = try html_email.sanitizeHTML(html);
    defer testing.allocator.free(sanitized);

    try testing.expect(std.mem.indexOf(u8, sanitized, "Safe content") != null);
    try testing.expect(std.mem.indexOf(u8, sanitized, "<script") == null);
}

test "multipart alternative creation" {
    const testing = std.testing;
    var html_email = HTMLEmail.init(testing.allocator);

    const plain = "Hello, World!";
    const html = "<html><body>Hello, World!</body></html>";
    const boundary = "----=_Part_123";

    const multipart = try html_email.createMultipartAlternative(plain, html, boundary);
    defer testing.allocator.free(multipart);

    try testing.expect(std.mem.indexOf(u8, multipart, "text/plain") != null);
    try testing.expect(std.mem.indexOf(u8, multipart, "text/html") != null);
    try testing.expect(std.mem.indexOf(u8, multipart, boundary) != null);
}
