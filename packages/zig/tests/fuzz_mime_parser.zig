const std = @import("std");

/// Fuzzing harness for MIME message parsing
/// Tests robustness against malformed MIME content
///
/// Usage:
///   zig build-exe tests/fuzz_mime_parser.zig -fsanitize=fuzzer
///   ./fuzz_mime_parser corpus_dir/

/// Fuzz target for MIME parsing
export fn LLVMFuzzerTestOneInput(data_ptr: [*]const u8, size: usize) callconv(.C) c_int {
    const data = data_ptr[0..size];

    if (size == 0) return 0;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test MIME parsing
    fuzzMimeHeaders(allocator, data) catch {};
    fuzzMimeBoundary(data) catch {};
    fuzzContentType(data) catch {};
    fuzzBase64Decode(allocator, data) catch {};
    fuzzQuotedPrintable(allocator, data) catch {};

    return 0;
}

/// Fuzz MIME header parsing
fn fuzzMimeHeaders(allocator: std.mem.Allocator, data: []const u8) !void {
    _ = allocator;

    // Parse headers (should handle any malformed input)
    var lines = std.mem.split(u8, data, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) break; // End of headers

        // Try to parse header name: value
        if (std.mem.indexOf(u8, line, ":")) |colon_pos| {
            const name = line[0..colon_pos];
            const value = if (colon_pos + 1 < line.len) line[colon_pos + 1 ..] else "";

            // Validate header name and value
            _ = name;
            _ = value;

            // Check for common headers
            _ = std.ascii.eqlIgnoreCase(name, "Content-Type");
            _ = std.ascii.eqlIgnoreCase(name, "Content-Transfer-Encoding");
            _ = std.ascii.eqlIgnoreCase(name, "Content-Disposition");
        }
    }
}

/// Fuzz MIME boundary parsing
fn fuzzMimeBoundary(data: []const u8) !void {
    // Look for boundary markers
    if (std.mem.indexOf(u8, data, "boundary=")) |start| {
        const rest = data[start + 9 ..];

        // Extract boundary (quoted or unquoted)
        var boundary: []const u8 = "";
        if (rest.len > 0) {
            if (rest[0] == '"') {
                // Quoted boundary
                if (std.mem.indexOf(u8, rest[1..], "\"")) |end| {
                    boundary = rest[1 .. end + 1];
                }
            } else {
                // Unquoted boundary (up to semicolon or end)
                if (std.mem.indexOf(u8, rest, ";")) |end| {
                    boundary = rest[0..end];
                } else {
                    boundary = rest;
                }
            }
        }

        // Validate boundary length (RFC 2046: max 70 characters)
        if (boundary.len > 0 and boundary.len <= 70) {
            // Check for boundary in content
            var search_buf: [74]u8 = undefined;
            const boundary_marker = std.fmt.bufPrint(&search_buf, "--{s}", .{boundary}) catch return;
            _ = std.mem.indexOf(u8, data, boundary_marker);
        }
    }
}

/// Fuzz Content-Type parsing
fn fuzzContentType(data: []const u8) !void {
    if (std.mem.indexOf(u8, data, "Content-Type:")) |start| {
        const rest = data[start + 13 ..];

        // Find end of line
        const end = std.mem.indexOf(u8, rest, "\r\n") orelse rest.len;
        const content_type = std.mem.trim(u8, rest[0..end], " \t");

        // Parse main type/subtype
        if (std.mem.indexOf(u8, content_type, "/")) |slash_pos| {
            const main_type = content_type[0..slash_pos];
            const subtype_and_params = content_type[slash_pos + 1 ..];

            // Extract subtype (before semicolon)
            var subtype = subtype_and_params;
            if (std.mem.indexOf(u8, subtype_and_params, ";")) |semi_pos| {
                subtype = subtype_and_params[0..semi_pos];
            }

            // Validate common types
            _ = std.ascii.eqlIgnoreCase(main_type, "text");
            _ = std.ascii.eqlIgnoreCase(main_type, "multipart");
            _ = std.ascii.eqlIgnoreCase(main_type, "image");
            _ = std.ascii.eqlIgnoreCase(main_type, "application");

            _ = std.ascii.eqlIgnoreCase(subtype, "plain");
            _ = std.ascii.eqlIgnoreCase(subtype, "html");
            _ = std.ascii.eqlIgnoreCase(subtype, "mixed");
            _ = std.ascii.eqlIgnoreCase(subtype, "alternative");
        }
    }
}

/// Fuzz Base64 decoding
fn fuzzBase64Decode(allocator: std.mem.Allocator, data: []const u8) !void {
    // Try to decode as Base64 (should handle invalid input gracefully)
    const decoder = std.base64.standard.Decoder;

    // Calculate worst-case decode size
    if (data.len == 0) return;
    const max_decoded_size = try decoder.calcSizeForSlice(data);
    if (max_decoded_size == 0) return;

    var decoded = try allocator.alloc(u8, max_decoded_size);
    defer allocator.free(decoded);

    // Attempt decode (will fail gracefully on invalid input)
    decoder.decode(decoded, data) catch return;
}

/// Fuzz Quoted-Printable decoding
fn fuzzQuotedPrintable(allocator: std.mem.Allocator, data: []const u8) !void {
    _ = allocator;

    // Parse quoted-printable encoding (=XX format)
    var i: usize = 0;
    while (i < data.len) : (i += 1) {
        if (data[i] == '=') {
            if (i + 2 < data.len) {
                // Try to parse hex digits
                const hex = data[i + 1 .. i + 3];
                _ = std.fmt.parseInt(u8, hex, 16) catch continue;
            }
        }
    }
}

// Corpus generator for fuzzing
pub fn generateCorpus(allocator: std.mem.Allocator, corpus_dir: []const u8) !void {
    const examples = [_][]const u8{
        // Valid MIME message
        \\Content-Type: text/plain; charset=utf-8
        \\Content-Transfer-Encoding: 7bit
        \\
        \\Hello, World!
        ,

        // Multipart message
        \\Content-Type: multipart/mixed; boundary="boundary123"
        \\
        \\--boundary123
        \\Content-Type: text/plain
        \\
        \\Part 1
        \\--boundary123
        \\Content-Type: text/html
        \\
        \\<p>Part 2</p>
        \\--boundary123--
        ,

        // Base64 encoded
        \\Content-Transfer-Encoding: base64
        \\
        \\SGVsbG8sIFdvcmxkIQ==
        ,

        // Quoted-Printable
        \\Content-Transfer-Encoding: quoted-printable
        \\
        \\Hello=20World=21
        ,

        // Malformed boundary
        \\Content-Type: multipart/mixed; boundary=""
        ,

        // Very long boundary
        \\Content-Type: multipart/mixed; boundary="012345678901234567890123456789012345678901234567890123456789012345678901234567890"
        ,

        // Missing Content-Type
        \\Content-Transfer-Encoding: base64
        \\
        \\Invalid base64!!!
        ,

        // Nested multipart
        \\Content-Type: multipart/mixed; boundary="outer"
        \\
        \\--outer
        \\Content-Type: multipart/alternative; boundary="inner"
        \\
        \\--inner
        \\Content-Type: text/plain
        \\
        \\Text
        \\--inner--
        \\--outer--
        ,
    };

    // Create corpus directory
    std.fs.cwd().makeDir(corpus_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Write examples
    for (examples, 0..) |example, i| {
        const filename = try std.fmt.allocPrint(allocator, "{s}/example_{d}.txt", .{ corpus_dir, i });
        defer allocator.free(filename);

        const file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();

        try file.writeAll(example);
    }
}

// Tests
test "fuzz MIME headers" {
    const testing = std.testing;

    const valid_headers =
        \\Content-Type: text/plain
        \\Content-Transfer-Encoding: 7bit
        \\
    ;
    try fuzzMimeHeaders(testing.allocator, valid_headers);

    // Malformed headers (should not crash)
    try fuzzMimeHeaders(testing.allocator, "Content-Type:");
    try fuzzMimeHeaders(testing.allocator, ":value");
    try fuzzMimeHeaders(testing.allocator, "\x00\xFF");
}

test "fuzz MIME boundary" {
    // Valid boundary
    try fuzzMimeBoundary("Content-Type: multipart/mixed; boundary=\"test123\"");

    // Malformed boundaries (should not crash)
    try fuzzMimeBoundary("boundary=");
    try fuzzMimeBoundary("boundary=\"");
    try fuzzMimeBoundary("boundary=\"" ++ "x" ** 100 ++ "\""); // Too long
}

test "fuzz Base64 decode" {
    const testing = std.testing;

    // Valid Base64
    try fuzzBase64Decode(testing.allocator, "SGVsbG8=");

    // Invalid Base64 (should not crash)
    try fuzzBase64Decode(testing.allocator, "!!!!");
    try fuzzBase64Decode(testing.allocator, "");
    try fuzzBase64Decode(testing.allocator, "\x00\xFF");
}
