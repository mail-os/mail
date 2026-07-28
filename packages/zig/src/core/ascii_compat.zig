const std = @import("std");

pub fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    return indexOfIgnoreCasePos(haystack, 0, needle);
}

pub fn indexOfIgnoreCasePos(haystack: []const u8, start_index: usize, needle: []const u8) ?usize {
    if (start_index > haystack.len) return null;
    if (needle.len == 0) return start_index;
    if (needle.len > haystack.len - start_index) return null;

    const first = std.ascii.toLower(needle[0]);
    const last_start = haystack.len - needle.len;
    var index = start_index;
    while (index <= last_start) : (index += 1) {
        if (std.ascii.toLower(haystack[index]) != first) continue;
        if (std.ascii.eqlIgnoreCase(haystack[index .. index + needle.len], needle)) return index;
    }
    return null;
}

test "case-insensitive substring search" {
    const testing = std.testing;

    try testing.expectEqual(@as(?usize, 5), indexOfIgnoreCase("Mail AUTH Login", "auth"));
    try testing.expectEqual(@as(?usize, 10), indexOfIgnoreCasePos("auth auth LOGIN", 5, "login"));
    try testing.expectEqual(@as(?usize, 0), indexOfIgnoreCase("mail", ""));
    try testing.expectEqual(@as(?usize, null), indexOfIgnoreCase("mail", "smtp"));
}
