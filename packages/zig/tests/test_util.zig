//! Helpers shared by the test files in this directory.

const std = @import("std");

/// `s` repeated `n` times, as a compile-time constant. Zig dropped the `**`
/// array-repetition operator these tests were written with.
pub inline fn repeat(comptime s: []const u8, comptime n: usize) *const [s.len * n]u8 {
    comptime {
        @setEvalBranchQuota(1_000_000);
        var out: [s.len * n]u8 = undefined;
        for (0..n) |i| @memcpy(out[i * s.len ..][0..s.len], s);
        const final = out;
        return &final;
    }
}

test "repeat" {
    try std.testing.expectEqualStrings("abab", repeat("ab", 2));
    const joined = repeat("a", 3) ++ "@" ++ repeat("b.", 2);
    try std.testing.expectEqualStrings("aaa@b.b.", joined);
}
