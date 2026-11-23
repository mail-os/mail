//! Expiring public links carry random bearer capabilities. Only hashes persist.
const std = @import("std");
const io = @import("../core/io_compat.zig");

pub fn new() [64]u8 {
    var random: [32]u8 = undefined;
    io.randomBytes(&random);
    return std.fmt.bytesToHex(random, .lower);
}

pub fn digest(value: []const u8) [64]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(value, &hash, .{});
    return std.fmt.bytesToHex(hash, .lower);
}

pub fn valid(value: []const u8) bool {
    if (value.len != 64) return false;
    for (value) |byte| if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte)) return false;
    return true;
}

pub fn validLifetime(seconds: i64) bool {
    const hour = 3600;
    return seconds == hour or seconds == 24 * hour or seconds == 7 * 24 * hour;
}
