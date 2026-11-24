const std = @import("std");

pub fn addressDomain(address: []const u8) ?[]const u8 {
    const at = std.mem.indexOfScalar(u8, address, '@') orelse return null;
    return address[at + 1 ..];
}

pub fn contains(list: ?[]const u8, domain: []const u8) bool {
    if (domain.len == 0) return false;
    var entries = std.mem.splitScalar(u8, list orelse return false, ',');
    while (entries.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(domain, std.mem.trim(u8, entry, " \t"))) return true;
    }
    return false;
}
