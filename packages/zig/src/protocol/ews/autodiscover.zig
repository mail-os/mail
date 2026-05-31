const std = @import("std");

/// Exchange Autodiscover v2 (the JSON variant modern macOS/Outlook use).
///
/// macOS issues:
///   GET /autodiscover/autodiscover.json/v1.0/{email}?Protocol=EWS
/// and expects, unauthenticated:
///   {"Protocol":"EWS","Url":"https://host/EWS/Exchange.asmx"}
///
/// This module is intentionally dependency-free (only std) so it can move into
/// a standalone `zig-ews` package unchanged.

/// Extract the `Protocol` query parameter from a request path/query.
pub fn protocolParam(path: []const u8) []const u8 {
    const q = std.mem.indexOfScalar(u8, path, '?') orelse return "EWS";
    var it = std.mem.splitScalar(u8, path[q + 1 ..], '&');
    while (it.next()) |pair| {
        if (std.mem.startsWith(u8, pair, "Protocol=")) return pair["Protocol=".len ..];
    }
    return "EWS";
}

/// Build the Autodiscover v2 JSON body. `url` is the absolute endpoint URL for
/// the requested protocol (the EWS .asmx for Protocol=EWS).
pub fn buildJson(allocator: std.mem.Allocator, protocol: []const u8, url: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{{\"Protocol\":\"{s}\",\"Url\":\"{s}\"}}", .{ protocol, url });
}

/// Map a requested Autodiscover protocol to its endpoint URL on `host`.
/// EWS -> /EWS/Exchange.asmx. ActiveSync -> /Microsoft-Server-ActiveSync.
pub fn urlForProtocol(allocator: std.mem.Allocator, host: []const u8, protocol: []const u8) ![]u8 {
    if (std.ascii.eqlIgnoreCase(protocol, "ActiveSync")) {
        return std.fmt.allocPrint(allocator, "https://{s}/Microsoft-Server-ActiveSync", .{host});
    }
    // Default to EWS (covers Protocol=EWS and unknown).
    return std.fmt.allocPrint(allocator, "https://{s}/EWS/Exchange.asmx", .{host});
}

test "protocol param + json" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("EWS", protocolParam("/autodiscover/autodiscover.json/v1.0/x@y.com?Protocol=EWS"));
    const url = try urlForProtocol(a, "mail.example.com", "EWS");
    try std.testing.expectEqualStrings("https://mail.example.com/EWS/Exchange.asmx", url);
    const json = try buildJson(a, "EWS", url);
    try std.testing.expectEqualStrings("{\"Protocol\":\"EWS\",\"Url\":\"https://mail.example.com/EWS/Exchange.asmx\"}", json);
}
