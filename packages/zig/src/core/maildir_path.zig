//! Mailbox identities and folder names are single filesystem components.
//! Validate at every writer, including aliases and locally generated DSNs.
const std = @import("std");

pub fn validate(component: []const u8) !void {
    if (component.len == 0 or component.len > 255 or
        std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
        return error.InvalidMailboxPath;
    for (component) |byte| {
        if (byte < 32 or byte == 127 or byte == '/' or byte == '\\' or byte == ':')
            return error.InvalidMailboxPath;
    }
}

test "security: mailbox path components never traverse" {
    for ([_][]const u8{ "", ".", "..", "../escape", "a/../../b", "a\\..\\b", "/tmp/x", "a\x00b", "a\r\nb", "C:escape" }) |bad|
        try std.testing.expectError(error.InvalidMailboxPath, validate(bad));
    for ([_][]const u8{ "chris", "first.last", "a+b@example.com", "Junk", ".Sent" }) |good|
        try validate(good);
}
