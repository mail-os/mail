//! Small, independent regressions for receipt durability and monitor freshness.
const std = @import("std");
test {
    std.testing.refAllDecls(@import("core/durable_maildir.zig"));
    std.testing.refAllDecls(@import("api/webmail_health.zig"));
}
