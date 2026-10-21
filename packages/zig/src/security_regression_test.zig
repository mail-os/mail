//! Keep security regressions discoverable with -Dtest-filter=security:.
comptime {
    _ = @import("core/maildir_path.zig");
    _ = @import("core/config.zig");
    _ = @import("message/submission.zig");
    _ = @import("core/protocol.zig");
    _ = @import("core/smtp.zig");
    _ = @import("auth/security.zig");
    _ = @import("delivery/queue.zig");
    _ = @import("delivery/aliases.zig");
}
