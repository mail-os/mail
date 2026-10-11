//! Test aggregator for the webmail backend modules.
//!
//! Rooted at `src/` so the modules' `../core/...` imports resolve correctly
//! (a test root inside `src/api/` cannot escape its module directory). Pulls in
//! the inline tests defined in the webmail api/* modules.
const std = @import("std");

test {
    std.testing.refAllDecls(@import("api/webmail_session.zig"));
    std.testing.refAllDecls(@import("api/webmail_maildir.zig"));
    std.testing.refAllDecls(@import("api/webmail_http.zig"));
    std.testing.refAllDecls(@import("api/webmail_compose.zig"));
    std.testing.refAllDecls(@import("api/webmail_store.zig"));
    std.testing.refAllDecls(@import("api/webmail_threads.zig"));
    std.testing.refAllDecls(@import("api/webmail_service.zig"));
    std.testing.refAllDecls(@import("api/webmail_service_test.zig"));
}
