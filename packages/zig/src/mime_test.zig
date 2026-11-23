//! Pulls the MIME adapter's and the attachment extractor's inline tests into
//! the unit-test suite. attachment.zig imports `../core/*`, so it cannot be a
//! test-module root on its own (imports would escape the module path);
//! rooting the test module at `src/` makes those imports resolve.

test {
    _ = @import("message/mime.zig");
    _ = @import("message/attachment.zig");
}
