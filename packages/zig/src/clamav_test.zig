//! Pulls the ClamAV-protocol client's inline tests into the unit-test suite.
//! clamav.zig imports `../core/*` compat shims, so it cannot be a test-module
//! root on its own (imports would escape the module path); rooting the test
//! module at `src/` makes those imports resolve.

test {
    _ = @import("antispam/clamav.zig");
}
