//! Pulls the antispam DKIM verifier's inline tests into the unit-test suite.
//! dkim.zig imports `../core/*` compat shims, so it cannot be a test-module
//! root on its own (imports would escape the module path); rooting the test
//! module at `src/` makes those imports resolve.

const std = @import("std");

test {
    _ = @import("antispam/dkim.zig");
    _ = @import("antispam/dkim_sign.zig");
}
