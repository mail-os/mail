//! Pulls the upgrade command's inline tests into the unit-test suite.
//! upgrade.zig imports `../core/*` compat shims, so it cannot be a test-module
//! root on its own (imports would escape the module path); rooting the test
//! module at `src/` makes those imports resolve.
//!
//! Worth having in the suite specifically because this code runs unattended on
//! a timer: release selection, version comparison and checksum verification
//! have no operator watching them.

const std = @import("std");

test {
    _ = @import("cli/upgrade.zig");
}
