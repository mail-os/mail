const std = @import("std");

/// Spinlock-based Mutex compatible with the old std.Thread.Mutex API.
/// In Zig 0.16, std.Thread.Mutex was removed; std.Io.Mutex requires
/// an io parameter. This provides the same lock()/unlock() API.
pub const Mutex = struct {
    _locked: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn lock(self: *Mutex) void {
        while (self._locked.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *Mutex) void {
        self._locked.store(0, .release);
    }

    pub fn tryLock(self: *Mutex) bool {
        return self._locked.cmpxchgWeak(0, 1, .acquire, .monotonic) == null;
    }
};
