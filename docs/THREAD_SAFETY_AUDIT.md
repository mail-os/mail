# Thread Safety Audit Report

**Date:** 2025-10-24
**Version:** v0.21.0
**Status:** ⚠️ Critical Issues Found

## Executive Summary

This document provides a comprehensive thread safety audit of the Mail Server codebase. The server uses a multi-threaded architecture where each client connection is handled in a separate thread, requiring careful synchronization of shared resources.

## Architecture Overview

### Thread Model
- **Main Thread**: Accepts incoming connections
- **Worker Threads**: One thread per client connection (spawned via `std.Thread.spawn`)
- **Background Threads**: Rate limiter cleanup thread

### Shared Resources
1. Database connection
2. Rate limiter
3. Logger
4. Configuration (read-only)
5. Greylist
6. Auth backend

## Thread Safety Analysis

### ✅ Thread-Safe Components

#### 1. ServerStats (src/health.zig)
**Status:** ✅ Thread-Safe (as of v0.21.0)

**Protection Mechanism:**
- Atomic operations (`std.atomic.Value`) for all counters
- Lock-free concurrent access

**Implementation:**
```zig
pub const ServerStats = struct {
    total_connections: std.atomic.Value(u64),
    active_connections: std.atomic.Value(u32),
    messages_received: std.atomic.Value(u64),
    // ... more atomic counters

    pub fn incrementMessagesReceived(self: *ServerStats) void {
        _ = self.messages_received.fetchAdd(1, .monotonic);
    }
}
```

**Analysis:**
- ✅ All counters use atomic operations
- ✅ Lock-free increment/decrement methods
- ✅ Thread-safe read via `.load(.monotonic)`
- ✅ No race conditions
- ✅ High performance (no mutex contention)

---

#### 2. RateLimiter (src/security.zig)
**Status:** ✅ Thread-Safe

**Protection Mechanism:**
- `std.Thread.Mutex` protects all HashMap operations
- Atomic flag (`std.atomic.Value(bool)`) for cleanup thread shutdown

**Critical Sections:**
```zig
pub fn checkAndIncrement(self: *RateLimiter, ip: []const u8) !bool {
    self.mutex.lock();
    defer self.mutex.unlock();
    // ... HashMap access protected
}
```

**Analysis:**
- ✅ All read/write operations on `ip_counters` are mutex-protected
- ✅ Cleanup thread uses atomic operations for `should_stop` flag
- ✅ Proper defer for mutex unlocking prevents deadlocks
- ✅ No race conditions identified

---

#### 2. Logger (src/logger.zig)
**Status:** ✅ Thread-Safe

**Protection Mechanism:**
- `std.Thread.Mutex` protects file and stderr writes

**Critical Sections:**
```zig
pub fn log(self: *Logger, level: LogLevel, comptime fmt: []const u8, args: anytype) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    // ... logging operations protected
}
```

**Analysis:**
- ✅ All log writes are mutex-protected
- ✅ Prevents interleaved log messages
- ✅ File operations are serialized
- ✅ No race conditions identified

---

#### 3. Configuration (src/config.zig)
**Status:** ✅ Thread-Safe (Read-Only)

**Access Pattern:** Read-only after initialization

**Analysis:**
- ✅ Config is loaded once at startup
- ✅ All worker threads only read config values
- ✅ No mutations during server runtime
- ✅ No synchronization needed for read-only data

---

### ⚠️ Thread-Unsafe Components (CRITICAL)

#### 1. Database (src/database.zig)
**Status:** ⚠️ **CRITICAL - NOT THREAD-SAFE**

**Problem:**
- No mutex protection
- Multiple threads can access SQLite database concurrently
- SQLite requires serialization of database operations
- Potential for database corruption and crashes

**Vulnerable Operations:**
```zig
pub const Database = struct {
    db: ?*sqlite.sqlite3,
    allocator: std.mem.Allocator,
    // ❌ NO MUTEX!

    pub fn exec(self: *Database, sql: []const u8) !void {
        // ❌ Unprotected database access
    }

    pub fn prepare(self: *Database, sql: []const u8) !Statement {
        // ❌ Unprotected statement preparation
    }
}
```

**Impact:**
- 🔴 **High**: Data corruption possible
- 🔴 **High**: Concurrent write conflicts
- 🔴 **Medium**: Statement finalization race conditions
- 🔴 **High**: Crashes on multi-threaded access

**Recommendation:** **IMMEDIATE FIX REQUIRED**

**Solution:**
```zig
pub const Database = struct {
    db: ?*sqlite.sqlite3,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex, // ✅ Add mutex

    pub fn init(allocator: std.mem.Allocator, db_path: []const u8) !Database {
        // ... existing init code ...
        return Database{
            .db = db,
            .allocator = allocator,
            .mutex = std.Thread.Mutex{}, // ✅ Initialize mutex
        };
    }

    pub fn exec(self: *Database, sql: []const u8) !void {
        self.mutex.lock(); // ✅ Lock before access
        defer self.mutex.unlock();
        // ... existing exec code ...
    }

    pub fn prepare(self: *Database, sql: []const u8) !Statement {
        self.mutex.lock(); // ✅ Lock before access
        defer self.mutex.unlock();
        // ... existing prepare code ...
    }
}
```

---

### 🟡 Components Needing Review

#### 1. Greylist (src/greylist.zig)
**Status:** 🟡 Needs Investigation

**Reason:** Not yet reviewed in this audit

**Recommendation:** Check if HashMap access is mutex-protected

---

#### 2. Auth Backend (src/auth.zig)
**Status:** 🟡 Needs Investigation

**Reason:** May depend on Database thread safety

**Recommendation:** Review after Database fix is implemented

---

#### 3. Search Engine (src/search.zig)
**Status:** 🟡 Needs Investigation

**Reason:** May have concurrent database access

**Recommendation:** Review database access patterns

---

## Race Condition Analysis

### Identified Race Conditions

#### 1. Database Access Race (CRITICAL)
**Location:** src/database.zig

**Scenario:**
```
Thread A                    Thread B
---------                   ---------
prepare("INSERT...")
                            prepare("SELECT...")
step()
                            step()
finalize()
                            finalize()
                            ❌ RACE: Concurrent access
```

**Impact:** Database corruption, crashes, lost data

**Fix Priority:** 🔴 **IMMEDIATE**

---

### Potential Race Conditions (Not Confirmed)

#### 1. Greylist Access
**Location:** src/greylist.zig

**Scenario:** Multiple threads checking/updating greylist entries

**Impact:** TBD - needs investigation

**Fix Priority:** 🟡 **HIGH**

---

## Deadlock Analysis

### No Deadlocks Found

**Reasoning:**
- Only one mutex per component
- No nested mutex acquisitions
- No circular lock dependencies
- All mutexes use `defer` for automatic unlocking

**Monitoring Recommendation:** Watch for future changes that introduce nested locking

---

## Memory Safety Analysis

### Allocation Patterns

#### Thread-Local Allocations
✅ Each connection thread uses its own arena allocator for session data

#### Shared Allocations
⚠️ Database query results may need careful lifetime management

---

## Performance Considerations

### Lock Contention Hotspots

#### 1. Logger (Low Impact)
- **Frequency:** Every log call
- **Duration:** Microseconds (I/O bound)
- **Impact:** Low - logging is fast
- **Recommendation:** Consider lock-free logging buffer if needed

#### 2. Rate Limiter (Medium Impact)
- **Frequency:** Every SMTP command
- **Duration:** HashMap lookup/insert
- **Impact:** Medium - could be a bottleneck under high load
- **Recommendation:** Consider sharded rate limiters for higher throughput

#### 3. Database (High Impact - Once Fixed)
- **Frequency:** Auth checks, message saves
- **Duration:** SQLite I/O operations
- **Impact:** High - database is I/O bound
- **Recommendation:**
  - Connection pooling with multiple database handles
  - Write-ahead logging (WAL) mode for SQLite
  - Consider async I/O for database operations

---

## Recommendations

### Immediate (CRITICAL)

1. ✅ **Add mutex to Database struct** (Priority: CRITICAL)
   - Files: `src/database.zig`
   - Impact: Prevents data corruption
   - Effort: Low (1-2 hours)

### High Priority

2. 🟡 **Audit Greylist thread safety**
   - Files: `src/greylist.zig`
   - Impact: Prevents greylist race conditions
   - Effort: Low (1 hour)

3. 🟡 **Audit Auth backend thread safety**
   - Files: `src/auth.zig`
   - Impact: Prevents auth race conditions
   - Effort: Low (1 hour)

4. 🟡 **Audit Search engine thread safety**
   - Files: `src/search.zig`
   - Impact: Prevents search race conditions
   - Effort: Medium (2 hours)

### Medium Priority

5. 📊 **Add connection pooling for Database**
   - Files: `src/database.zig`, `src/main.zig`
   - Impact: Reduces database lock contention
   - Effort: High (1 day)

6. 📊 **Enable SQLite WAL mode**
   - Files: `src/database.zig`
   - Impact: Improves concurrent read performance
   - Effort: Low (30 minutes)

### Low Priority

7. 📈 **Performance profiling under load**
   - Tools: Perf, Valgrind Helgrind
   - Impact: Identifies real-world bottlenecks
   - Effort: Medium (half day)

---

## Testing Recommendations

### Thread Safety Tests

#### 1. Concurrent Connection Test
```bash
# Spawn 100 concurrent connections
for i in {1..100}; do
    (
        echo "EHLO test$i"
        echo "MAIL FROM:<user$i@example.com>"
        echo "RCPT TO:<rcpt$i@example.com>"
        echo "DATA"
        echo "Subject: Test $i"
        echo "."
        echo "QUIT"
    ) | nc localhost 2525 &
done
wait
```

#### 2. Database Stress Test
```bash
# Enable SQLite thread safety check
export SQLITE_ENABLE_API_ARMOR=1

# Run concurrent auth operations
for i in {1..50}; do
    ./zig-out/bin/user-cli create "user$i" "user$i@example.com" "password" &
done
wait
```

#### 3. Race Detector (if available)
```bash
# Build with thread sanitizer (if Zig supports it)
zig build -Dthread-sanitizer=true

# Run under Valgrind Helgrind
valgrind --tool=helgrind ./zig-out/bin/mail
```

---

## Monitoring and Observability

### Metrics to Track

1. **Lock Contention:**
   - Rate limiter lock wait time
   - Database lock wait time
   - Logger lock wait time

2. **Thread Count:**
   - Active connection threads
   - Peak concurrent connections

3. **Database Performance:**
   - Query execution time
   - Lock wait time
   - Transaction throughput

### Logging Recommendations

Add debug logging for:
- Mutex acquisition/release (with timing)
- Thread spawn/join events
- Database transaction begin/commit/rollback

---

## Change History

| Version | Date | Changes |
|---------|------|---------|
| v0.21.0 | 2025-10-24 | Initial thread safety audit |

---

## References

- [SQLite Thread Safety](https://www.sqlite.org/threadsafe.html)
- [Zig Thread Documentation](https://ziglang.org/documentation/master/std/#A;std:Thread)
- [Zig Mutex Documentation](https://ziglang.org/documentation/master/std/#A;std:Thread.Mutex)
- [Database Locking in SQLite](https://www.sqlite.org/lockingv3.html)

---

**Next Steps:**
1. Fix Database thread safety (CRITICAL)
2. Audit remaining components
3. Implement performance improvements
4. Add thread safety tests
