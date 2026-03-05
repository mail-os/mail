# Known Issues and Solutions

This document tracks known issues with the SMTP server and provides solutions or workarounds.

## ✅ Resolved Issues

### STARTTLS Memory Alignment Bug (Fixed in v0.21.0)

**Problem:** Memory alignment mismatch when freeing TLS reader/writer structures allocated with `create()` but freed with incorrect alignment.

**Solution:** Implemented proper aligned memory deallocation:
- Store alignment information along with pointer and size
- Use `rawFree()` with correct alignment enum
- Switch statement to handle different alignment values (1, 2, 4, 8, 16 bytes)
- Properly cast pointers to correct alignment before freeing

**Error Message (Before Fix):**
```
error(gpa): Allocation alignment 8 does not match free alignment 1
```

**Files Changed:**
- `src/protocol.zig` - Fixed TLS reader/writer cleanup in deinit()

**Impact:**
- 🟢 **STARTTLS Now Works**: TLS 1.3 handshake completes successfully
- 🟢 **No Memory Leaks**: Proper cleanup of TLS resources
- 🟢 **Production Ready**: Native STARTTLS is now stable

**Test Results:**
```bash
# Successfully completes TLS handshake
openssl s_client -connect localhost:2525 -starttls smtp
# Result: New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

---

### Database Thread Safety (Fixed in v0.21.0)

**Problem:** Database struct had no mutex protection, allowing concurrent access from multiple threads leading to potential data corruption.

**Solution:** Implemented thread-safe Database access with mutex protection:
- Added `std.Thread.Mutex` to Database struct
- Protected all database operations: exec(), prepare(), createUser(), getUserByUsername(), etc.
- Used defer pattern for automatic mutex unlocking
- No nested mutex acquisitions (prevents deadlocks)

**Files Changed:**
- `src/database.zig` - Added mutex field and protection to all methods
- `docs/THREAD_SAFETY_AUDIT.md` - Comprehensive thread safety audit

**Impact:**
- 🔴 **CRITICAL**: Prevents database corruption
- 🔴 **CRITICAL**: Prevents concurrent write conflicts
- 🔴 **CRITICAL**: Prevents crashes on multi-threaded access

**Thread Safety Summary:**
- ✅ Database - mutex protected
- ✅ RateLimiter - mutex protected
- ✅ Logger - mutex protected
- ✅ Config - read-only (no protection needed)

---

### DATA Command Timeout (Fixed in v0.21.0)

**Problem:** No specific timeout for DATA phase, allowing slow clients to hold connections indefinitely during message transfer.

**Solution:** Implemented configurable timeout enforcement for DATA command:
- Added `data_timeout_seconds` configuration field (default: 600 seconds / 10 minutes)
- Environment variable support: `SMTP_DATA_TIMEOUT_SECONDS`
- Timer-based timeout checking in handleData() using std.time.milliTimestamp()
- Returns 451 SMTP error code with descriptive message on timeout
- Warning logs include client address and elapsed time

**Usage:**
```bash
# Configure DATA timeout via environment variable
SMTP_DATA_TIMEOUT_SECONDS=600  # 10 minutes (default)
SMTP_DATA_TIMEOUT_SECONDS=1200 # 20 minutes (for large messages)

# Start server with custom DATA timeout
SMTP_DATA_TIMEOUT_SECONDS=300 ./zig-out/bin/mail
```

**Files Changed:**
- `src/config.zig` - Added data_timeout_seconds field and environment variable support
- `src/protocol.zig` - Added timeout enforcement in handleData() function

**Benefits:**
- Prevents resource exhaustion from slow/stalled clients
- Configurable per-deployment needs
- Clear error messages for troubleshooting
- Separate from general connection timeout for better control

---

### HTTPS Webhooks Not Supported (Fixed in v0.20.0)

**Problem:** Webhook implementation only supported HTTP URLs, not HTTPS, preventing secure webhook notifications.

**Solution:** Implemented full TLS client support for HTTPS webhooks:
- Uses zig-tls library's `clientFromStream` for TLS connections
- Automatic protocol detection based on URL scheme (http:// vs https://)
- Optional certificate verification (insecure_skip_verify for development)
- Proper TLS handshake and encrypted communication
- Graceful fallback to HTTP for non-HTTPS URLs

**Usage:**
```bash
# SMTP server now supports both HTTP and HTTPS webhook URLs
SMTP_WEBHOOK_URL=https://secure-endpoint.example.com/webhook
```

**Files Changed:**
- `src/webhook.zig` - Added TLS client support for HTTPS

**Benefits:**
- Secure webhook notifications to HTTPS endpoints
- Protection of sensitive email metadata in transit
- Production-ready webhook integration

---

### Rate Limiter Cleanup Not Scheduled (Fixed in v0.18.0)

**Problem:** The RateLimiter had a `cleanup()` method but it was never called, causing memory to grow over time as old IP entries were never removed.

**Solution:** Added automatic cleanup scheduling with background thread:
- New `startAutomaticCleanup()` method launches a background worker thread
- Cleanup runs every hour by default
- Thread uses atomic flag for clean shutdown
- Entries are removed after 2x the window time of inactivity
- Call `rate_limiter.startAutomaticCleanup()` after initialization

**Usage:**
```zig
var rate_limiter = security.RateLimiter.init(allocator, 3600, 100);
defer rate_limiter.deinit(); // Automatically stops cleanup thread

// Start automatic cleanup
try rate_limiter.startAutomaticCleanup();
```

**Files Changed:**
- `src/security.zig` - Added automatic cleanup with background thread

---

### Per-User Rate Limiting (Fixed in v0.22.0)

**Problem:** Rate limiting was only by IP address, not by authenticated user. This prevented better control for authenticated submissions and could block legitimate users sharing the same IP.

**Solution:** Implemented per-user rate limiting alongside IP-based limiting:
- Added `user_counters: std.StringHashMap(RateCounter)` to RateLimiter
- New `checkAndIncrementUser()` method for authenticated user rate limiting
- New `getRemainingRequestsUser()` method to check user limits
- Configurable `max_requests_per_user` field (default: 200/hour)
- Cleanup logic handles both IP and user counters
- Environment variable support: `SMTP_RATE_LIMIT_PER_USER`

**Usage:**
```zig
// Check rate limit for authenticated user
if (authenticated_user) |user| {
    if (!try rate_limiter.checkAndIncrementUser(user)) {
        // User rate limit exceeded
        try self.sendResponse(writer, 451, "Rate limit exceeded for user", null);
        return;
    }
}
```

**Configuration:**
```bash
# Environment variables
SMTP_RATE_LIMIT_PER_IP=100          # 100 messages/hour per IP
SMTP_RATE_LIMIT_PER_USER=200        # 200 messages/hour per user
SMTP_RATE_LIMIT_CLEANUP_INTERVAL=3600  # Cleanup every 1 hour
```

**Files Changed:**
- `src/security.zig` - Added per-user rate limiting methods
- `src/config.zig` - Added configuration fields and environment variables
- `src/smtp.zig` - Updated RateLimiter initialization

**Benefits:**
- Better control for authenticated submissions
- Prevents legitimate users from being blocked by shared IP
- Complements IP-based rate limiting
- Configurable per-deployment needs

---

### Configurable Cleanup Interval (Fixed in v0.22.0)

**Problem:** Rate limiter cleanup interval was hardcoded to 1 hour, not allowing customization for different deployment scenarios.

**Solution:** Made cleanup interval configurable:
- Added `cleanup_interval_seconds: u64` field to RateLimiter
- Updated `cleanupWorker()` to use configurable interval
- Environment variable support: `SMTP_RATE_LIMIT_CLEANUP_INTERVAL`
- Default remains 3600 seconds (1 hour)

**Configuration:**
```bash
# Cleanup every 30 minutes for high-traffic deployments
SMTP_RATE_LIMIT_CLEANUP_INTERVAL=1800

# Cleanup every 2 hours for low-traffic deployments
SMTP_RATE_LIMIT_CLEANUP_INTERVAL=7200
```

**Files Changed:**
- `src/security.zig` - Updated cleanup worker to use configurable interval
- `src/config.zig` - Added configuration field and environment variable

**Benefits:**
- Customizable cleanup frequency based on traffic patterns
- Better memory management for different deployment scenarios
- Maintains backward compatibility with 1-hour default

---

## 🔴 Critical Issues

**None!** All critical issues have been resolved in v0.21.0.

---

### Thread Safety Audit Complete (Fixed in v0.21.0)

**Problem:** Need to verify thread safety of all shared resources.

**Solution:** Completed comprehensive thread safety audit and fixes:
- ✅ **ServerStats**: Implemented atomic operations for all counters
- ✅ **Database**: Added mutex protection (already fixed)
- ✅ **RateLimiter**: Verified mutex protection (already thread-safe)
- ✅ **Greylist**: Verified mutex protection (already thread-safe)
- ✅ **Logger**: Verified mutex protection (already thread-safe)
- ✅ **Config**: Read-only after initialization (thread-safe)

**Implementation:**
```zig
pub const ServerStats = struct {
    messages_received: std.atomic.Value(u64),
    total_connections: std.atomic.Value(u64),
    active_connections: std.atomic.Value(u32),
    // ... more atomic counters

    pub fn incrementMessagesReceived(self: *ServerStats) void {
        _ = self.messages_received.fetchAdd(1, .monotonic);
    }
};
```

**Files Changed:**
- `src/health.zig` - Atomic operations for statistics
- `docs/THREAD_SAFETY_AUDIT.md` - Comprehensive audit document

**Benefits:**
- 🟢 **Lock-Free Counters**: High performance statistics without mutex contention
- 🟢 **All Resources Audited**: Complete verification of thread safety
- 🟢 **Documented**: Thread safety guarantees documented
- 🟢 **Production Ready**: No thread safety concerns

---

## 🟡 High Priority Issues

**None!** All high priority thread safety issues have been resolved in v0.21.0.

---

## 🟠 Medium Priority Issues

**None!** All medium priority issues have been resolved in v0.22.0.

---

## 💡 Enhancement Opportunities

All identified medium-priority enhancements have been implemented! Remaining opportunities are for future consideration:

---

## 📊 Performance Considerations

### Memory Usage in DATA Phase

**Observation:** Message data is accumulated in ArrayList

**Potential Issue:** Large messages (50MB) held entirely in memory

**Mitigation:**
1. ✅ Max message size enforcement (already implemented)
2. Consider streaming to disk for large messages:
```zig
if (message_data.items.len > threshold) {
    // Stream to temporary file
    const temp_file = try std.fs.cwd().createFile(temp_path, .{});
    defer temp_file.close();
    try temp_file.writeAll(message_data.items);
}
```

### Database Connection Pooling

**Current:** Single database connection per server

**Enhancement:** Connection pool for concurrent operations:
```zig
pub const ConnectionPool = struct {
    connections: []Database,
    available: std.ArrayList(usize),
    mutex: std.Thread.Mutex,

    pub fn acquire(self: *ConnectionPool) !*Database {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.available.popOrNull()) |idx| {
            return &self.connections[idx];
        }
        return error.NoAvailableConnections;
    }
};
```

---

## 🔧 Testing Recommendations

### Load Testing

Test scenarios to validate fixes:

1. **Rate Limiter Cleanup:**
```bash
# Generate traffic from many IPs
for i in {1..1000}; do
    curl -X POST http://localhost:25 \
        --header "X-Forwarded-For: 192.168.1.$i" &
done

# Monitor memory growth
watch -n 1 'ps aux | grep mail'
```

2. **DATA Timeout:**
```python
import socket
import time

sock = socket.socket()
sock.connect(('localhost', 25))

# Send EHLO, MAIL, RCPT
sock.sendall(b'EHLO test\r\n')
sock.recv(1024)
sock.sendall(b'MAIL FROM:<test@example.com>\r\n')
sock.recv(1024)
sock.sendall(b'RCPT TO:<test@example.com>\r\n')
sock.recv(1024)

# Send DATA and wait
sock.sendall(b'DATA\r\n')
sock.recv(1024)

# Don't send anything - test timeout
time.sleep(620)  # Wait 10+ minutes
```

3. **Thread Safety:**
```bash
# Concurrent connections
for i in {1..100}; do
    (telnet localhost 25 << EOF
EHLO test$i
MAIL FROM:<user$i@example.com>
QUIT
EOF
    ) &
done
wait
```

---

## 📝 Documentation Updates Needed

1. **deployment.md** - Add TLS proxy configuration
2. **configuration.md** - Add DATA timeout options
3. **troubleshooting.md** - Add timeout debugging section
4. **performance.md** - Add rate limiter tuning guide

---

## 🎯 Priority Roadmap

### Immediate (v0.21.0)
- [x] Fix rate limiter cleanup scheduling (v0.18.0)
- [x] Add HTTPS webhook support (v0.20.0)
- [x] Add DATA command timeout (v0.21.0)
- [ ] Document TLS proxy workaround
- [ ] Thread safety audit and fixes

### Short-term (v0.22.0)
- [x] Per-user rate limiting (v0.22.0)
- [x] Configurable cleanup interval (v0.22.0)
- [ ] Connection pooling

### Medium-term (v0.23.0)
- [ ] Fix TLS handshake issue (if feasible)
- [ ] OpenTelemetry traces
- [ ] Advanced monitoring and alerting

### Long-term
- [ ] Streaming large message handling
- [ ] Performance optimizations
- [ ] Advanced load balancing

---

## 🤝 Contributing

If you encounter issues or have solutions:

1. Check this document first
2. Search GitHub issues
3. If new, open an issue with:
   - Problem description
   - Reproduction steps
   - Environment details
   - Proposed solution (if any)

---

**Last Updated:** 2025-10-24
**Version:** v0.22.0
