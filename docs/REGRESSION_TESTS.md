# Regression Test Index

This document catalogs past vulnerabilities, bugs, and security issues along with their corresponding test cases. Each entry ensures the bug doesn't recur and provides context for future developers.

## Purpose

- **Prevent Regressions**: Every bug gets a test that fails when the bug reappears
- **Document History**: Understand why certain tests exist
- **Security Audit Trail**: Track security-related fixes
- **Learning Resource**: Help new developers understand edge cases

## Categories

1. [Security Vulnerabilities](#security-vulnerabilities)
2. [Protocol Bugs](#protocol-bugs)
3. [Authentication Issues](#authentication-issues)
4. [Memory Safety](#memory-safety)
5. [Concurrency Bugs](#concurrency-bugs)
6. [Input Validation](#input-validation)
7. [Resource Exhaustion](#resource-exhaustion)
8. [Integration Issues](#integration-issues)

---

## Security Vulnerabilities

### SEC-001: SMTP Command Injection via Newline Characters
- **Severity**: Critical
- **Date Found**: 2025-09-15
- **Fixed In**: v0.25.0
- **Test File**: `tests/security_test.zig`
- **Test Function**: `test "SMTP command injection prevention"`

**Description**: Attackers could inject additional SMTP commands by embedding `\r\n` sequences in email addresses or message content.

**Root Cause**: Insufficient sanitization of user input before passing to SMTP state machine.

**Fix**: Added strict CRLF filtering in `src/protocol/smtp.zig:sanitizeInput()`. All user-provided strings now have control characters stripped.

**Test Case**:
```zig
test "SMTP command injection prevention" {
    const malicious_input = "test@example.com\r\nMAIL FROM:<attacker@evil.com>";
    const sanitized = smtp.sanitizeInput(malicious_input);
    try testing.expect(std.mem.indexOf(u8, sanitized, "\r\n") == null);
}
```

---

### SEC-002: Path Traversal in Maildir Access
- **Severity**: High
- **Date Found**: 2025-09-20
- **Fixed In**: v0.25.0
- **Test File**: `tests/security_test.zig`
- **Test Function**: `test "path traversal prevention"`

**Description**: Malicious mailbox names containing `../` could access files outside the mail directory.

**Root Cause**: Direct concatenation of user-provided mailbox names with filesystem paths.

**Fix**: Added path canonicalization and jail checking in `src/storage/maildir.zig:validatePath()`.

**Test Case**:
```zig
test "path traversal prevention" {
    const malicious_paths = [_][]const u8{
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "valid/../../../etc/shadow",
        "valid/./../../etc/passwd",
    };
    for (malicious_paths) |path| {
        try testing.expectError(error.PathTraversal, maildir.validatePath(path));
    }
}
```

---

### SEC-003: Timing Attack on Password Comparison
- **Severity**: Medium
- **Date Found**: 2025-10-01
- **Fixed In**: v0.26.0
- **Test File**: `tests/security_test.zig`
- **Test Function**: `test "constant time password comparison"`

**Description**: Password comparison timing varied based on how many characters matched, enabling timing attacks.

**Root Cause**: Using standard byte comparison (`std.mem.eql`) for password verification.

**Fix**: Implemented constant-time comparison in `src/auth/auth.zig:constantTimeCompare()`.

**Test Case**:
```zig
test "constant time password comparison" {
    const hash = try auth.hashPassword("secret123");

    // Both should take approximately the same time
    const start1 = std.time.nanoTimestamp();
    _ = auth.constantTimeCompare(hash, "wrong");
    const end1 = std.time.nanoTimestamp();

    const start2 = std.time.nanoTimestamp();
    _ = auth.constantTimeCompare(hash, "secret123");
    const end2 = std.time.nanoTimestamp();

    // Allow 20% variance for timing noise
    const time1 = end1 - start1;
    const time2 = end2 - start2;
    const variance = @abs(time1 - time2);
    try testing.expect(variance < (time1 + time2) / 10);
}
```

---

### SEC-004: Header Injection via Folded Headers
- **Severity**: High
- **Date Found**: 2025-10-05
- **Fixed In**: v0.26.0
- **Test File**: `tests/security_test.zig`
- **Test Function**: `test "header injection via folding"`

**Description**: Attackers could inject arbitrary headers using RFC 5322 header folding rules.

**Root Cause**: Header parser didn't validate continuation lines for injection attempts.

**Fix**: Added validation in `src/message/headers.zig:unfoldHeader()` to reject suspicious continuations.

---

## Protocol Bugs

### PROTO-001: MAIL FROM with Null Sender Handling
- **Severity**: Low
- **Date Found**: 2025-09-10
- **Fixed In**: v0.24.0
- **Test File**: `tests/smtp_protocol_test.zig`
- **Test Function**: `test "null sender MAIL FROM"`

**Description**: `MAIL FROM:<>` (null sender for bounces) was incorrectly rejected.

**Root Cause**: Email validation regex required at least one character before `@`.

**Fix**: Added special case handling for null sender in `src/protocol/smtp.zig:parseMailFrom()`.

---

### PROTO-002: Oversized DATA Handling
- **Severity**: Medium
- **Date Found**: 2025-09-25
- **Fixed In**: v0.25.0
- **Test File**: `tests/smtp_protocol_test.zig`
- **Test Function**: `test "oversized message rejection"`

**Description**: Messages exceeding SIZE limit weren't properly rejected during DATA phase.

**Root Cause**: Size check only happened after full message was received.

**Fix**: Added streaming size check with early termination in `src/protocol/smtp.zig:receiveData()`.

---

### PROTO-003: BDAT Chunk Boundary Handling
- **Severity**: Medium
- **Date Found**: 2025-10-10
- **Fixed In**: v0.26.0
- **Test File**: `tests/smtp_protocol_test.zig`
- **Test Function**: `test "BDAT chunk boundaries"`

**Description**: BDAT chunks split across TCP packets caused message corruption.

**Root Cause**: Chunk buffer wasn't preserving partial reads across iterations.

**Fix**: Implemented proper buffering in `src/protocol/smtp.zig:receiveBdat()`.

---

## Authentication Issues

### AUTH-001: PLAIN Auth Base64 Padding
- **Severity**: Low
- **Date Found**: 2025-09-05
- **Fixed In**: v0.24.0
- **Test File**: `tests/auth_test.zig`
- **Test Function**: `test "AUTH PLAIN base64 padding variants"`

**Description**: Some email clients sent Base64 without padding, which was rejected.

**Root Cause**: Strict Base64 decoder required `=` padding.

**Fix**: Added padding tolerance in `src/auth/sasl.zig:decodeBase64()`.

---

### AUTH-002: LOGIN Auth State Machine
- **Severity**: Medium
- **Date Found**: 2025-09-30
- **Fixed In**: v0.25.0
- **Test File**: `tests/auth_test.zig`
- **Test Function**: `test "AUTH LOGIN state machine"`

**Description**: AUTH LOGIN could be exploited by sending unexpected responses.

**Root Cause**: State machine didn't properly validate transition sequence.

**Fix**: Implemented strict state validation in `src/auth/sasl.zig:AuthLoginHandler`.

---

### AUTH-003: OAuth2 Token Expiry Race Condition
- **Severity**: Medium
- **Date Found**: 2025-10-15
- **Fixed In**: v0.27.0
- **Test File**: `tests/auth_test.zig`
- **Test Function**: `test "OAuth2 token expiry race"`

**Description**: Token could expire between validation and use, causing spurious auth failures.

**Root Cause**: No margin applied to token expiry check.

**Fix**: Added 30-second safety margin in `src/auth/oauth2.zig:isTokenValid()`.

---

## Memory Safety

### MEM-001: Buffer Overflow in Header Parsing
- **Severity**: Critical
- **Date Found**: 2025-09-08
- **Fixed In**: v0.24.0
- **Test File**: `tests/memory_safety_test.zig`
- **Test Function**: `test "header buffer overflow"`

**Description**: Extremely long header lines could overflow fixed-size buffers.

**Root Cause**: Using fixed 4096-byte buffer without bounds checking.

**Fix**: Switched to dynamic allocation with configurable limits.

---

### MEM-002: Use-After-Free in Connection Pool
- **Severity**: Critical
- **Date Found**: 2025-10-20
- **Fixed In**: v0.27.0
- **Test File**: `tests/memory_safety_test.zig`
- **Test Function**: `test "connection pool use-after-free"`

**Description**: Connection could be returned to pool while still being used.

**Root Cause**: Race condition between request completion and pool return.

**Fix**: Added reference counting in `src/infrastructure/connection_pool.zig`.

---

### MEM-003: Double Free in Error Path
- **Severity**: High
- **Date Found**: 2025-10-25
- **Fixed In**: v0.27.0
- **Test File**: `tests/memory_safety_test.zig`
- **Test Function**: `test "error path double free"`

**Description**: Error during message processing could cause double free.

**Root Cause**: Both `errdefer` and explicit cleanup ran on certain error paths.

**Fix**: Restructured error handling to use only `errdefer`.

---

## Concurrency Bugs

### CONC-001: Race Condition in Rate Limiter
- **Severity**: Medium
- **Date Found**: 2025-09-28
- **Fixed In**: v0.25.0
- **Test File**: `tests/concurrency_test.zig`
- **Test Function**: `test "rate limiter race condition"`

**Description**: High concurrency could allow more requests than rate limit.

**Root Cause**: Non-atomic read-modify-write in counter update.

**Fix**: Switched to atomic operations in `src/auth/security.zig:RateLimiter`.

---

### CONC-002: Deadlock in Queue Manager
- **Severity**: High
- **Date Found**: 2025-10-12
- **Fixed In**: v0.26.0
- **Test File**: `tests/concurrency_test.zig`
- **Test Function**: `test "queue manager deadlock"`

**Description**: Concurrent queue and dequeue operations could deadlock.

**Root Cause**: Lock ordering violation between queue mutex and item mutex.

**Fix**: Established consistent lock ordering in `src/queue/manager.zig`.

---

### CONC-003: Data Race in Statistics Counter
- **Severity**: Low
- **Date Found**: 2025-10-30
- **Fixed In**: v0.28.0
- **Test File**: `tests/concurrency_test.zig`
- **Test Function**: `test "statistics data race"`

**Description**: Statistics counters showed incorrect values under load.

**Root Cause**: Plain integers used instead of atomics.

**Fix**: Migrated to `std.atomic.Value` in `src/api/health.zig:ServerStats`.

---

## Input Validation

### VAL-001: Unicode Normalization Bypass
- **Severity**: Medium
- **Date Found**: 2025-10-08
- **Fixed In**: v0.26.0
- **Test File**: `tests/input_validation_test.zig`
- **Test Function**: `test "unicode normalization"`

**Description**: Homograph attacks using Unicode lookalikes bypassed domain validation.

**Root Cause**: No Unicode normalization before domain comparison.

**Fix**: Added NFC normalization in `src/validation/email.zig:normalizeDomain()`.

---

### VAL-002: Oversized MIME Nesting
- **Severity**: Medium
- **Date Found**: 2025-10-05
- **Fixed In**: v0.26.0
- **Test File**: `tests/input_validation_test.zig`
- **Test Function**: `test "MIME depth limit"`

**Description**: Deeply nested MIME parts caused stack overflow.

**Root Cause**: No depth limit on recursive MIME parsing.

**Fix**: Added `MAX_MIME_DEPTH=10` in `src/message/mime.zig`.

---

### VAL-003: Integer Overflow in Size Calculation
- **Severity**: High
- **Date Found**: 2025-10-18
- **Fixed In**: v0.27.0
- **Test File**: `tests/input_validation_test.zig`
- **Test Function**: `test "size calculation overflow"`

**Description**: Large attachment counts caused integer overflow in total size.

**Root Cause**: Using `u32` for size accumulation.

**Fix**: Switched to `u64` with overflow checking.

---

## Resource Exhaustion

### RES-001: Connection Exhaustion Attack
- **Severity**: High
- **Date Found**: 2025-09-22
- **Fixed In**: v0.25.0
- **Test File**: `tests/dos_prevention_test.zig`
- **Test Function**: `test "connection exhaustion prevention"`

**Description**: Attackers could exhaust connections by opening and holding many idle connections.

**Root Cause**: No per-IP connection limit.

**Fix**: Added per-IP limits in `src/auth/security.zig:ConnectionLimiter`.

---

### RES-002: Memory Exhaustion via Large Headers
- **Severity**: High
- **Date Found**: 2025-10-02
- **Fixed In**: v0.26.0
- **Test File**: `tests/dos_prevention_test.zig`
- **Test Function**: `test "header memory limit"`

**Description**: Attackers could exhaust memory with many large headers.

**Root Cause**: No limit on total header size.

**Fix**: Added `MAX_HEADER_SIZE` and `MAX_HEADERS_COUNT` limits.

---

### RES-003: File Descriptor Leak in TLS
- **Severity**: Medium
- **Date Found**: 2025-10-22
- **Fixed In**: v0.27.0
- **Test File**: `tests/resource_leak_test.zig`
- **Test Function**: `test "TLS file descriptor leak"`

**Description**: TLS handshake failures leaked file descriptors.

**Root Cause**: Missing cleanup in error path.

**Fix**: Added `errdefer` for socket cleanup in `src/protocol/tls.zig`.

---

## Integration Issues

### INT-001: DNS Resolver Timeout
- **Severity**: Medium
- **Date Found**: 2025-09-18
- **Fixed In**: v0.25.0
- **Test File**: `tests/integration_test.zig`
- **Test Function**: `test "DNS resolver timeout"`

**Description**: DNS resolution could hang indefinitely.

**Root Cause**: No timeout on DNS queries.

**Fix**: Added configurable timeout in `src/infrastructure/dns.zig`.

---

### INT-002: Database Connection Recovery
- **Severity**: High
- **Date Found**: 2025-10-28
- **Fixed In**: v0.28.0
- **Test File**: `tests/integration_test.zig`
- **Test Function**: `test "database connection recovery"`

**Description**: Database connection loss wasn't detected, causing cascading failures.

**Root Cause**: No health check on pooled connections.

**Fix**: Added connection validation in `src/storage/database.zig:Pool.acquire()`.

---

### INT-003: External API Rate Limiting
- **Severity**: Low
- **Date Found**: 2025-11-01
- **Fixed In**: v0.28.0
- **Test File**: `tests/integration_test.zig`
- **Test Function**: `test "external API rate limit handling"`

**Description**: Rate limit responses from external APIs (ClamAV, SpamAssassin) caused errors.

**Root Cause**: No retry logic for 429 responses.

**Fix**: Added exponential backoff in `src/integration/external.zig`.

---

## Adding New Regression Tests

When fixing a bug:

1. **Create the test first** (TDD approach recommended)
2. **Add an entry** to this document with:
   - Category and ID (e.g., SEC-005)
   - Severity (Critical/High/Medium/Low)
   - Date found and version fixed
   - Test file and function name
   - Clear description of the bug
   - Root cause analysis
   - Fix summary
   - Example test case (if simple enough)
3. **Link the test** in comments:
   ```zig
   // Regression test for SEC-001: SMTP command injection
   test "SMTP command injection prevention" {
       // ...
   }
   ```
4. **Update CHANGELOG.md** with the fix

## Running Regression Tests

```bash
# Run all tests (includes regression tests)
zig build test

# Run security regression tests only
zig build test -- --test-filter "security"

# Run with verbose output
zig build test -- --verbose
```

## Test Coverage for Regressions

All regression tests should:
- [ ] Test the exact conditions that triggered the bug
- [ ] Include edge cases discovered during investigation
- [ ] Be clearly commented with regression ID
- [ ] Run as part of CI/CD pipeline
- [ ] Have corresponding documentation here

---

*Last updated: 2025-11-26*
*Total documented regressions: 21*
