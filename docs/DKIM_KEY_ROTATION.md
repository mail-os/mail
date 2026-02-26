# DKIM Key Rotation

Automated DKIM key rotation scheduler for periodic key management with configurable intervals, overlap periods, and notification callbacks.

## Purpose

DKIM (DomainKeys Identified Mail, RFC 6376) signs outbound email so recipients can verify message integrity and sender authenticity. Private keys used for signing should be rotated periodically to limit exposure if a key is compromised. The DKIM Key Rotation Scheduler automates this process, generating new keys on a configurable schedule while maintaining an overlap window where both old and new keys remain valid.

## Relevant RFCs

- **RFC 6376** -- DomainKeys Identified Mail (DKIM) Signatures
- **RFC 7489** -- DMARC (relies on DKIM alignment)

## Configuration

### Environment Variables

```bash
# Enable automatic DKIM key rotation
SMTP_ENABLE_DKIM_ROTATION=true

# Rotation interval in days (default: 90)
SMTP_DKIM_ROTATION_INTERVAL_DAYS=90
```

### TOML Configuration

```toml
[dkim]
rotation_enabled = true
rotation_interval_days = 90
```

### Rotation Config Defaults

| Parameter                | Default | Description                                        |
|--------------------------|---------|----------------------------------------------------|
| `rotation_interval_days` | 90      | Days between key rotations                         |
| `overlap_period_days`    | 7       | Days both old and new keys remain valid             |
| `warning_threshold_days` | 30      | Days before expiry to emit a warning event          |
| `default_algorithm`      | RSA-2048| Algorithm for newly generated keys                  |
| `auto_rotate`            | true    | Automatically rotate when keys approach expiry      |
| `max_keys_per_domain`    | 5       | Maximum active keys per domain before cleanup       |

## How Rotation Works

1. **Registration** -- Call `registerDomain("example.com")` to enroll a domain. The scheduler records the current timestamp as `last_rotation` and computes `next_rotation`.

2. **Periodic Check** -- A background thread (`RotationSchedulerThread`) calls `checkAndRotate()` at a configurable interval. For each registered domain whose `next_rotation` timestamp has passed, the scheduler:
   - Generates a new key pair with a timestamp-based selector (e.g., `s1706140800`).
   - Sets the new key as the active signing key.
   - Schedules the old key for deactivation after the overlap period.
   - Emits a `rotation_completed` event.

3. **Overlap Period** -- During the overlap window (default 7 days), both the old and new keys are valid. This allows remote DNS caches to pick up the new DKIM public key record before the old key stops being used for verification.

4. **Cleanup** -- `cleanupExpiredKeys()` removes inactive expired keys that exceed `max_keys_per_domain`.

## Rotation Events

The scheduler emits structured events for monitoring and alerting:

| Event Type            | Description                                      |
|-----------------------|--------------------------------------------------|
| `rotation_started`    | Key rotation has begun for a domain              |
| `rotation_completed`  | New key is active, old key enters overlap period  |
| `rotation_failed`     | Rotation failed (error details in message)       |
| `key_expiring_soon`   | Active key will expire within warning threshold   |
| `key_expired`         | A key has expired                                |
| `overlap_started`     | Both old and new keys are now valid               |
| `overlap_ended`       | Old key has been deactivated                     |

## DNS Record Updates

When a rotation occurs, you must publish the new DKIM public key as a DNS TXT record at `<selector>._domainkey.<domain>`:

```
; New key (active)
s1706140800._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjAN..."

; Old key (keep during overlap, then remove)
s1703548800._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIGfMA0G..."
```

After the overlap period ends, remove the old selector's DNS record.

## API Usage

```zig
// Initialize
var scheduler = DKIMRotationScheduler.init(allocator, &key_manager, .{
    .rotation_interval_days = 90,
    .overlap_period_days = 7,
});
defer scheduler.deinit();

// Register a domain
try scheduler.registerDomain("example.com");

// Check status
const status = scheduler.getDomainStatus("example.com");

// Force immediate rotation
const event = try scheduler.forceRotation("example.com");

// Update config at runtime
scheduler.updateConfig(.{ .rotation_interval_days = 60 });
```

## Best Practices

- Set `rotation_interval_days` to 90 or less per industry recommendations.
- Keep the overlap period at least 2x your DNS TTL for the DKIM TXT record.
- Monitor `rotation_failed` events and alert on consecutive failures.
- Use `forceRotation()` if you suspect a key has been compromised.
- Run `cleanupExpiredKeys()` periodically to avoid accumulating stale keys.

## See Also

- [Configuration Guide](CONFIGURATION.md)
- [Security Guide](SECURITY_GUIDE.md)
- Source: `src/features/dkim_rotation.zig`
