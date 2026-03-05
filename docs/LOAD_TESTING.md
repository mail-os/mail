# Load Testing Guide

**Version:** v0.28.0
**Date:** 2025-10-24

## Overview

This document describes how to perform load testing on the SMTP server to validate performance, capacity, and reliability under high concurrent load.

## Load Testing Framework

### Features

- **Concurrent Connections**: Test with 10,000+ simultaneous connections
- **Throughput Measurement**: Messages per second, bytes per second
- **Latency Analysis**: p50, p95, p99 percentiles
- **Error Tracking**: Connection and message failures
- **Resource Monitoring**: Memory and CPU usage tracking
- **Realistic Simulation**: Full SMTP conversation (EHLO, MAIL, RCPT, DATA, QUIT)
- **JSON Output**: Machine-readable results for CI/CD integration

### Building the Load Tester

```bash
# Build with optimizations
zig build-exe tests/load_test.zig -O ReleaseFast --name load_test

# Or use Makefile
make load-test
```

---

## Quick Start

### Basic Load Test

```bash
# Test with 1000 connections for 60 seconds
./load_test --connections 1000 --duration 60
```

### High Load Test

```bash
# Test with 10,000 connections
./load_test -c 10000 -d 300 -m 5
```

### JSON Output for CI/CD

```bash
# Output results in JSON format
./load_test --json > results.json
```

---

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--host <HOST>` | Target SMTP server hostname | `localhost` |
| `--port <PORT>` | Target SMTP server port | `2525` |
| `-c, --connections <N>` | Number of concurrent connections | `1000` |
| `-d, --duration <SECONDS>` | Test duration in seconds | `60` |
| `-m, --messages <N>` | Messages to send per connection | `10` |
| `--json` | Output results in JSON format | `false` |
| `-h, --help` | Print help message | - |

---

## Test Scenarios

### Scenario 1: Baseline Performance

**Goal**: Establish baseline performance metrics

```bash
./load_test \
  --connections 100 \
  --duration 60 \
  --messages 10
```

**Expected Results**:
- 100 connections/s sustained
- p99 latency < 100ms
- 0% error rate

---

### Scenario 2: High Concurrency

**Goal**: Test connection pooling and resource limits

```bash
./load_test \
  --connections 5000 \
  --duration 120 \
  --messages 5
```

**Expected Results**:
- 5,000 concurrent connections
- Connection pool efficiency > 90%
- Memory usage stable
- p99 latency < 500ms

---

### Scenario 3: Maximum Throughput

**Goal**: Find maximum messages per second

```bash
./load_test \
  --connections 10000 \
  --duration 300 \
  --messages 20
```

**Expected Results**:
- 10,000+ messages/second
- CPU usage < 80%
- No connection failures
- Latency p99 < 1s

---

### Scenario 4: Sustained Load

**Goal**: Verify stability over extended period

```bash
./load_test \
  --connections 2000 \
  --duration 3600 \
  --messages 50
```

**Expected Results**:
- Stable performance over 1 hour
- No memory leaks (constant RSS)
- Consistent latency (p99 variation < 20%)
- No gradual degradation

---

### Scenario 5: Spike Test

**Goal**: Test rapid load increase

```bash
# Start with baseline
./load_test -c 100 -d 60 &

# Wait 30 seconds
sleep 30

# Add spike load
./load_test -c 5000 -d 30
```

**Expected Results**:
- Graceful handling of spike
- No existing connection drops
- Recovery to baseline after spike

---

## Interpreting Results

### Sample Output

```
=== Load Test Results ===

Duration: 60.00s

Connections:
  Total:      1000
  Successful: 998
  Failed:     2
  Rate:       16.63/s

Messages:
  Total:      9980
  Successful: 9975
  Failed:     5
  Rate:       166.25/s

Throughput:
  Sent:     12.45 MB (0.21 MB/s)
  Received: 3.21 MB (0.05 MB/s)

Latency (message send time):
  p50: 45.23ms
  p95: 123.45ms
  p99: 234.56ms
```

### Metrics Explained

**Connections**:
- **Total**: Number of connection attempts
- **Successful**: Connections that completed SMTP handshake
- **Failed**: Connection errors (timeout, refused, etc.)
- **Rate**: Successful connections per second

**Messages**:
- **Total**: Number of message send attempts
- **Successful**: Messages accepted by server (250 OK)
- **Failed**: Message rejections or errors
- **Rate**: Successful messages per second

**Throughput**:
- **Sent**: Total bytes sent to server (MB)
- **Received**: Total bytes received from server (MB)
- MB/s: Megabytes per second

**Latency**:
- **p50 (median)**: 50% of messages completed in this time or less
- **p95**: 95% of messages completed in this time or less
- **p99**: 99% of messages completed in this time or less

---

## Performance Targets

### Production Requirements

| Metric | Target | Notes |
|--------|--------|-------|
| Concurrent Connections | 10,000+ | OS limits may need tuning |
| Messages/second | 1,000+ | Depends on message size |
| Connection Success Rate | > 99% | < 1% failures acceptable |
| Message Success Rate | > 99.9% | < 0.1% failures acceptable |
| Latency p50 | < 50ms | Median response time |
| Latency p95 | < 200ms | 95th percentile |
| Latency p99 | < 500ms | 99th percentile |
| CPU Usage | < 70% | Leave headroom for spikes |
| Memory Usage | Stable | No leaks over time |

---

## System Tuning

### OS Limits

Increase file descriptor limits for high concurrency:

```bash
# Check current limits
ulimit -n

# Temporary increase (current session)
ulimit -n 65536

# Permanent increase (add to /etc/security/limits.conf)
*  soft  nofile  65536
*  hard  nofile  65536

# Kernel tuning (/etc/sysctl.conf)
net.core.somaxconn = 65536
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
```

### Server Configuration

Tune SMTP server for high load:

```bash
# Use production profile
export SMTP_PROFILE=production

# Increase connection pool
export SMTP_MAX_CONNECTIONS=10000

# Adjust worker threads (number of CPU cores)
export SMTP_WORKER_THREADS=8

# Increase buffer sizes
export SMTP_BUFFER_SIZE=65536
```

---

## Monitoring During Load Tests

### Server Metrics

Monitor these metrics during load testing:

```bash
# CPU and memory usage
top -p $(pgrep mail)

# Network connections
watch -n 1 'ss -tan | grep :2525 | wc -l'

# File descriptors
watch -n 1 'ls -l /proc/$(pgrep mail)/fd | wc -l'

# Prometheus metrics
curl http://localhost:8081/metrics
```

### Database Performance

```bash
# SQLite connection count
sqlite3 smtp.db "PRAGMA database_list;"

# Database size
ls -lh smtp.db

# Locked transactions (should be 0)
sqlite3 smtp.db "PRAGMA lock_status;"
```

---

## Troubleshooting

### Issue: Connection Failures

**Symptoms**:
- High connection failure rate
- "Connection refused" errors

**Solutions**:
1. Check server is running: `pgrep mail`
2. Verify port: `netstat -tulpn | grep 2525`
3. Increase OS limits: `ulimit -n 65536`
4. Check server logs for errors

---

### Issue: High Latency

**Symptoms**:
- p99 latency > 1 second
- Slow message processing

**Solutions**:
1. Check CPU usage: If > 90%, reduce load or add cores
2. Check disk I/O: If high, optimize database writes
3. Review database indices: Ensure proper indexing
4. Enable connection pooling
5. Increase worker threads

---

### Issue: Memory Growth

**Symptoms**:
- RSS continuously increasing
- OOM killer triggered

**Solutions**:
1. Check for memory leaks: Use valgrind or AddressSanitizer
2. Reduce buffer sizes
3. Limit concurrent connections
4. Review allocator usage (ensure proper `defer` cleanup)

---

### Issue: Gradual Degradation

**Symptoms**:
- Performance degrades over time
- Latency increases during test

**Solutions**:
1. Check for resource leaks (file descriptors, memory)
2. Review rate limiter cleanup
3. Monitor database growth
4. Check log file size

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Load Testing

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  workflow_dispatch:

jobs:
  load-test:
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - uses: actions/checkout@v3

      - name: Setup Zig
        uses: goto-bus-stop/setup-zig@v2
        with:
          version: 0.15.1

      - name: Build server
        run: zig build -Doptimize=ReleaseFast

      - name: Build load tester
        run: zig build-exe tests/load_test.zig -O ReleaseFast

      - name: Start server
        run: |
          ./zig-out/bin/mail &
          sleep 5

      - name: Run load test
        run: |
          ./load_test \
            --connections 1000 \
            --duration 60 \
            --json > results.json

      - name: Parse results
        run: |
          SUCCESS_RATE=$(jq '.messages.successful / .messages.total * 100' results.json)
          P99_MS=$(jq '.latency_ms.p99' results.json)

          echo "Success rate: $SUCCESS_RATE%"
          echo "p99 latency: ${P99_MS}ms"

          # Fail if metrics don't meet targets
          if (( $(echo "$SUCCESS_RATE < 99" | bc -l) )); then
            echo "Error: Success rate below 99%"
            exit 1
          fi

          if (( $(echo "$P99_MS > 500" | bc -l) )); then
            echo "Error: p99 latency above 500ms"
            exit 1
          fi

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: load-test-results
          path: results.json
```

---

## Advanced Scenarios

### Distributed Load Testing

Run load from multiple machines:

```bash
# Machine 1
./load_test --host production.smtp.com -c 5000 -d 300 --json > machine1.json

# Machine 2
./load_test --host production.smtp.com -c 5000 -d 300 --json > machine2.json

# Combine results
jq -s '
  {
    total_connections: (.[0].connections.total + .[1].connections.total),
    total_messages: (.[0].messages.total + .[1].messages.total),
    combined_rate: ((.[0].messages.rate + .[1].messages.rate))
  }
' machine1.json machine2.json
```

---

### Custom Message Content

Modify `load_test.zig` to send custom messages:

```zig
const message =
    \\From: custom@example.com
    \\To: recipient@example.com
    \\Subject: Custom Test Message
    \\Content-Type: text/html
    \\
    \\<html><body>Custom HTML content</body></html>
    \\
    \\.
    \\
;
```

---

### TLS Load Testing

Test TLS performance:

```bash
# Enable TLS in server
export SMTP_ENABLE_TLS=true
export SMTP_TLS_CERT=/path/to/cert.pem
export SMTP_TLS_KEY=/path/to/key.pem

# Run load test (update load_test.zig to enable TLS)
./load_test --host localhost --port 2525
```

---

## Best Practices

### 1. Baseline First

Always establish baseline performance before optimizations:

```bash
# Run baseline test
./load_test -c 100 -d 60 --json > baseline.json

# Make changes...

# Run comparison test
./load_test -c 100 -d 60 --json > after.json

# Compare
jq -s '.[1].messages.rate / .[0].messages.rate' baseline.json after.json
```

### 2. Incremental Load

Gradually increase load to find breaking point:

```bash
for CONN in 100 500 1000 2000 5000 10000; do
  echo "Testing with $CONN connections..."
  ./load_test -c $CONN -d 60 --json > results_${CONN}.json
  sleep 30  # Cool down between tests
done
```

### 3. Monitor Server

Always monitor server during load tests:

```bash
# Terminal 1: Run load test
./load_test -c 10000 -d 300

# Terminal 2: Monitor server
watch -n 1 'curl -s http://localhost:8081/stats | jq .'

# Terminal 3: Monitor system
htop
```

### 4. Cleanup Between Tests

Ensure clean state:

```bash
# Stop server
pkill mail

# Clean database
rm -f smtp.db smtp.db-shm smtp.db-wal

# Restart server
./zig-out/bin/mail &
sleep 5

# Run test
./load_test -c 1000 -d 60
```

---

## See Also

- [PERFORMANCE.md](PERFORMANCE.md) - Performance optimization guide
- [MONITORING.md](MONITORING.md) - Monitoring setup
- [DEPLOYMENT_RUNBOOK.md](DEPLOYMENT_RUNBOOK.md) - Production deployment
- [API_REFERENCE.md](API_REFERENCE.md) - REST API reference

---

**Last Updated:** 2025-10-24
**Version:** v0.28.0
