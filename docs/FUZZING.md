# Fuzzing Guide

**Version:** v0.28.0
**Date:** 2025-10-24

## Overview

This document describes how to use fuzzing to test the SMTP server for security vulnerabilities and crashes caused by malformed input.

## What is Fuzzing?

Fuzzing (or fuzz testing) is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a program. The goal is to find bugs, crashes, memory leaks, and security vulnerabilities.

## Available Fuzz Targets

### 1. SMTP Protocol Fuzzer

Tests SMTP command parsing for robustness against malformed protocol commands.

**File:** `tests/fuzz_smtp_protocol.zig`

**Coverage:**
- SMTP command parsing (HELO, EHLO, MAIL FROM, RCPT TO, DATA, QUIT)
- Email address validation
- MAIL FROM parsing with angle brackets
- RCPT TO parsing with angle brackets

**Build:**
```bash
zig build-exe tests/fuzz_smtp_protocol.zig \
  -fsanitize=fuzzer \
  -fsanitize=address \
  -fsanitize=undefined \
  --name fuzz_smtp_protocol
```

**Run:**
```bash
# Create corpus directory
mkdir -p corpus/smtp_protocol

# Run fuzzer
./fuzz_smtp_protocol corpus/smtp_protocol
```

---

### 2. MIME Parser Fuzzer

Tests MIME message parsing for robustness against malformed MIME content.

**File:** `tests/fuzz_mime_parser.zig`

**Coverage:**
- MIME header parsing
- Content-Type parsing
- Multipart boundary extraction
- Base64 decoding
- Quoted-Printable decoding

**Build:**
```bash
zig build-exe tests/fuzz_mime_parser.zig \
  -fsanitize=fuzzer \
  -fsanitize=address \
  -fsanitize=undefined \
  --name fuzz_mime_parser
```

**Run:**
```bash
# Generate initial corpus
mkdir -p corpus/mime_parser

# Run fuzzer
./fuzz_mime_parser corpus/mime_parser
```

---

## Using libFuzzer (Built-in)

Zig's `-fsanitize=fuzzer` flag uses LLVM's libFuzzer.

### Basic Usage

```bash
# Build fuzz target
zig build-exe tests/fuzz_smtp_protocol.zig -fsanitize=fuzzer

# Run with default settings
./fuzz_smtp_protocol corpus_dir/

# Run with specific options
./fuzz_smtp_protocol corpus_dir/ \
  -max_len=8192 \
  -timeout=10 \
  -runs=1000000
```

### Common Options

- `-max_len=N`: Maximum input length (bytes)
- `-timeout=N`: Timeout per input (seconds)
- `-runs=N`: Number of runs (0 = infinite)
- `-dict=file`: Use dictionary file
- `-jobs=N`: Parallel fuzzing jobs
- `-workers=N`: Number of workers
- `-print_final_stats=1`: Print statistics at end

### Example

```bash
# Fuzz SMTP protocol with 10 parallel jobs, 5-second timeout
./fuzz_smtp_protocol corpus/smtp_protocol \
  -jobs=10 \
  -timeout=5 \
  -max_len=4096 \
  -print_final_stats=1
```

---

## Using AFL (American Fuzzy Lop)

AFL is a popular fuzzing tool with excellent code coverage.

### Install AFL

```bash
# Ubuntu/Debian
sudo apt-get install afl++

# macOS
brew install afl++
```

### Build with AFL

```bash
# Set AFL compiler
export CC=afl-clang-fast
export CXX=afl-clang-fast++

# Build with AFL instrumentation
zig build-exe tests/fuzz_smtp_protocol.zig \
  -Doptimize=ReleaseFast \
  --name fuzz_smtp_protocol_afl

# Or use afl-zig (if available)
afl-zig build-exe tests/fuzz_smtp_protocol.zig
```

### Run AFL

```bash
# Create corpus directories
mkdir -p corpus_in/smtp_protocol corpus_out/smtp_protocol

# Add seed inputs
echo "HELO example.com" > corpus_in/smtp_protocol/helo.txt
echo "MAIL FROM:<user@example.com>" > corpus_in/smtp_protocol/mail.txt
echo "RCPT TO:<user@example.com>" > corpus_in/smtp_protocol/rcpt.txt

# Run AFL
afl-fuzz -i corpus_in/smtp_protocol -o corpus_out/smtp_protocol -- ./fuzz_smtp_protocol_afl @@
```

### AFL Options

- `-i dir`: Input corpus directory
- `-o dir`: Output directory (for crashes, hangs, etc.)
- `-M name`: Master fuzzer (for parallel fuzzing)
- `-S name`: Slave fuzzer (for parallel fuzzing)
- `-t timeout`: Timeout (ms)

### Parallel Fuzzing with AFL

```bash
# Terminal 1: Master
afl-fuzz -i corpus_in -o corpus_out -M fuzzer1 -- ./fuzz_smtp_protocol @@

# Terminal 2: Slave
afl-fuzz -i corpus_in -o corpus_out -S fuzzer2 -- ./fuzz_smtp_protocol @@

# Terminal 3: Slave
afl-fuzz -i corpus_in -o corpus_out -S fuzzer3 -- ./fuzz_smtp_protocol @@
```

---

## Analyzing Crashes

### Finding Crashes

**libFuzzer:**
Crashes are saved in the current directory as `crash-*` files.

**AFL:**
Crashes are saved in `corpus_out/crashes/` directory.

### Reproducing Crashes

```bash
# With libFuzzer
./fuzz_smtp_protocol crash-da39a3ee5e6b4b0d3255bfef95601890afd80709

# With AFL
./fuzz_smtp_protocol_afl corpus_out/crashes/id:000000,sig:06,src:000000,op:flip1,pos:0
```

### Debugging Crashes

```bash
# Build with debug symbols
zig build-exe tests/fuzz_smtp_protocol.zig -fsanitize=fuzzer -g

# Run with debugger
lldb ./fuzz_smtp_protocol -- crash-file

# Or with GDB
gdb --args ./fuzz_smtp_protocol crash-file
```

### AddressSanitizer Output

```
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
READ of size 1 at 0x... thread T0
    #0 0x... in fuzzSmtpCommand tests/fuzz_smtp_protocol.zig:45
    #1 0x... in LLVMFuzzerTestOneInput tests/fuzz_smtp_protocol.zig:28
```

---

## Creating Seed Corpus

Good seed inputs improve fuzzing efficiency.

### SMTP Protocol Seeds

```bash
mkdir -p corpus/smtp_protocol

# Valid commands
echo "HELO example.com" > corpus/smtp_protocol/helo.txt
echo "EHLO example.com" > corpus/smtp_protocol/ehlo.txt
echo "MAIL FROM:<sender@example.com>" > corpus/smtp_protocol/mail.txt
echo "RCPT TO:<recipient@example.com>" > corpus/smtp_protocol/rcpt.txt
echo "DATA" > corpus/smtp_protocol/data.txt
echo "QUIT" > corpus/smtp_protocol/quit.txt
echo "RSET" > corpus/smtp_protocol/rset.txt
echo "NOOP" > corpus/smtp_protocol/noop.txt
echo "VRFY user@example.com" > corpus/smtp_protocol/vrfy.txt

# Edge cases
echo "HELO" > corpus/smtp_protocol/helo_no_domain.txt
echo "MAIL FROM:<>" > corpus/smtp_protocol/mail_empty.txt
echo "RCPT TO:<user@@example.com>" > corpus/smtp_protocol/rcpt_invalid.txt
```

### MIME Parser Seeds

```bash
mkdir -p corpus/mime_parser

# Simple text message
cat > corpus/mime_parser/text_plain.txt << 'EOF'
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

Hello, World!
EOF

# Multipart message
cat > corpus/mime_parser/multipart.txt << 'EOF'
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Part 1
--boundary123
Content-Type: text/html

<p>Part 2</p>
--boundary123--
EOF

# Base64 encoded
cat > corpus/mime_parser/base64.txt << 'EOF'
Content-Transfer-Encoding: base64

SGVsbG8sIFdvcmxkIQ==
EOF
```

---

## Dictionary Files

Dictionary files provide hints to the fuzzer about interesting input patterns.

### SMTP Dictionary

```bash
cat > smtp.dict << 'EOF'
# SMTP Commands
"HELO"
"EHLO"
"MAIL FROM:"
"RCPT TO:"
"DATA"
"QUIT"
"RSET"
"NOOP"
"VRFY"
"EXPN"

# Common patterns
"<>"
"@"
"\r\n"
"250 "
"550 "

# Email patterns
"@example.com"
"user@"
"@domain"
EOF

# Use dictionary
./fuzz_smtp_protocol corpus/ -dict=smtp.dict
```

---

## Continuous Fuzzing

### CI Integration

```yaml
# .github/workflows/fuzz.yml
name: Fuzzing

on:
  schedule:
    - cron: '0 0 * * *'  # Daily
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    timeout-minutes: 60

    steps:
      - uses: actions/checkout@v3

      - name: Setup Zig
        uses: goto-bus-stop/setup-zig@v2
        with:
          version: 0.15.1

      - name: Build fuzz targets
        run: |
          zig build-exe tests/fuzz_smtp_protocol.zig -fsanitize=fuzzer
          zig build-exe tests/fuzz_mime_parser.zig -fsanitize=fuzzer

      - name: Run fuzzing
        run: |
          mkdir -p corpus/smtp_protocol corpus/mime_parser
          timeout 3000 ./fuzz_smtp_protocol corpus/smtp_protocol || true
          timeout 3000 ./fuzz_mime_parser corpus/mime_parser || true

      - name: Upload crashes
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: crashes
          path: crash-*
```

---

## OSS-Fuzz Integration

[OSS-Fuzz](https://github.com/google/oss-fuzz) provides continuous fuzzing for open source projects.

### Setup

1. Add project to OSS-Fuzz
2. Create build script (`build.sh`)
3. Submit pull request

**Example build.sh:**
```bash
#!/bin/bash
set -e

# Build fuzz targets
zig build-exe $SRC/mail/tests/fuzz_smtp_protocol.zig \
  -fsanitize=fuzzer \
  -fsanitize=address \
  --name fuzz_smtp_protocol

zig build-exe $SRC/mail/tests/fuzz_mime_parser.zig \
  -fsanitize=fuzzer \
  -fsanitize=address \
  --name fuzz_mime_parser

# Copy to output
cp fuzz_smtp_protocol $OUT/
cp fuzz_mime_parser $OUT/

# Copy seed corpus
cp -r corpus/smtp_protocol $OUT/fuzz_smtp_protocol_seed_corpus/
cp -r corpus/mime_parser $OUT/fuzz_mime_parser_seed_corpus/
```

---

## Best Practices

### 1. Start with Good Seeds

Create a diverse seed corpus covering normal and edge cases.

### 2. Use Sanitizers

Always build with AddressSanitizer and UndefinedBehaviorSanitizer:
```bash
zig build-exe tests/fuzz_smtp_protocol.zig \
  -fsanitize=fuzzer \
  -fsanitize=address \
  -fsanitize=undefined
```

### 3. Run Continuously

Fuzz for extended periods (hours or days) to find rare bugs.

### 4. Minimize Corpus

Periodically minimize corpus to remove redundant inputs:
```bash
./fuzz_smtp_protocol -merge=1 corpus_new/ corpus_old/
```

### 5. Monitor Coverage

Track code coverage to ensure fuzzer is exploring code paths:
```bash
zig build-exe tests/fuzz_smtp_protocol.zig \
  -fsanitize=fuzzer \
  -fprofile-instr-generate \
  -fcoverage-mapping
```

### 6. Fix Bugs Quickly

When a crash is found:
1. Reproduce locally
2. Create unit test from crash input
3. Fix the bug
4. Verify fix with fuzzer
5. Add to regression suite

---

## Troubleshooting

### Slow Fuzzing

**Problem:** Fuzzer not finding new paths

**Solutions:**
- Add more diverse seeds
- Use dictionary file
- Reduce `-max_len` to focus on smaller inputs
- Check if code has expensive operations (remove or mock)

### Too Many Crashes

**Problem:** Fuzzer finds many similar crashes

**Solutions:**
- Fix the most common crash first
- Use `-artifact_prefix=` to organize crashes
- Minimize corpus after fixing bugs

### Out of Memory

**Problem:** Fuzzer crashes with OOM

**Solutions:**
- Reduce `-max_len`
- Reduce `-rss_limit_mb`
- Fix memory leaks in code
- Use smaller corpus

---

## See Also

- [LLVM libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [AFL++ Documentation](https://aflplus.plus/)
- [OSS-Fuzz](https://google.github.io/oss-fuzz/)
- [Fuzzing Book](https://www.fuzzingbook.org/)

---

**Last Updated:** 2025-10-24
**Version:** v0.28.0
