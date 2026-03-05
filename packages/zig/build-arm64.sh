#!/bin/bash
# Build mail server for ARM64 Linux
# This script downloads sqlite3 source and builds statically

set -e

echo "Building mail server for ARM64 Linux..."

# For cross-compilation, we need to either:
# 1. Use a pre-built sqlite3 for ARM64
# 2. Build sqlite3 from source
# 3. Remove sqlite3 dependency

# Option 3: Build without sqlite3 for now (use in-memory or file-based storage)
# The main server can work without sqlite3 if we disable the database features

# Try building with static linking
zig build \
    -Dtarget=aarch64-linux-gnu \
    -Doptimize=ReleaseFast \
    --verbose 2>&1 || echo "Build failed - see errors above"

# Check if binary was created
if [ -f "zig-out/bin/mail-aarch64-linux" ]; then
    echo "✅ Built: zig-out/bin/mail-aarch64-linux"
    file zig-out/bin/mail-aarch64-linux
else
    echo "❌ Build failed"
fi
