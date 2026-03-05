#!/bin/bash
# Cross-platform build script for mail server
# Builds for all supported platforms and architectures

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Build configuration
BUILD_MODE="${1:-ReleaseSafe}"
OUTPUT_DIR="${2:-releases}"

echo -e "${GREEN}Cross-Platform Build Script${NC}"
echo "=================================="
echo "Build mode: $BUILD_MODE"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Define targets
declare -a TARGETS=(
    "x86_64-linux-gnu"
    "aarch64-linux-gnu"
    "x86_64-macos"
    "aarch64-macos"
    "x86_64-windows-gnu"
    "aarch64-windows-gnu"
    "x86_64-freebsd"
    "aarch64-freebsd"
    "x86_64-openbsd"
)

# Build for each target
build_target() {
    local target=$1
    echo -e "${YELLOW}Building for $target...${NC}"

    # Parse target triple
    IFS='-' read -ra PARTS <<< "$target"
    local arch="${PARTS[0]}"
    local os="${PARTS[1]}"
    local abi="${PARTS[2]:-}"

    # Construct zig target
    local zig_target="$arch-$os"
    if [ -n "$abi" ]; then
        zig_target="$zig_target-$abi"
    fi

    # Build
    if zig build -Dtarget="$zig_target" -Doptimize="$BUILD_MODE"; then
        echo -e "${GREEN}✓ Built successfully: $target${NC}"

        # Copy to releases directory
        local binary_name="mail"
        if [[ "$os" == "windows" ]]; then
            binary_name="mail.exe"
        fi

        local output_name="mail-$target"
        if [[ "$os" == "windows" ]]; then
            output_name="$output_name.exe"
        fi

        if [ -f "zig-out/bin/$binary_name" ]; then
            cp "zig-out/bin/$binary_name" "$OUTPUT_DIR/$output_name"
            echo -e "${GREEN}✓ Copied to: $OUTPUT_DIR/$output_name${NC}"

            # Create checksum
            (cd "$OUTPUT_DIR" && shasum -a 256 "$output_name" > "$output_name.sha256")
        fi
    else
        echo -e "${RED}✗ Build failed: $target${NC}"
        return 1
    fi

    echo ""
}

# Build all targets
echo -e "${GREEN}Starting cross-platform builds...${NC}"
echo ""

FAILED_TARGETS=()
for target in "${TARGETS[@]}"; do
    if ! build_target "$target"; then
        FAILED_TARGETS+=("$target")
    fi
done

# Summary
echo -e "${GREEN}=================================="
echo "Build Summary"
echo "==================================${NC}"

TOTAL=${#TARGETS[@]}
FAILED=${#FAILED_TARGETS[@]}
SUCCESS=$((TOTAL - FAILED))

echo "Total targets: $TOTAL"
echo -e "${GREEN}Successful: $SUCCESS${NC}"

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED${NC}"
    echo ""
    echo "Failed targets:"
    for target in "${FAILED_TARGETS[@]}"; do
        echo -e "  ${RED}- $target${NC}"
    done
    exit 1
fi

# Create release archive
if [ "$SUCCESS" -gt 0 ]; then
    echo ""
    echo -e "${GREEN}Creating release archive...${NC}"

    VERSION=$(grep 'version' build.zig.zon | cut -d'"' -f2 || echo "latest")
    ARCHIVE_NAME="mail-$VERSION-all-platforms.tar.gz"

    tar -czf "$OUTPUT_DIR/$ARCHIVE_NAME" -C "$OUTPUT_DIR" \
        --exclude="*.tar.gz" \
        .

    echo -e "${GREEN}✓ Created: $OUTPUT_DIR/$ARCHIVE_NAME${NC}"

    # List all binaries
    echo ""
    echo -e "${GREEN}Built binaries:${NC}"
    ls -lh "$OUTPUT_DIR" | grep mail | grep -v sha256 | grep -v tar.gz
fi

echo ""
echo -e "${GREEN}✓ Cross-platform build complete!${NC}"
