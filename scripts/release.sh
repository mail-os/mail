#!/usr/bin/env bash

# Interactive release script for the mail server project
# This script provides a user-friendly interface for version bumping and releasing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${BOLD}${CYAN}$1${NC}"
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}▶${NC} $1"
}

# Change to project root
cd "$PROJECT_ROOT"

# Clear screen for better UX
clear

# Print header
echo ""
print_header "╔═══════════════════════════════════════════════════════╗"
print_header "║         Mail Server Release Manager                  ║"
print_header "╚═══════════════════════════════════════════════════════╝"
echo ""

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "Not in a git repository!"
    exit 1
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    print_warn "You have uncommitted changes:"
    echo ""
    git status --short
    echo ""
    read -p "$(echo -e ${YELLOW}Continue anyway? [y/N]:${NC} )" -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Aborting. Please commit or stash your changes first."
        exit 1
    fi
    echo ""
fi

# Get current version
CURRENT_VERSION=$(grep -o '\.version = "[^"]*"' "$PROJECT_ROOT/build.zig.zon" | cut -d'"' -f2)

# Display current version
print_info "Current version: ${BOLD}${CYAN}v$CURRENT_VERSION${NC}"
echo ""

# Check if bump binary exists
BUMP_BIN="$PROJECT_ROOT/zig-out/bin/bump"
if [ ! -f "$BUMP_BIN" ]; then
    print_step "Building zig-bump..."
    zig build install-bump
    echo ""
fi

# Pre-release checklist
print_header "Pre-Release Checklist"
echo ""
print_step "Have you updated CHANGELOG.md? [y/N]"
read -n 1 -r CHANGELOG_UPDATED
echo ""
if [[ ! $CHANGELOG_UPDATED =~ ^[Yy]$ ]]; then
    print_warn "Consider updating CHANGELOG.md before releasing"
    echo ""
    read -p "$(echo -e ${YELLOW}Edit CHANGELOG.md now? [y/N]:${NC} )" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        ${EDITOR:-vim} CHANGELOG.md
        echo ""
        print_info "Please commit CHANGELOG.md changes and run this script again"
        exit 0
    fi
fi

echo ""
print_step "Have all tests passed? [y/N]"
read -n 1 -r TESTS_PASSED
echo ""
if [[ ! $TESTS_PASSED =~ ^[Yy]$ ]]; then
    print_warn "Consider running tests before releasing"
    echo ""
    read -p "$(echo -e ${YELLOW}Run tests now? [y/N]:${NC} )" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_step "Running tests..."
        zig build test
        echo ""
        print_info "Tests passed! Continuing with release..."
        echo ""
    else
        print_error "Aborting release. Please run tests first."
        exit 1
    fi
fi

echo ""
print_header "╔═══════════════════════════════════════════════════════╗"
print_header "║         Select Version to Bump                       ║"
print_header "╚═══════════════════════════════════════════════════════╝"
echo ""

# Calculate version options
IFS='.' read -ra VERSION_PARTS <<< "$CURRENT_VERSION"
MAJOR="${VERSION_PARTS[0]}"
MINOR="${VERSION_PARTS[1]}"
PATCH="${VERSION_PARTS[2]}"

NEXT_PATCH="$MAJOR.$MINOR.$((PATCH + 1))"
NEXT_MINOR="$MAJOR.$((MINOR + 1)).0"
NEXT_MAJOR="$((MAJOR + 1)).0.0"

# Display version options with descriptions
echo -e "  ${YELLOW}${BOLD}1)${NC} ${BOLD}Patch${NC}  v$CURRENT_VERSION → ${GREEN}v$NEXT_PATCH${NC}"
echo -e "     ${CYAN}└─${NC} Bug fixes, security patches, minor updates"
echo ""
echo -e "  ${YELLOW}${BOLD}2)${NC} ${BOLD}Minor${NC}  v$CURRENT_VERSION → ${GREEN}v$NEXT_MINOR${NC}"
echo -e "     ${CYAN}└─${NC} New features, backwards compatible changes"
echo ""
echo -e "  ${YELLOW}${BOLD}3)${NC} ${BOLD}Major${NC}  v$CURRENT_VERSION → ${GREEN}v$NEXT_MAJOR${NC}"
echo -e "     ${CYAN}└─${NC} Breaking changes, major refactors"
echo ""
echo -e "  ${YELLOW}${BOLD}4)${NC} ${BOLD}Dry Run${NC} - Preview changes without applying"
echo ""
echo -e "  ${YELLOW}${BOLD}0)${NC} ${BOLD}Cancel${NC}"
echo ""

# Get user selection
read -p "$(echo -e ${BOLD}Enter selection [1-4, 0 to cancel]:${NC} )" SELECTION

case $SELECTION in
    1)
        BUMP_TYPE="patch"
        NEW_VERSION="$NEXT_PATCH"
        DESCRIPTION="Bug fixes"
        ;;
    2)
        BUMP_TYPE="minor"
        NEW_VERSION="$NEXT_MINOR"
        DESCRIPTION="New features"
        ;;
    3)
        BUMP_TYPE="major"
        NEW_VERSION="$NEXT_MAJOR"
        DESCRIPTION="Breaking changes"
        ;;
    4)
        echo ""
        print_header "Dry Run Mode"
        echo ""
        print_info "Select version type for preview:"
        echo ""
        echo "  1) Patch"
        echo "  2) Minor"
        echo "  3) Major"
        echo ""
        read -p "Selection: " DRY_SELECTION

        case $DRY_SELECTION in
            1) DRY_TYPE="patch" ;;
            2) DRY_TYPE="minor" ;;
            3) DRY_TYPE="major" ;;
            *) print_error "Invalid selection"; exit 1 ;;
        esac

        echo ""
        print_step "Running dry-run for $DRY_TYPE version bump..."
        echo ""
        "$BUMP_BIN" "$DRY_TYPE" --dry-run
        echo ""
        print_info "This was a preview. No changes were made."
        exit 0
        ;;
    0)
        print_info "Release cancelled"
        exit 0
        ;;
    *)
        print_error "Invalid selection"
        exit 1
        ;;
esac

# Confirm the release
echo ""
print_header "╔═══════════════════════════════════════════════════════╗"
print_header "║         Confirm Release                              ║"
print_header "╚═══════════════════════════════════════════════════════╝"
echo ""
echo -e "  ${BOLD}Release Type:${NC}    $BUMP_TYPE ($DESCRIPTION)"
echo -e "  ${BOLD}Current Version:${NC} v$CURRENT_VERSION"
echo -e "  ${BOLD}New Version:${NC}     ${GREEN}v$NEW_VERSION${NC}"
echo ""
echo -e "  ${BOLD}This will:${NC}"
echo -e "    • Update build.zig.zon"
echo -e "    • Create a git commit"
echo -e "    • Create a git tag (v$NEW_VERSION)"
echo -e "    • Push to GitHub"
echo -e "    • Trigger the release workflow"
echo ""

read -p "$(echo -e ${BOLD}${YELLOW}Proceed with release? [y/N]:${NC} )" -r
echo

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Release cancelled"
    exit 0
fi

# Execute the version bump
echo ""
print_header "╔═══════════════════════════════════════════════════════╗"
print_header "║         Executing Release                            ║"
print_header "╚═══════════════════════════════════════════════════════╝"
echo ""

print_step "Bumping version from v$CURRENT_VERSION to v$NEW_VERSION..."
echo ""

# Run the bump command
"$BUMP_BIN" "$BUMP_TYPE"

# Check if successful
if [ $? -eq 0 ]; then
    echo ""
    print_header "╔═══════════════════════════════════════════════════════╗"
    print_header "║         Release Complete! 🎉                         ║"
    print_header "╚═══════════════════════════════════════════════════════╝"
    echo ""
    print_info "Version ${GREEN}v$NEW_VERSION${NC} has been released!"
    echo ""
    echo -e "  ${BOLD}Next steps:${NC}"
    echo -e "    1. Monitor the release workflow on GitHub Actions"
    echo -e "    2. Check the release page: ${CYAN}https://github.com/<your-repo>/releases${NC}"
    echo -e "    3. Verify Docker image: ${CYAN}docker pull <username>/mail:$NEW_VERSION${NC}"
    echo ""
    print_info "The release workflow will build binaries and create a GitHub release."
    echo ""
else
    echo ""
    print_error "Release failed!"
    print_info "Please check the error messages above and try again."
    exit 1
fi
