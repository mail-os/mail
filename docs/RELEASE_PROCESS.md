# Release Process

This document describes how to create releases for the SMTP server using zig-bump.

## Overview

The release process is automated using [zig-bump](https://github.com/stacksjs/zig-bump), a fast version bumping tool for Zig projects. When you bump the version, zig-bump will:

1. Update the version in `build.zig.zon`
2. Create a git commit
3. Create a git tag (e.g., `v0.1.0`)
4. Push the changes and tag to GitHub
5. Trigger the release workflow automatically

The GitHub Actions release workflow will then:
- Build binaries for all supported platforms
- Build and push Docker images
- Create a GitHub release with all artifacts

## Prerequisites

1. Install zig-bump:
   ```bash
   make install
   ```

2. Ensure you have commit access to the repository
3. Ensure you're on the `main` branch and it's up to date:
   ```bash
   git checkout main
   git pull origin main
   ```

## Quick Start

### Using Interactive Script (Easiest!) 🎯

The interactive release script provides a guided experience:

```bash
./scripts/release.sh
# or
make release
```

**Features:**
- 🎨 Beautiful colored interface
- ✅ Pre-release checklist (CHANGELOG, tests)
- 📊 Visual version preview
- 🔍 Dry-run option
- ✋ Confirmation before release
- 🎯 Clear next steps after release

**What it looks like:**
```
╔═══════════════════════════════════════════════════════╗
║         Mail Server Release Manager                  ║
╚═══════════════════════════════════════════════════════╝

[INFO] Current version: v0.0.0

Pre-Release Checklist

▶ Have you updated CHANGELOG.md? [y/N]
▶ Have all tests passed? [y/N]

╔═══════════════════════════════════════════════════════╗
║         Select Version to Bump                       ║
╚═══════════════════════════════════════════════════════╝

  1) Patch  v0.0.0 → v0.0.1
     └─ Bug fixes, security patches, minor updates

  2) Minor  v0.0.0 → v0.1.0
     └─ New features, backwards compatible changes

  3) Major  v0.0.0 → v1.0.0
     └─ Breaking changes, major refactors

  4) Dry Run - Preview changes without applying

  0) Cancel

Enter selection [1-4, 0 to cancel]:
```

### Using Zig Build (Recommended for automation)

The native Zig way - no external tools needed:

```bash
# Patch release (0.0.1 -> 0.0.2) - Bug fixes
zig build bump-patch

# Minor release (0.0.1 -> 0.1.0) - New features
zig build bump-minor

# Major release (0.0.1 -> 1.0.0) - Breaking changes
zig build bump-major

# Interactive mode (choose version type)
zig build bump

# Dry-run (preview without applying)
zig build bump-patch-dry
zig build bump-minor-dry
zig build bump-major-dry
```

### Using Make (Alternative)

For those who prefer Makefile shortcuts:

```bash
# Patch release (0.0.1 -> 0.0.2)
make release-patch

# Minor release (0.0.1 -> 0.1.0)
make release-minor

# Major release (0.0.1 -> 1.0.0)
make release-major

# Interactive mode (choose version type)
make bump-interactive
```

### Using the Script Directly (Alternative)

```bash
# Bump patch version
./scripts/bump-version.sh patch

# Bump minor version
./scripts/bump-version.sh minor

# Bump major version
./scripts/bump-version.sh major

# Interactive mode
./scripts/bump-version.sh
```

### Using zig-bump Binary Directly (Low-level)

If you want full control:

```bash
# The bump binary is built automatically with zig build
./zig-out/bin/bump patch
./zig-out/bin/bump minor
./zig-out/bin/bump major

# Interactive mode
./zig-out/bin/bump
```

## Release Types

Following [Semantic Versioning](https://semver.org/):

- **Patch** (x.y.Z): Bug fixes, minor changes
- **Minor** (x.Y.0): New features, backwards compatible
- **Major** (X.0.0): Breaking changes

## Detailed Process

### 1. Prepare the Release

Before bumping the version:

1. Ensure all changes are committed:
   ```bash
   git status
   ```

2. Update the CHANGELOG.md (recommended):
   ```bash
   vim CHANGELOG.md
   ```

   Add a new section for the version:
   ```markdown
   ## [0.1.0] - 2025-10-24

   ### Added
   - Feature X
   - Feature Y

   ### Fixed
   - Bug A
   - Bug B

   ### Changed
   - Updated dependency Z
   ```

3. Commit the changelog:
   ```bash
   git add CHANGELOG.md
   git commit -m "docs: update changelog for v0.1.0"
   git push
   ```

### 2. Bump the Version

Using native Zig build (recommended):

```bash
zig build bump-patch  # or bump-minor, bump-major
```

Or using Make:

```bash
make release-patch  # or release-minor, release-major
```

Or using the script:

```bash
./scripts/bump-version.sh patch
```

This will:
- Update `build.zig.zon`
- Create a commit with message: `chore: release vX.Y.Z`
- Create an annotated git tag: `vX.Y.Z`
- Push the commit and tag to GitHub

### 3. Monitor the Release

1. Go to the [Actions tab](../../actions) on GitHub
2. Watch the "Release" workflow
3. The workflow will:
   - Build binaries for Linux (x86_64)
   - Build binaries for macOS (x86_64, ARM64)
   - Build and push Docker images
   - Create a GitHub release

### 4. Verify the Release

1. Check the [Releases page](../../releases)
2. Verify the release includes:
   - Release notes (from CHANGELOG.md or auto-generated)
   - Binary artifacts for all platforms
   - Docker image tag in the description

3. Test the Docker image:
   ```bash
   docker pull <username>/mail:X.Y.Z
   docker run <username>/mail:X.Y.Z
   ```

## Advanced Options

### Dry Run

Preview what would happen without making changes:

```bash
~/Code/zig-bump/zig-out/bin/bump patch --dry-run
```

### Skip Push

Bump and commit locally without pushing:

```bash
~/Code/zig-bump/zig-out/bin/bump patch --no-push
```

### Custom Tag Name

Use a custom tag name:

```bash
~/Code/zig-bump/zig-out/bin/bump patch --tag-name "release-0.1.0"
```

### Skip Git Operations

Just update the version file:

```bash
~/Code/zig-bump/zig-out/bin/bump patch --no-commit
```

## Manual Release (GitHub Actions)

You can also trigger a release manually from GitHub:

1. Go to [Actions](../../actions)
2. Select "Version Management" workflow
3. Click "Run workflow"
4. Choose the release type (patch/minor/major)
5. Optionally enable dry-run mode
6. Click "Run workflow"

## Rollback

If you need to rollback a release:

1. Delete the tag locally and remotely:
   ```bash
   git tag -d vX.Y.Z
   git push origin :refs/tags/vX.Y.Z
   ```

2. Delete the GitHub release (if created)

3. Revert the version commit:
   ```bash
   git revert HEAD
   git push
   ```

## Troubleshooting

### Issue: "zig-bump not found"

Run:
```bash
make install
```

### Issue: "Permission denied"

Make the script executable:
```bash
chmod +x scripts/bump-version.sh
```

### Issue: "Not in a git repository"

Ensure you're in the project root directory.

### Issue: "Uncommitted changes"

Commit or stash your changes before bumping:
```bash
git stash
make release-patch
git stash pop
```

### Issue: "Failed to push"

Ensure you have push permissions and are authenticated:
```bash
git config --list | grep remote.origin.url
```

## CI/CD Integration

The release process integrates with two workflows:

1. **version.yml**: Manual version bumping via GitHub Actions
2. **release.yml**: Automatically triggered on version tags

### Workflow Trigger Chain

```
make release-patch
  ↓
zig-bump updates version
  ↓
git commit + tag + push
  ↓
GitHub detects tag push (v*)
  ↓
release.yml workflow starts
  ↓
Build → Docker → GitHub Release
```

## Best Practices

1. **Always update CHANGELOG.md** before releasing
2. **Use semantic versioning** consistently
3. **Test thoroughly** before releasing
4. **Use patch releases** for bug fixes
5. **Use minor releases** for new features
6. **Use major releases** for breaking changes
7. **Tag releases** with descriptive messages
8. **Document** breaking changes clearly

## Examples

### Example 1: Bug Fix Release

```bash
# Fix bugs
git add .
git commit -m "fix: resolve connection timeout issue"

# Update changelog
vim CHANGELOG.md
git add CHANGELOG.md
git commit -m "docs: update changelog for v0.0.2"

# Release (choose one)
zig build bump-patch    # Recommended
make release-patch      # Alternative
```

### Example 2: Feature Release

```bash
# Implement feature
git add .
git commit -m "feat: add DKIM signature support"

# Update changelog
vim CHANGELOG.md
git add CHANGELOG.md
git commit -m "docs: update changelog for v0.1.0"

# Release (choose one)
zig build bump-minor    # Recommended
make release-minor      # Alternative
```

### Example 3: Breaking Change Release

```bash
# Implement breaking changes
git add .
git commit -m "feat!: redesign configuration format"

# Update changelog and migration guide
vim CHANGELOG.md
vim docs/MIGRATION.md
git add CHANGELOG.md docs/MIGRATION.md
git commit -m "docs: update changelog and migration guide for v1.0.0"

# Release (choose one)
zig build bump-major    # Recommended
make release-major      # Alternative
```

## Resources

- [zig-bump Documentation](https://github.com/stacksjs/zig-bump)
- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)

## Support

If you encounter issues with the release process:

1. Check this documentation
2. Review the GitHub Actions logs
3. Open an issue on the repository
4. Contact the maintainers
