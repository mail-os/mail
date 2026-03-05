# Release Checklist

Use this checklist when preparing and executing releases.

## Pre-Release Checklist

- [ ] All changes committed and pushed
- [ ] Tests passing (`zig build test`)
- [ ] Code formatted (`zig fmt src/`)
- [ ] CHANGELOG.md updated with release notes
- [ ] Version bump type determined (patch/minor/major)
- [ ] No uncommitted changes (`git status`)
- [ ] On main branch (`git branch --show-current`)
- [ ] Branch up to date (`git pull origin main`)

## Release Preparation

- [ ] Review changes since last release
  ```bash
  git log $(git describe --tags --abbrev=0)..HEAD --oneline
  ```
- [ ] Update CHANGELOG.md with:
  - Version number and date
  - Added features
  - Changed functionality
  - Fixed bugs
  - Breaking changes (if any)
- [ ] Update documentation if needed
- [ ] Run integration tests
  ```bash
  ./scripts/test-version-bump.sh
  ```

## Release Execution

Choose one:

### Option A: Using Makefile (Recommended)
- [ ] Execute release command:
  ```bash
  make release-patch   # For bug fixes
  make release-minor   # For new features
  make release-major   # For breaking changes
  ```

### Option B: Using Script
- [ ] Execute bump script:
  ```bash
  ./scripts/bump-version.sh patch
  ./scripts/bump-version.sh minor
  ./scripts/bump-version.sh major
  ```

### Option C: Using GitHub Actions
- [ ] Go to Actions → Version Management
- [ ] Click "Run workflow"
- [ ] Select release type
- [ ] Click "Run workflow"

## Post-Release Verification

- [ ] Verify version tag pushed to GitHub
  ```bash
  git fetch --tags
  git tag -l | tail -5
  ```
- [ ] Monitor release workflow in GitHub Actions
  - [ ] Build jobs completed successfully
  - [ ] Docker job completed successfully
  - [ ] Release job completed successfully
- [ ] Verify GitHub Release created
  - [ ] Release notes present
  - [ ] Binary artifacts attached (Linux, macOS)
  - [ ] Version number correct
- [ ] Test Docker image
  ```bash
  docker pull <username>/mail:<version>
  docker run <username>/mail:<version>
  ```
- [ ] Verify binaries work
  ```bash
  # Download from GitHub releases
  # Test on each platform
  ```

## Post-Release Tasks

- [ ] Announce release (if applicable)
  - [ ] Social media
  - [ ] Mailing list
  - [ ] Discord/Slack
  - [ ] Project website
- [ ] Update documentation site (if applicable)
- [ ] Create milestone for next version
- [ ] Update project roadmap

## Rollback (If Needed)

If something goes wrong:

1. Delete the tag locally and remotely:
   ```bash
   git tag -d v<version>
   git push origin :refs/tags/v<version>
   ```

2. Delete the GitHub release
   - Go to Releases
   - Click on the release
   - Click "Delete this release"

3. Revert the version commit:
   ```bash
   git revert HEAD
   git push origin main
   ```

4. Fix the issues

5. Try again with corrected version

## Common Issues

### Issue: Tag already exists
**Solution:** Delete the tag first
```bash
git tag -d v<version>
git push origin :refs/tags/v<version>
```

### Issue: GitHub Actions failing
**Solution:** Check workflow logs
- Go to Actions tab
- Click on the failed workflow
- Review error messages
- Fix issues and re-tag

### Issue: Docker push fails
**Solution:** Check Docker credentials
- Verify DOCKER_USERNAME secret
- Verify DOCKER_PASSWORD secret
- Test login manually:
  ```bash
  docker login -u <username>
  ```

### Issue: Binaries not building for all platforms
**Solution:** Check build configuration
- Review build.zig cross-compilation settings
- Check if all dependencies available on target platforms
- Review workflow matrix configuration

## Emergency Release Process

If you need to release urgently:

1. Ensure critical fixes are tested
2. Update only critical sections of CHANGELOG
3. Use `--no-verify` if needed (not recommended):
   ```bash
   ./zig-out/bin/bump patch --no-verify
   ```
4. Monitor release closely
5. Be ready to rollback
6. Update documentation afterward

## Version Numbering Guide

Following Semantic Versioning (semver.org):

**MAJOR.MINOR.PATCH** (e.g., 1.2.3)

- **MAJOR**: Breaking changes
  - API changes
  - Removed functionality
  - Incompatible changes
  - Example: 1.0.0 → 2.0.0

- **MINOR**: New features (backwards compatible)
  - New functionality
  - New features
  - Deprecations (but not removals)
  - Example: 1.0.0 → 1.1.0

- **PATCH**: Bug fixes (backwards compatible)
  - Bug fixes
  - Security patches
  - Performance improvements
  - Example: 1.0.0 → 1.0.1

## Notes

- Always test with `--dry-run` first when unsure
- Keep CHANGELOG.md up to date
- Communicate breaking changes clearly
- Follow semantic versioning strictly
- Tag all releases consistently
- Document all major changes
- Test releases on all platforms when possible
