# Release Process

Releases are cut with [bumpx](https://github.com/stacksjs/bumpx) and
[logsmith](https://github.com/stacksjs/logsmith), both of which arrive with the
`better-dx` dev dependency — there is nothing else to install.

## The one-liner

```bash
pantry run release:patch   # or release:minor, release:major
```

`bun run release:patch` does the same thing; `pantry run` just forwards to it.

## What that actually does

1. **`scripts/release.ts`** refuses to continue unless the tree is releasable:
   on `main`, no uncommitted tracked files, `main` matching `origin/main`, and —
   the one bumpx cannot check for itself — every versioned manifest sitting on
   the same version.
2. **bumpx** rewrites the version in each of them:
   - `package.json` (root) and each `packages/*/package.json`
   - `packages/zig/build.zig.zon`
3. **logsmith** (invoked by bumpx) regenerates `CHANGELOG.md` from the
   conventional commits since the last tag and prepends the new section.
4. bumpx commits the lot, tags it `vX.Y.Z`, and pushes both.
5. The tag push starts `.github/workflows/release.yml`, which cross-compiles
   every target, attaches the binaries to a GitHub release whose body logsmith
   regenerates for that tag range, and publishes `ts-mail` to npm.

The version bump is therefore repo-wide: one tag, one version, every package.

### Why the manifest list is explicit

`scripts/release.ts` passes bumpx `--no-recursive --files <list>` rather than
letting it discover manifests. Recursive discovery walks the tree for anything
named `package.json` or `build.zig.zon`, and bumpx's `.gitignore` matching only
handles top-level patterns — so it also finds the vendored Zig dependencies
under `packages/zig/vendor/`, `packages/zig/zig-pkg/` and `packages/zig/pantry/`
and rewrites *their* versions too.

`pantry.jsonc` is not in the list. Its version is package metadata that has
never tracked releases, and bumpx cannot rewrite it anyway: its JSONC comment
stripper mangles the `https://` in `repository.url` and the parse fails, so the
file is skipped without a word.

### Why the manifests must stay in lockstep

bumpx only rewrites a manifest whose current version matches the version it is
bumping *from*. A manifest that has drifted is skipped **silently** and ships
stale. `bun test scripts` asserts they all match, and CI runs it on every PR, so
drift fails a pull request rather than a release.

## Preview before you push

```bash
pantry run release:dry     # preflight + a bumpx dry run
pantry run changelog       # print the changelog logsmith would generate
```

Neither writes anything or touches git.

## Releasing from GitHub Actions

The **Version Management** workflow (`.github/workflows/version.yml`) is the
same flow, run manually from the Actions tab: pick `patch`/`minor`/`major`, tick
*Dry run* to preview. It calls the same `scripts/release.ts`, and pushes the tag
as `github-actions[bot]`.

## Commit messages matter

logsmith builds both `CHANGELOG.md` and the GitHub release body from
conventional commits, so a malformed subject line just disappears from the
release. The `commit-msg` git hook runs `gitlint` to catch that locally; run
`bun install` once to install the hook.

| prefix | lands in | bump it deserves |
| --- | --- | --- |
| `fix:` | Bug Fixes | patch |
| `feat:` | Features | minor |
| `feat!:` / `BREAKING CHANGE:` | Breaking Changes | major |
| `chore:`, `ci:`, `docs:` | grouped, low prominence | patch |

## Manual changelog regeneration

```bash
pantry run changelog:generate   # rewrites CHANGELOG.md in place
```

logsmith prepends new sections under the existing `# Changelog` heading, so the
hand-written history further down the file is preserved.

## Troubleshooting

**"Manifest versions are out of sync"** — the preflight lists exactly which file
drifted and what it expected. Set it by hand to the root `package.json` version,
commit, and re-run.

**"Releases must run from main" / "Tracked files must be clean"** — the preflight
is doing its job. A tag is not a local mistake; it ships binaries.

**"Git working tree is not clean"** from bumpx — same cause, raised by bumpx's
own check after the preflight passed (something changed in between).

**The release notes look generic** — the Pantry action is configured with
`release-changelog: auto`, so it regenerates the notes with logsmith over
previous-tag → this-tag. Empty notes mean no conventional commits landed in that
range.

**A release tag exists but no release appeared** — check the Release workflow
run. The cross-compile step is the long pole; the Pantry action only creates the
release after every required target has been built.

## Resources

- [bumpx](https://github.com/stacksjs/bumpx)
- [logsmith](https://github.com/stacksjs/logsmith)
- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)
