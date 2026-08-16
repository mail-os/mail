# Quick Release Guide

The cheat sheet. [RELEASE_PROCESS.md](RELEASE_PROCESS.md) explains what each step
does and why.

## Cut a release

```bash
pantry run release:patch   # 0.2.0 → 0.2.1
pantry run release:minor   # 0.2.0 → 0.3.0
pantry run release:major   # 0.2.0 → 1.0.0
pantry run release         # prompts for the level
```

Each one runs the preflight, bumps every manifest in the workspace, regenerates
`CHANGELOG.md`, commits, tags and pushes. The tag push is what builds and
publishes the release.

`bun run release:patch` is the same command — `pantry run` just forwards to it.

## Look before you leap

```bash
pantry run release:dry     # preflight + a bumpx dry run, writes nothing
pantry run changelog       # print the changelog logsmith would generate
bun test scripts           # assert every manifest is on the same version
```

## From the GitHub UI

Actions → **Version Management** → *Run workflow* → pick the level. Tick
*Dry run* to preview without pushing anything.

## Requirements the preflight enforces

- on `main`, and `main` matches `origin/main`
- no uncommitted tracked files
- every versioned manifest on the same version — `package.json` (root and each
  `packages/*`) and `packages/zig/build.zig.zon`

## Commit messages

`CHANGELOG.md` and the GitHub release body are generated from conventional
commits, so anything not prefixed `feat:` / `fix:` / `chore:` / … is dropped
from the release notes. `bun install` installs a `commit-msg` hook that catches
that before it happens.

## After the tag lands

Watch the **Release** workflow. It cross-compiles linux and macOS (x86_64 +
arm64), attaches the binaries to a GitHub release, and publishes `@stacksjs/mail` to
npm.
