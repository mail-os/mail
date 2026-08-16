/**
 * Release driver.
 *
 * bumpx does the work — rewrite the version everywhere, regenerate CHANGELOG.md
 * through logsmith, commit, tag, push — and the pushed tag is what starts
 * .github/workflows/release.yml. This wrapper exists for two reasons bumpx
 * cannot cover on its own:
 *
 *   1. The manifest list. `--recursive` discovers anything named package.json or
 *      build.zig.zon, and bumpx's .gitignore matching only handles top-level
 *      patterns — so in this repo it also finds the vendored Zig dependencies
 *      under packages/zig/{vendor,zig-pkg,pantry}/ and would rewrite their
 *      versions too. The set below is passed explicitly instead.
 *
 *   2. The gate. Nothing in bumpx knows whether *this* tree is allowed to cut a
 *      release, and a tag is not a local mistake — it ships binaries.
 *
 * pantry.jsonc is deliberately not in the list: its version is package metadata
 * that has never tracked releases (the pantry repo does the same), and bumpx
 * cannot rewrite it anyway — its JSONC comment stripper mangles the `https://`
 * in `repository.url` and the parse fails.
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

export type ReleaseLevel = 'patch' | 'minor' | 'major' | 'prompt'

/** Every manifest carrying the release version, relative to the repo root. */
export const VERSIONED_MANIFESTS = [
  'package.json',
  'packages/zig/build.zig.zon',
  'packages/cloud/package.json',
  'packages/devtools/package.json',
  'packages/ts/package.json',
  'packages/webmail/package.json',
] as const

export function readManifestVersion(path: string, source: string): string {
  const version = path.endsWith('.zon')
    ? source.match(/\.version\s*=\s*"([^"]+)"/)?.[1]
    : source.match(/"version"\s*:\s*"([^"]+)"/)?.[1]

  if (!version)
    throw new Error(`Unable to read a version out of ${path}`)

  return version
}

/**
 * bumpx only rewrites a manifest whose current version matches the version it
 * bumped *from*; one that has drifted is skipped **silently** and ships stale.
 * Catch the drift here, and in CI, rather than after the tag is pushed.
 */
export function findVersionDrift(versions: Record<string, string>): string[] {
  const expected = versions['package.json']
  return Object.entries(versions)
    .filter(([, version]) => version !== expected)
    .map(([path, version]) => `${path} is ${version}, expected ${expected}`)
}

export function readManifestVersions(root: string): Record<string, string> {
  return Object.fromEntries(
    VERSIONED_MANIFESTS.map(path => [
      path,
      readManifestVersion(path, readFileSync(resolve(root, path), 'utf8')),
    ]),
  )
}

function run(command: string[], cwd: string): string {
  const result = Bun.spawnSync(command, { cwd, stdout: 'pipe', stderr: 'pipe' })
  const output = `${result.stdout.toString()}${result.stderr.toString()}`
  if (result.exitCode !== 0)
    throw new Error(`${command.join(' ')} failed\n${output}`)
  return output.trim()
}

/** Everything that has to be true before a tag may be pushed. */
export function preflight(root: string, dryRun: boolean): string {
  const versions = readManifestVersions(root)
  const drift = findVersionDrift(versions)
  if (drift.length > 0) {
    throw new Error(
      `Manifest versions are out of sync — bumpx would skip the stragglers:\n  ${drift.join('\n  ')}`,
    )
  }

  const current = versions['package.json']
  if (dryRun)
    return `[dry-run] every manifest is at v${current}`

  if (run(['git', 'branch', '--show-current'], root) !== 'main')
    throw new Error('Releases must run from main')
  if (run(['git', 'status', '--porcelain', '--untracked-files=no'], root))
    throw new Error('Tracked files must be clean before releasing')

  run(['git', 'fetch', 'origin', 'main'], root)
  if (run(['git', 'rev-parse', 'HEAD'], root) !== run(['git', 'rev-parse', 'origin/main'], root))
    throw new Error('main must match origin/main before releasing')

  return `preflight ok — releasing from v${current}`
}

export function bumpxArgs(level: ReleaseLevel, extra: string[]): string[] {
  return [
    // Scoped, not the bare `bumpx` bin name: there is an unrelated `bumpx` on
    // npm, and bunx reaches for it whenever node_modules has not been installed.
    '@stacksjs/bumpx',
    level,
    '--no-recursive',
    '--files',
    VERSIONED_MANIFESTS.join(','),
    '--commit',
    '--tag',
    '--push',
    // `prompt` is the interactive level; forcing --yes would defeat it.
    ...(level === 'prompt' ? [] : ['--yes']),
    ...extra,
  ]
}

if (import.meta.main) {
  const level = process.argv[2] as ReleaseLevel
  if (!['patch', 'minor', 'major', 'prompt'].includes(level)) {
    console.error('usage: bun scripts/release.ts <patch|minor|major|prompt> [--dry-run]')
    process.exit(2)
  }

  const root = resolve(import.meta.dir, '..')
  const dryRun = process.argv.includes('--dry-run')

  try {
    console.log(preflight(root, dryRun))
  }
  catch (error) {
    console.error(`✖ ${error instanceof Error ? error.message : error}`)
    process.exit(1)
  }

  const args = bumpxArgs(level, dryRun ? ['--dry-run', '--no-git-check'] : [])
  const bumpx = Bun.spawnSync(['bunx', '--bun', ...args], { cwd: root, stdio: ['inherit', 'inherit', 'inherit'] })
  process.exit(bumpx.exitCode ?? 1)
}
