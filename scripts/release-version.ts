import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

export type ReleaseLevel = 'patch' | 'minor' | 'major'

export function nextVersion(version: string, level: ReleaseLevel): string {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version)
  if (!match) throw new TypeError(`Invalid semantic version: ${version}`)
  const major = Number(match[1])
  const minor = Number(match[2])
  const patch = Number(match[3])
  if (level === 'major') return `${major + 1}.0.0`
  if (level === 'minor') return `${major}.${minor + 1}.0`
  return `${major}.${minor}.${patch + 1}`
}

export function readZigVersion(source: string): string {
  const version = source.match(/\.version\s*=\s*"([^"]+)"/)?.[1]
  if (!version) throw new Error('Unable to read packages/zig/build.zig.zon version')
  return version
}

function run(command: string[], cwd: string): string {
  const result = Bun.spawnSync(command, { cwd, stdout: 'pipe', stderr: 'pipe' })
  const output = `${result.stdout.toString()}${result.stderr.toString()}`
  if (result.exitCode !== 0) throw new Error(`${command.join(' ')} failed\n${output}`)
  return output.trim()
}

function replaceZigVersion(source: string, current: string, next: string): string {
  return source.replace(`.version = "${current}"`, `.version = "${next}"`)
}

export function release(level: ReleaseLevel, dryRun = false): string {
  const root = resolve(import.meta.dir, '..')
  const zigPath = resolve(root, 'packages/zig/build.zig.zon')
  const sdkPath = resolve(root, 'packages/ts/package.json')
  const zigSource = readFileSync(zigPath, 'utf8')
  const sdk = JSON.parse(readFileSync(sdkPath, 'utf8')) as { version: string }
  const current = readZigVersion(zigSource)
  const next = nextVersion(current, level)
  const message = `mail ${current} -> ${next}; ts-mail ${sdk.version} -> ${next}`

  if (dryRun) return `[dry-run] ${message}`

  if (run(['git', 'branch', '--show-current'], root) !== 'main')
    throw new Error('Releases must run from main')
  if (run(['git', 'status', '--porcelain', '--untracked-files=no'], root))
    throw new Error('Tracked files must be clean before releasing')

  run(['git', 'fetch', 'origin', 'main'], root)
  const localHead = run(['git', 'rev-parse', 'HEAD'], root)
  const remoteHead = run(['git', 'rev-parse', 'origin/main'], root)
  if (localHead !== remoteHead) throw new Error('main must match origin/main before releasing')

  writeFileSync(zigPath, replaceZigVersion(zigSource, current, next))
  writeFileSync(sdkPath, `${JSON.stringify({ ...sdk, version: next }, null, 2)}\n`)
  run(['git', 'add', 'packages/zig/build.zig.zon', 'packages/ts/package.json'], root)
  run(['git', 'commit', '-m', `chore: release v${next}`], root)
  run(['git', 'tag', '-a', `v${next}`, '-m', `Release v${next}`], root)
  run(['git', 'push', '--atomic', 'origin', 'main', `v${next}`], root)
  return message
}

if (import.meta.main) {
  const level = process.argv[2]
  if (!['patch', 'minor', 'major'].includes(level ?? '')) {
    console.error('usage: bun scripts/release-version.ts <patch|minor|major> [--dry-run]')
    process.exit(2)
  }
  console.log(release(level as ReleaseLevel, process.argv.includes('--dry-run')))
}
