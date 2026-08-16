import { resolve } from 'node:path'
import { describe, expect, test } from 'bun:test'
import { bumpxArgs, findVersionDrift, readManifestVersion, readManifestVersions, VERSIONED_MANIFESTS } from './release'

const root = resolve(import.meta.dir, '..')

describe('mail release', () => {
  test('reads versions out of both manifest flavours', () => {
    expect(readManifestVersion('packages/zig/build.zig.zon', '.{ .version = "0.4.2", }')).toBe('0.4.2')
    expect(readManifestVersion('package.json', '{ "version": "0.4.2" }')).toBe('0.4.2')
  })

  test('reports every manifest that drifted away from the root version', () => {
    expect(findVersionDrift({ 'package.json': '1.0.0', 'packages/ts/package.json': '1.0.0' })).toEqual([])
    expect(findVersionDrift({ 'package.json': '1.0.0', 'packages/ts/package.json': '0.9.0' }))
      .toEqual(['packages/ts/package.json is 0.9.0, expected 1.0.0'])
  })

  // The guard that matters: bumpx skips a drifted manifest silently, so this
  // failing in CI is the only thing standing between drift and a stale release.
  test('every manifest is in lockstep today', () => {
    expect(findVersionDrift(readManifestVersions(root))).toEqual([])
  })

  test('confines bumpx to the listed manifests', () => {
    const args = bumpxArgs('patch', [])
    expect(args).toContain('--no-recursive')
    expect(args[args.indexOf('--files') + 1]).toBe(VERSIONED_MANIFESTS.join(','))
    expect(args).toContain('--yes')
  })

  test('leaves the interactive level interactive', () => {
    expect(bumpxArgs('prompt', [])).not.toContain('--yes')
  })
})
