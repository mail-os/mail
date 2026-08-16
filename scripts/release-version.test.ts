import { describe, expect, test } from 'bun:test'
import { nextVersion, readZigVersion } from './release-version'

describe('mail release versions', () => {
  test('calculates every release level', () => {
    expect(nextVersion('1.2.3', 'patch')).toBe('1.2.4')
    expect(nextVersion('1.2.3', 'minor')).toBe('1.3.0')
    expect(nextVersion('1.2.3', 'major')).toBe('2.0.0')
  })

  test('reads the Zig package version', () => {
    expect(readZigVersion('.{ .version = "0.4.2", }')).toBe('0.4.2')
  })
})
