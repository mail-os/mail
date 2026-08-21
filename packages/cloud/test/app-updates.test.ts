/**
 * Guards the one thing this package promises about auto-updates: that the
 * `compute.appUpdates` declaration in cloud.config.ts actually reaches a
 * provisioned instance.
 *
 * It asserts against the real exported config rather than a fixture, so
 * deleting or renaming the declaration fails here instead of silently
 * producing an instance that never updates itself — a failure mode that is
 * invisible until months later, when a box is found running an old release.
 */

import { describe, expect, it } from 'bun:test'
import { InfrastructureGenerator } from '@stacksjs/ts-cloud'
import config from '../cloud.config'

/** Decode the UserData off whichever EC2 instance the template defines. */
function instanceUserData(template: any): string {
  const instance: any = Object.values(template.Resources ?? {})
    .find((r: any) => r.Type === 'AWS::EC2::Instance')
  const encoded = instance?.Properties?.UserData
  const raw = encoded?.['Fn::Base64'] ?? encoded
  return typeof raw === 'string' ? raw : JSON.stringify(raw)
}

describe('mail server auto-updates', () => {
  it('declares the mail binary as a self-updating tool', () => {
    const targets = config.infrastructure?.compute?.appUpdates
    expect(targets).toBeDefined()
    expect(targets).toHaveLength(1)
    expect(targets![0].service).toBe('mail')
    expect(targets![0].binary).toEndWith('/mail-server')
  })

  it('renders the updater timer into the instance boot script', () => {
    const generator = new InfrastructureGenerator({ config, environment: 'production' })
    generator.generate()
    const userData = instanceUserData(JSON.parse(generator.toJSON()))

    expect(userData).toContain('/etc/systemd/system/mail-upgrade.service')
    expect(userData).toContain('/etc/systemd/system/mail-upgrade.timer')
    expect(userData).toContain('systemctl enable --now mail-upgrade.timer')
    expect(userData).toContain('upgrade --path')
    expect(userData).toContain('--service mail')
  })

  it('keeps the updater units out of this repo — ts-cloud owns that text', async () => {
    // The point of the refactor: this file declares, the framework renders.
    // Scoped to the *upgrade* units on purpose — the unrelated logrotate timer
    // this config writes by hand is not what moved.
    const text = await Bun.file(new URL('../cloud.config.ts', import.meta.url)).text()
    expect(text).not.toContain('mail-upgrade.service')
    expect(text).not.toContain('mail-upgrade.timer')
    expect(text).not.toContain('--install-timer')
  })
})
