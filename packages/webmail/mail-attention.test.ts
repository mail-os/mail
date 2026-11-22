import { expect, test } from 'bun:test'
import { fileURLToPath } from 'node:url'

const modulePath = fileURLToPath(new URL('./functions/mail-attention.ts', import.meta.url))

function inZone(zone: string, body: string): string {
  const program = 'import { localDateInput, localDeadline } from ' + JSON.stringify(modulePath) + '; ' + body
  const result = Bun.spawnSync([process.execPath, '-e', program], { env: { ...process.env, TZ: zone } })
  expect(result.success).toBe(true)
  return result.stdout.toString().trim()
}

test('workflow deadlines persist as the same UTC instant across browser time zones', () => {
  const fromLosAngeles = inZone('America/Los_Angeles', 'console.log(localDeadline("2026-12-04T09:30", 0))')
  const fromTokyo = inZone('Asia/Tokyo', 'console.log(localDeadline("2026-12-05T02:30", 0))')
  expect(fromLosAngeles).toBe(String(Date.UTC(2026, 11, 4, 17, 30) / 1000))
  expect(fromTokyo).toBe(fromLosAngeles)
})

test('workflow local dates handle daylight saving and reject nonexistent wall times', () => {
  expect(inZone('America/Los_Angeles', `
    try { localDeadline("2026-03-08T02:30", 0) }
    catch { console.log("nonexistent") }
    console.log(localDateInput(new Date("2026-03-08T10:30:00Z")))
  `)).toBe('nonexistent\n2026-03-08T03:30')
})
