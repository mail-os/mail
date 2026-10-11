import { describe, expect, test } from 'bun:test'
import { newPasswordProblem, recoveryAddressProblem, resetErrorMessage, tokenFromHash } from './functions/recovery'

const token = 'ab'.repeat(32)

describe('reset links', () => {
  test('read the token from the fragment and nothing else', () => {
    expect(tokenFromHash(`#token=${token}`)).toBe(token)
    expect(tokenFromHash(`token=${token.toUpperCase()}`)).toBe(token)
    expect(tokenFromHash('')).toBe('')
    expect(tokenFromHash('#token=short')).toBe('')
    expect(tokenFromHash(`#token=${token}zz`)).toBe('')
    expect(tokenFromHash(`#other=${token}`)).toBe('')
  })

  test('explain failures without telling anything about the mailbox', () => {
    expect(resetErrorMessage(400)).toContain('invalid, already used or expired')
    expect(resetErrorMessage(429)).toContain('wait')
    expect(resetErrorMessage(500, 'fallback')).toBe('fallback')
  })
})

describe('new password', () => {
  test('matches the server bounds and asks for a matching confirmation', () => {
    expect(newPasswordProblem('short', 'short')).toContain('12')
    expect(newPasswordProblem('long-enough-pass', 'different-pass!')).toContain('do not match')
    expect(newPasswordProblem('x'.repeat(1025), 'x'.repeat(1025))).toContain('1024')
    expect(newPasswordProblem('long-enough-pass', 'long-enough-pass')).toBe('')
  })
})

describe('recovery address', () => {
  test('is an address outside the mailbox, or empty to remove it', () => {
    expect(recoveryAddressProblem('pawel@hq.training', 'pawel@outlook.de')).toBe('')
    expect(recoveryAddressProblem('pawel@hq.training', '  ')).toBe('')
    expect(recoveryAddressProblem('pawel@hq.training', 'Pawel@HQ.training')).toContain('outside this mailbox')
    expect(recoveryAddressProblem('pawel@hq.training', 'not-an-address')).toContain('valid')
    expect(recoveryAddressProblem('pawel@hq.training', 'x@localhost')).toContain('valid')
    expect(recoveryAddressProblem('pawel@hq.training', 'a b@c.de')).toContain('valid')
  })
})
