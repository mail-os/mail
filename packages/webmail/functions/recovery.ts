/**
 * Password reset and recovery address helpers shared by the reset page and
 * the settings dialog. Pure functions, so they are tested without a browser.
 */

/** A reset token is 32 bytes as 64 lowercase hex characters. */
const TOKEN = /^[0-9a-f]{64}$/

/**
 * The token from a reset link's fragment (`#token=<hex>`). The link carries
 * it in the fragment so it never reaches a server log; anything that is not a
 * well-formed token reads as none.
 */
export function tokenFromHash(hash: string): string {
  const params = new URLSearchParams(hash.replace(/^#/, ''))
  const token = (params.get('token') || '').trim().toLowerCase()
  return TOKEN.test(token) ? token : ''
}

export const MIN_PASSWORD_LENGTH = 12

/** Why a new password cannot be submitted, or '' when it can. */
export function newPasswordProblem(password: string, confirmation: string): string {
  if (password.length < MIN_PASSWORD_LENGTH) return `Use at least ${MIN_PASSWORD_LENGTH} characters.`
  if (password.length > 1024) return 'Use at most 1024 characters.'
  if (password !== confirmation) return 'The new passwords do not match.'
  return ''
}

/**
 * Why a recovery address cannot be saved for `mailbox`, or '' when it can.
 * An empty address is allowed: it removes the recovery address. The server
 * applies the same rules; this only answers sooner.
 */
export function recoveryAddressProblem(mailbox: string, address: string): string {
  const value = address.trim()
  if (!value) return ''
  if (!/^[^\s@,;:"<>\\/]+@[^\s@,;:"<>\\/]+\.[^\s@,;:"<>\\/]+$/.test(value)) return 'Enter a valid email address.'
  if (value.toLowerCase() === mailbox.trim().toLowerCase()) return 'Use an address outside this mailbox.'
  return ''
}

/** The message for a failed reset request, by HTTP status. */
export function resetErrorMessage(status: number, fallback = 'Something went wrong. Please try again.'): string {
  if (status === 429) return 'Too many attempts. Please wait a few minutes.'
  if (status === 400) return 'This reset link is invalid, already used or expired. Ask for a new one.'
  return fallback
}
