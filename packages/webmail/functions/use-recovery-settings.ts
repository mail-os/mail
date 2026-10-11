import type { createMailApi } from './mail-api'
import { state } from '@stacksjs/stx'
import { recoveryAddressProblem } from './recovery'

/** What GET/PUT /webmail/auth/recovery return. */
export interface RecoveryState {
  recovery: string | null
  /** Who set it: the mailbox owner, or the operator (deploy configuration). */
  setBy: 'user' | 'operator' | null
}

type Api = ReturnType<typeof createMailApi>

/**
 * The recovery address section of account settings. Saving asks for the
 * mailbox password again: an open session alone must not be enough to send
 * the account's reset links somewhere else.
 */
export function useRecoverySettings(api: Api, mailbox: () => string) {
  const recoveryAddress = state<string | null>(null)
  const recoverySetBy = state<RecoveryState['setBy']>(null)
  const recoveryInput = state('')
  const recoveryPassword = state('')
  const recoveryError = state('')
  const recoveryNotice = state('')
  const recoveryLoading = state(false)
  const savingRecovery = state(false)

  function install(result: RecoveryState): void {
    recoveryAddress.set(result.recovery)
    recoverySetBy.set(result.setBy)
    recoveryInput.set(result.recovery || '')
  }

  async function loadRecovery(): Promise<void> {
    recoveryError.set('')
    recoveryNotice.set('')
    recoveryPassword.set('')
    recoveryLoading.set(true)
    try { install(await api<RecoveryState>('/webmail/auth/recovery')) }
    catch (cause) { recoveryError.set(cause instanceof Error ? cause.message : 'Could not load the recovery address.') }
    finally { recoveryLoading.set(false) }
  }

  async function saveRecovery(): Promise<void> {
    if (savingRecovery()) return
    recoveryError.set('')
    recoveryNotice.set('')
    const wanted = recoveryInput().trim()
    const problem = recoveryAddressProblem(mailbox(), wanted)
    if (problem) { recoveryError.set(problem); return }
    if (!recoveryPassword()) { recoveryError.set('Enter your current password to change the recovery address.'); return }
    savingRecovery.set(true)
    try {
      install(await api<RecoveryState>('/webmail/auth/recovery', { method: 'PUT', body: JSON.stringify({ currentPassword: recoveryPassword(), recovery: wanted }) }))
      recoveryPassword.set('')
      recoveryNotice.set(wanted ? 'Recovery address saved.' : 'Recovery address removed. Password reset by email is off for this mailbox.')
    }
    catch (cause) { recoveryError.set(cause instanceof Error ? cause.message : 'Could not save the recovery address.') }
    finally { savingRecovery.set(false) }
  }

  return { recoveryAddress, recoverySetBy, recoveryInput, recoveryPassword, recoveryError, recoveryNotice, recoveryLoading, savingRecovery, loadRecovery, saveRecovery }
}
