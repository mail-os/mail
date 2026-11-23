import type { createMailApi } from './mail-api'
import { state } from '@stacksjs/stx'

interface ForwardingState {
  address: string | null
  pendingAddress: string | null
  expiresAt: number | null
  revision: number
  scope: { sender: string | null, recipient: string | null }
}

type Action = 'request' | 'confirm' | 'cancel' | 'disable' | 'scope'
const endpoint = '/webmail/api/forwarding'

export function useForwarding(api: ReturnType<typeof createMailApi>) {
  const forwarding = state<ForwardingState | null>(null)
  const forwardingAddress = state('')
  const forwardingPassword = state('')
  const forwardingCode = state('')
  const forwardingMode = state('all')
  const forwardingSenderFilter = state('')
  const forwardingRecipientFilter = state('')
  const forwardingScopePassword = state('')
  const forwardingBusy = state(false)
  const forwardingError = state('')
  const forwardingNotice = state('')
  let request = 0

  function showScope(scope?: ForwardingState['scope']): void {
    forwardingMode.set(scope?.sender || scope?.recipient ? 'matching' : 'all')
    forwardingSenderFilter.set(scope?.sender || '')
    forwardingRecipientFilter.set(scope?.recipient || '')
    forwardingScopePassword.set('')
  }

  function clearForwarding(): void {
    request += 1
    forwarding.set(null)
    forwardingAddress.set('')
    forwardingPassword.set('')
    forwardingCode.set('')
    showScope()
    forwardingBusy.set(false)
    forwardingError.set('')
    forwardingNotice.set('')
  }

  async function loadForwarding(): Promise<void> {
    clearForwarding()
    const current = request
    forwardingBusy.set(true)
    try {
      const result = await api<ForwardingState>(endpoint)
      if (current !== request) return
      forwarding.set(result)
      forwardingAddress.set(result.pendingAddress || '')
      showScope(result.scope)
    }
    catch (cause) {
      if (current === request) forwardingError.set(cause instanceof Error ? cause.message : 'Could not load forwarding.')
    }
    finally {
      if (current === request) forwardingBusy.set(false)
    }
  }

  async function changeForwarding(action: Action): Promise<void> {
    const settings = forwarding()
    if (!settings || forwardingBusy()) return
    const usesScope = action === 'confirm' || action === 'scope'
    const matching = forwardingMode() === 'matching'
    const scope = {
      sender: matching ? forwardingSenderFilter().trim() || null : null,
      recipient: matching ? forwardingRecipientFilter().trim() || null : null,
    }
    if (usesScope && matching && !scope.sender && !scope.recipient) {
      forwardingError.set('Enter a sender or a delivered-to address.')
      return
    }
    const body = {
      action,
      revision: settings.revision,
      ...(action === 'request' ? { address: forwardingAddress() } : {}),
      ...(action === 'request' || action === 'disable' ? { currentPassword: forwardingPassword() } : {}),
      ...(action === 'scope' ? { currentPassword: forwardingScopePassword() } : {}),
      ...(action === 'confirm' ? { code: forwardingCode() } : {}),
      ...(usesScope ? { scope } : {}),
    }
    const current = request
    forwardingBusy.set(true)
    forwardingError.set('')
    forwardingNotice.set('')
    forwardingPassword.set('')
    forwardingScopePassword.set('')
    try {
      const result = await api<ForwardingState>(endpoint, { method: 'POST', body: JSON.stringify(body) })
      if (current !== request) return
      forwarding.set(result)
      forwardingAddress.set(result.pendingAddress || '')
      forwardingCode.set('')
      showScope(result.scope)
      const messages = {
        request: '',
        confirm: 'Forwarding is on.',
        cancel: 'Verification request cancelled.',
        disable: 'Forwarding is off.',
        scope: 'Forwarding filters saved.',
      }
      forwardingNotice.set(messages[action])
    }
    catch (cause) {
      if (current === request) forwardingError.set(cause instanceof Error ? cause.message : 'Could not update forwarding.')
    }
    finally {
      if (current === request) forwardingBusy.set(false)
    }
  }

  return { forwarding, forwardingAddress, forwardingPassword, forwardingCode, forwardingMode, forwardingSenderFilter, forwardingRecipientFilter, forwardingScopePassword, forwardingBusy, forwardingError, forwardingNotice, loadForwarding, changeForwarding, clearForwarding }
}
