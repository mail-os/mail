import type { createMailApi } from './mail-api'
import { state } from '@stacksjs/stx'

interface ForwardingState {
  address: string | null
  pendingAddress: string | null
  expiresAt: number | null
  revision: number
}

type Action = 'request' | 'confirm' | 'cancel' | 'disable'
const endpoint = '/webmail/api/forwarding'

export function useForwarding(api: ReturnType<typeof createMailApi>) {
  const forwarding = state<ForwardingState | null>(null)
  const forwardingAddress = state('')
  const forwardingPassword = state('')
  const forwardingCode = state('')
  const forwardingBusy = state(false)
  const forwardingError = state('')
  const forwardingNotice = state('')
  let request = 0

  function clearForwarding(): void {
    request += 1
    forwarding.set(null)
    forwardingAddress.set('')
    forwardingPassword.set('')
    forwardingCode.set('')
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
    const body = {
      action,
      revision: settings.revision,
      ...(action === 'request' ? { address: forwardingAddress() } : {}),
      ...(action === 'request' || action === 'disable' ? { currentPassword: forwardingPassword() } : {}),
      ...(action === 'confirm' ? { code: forwardingCode() } : {}),
    }
    const current = request
    forwardingBusy.set(true)
    forwardingError.set('')
    forwardingNotice.set('')
    forwardingPassword.set('')
    try {
      const result = await api<ForwardingState>(endpoint, { method: 'POST', body: JSON.stringify(body) })
      if (current !== request) return
      forwarding.set(result)
      forwardingAddress.set(result.pendingAddress || '')
      forwardingCode.set('')
      const messages = {
        request: '',
        confirm: 'Forwarding is on.',
        cancel: 'Verification request cancelled.',
        disable: 'Forwarding is off.',
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

  return { forwarding, forwardingAddress, forwardingPassword, forwardingCode, forwardingBusy, forwardingError, forwardingNotice, loadForwarding, changeForwarding, clearForwarding }
}
