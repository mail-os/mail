import type { createMailApi } from './mail-api'
import { state } from '@stacksjs/stx'

const path = '/webmail/api/client-passwords'
const types = { mail: 'Mail', dav: 'Calendars and contacts', exchange: 'Exchange' } as const
type ClientType = keyof typeof types
interface ClientPassword { id: number, label: string, scope: ClientType, created_at: number }

export function useClientPasswords(api: ReturnType<typeof createMailApi>) {
  const clientPasswordsOpen = state(false)
  const canCreateClientPassword = state(false)
  const clientPasswords = state<ClientPassword[]>([])
  const clientPasswordName = state('')
  const clientPasswordType = state<ClientType>('mail')
  const clientMailboxPassword = state('')
  const createdClientPassword = state<{ entry: ClientPassword, password: string } | null>(null)
  const revokingClientPassword = state<ClientPassword | null>(null)
  const clientPasswordsBusy = state(false)
  const clientPasswordsError = state('')
  const clientPasswordsNotice = state('')
  const clientPasswordTypes = Object.entries(types).map(([id, label]) => ({ id, label }))
  let panel = 0

  function closeClientPasswords() {
    panel++
    clientPasswordsOpen.set(false)
    canCreateClientPassword.set(false)
    clientPasswords.set([])
    clientPasswordName.set('')
    clientPasswordType.set('mail')
    clientMailboxPassword.set('')
    createdClientPassword.set(null)
    revokingClientPassword.set(null)
    clientPasswordsBusy.set(false)
    clientPasswordsError.set('')
    clientPasswordsNotice.set('')
  }

  async function toggleClientPasswords() {
    if (clientPasswordsOpen()) {
      closeClientPasswords()
      return
    }
    clientPasswordsOpen.set(true)
    await updateClientPasswords(async (current) => {
      const result = await api<{ passwords: ClientPassword[], can_create: boolean }>(path)
      if (current !== panel) return
      clientPasswords.set(result.passwords)
      canCreateClientPassword.set(result.can_create)
    })
  }

  async function updateClientPasswords(action: (current: number) => Promise<void>) {
    if (clientPasswordsBusy()) return
    const current = panel
    clientPasswordsBusy.set(true)
    clientPasswordsError.set('')
    clientPasswordsNotice.set('')
    try { await action(current) }
    catch (error) {
      if (current === panel)
        clientPasswordsError.set(error instanceof Error ? error.message : 'Could not update app passwords.')
    }
    finally { if (current === panel) clientPasswordsBusy.set(false) }
  }

  async function createClientPassword() {
    if (createdClientPassword()) return
    await updateClientPasswords(async (current) => {
      const body = JSON.stringify({ label: clientPasswordName().trim(), scope: clientPasswordType(), current_password: clientMailboxPassword() })
      clientMailboxPassword.set('')
      const created = await api<{ entry: ClientPassword, password: string }>(path, { method: 'POST', body })
      if (current !== panel) return
      createdClientPassword.set(created)
      clientPasswords.set([created.entry, ...clientPasswords()])
      clientPasswordName.set('')
    })
  }

  async function revokeClientPassword() {
    const entry = revokingClientPassword()
    if (!entry) return
    await updateClientPasswords(async (current) => {
      await api(`${path}/${entry.id}`, { method: 'DELETE' })
      if (current !== panel) return
      if (createdClientPassword()?.entry.id === entry.id) createdClientPassword.set(null)
      clientPasswords.set(clientPasswords().filter(item => item.id !== entry.id))
      revokingClientPassword.set(null)
      clientPasswordsNotice.set('App password revoked.')
    })
  }

  async function copyClientPassword() {
    const created = createdClientPassword()
    if (!created) return
    try {
      await globalThis.navigator.clipboard.writeText(created.password)
      if (createdClientPassword() === created) clientPasswordsNotice.set('App password copied.')
    }
    catch {
      if (createdClientPassword() === created) clientPasswordsNotice.set('Select the displayed password to copy it.')
    }
  }

  function clientPasswordTypeLabel(type: ClientType) { return types[type] }

  return {
    clientPasswordsOpen, canCreateClientPassword, clientPasswords, clientPasswordName, clientPasswordType, clientMailboxPassword,
    createdClientPassword, revokingClientPassword, clientPasswordsBusy, clientPasswordsError, clientPasswordsNotice,
    clientPasswordTypes, clientPasswordTypeLabel, closeClientPasswords, toggleClientPasswords,
    createClientPassword, revokeClientPassword, copyClientPassword,
  }
}
