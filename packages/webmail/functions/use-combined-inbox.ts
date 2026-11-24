import { derived, state } from '@stacksjs/stx'
import { createMailApi, MailApiError } from './mail-api'
import type { IndexProgress, MessageSummary, User } from './mail-types'

interface Account { id: string, username: string, address: string }
interface Row { source: Account, message: MessageSummary }
interface Listing { page: number, total: number, more: boolean, items: Row[], index: IndexProgress }
interface Accounts { owner: Account, accounts: Account[] }
interface ActionReport { account: string, affected: number, error_code?: string }
type Action = 'read' | 'unread' | 'archive' | 'trash'
const endpoint = '/webmail/api/combined'

export function combinedMessageKey(row: Row): string {
  return `${row.source.id}:${row.message.reference}`
}

export function combinedMessagePath(row: Row): string {
  const query = new URLSearchParams({ message: row.message.reference ?? '', account: row.source.username })
  if (row.source.id) query.set('linked', row.source.id)
  return `/?${query}`
}

export function useCombinedInbox(signIn: () => void) {
  const user = state<User | null>(null)
  const accounts = state<Account[]>([])
  const linking = state(false)
  const manageOpen = state(false)
  const username = state('')
  const password = state('')
  const linkFactor = state('')
  const linkNeedsFactor = state(false)
  const query = state('')
  const searchScope = state('inbox')
  const listing = state<Listing | null>(null)
  const loading = state(true)
  const busy = state(false)
  const error = state('')
  const notice = state('')
  const selection = state<string[]>([])
  const selectedRows = derived(() => (listing()?.items ?? []).filter(row => selection().includes(combinedMessageKey(row))))
  const channel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel('mail-combined-accounts')
  let active = true
  let pending: AbortController | undefined
  let appliedQuery = ''
  let pageNumber = 1
  let scanNotice = false
  const api = createMailApi(() => user()?.username, () => {
    if (!active) return
    destroy()
    signIn()
  }, () => active)

  function hideStaleResults() {
    pending?.abort()
    pending = undefined
    listing.set(null)
    selection.set([])
  }

  async function refresh() {
    if (!active || !user() || busy()) return
    pending?.abort()
    const request = new AbortController()
    pending = request
    loading.set(true)
    const params = new URLSearchParams({ q: appliedQuery, scope: searchScope(), page: String(pageNumber), index_budget: '256' })
    try {
      const [result, linked] = await Promise.all([
        api<Listing>(`${endpoint}/messages?${params}`, { signal: request.signal }),
        api<Accounts>(`${endpoint}/accounts`, { signal: request.signal }),
      ])
      if (pending !== request || !active) return
      const available = new Set(linked.accounts.map(account => account.id))
      if (result.items.some(row => row.source.id && !available.has(row.source.id))) {
        // The accounts lookup can finish before or after the list lookup.
        hideStaleResults()
        await refresh()
        return
      }
      accounts.set(linked.accounts)
      listing.set(result)
      pageNumber = result.page
      const visible = new Set(result.items.map(combinedMessageKey))
      selection.update(keys => keys.filter(key => visible.has(key)))
      if (scanNotice) error.set('')
      scanNotice = false
    }
    catch (cause) {
      if (pending !== request || !active) return
      if (cause instanceof MailApiError && cause.code === 'linked_account_unavailable') {
        hideStaleResults()
        void refresh()
        return
      }
      error.set(cause instanceof Error ? cause.message : 'The combined inbox could not be loaded.')
      scanNotice = true
    }
    finally {
      if (pending === request) {
        pending = undefined
        loading.set(false)
      }
    }
  }

  function runSearch() {
    appliedQuery = query().trim()
    pageNumber = 1
    selection.set([])
    void refresh()
  }

  function turnPage(delta: number) {
    const current = listing()
    if (!current || busy() || loading() || (delta < 0 ? current.page <= 1 : !current.more)) return
    pageNumber = current.page + delta
    selection.set([])
    void refresh()
  }

  function toggleRow(row: Row) {
    const key = combinedMessageKey(row)
    selection.update(keys => keys.includes(key) ? keys.filter(value => value !== key) : [...keys, key])
  }

  function cancelLink() {
    password.set('')
    linkFactor.set('')
    linkNeedsFactor.set(false)
    linking.set(false)
  }

  function toggleAccountManagement() {
    if (busy()) return
    if (manageOpen()) cancelLink()
    manageOpen.set(!manageOpen())
  }

  async function changeAccounts(id: string | null = null) {
    if (busy()) return
    busy.set(true)
    error.set('')
    notice.set('')
    const credentials = { username: username().trim(), password: password(), ...(linkNeedsFactor() ? { factor: linkFactor().trim() } : {}) }
    linkFactor.set('')
    if (id) hideStaleResults()
    try {
      const response = await api<Accounts>(`${endpoint}/accounts${id ? '/' + encodeURIComponent(id) : ''}`,
        id ? { method: 'DELETE' } : { method: 'POST', body: JSON.stringify(credentials) })
      if (!active) return
      accounts.set(response.accounts)
      username.set('')
      cancelLink()
      notice.set(id ? 'Mailbox removed from this browser.' : 'Mailbox added to this browser.')
      channel?.postMessage(id ?? '')
      pageNumber = 1
    }
    catch (cause) {
      if (!active) return
      if (!id && cause instanceof MailApiError && cause.code === 'factor_required') {
        linkNeedsFactor.set(true)
        return
      }
      if (!id && (!linkNeedsFactor() || (cause instanceof MailApiError && cause.code === 'invalid_credentials'))) {
        password.set('')
        linkNeedsFactor.set(false)
      }
      error.set(cause instanceof Error ? cause.message : 'Could not change the linked mailboxes.')
    }
    finally {
      if (active) {
        busy.set(false)
        if (!linkNeedsFactor()) await refresh()
      }
    }
  }

  async function applyAction(action: Action) {
    if (busy() || !selectedRows().length) return
    const messages = selectedRows().map(row => ({ account: row.source.id, reference: row.message.reference, revision: row.message.revision }))
    busy.set(true)
    error.set('')
    notice.set('')
    try {
      const report = await api<{ items: ActionReport[] }>(`${endpoint}/actions`, { method: 'POST', body: JSON.stringify({ action, messages }) })
      if (!active) return
      selection.set([])
      const affected = report.items.reduce((sum, item) => sum + item.affected, 0)
      if (affected > 0) notice.set(affected === 1 ? '1 message updated.' : `${affected} messages updated.`)
      if (report.items.some(item => item.error_code)) error.set('Some messages changed or their accounts were removed. Check the current list.')
    }
    catch (cause) {
      if (active) error.set(cause instanceof Error ? cause.message : 'Could not update the selected messages.')
    }
    finally {
      if (active) {
        busy.set(false)
        await refresh()
      }
    }
  }

  async function mount() {
    try {
      const result = await api<{ user: User }>('/webmail/auth/me')
      if (!active) return
      user.set(result.user)
      if (globalThis.location?.href && new URL(globalThis.location.href).searchParams.get('notice') === 'removed')
        notice.set('The linked mailbox is no longer available.')
      if (channel) channel.onmessage = () => {
        hideStaleResults()
        void refresh()
      }
      await refresh()
    }
    catch (cause) {
      if (active) error.set(cause instanceof Error ? cause.message : 'Could not open the combined inbox.')
    }
    finally { if (active && !pending) loading.set(false) }
  }

  function destroy() {
    active = false
    hideStaleResults()
    channel?.close()
    cancelLink()
  }

  return {
    user, accounts, linking, manageOpen, username, password, linkFactor, linkNeedsFactor, query, searchScope, listing, loading, busy, error, notice, selection, selectedRows,
    mount, destroy, refresh, runSearch, turnPage, toggleRow, changeAccounts, applyAction, cancelLink, toggleAccountManagement,
  }
}
