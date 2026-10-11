import type { Contact, Recipient, RecipientField } from './mail-types'
import { batch, derived, state } from '@stacksjs/stx'
import { mergeRecipients, recipient, recipientKey, recipients } from './mail-utils'

export function useRecipientEditor(search: (query: string) => Promise<Contact[]>) {
  const toRecipients = state<Recipient[]>([])
  const ccRecipients = state<Recipient[]>([])
  const bccRecipients = state<Recipient[]>([])
  const toInput = state('')
  const ccInput = state('')
  const bccInput = state('')
  const recipientFocus = state<RecipientField | ''>('')
  const suggestions = state<Contact[]>([])
  const suggestionIndex = state(-1)
  const recipientSearching = state(false)
  const fields = { to: toRecipients, cc: ccRecipients, bcc: bccRecipients }
  const inputs = { to: toInput, cc: ccInput, bcc: bccInput }
  const recipientErrors = derived(() => Object.values(fields).flatMap(field => field().filter(item => !item.valid).map(item => item.raw)))
  let request = 0
  let timer: ReturnType<typeof setTimeout> | undefined

  function commit(field: RecipientField): void {
    const input = inputs[field]()
    if (input.trim()) fields[field].set(mergeRecipients(fields[field](), recipients(input)))
    inputs[field].set('')
    suggestions.set([])
    suggestionIndex.set(-1)
    recipientSearching.set(false)
    ++request
  }
  function commitAll(): void { batch(() => { commit('to'); commit('cc'); commit('bcc') }) }
  function removeRecipient(field: RecipientField, index: number): void {
    fields[field].update(value => value.filter((item, position) => position !== index))
  }
  function editRecipient(field: RecipientField, index: number): void {
    commit(field)
    const item = fields[field]()[index]
    if (!item) return
    removeRecipient(field, index)
    inputs[field].set(item.raw)
    recipientFocus.set(field)
  }
  function chooseContact(field: RecipientField, contact: Contact): void {
    const item = recipient(contact.address)
    item.name = contact.name
    item.raw = contact.name ? `${contact.name} <${contact.address}>` : contact.address
    fields[field].set(mergeRecipients(fields[field](), [item]))
    inputs[field].set('')
    suggestions.set([])
    suggestionIndex.set(-1)
    recipientSearching.set(false)
    ++request
  }
  function lookup(field: RecipientField): void {
    recipientFocus.set(field)
    clearTimeout(timer)
    const query = inputs[field]().trim()
    const version = ++request
    suggestionIndex.set(-1)
    if (query.length < 2) { suggestions.set([]); recipientSearching.set(false); return }
    recipientSearching.set(true)
    timer = setTimeout(async () => {
      try {
        const result = await search(query)
        if (version !== request || recipientFocus() !== field) return
        const known = new Set(Object.values(fields).flatMap(value => value().map(recipientKey)))
        suggestions.set(result.filter(contact => !known.has(contact.address.toLowerCase())))
      }
      catch { if (version === request) suggestions.set([]) }
      finally { if (version === request) recipientSearching.set(false) }
    }, 180)
  }
  function recipientKeydown(event: KeyboardEvent, field: RecipientField): void {
    if (event.key === 'ArrowDown' && suggestions().length) { event.preventDefault(); suggestionIndex.update(index => (index + 1) % suggestions().length); return }
    if (event.key === 'ArrowUp' && suggestions().length) { event.preventDefault(); suggestionIndex.update(index => (index + suggestions().length - 1) % suggestions().length); return }
    if (event.key === 'Escape' && suggestions().length) { event.preventDefault(); event.stopPropagation(); suggestions.set([]); return }
    if (event.key === 'Enter' || event.key === ';' || event.key === ',') {
      // A comma inside an unfinished quoted display name is ordinary text.
      if (event.key === ',' && (inputs[field]().match(/(?<!\\)"/g)?.length ?? 0) % 2) return
      event.preventDefault()
      if (event.key === 'Enter' && suggestionIndex() >= 0) chooseContact(field, suggestions()[suggestionIndex()])
      else commit(field)
    }
    else if (event.key === 'Backspace' && !inputs[field]() && fields[field]().length) {
      event.preventDefault()
      editRecipient(field, fields[field]().length - 1)
    }
  }
  function recipientBlur(event: FocusEvent, field: RecipientField): void {
    const target = event.relatedTarget
    if (target instanceof Element && target.closest('[data-recipient-suggestion]')) return
    commit(field)
    recipientFocus.set('')
  }
  function restore(values: Record<RecipientField, string[]>, pending: Record<RecipientField, string>, labels?: Record<RecipientField, string[]>): void {
    ++request
    clearTimeout(timer)
    batch(() => {
      for (const field of ['to', 'cc', 'bcc'] as const) {
        fields[field].set(mergeRecipients([], values[field].map((address, index) => {
          const item = recipient(address)
          if (labels?.[field]?.[index]) { item.name = labels[field][index]; item.raw = `${item.name} <${address}>` }
          return item
        })))
        inputs[field].set(pending[field] || '')
      }
      suggestions.set([])
      suggestionIndex.set(-1)
      recipientFocus.set('')
      recipientSearching.set(false)
    })
  }
  function snapshot() {
    return {
      to: toRecipients().map(item => item.valid ? item.address : item.raw),
      cc: ccRecipients().map(item => item.valid ? item.address : item.raw),
      bcc: bccRecipients().map(item => item.valid ? item.address : item.raw),
      recipientInputs: { to: toInput(), cc: ccInput(), bcc: bccInput() },
      recipientLabels: { to: toRecipients().map(item => item.name), cc: ccRecipients().map(item => item.name), bcc: bccRecipients().map(item => item.name) },
    }
  }
  function destroy(): void { ++request; clearTimeout(timer) }
  return { toRecipients, ccRecipients, bccRecipients, toInput, ccInput, bccInput, recipientFocus, suggestions, suggestionIndex, recipientSearching, recipientErrors, commitAll, commit, lookup, chooseContact, removeRecipient, editRecipient, recipientKeydown, recipientBlur, restore, snapshot, destroy }
}
