import type { createMailApi } from './mail-api'
import { batch, derived, state } from '@stacksjs/stx'

interface Entry { id: string, name: string, text: string }
interface Library { revision: number, snippets: Entry[], signatures: Entry[], defaultSignatureId: string | null }
type Kind = 'snippets' | 'signatures'
const endpoint = '/webmail/api/compose-library'

export function useComposeLibrary(api: ReturnType<typeof createMailApi>) {
  const writingLibrary = state<Library | null>(null)
  const writingKind = state<Kind>('snippets')
  const writingId = state<string | null>(null)
  const writingName = state('')
  const writingText = state('')
  const writingBusy = state(false)
  const writingError = state('')
  const writingNotice = state('')
  const writingEntries = derived(() => writingLibrary()?.[writingKind()] || [])
  let generation = 0
  let loading: Promise<void> | null = null

  function editWritingEntry(entry?: Entry): void {
    batch(() => {
      writingId.set(entry?.id ?? null)
      writingName.set(entry?.name ?? '')
      writingText.set(entry?.text ?? '')
    })
  }
  function chooseWritingKind(kind: Kind): void {
    writingKind.set(kind)
    writingNotice.set('')
    editWritingEntry()
  }
  function clearWritingLibrary(): void {
    generation += 1
    loading = null
    writingLibrary.set(null)
    writingBusy.set(false)
    writingError.set('')
    chooseWritingKind('snippets')
  }

  function loadWritingLibrary(reload = false): Promise<void> {
    if (loading) return loading
    if (writingBusy() || (!reload && writingLibrary())) return Promise.resolve()
    const account = generation
    writingBusy.set(true)
    writingError.set('')
    loading = api<Library>(endpoint).then((library) => {
      if (!Array.isArray(library?.snippets) || !Array.isArray(library?.signatures)) throw new Error('Could not load writing tools.')
      if (account === generation) writingLibrary.set(library)
    }).catch((cause) => {
      if (account === generation) writingError.set(String(cause instanceof Error ? cause.message : cause))
    }).finally(() => {
      if (account === generation) {
        loading = null
        writingBusy.set(false)
      }
    })
    return loading
  }

  async function update(library: Library, notice: string): Promise<boolean> {
    if (writingBusy()) return false
    const account = generation
    writingBusy.set(true)
    writingNotice.set('')
    writingError.set('')
    try {
      const saved = await api<Library>(endpoint, { method: 'PUT', body: JSON.stringify(library) })
      if (account !== generation) return false
      writingLibrary.set(saved)
      writingNotice.set(notice)
      return true
    }
    catch (cause) {
      if (account === generation) writingError.set(String(cause instanceof Error ? cause.message : cause))
      return false
    }
    finally {
      if (account === generation) writingBusy.set(false)
    }
  }

  async function saveWritingEntry(): Promise<void> {
    const library = writingLibrary()
    const kind = writingKind()
    const id = writingId()
    if (!library) return
    if (id && !library[kind].some(entry => entry.id === id)) {
      writingError.set('This item was removed. Add a new entry to keep its text.')
      return
    }
    const entry = { id: id || crypto.randomUUID(), name: writingName().trim(), text: writingText() }
    const entries = id ? library[kind].map(item => item.id === id ? entry : item) : [...library[kind], entry]
    if (await update({ ...library, [kind]: entries }, kind === 'snippets' ? 'Snippet saved.' : 'Signature saved.')) editWritingEntry()
  }

  async function removeWritingEntry(id: string): Promise<void> {
    const library = writingLibrary()
    const kind = writingKind()
    if (!library) return
    const defaultSignatureId = kind === 'signatures' && library.defaultSignatureId === id ? null : library.defaultSignatureId
    const entries = library[kind].filter(entry => entry.id !== id)
    if (await update({ ...library, defaultSignatureId, [kind]: entries }, kind === 'snippets' ? 'Snippet removed.' : 'Signature removed.')) {
      if (writingId() === id) editWritingEntry()
    }
  }

  async function changeDefaultSignature(event: Event): Promise<void> {
    const select = event.target as HTMLSelectElement
    const library = writingLibrary()
    if (!library) return
    if (!await update({ ...library, defaultSignatureId: select.value || null }, 'Default signature saved.')) {
      select.value = library.defaultSignatureId || ''
    }
  }

  return { writingLibrary, writingKind, writingId, writingName, writingText, writingBusy, writingError, writingNotice, writingEntries,
    editWritingEntry, chooseWritingKind, clearWritingLibrary, loadWritingLibrary, saveWritingEntry, removeWritingEntry, changeDefaultSignature }
}
