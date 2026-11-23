import { batch, derived, state } from '@stacksjs/stx'
import type { createMailApi } from './mail-api'
import type { MessageRef, PrivateCollection, PrivateEntry, PrivateMessageTools } from './mail-types'

const toolsPath = '/webmail/api/private/message'
const collectionsPath = '/webmail/api/private/collections'
type ToolsTab = 'notes' | 'clips' | 'organize'

export function usePrivateMail(api: ReturnType<typeof createMailApi>, selected: () => MessageRef | null) {
  const privateOpen = state(false)
  const privateTab = state<ToolsTab>('notes')
  const privateTools = state<PrivateMessageTools | null>(null)
  const privateBusy = state(false)
  const privateError = state('')
  const editingNote = state<PrivateEntry | null>(null)
  const noteText = state('')
  const clipText = state('')
  const privateLabel = state('')
  const privateEntries = derived(() => privateTools()?.entries.filter(entry => entry.kind === (privateTab() === 'clips' ? 'clip' : 'note')) || [])

  const privateCollections = state<PrivateCollection[]>([])
  const collectionsOpen = state(false)
  const collectionsBusy = state(false)
  const collectionsError = state('')
  const collectionName = state('')
  const editingCollection = state<PrivateCollection | null>(null)
  const deletingCollection = state<PrivateCollection | null>(null)
  let messageRequest = 0
  let collectionRequest = 0

  function closePrivate(): void {
    messageRequest += 1
    batch(() => {
      privateOpen.set(false)
      privateBusy.set(false)
      privateError.set('')
      privateTools.set(null)
      privateTab.set('notes')
      editingNote.set(null)
      noteText.set('')
      clipText.set('')
      privateLabel.set('')
    })
  }

  async function showPrivate(): Promise<void> {
    const reference = selected()?.reference
    if (privateOpen() || !reference) return
    const request = ++messageRequest
    batch(() => {
      privateOpen.set(true)
      privateBusy.set(true)
      privateError.set('')
    })
    try {
      const result = await api<PrivateMessageTools>(`${toolsPath}?reference=${encodeURIComponent(reference)}`)
      if (request !== messageRequest || selected()?.reference !== reference) return
      privateTools.set(result)
      privateLabel.set(result.label.value)
    }
    catch (cause) {
      if (request === messageRequest) privateError.set(cause instanceof Error ? cause.message : 'Could not load private tools.')
    }
    finally {
      if (request === messageRequest) privateBusy.set(false)
    }
  }

  async function saveTools(change: object): Promise<PrivateMessageTools | null> {
    const message = selected()
    if (!message?.reference || !message.revision || privateBusy()) return null
    const request = ++messageRequest
    privateBusy.set(true)
    privateError.set('')
    try {
      const result = await api<PrivateMessageTools>(toolsPath, {
        method: 'POST',
        headers: { 'If-Match': message.revision },
        body: JSON.stringify({ ...change, reference: message.reference }),
      })
      if (request !== messageRequest || selected()?.reference !== message.reference) return null
      privateTools.set(result)
      return result
    }
    catch (cause) {
      if (request === messageRequest) privateError.set(cause instanceof Error ? cause.message : 'Could not save the private change.')
      return null
    }
    finally {
      if (request === messageRequest) privateBusy.set(false)
    }
  }

  function editPrivateNote(entry: PrivateEntry): void {
    editingNote.set(entry)
    noteText.set(entry.body)
  }

  function cancelPrivateNote(): void {
    editingNote.set(null)
    noteText.set('')
  }

  async function savePrivateNote(): Promise<void> {
    const draft = editingNote()
    const body = noteText().trim()
    if (!body) return
    if (await saveTools(draft ? { action: 'edit', entry: draft.id, revision: draft.revision, body } : { action: 'note', body })) cancelPrivateNote()
  }

  async function removePrivateEntry(entry: PrivateEntry): Promise<void> {
    const result = await saveTools({ action: 'remove', entry: entry.id, revision: entry.revision })
    if (result && editingNote()?.id === entry.id) cancelPrivateNote()
  }

  function startPrivateClip(): void {
    const source = privateTools()?.clip_source.trim() || ''
    const paragraph = source.split(/\r?\n\s*\r?\n/, 1)[0]
    clipText.set(Array.from(paragraph).slice(0, 480).join('').trim())
  }

  async function savePrivateClip(): Promise<void> {
    const body = clipText().trim().replace(/\r\n?/g, '\n')
    if (body && await saveTools({ action: 'clip', body })) clipText.set('')
  }

  async function storePrivateLabel(): Promise<PrivateMessageTools | null> {
    const result = await saveTools({ action: 'label', body: privateLabel().trim(), label_revision: privateTools()?.label.revision })
    if (result) privateLabel.set(result.label.value)
    return result
  }

  async function changePrivateMembership(collection: PrivateCollection, event: Event): Promise<boolean> {
    const input = event.target as HTMLInputElement
    if (await saveTools({ action: 'collection', collection: collection.id, included: input.checked, shareCollectionMessage: collection.shared })) return true
    input.checked = collection.shared ? collection.explicit : collection.included
    return false
  }

  function replaceCollections(items: PrivateCollection[]): void {
    privateCollections.set(items)
    const tools = privateTools()
    if (!tools) return
    const membership = new Map(tools.collections.map(item => [item.id, item]))
    privateTools.set({ ...tools, collections: items.map((item) => {
      const previous = membership.get(item.id)
      return { ...item, included: previous?.included ?? false, explicit: previous?.explicit ?? false }
    }) })
  }

  async function loadPrivateCollections(): Promise<void> {
    const request = ++collectionRequest
    try {
      const result = await api<{ items: PrivateCollection[] }>(collectionsPath)
      if (request === collectionRequest) replaceCollections(result.items)
    }
    catch (cause) {
      if (request === collectionRequest && collectionsOpen())
        collectionsError.set(cause instanceof Error ? cause.message : 'Could not load collections.')
    }
  }

  function clearCollectionEditor(): void {
    collectionName.set('')
    editingCollection.set(null)
    deletingCollection.set(null)
  }

  function editPrivateCollection(item: PrivateCollection): void {
    editingCollection.set(item)
    deletingCollection.set(null)
    collectionName.set(item.name)
  }

  async function changePrivateCollection(change: object): Promise<boolean> {
    if (collectionsBusy()) return false
    const request = ++collectionRequest
    collectionsBusy.set(true)
    collectionsError.set('')
    try {
      const result = await api<{ items: PrivateCollection[] }>(collectionsPath, { method: 'POST', body: JSON.stringify(change) })
      if (request === collectionRequest) replaceCollections(result.items)
      clearCollectionEditor()
      return true
    }
    catch (cause) {
      collectionsError.set(cause instanceof Error ? cause.message : 'Could not change the collection.')
      return false
    }
    finally { collectionsBusy.set(false) }
  }

  async function savePrivateCollection(): Promise<void> {
    const name = collectionName().trim()
    const item = editingCollection()
    if (name) await changePrivateCollection(item ? { action: 'rename', id: item.id, revision: item.revision, name } : { action: 'create', name })
  }

  async function deletePrivateCollection(): Promise<boolean> {
    const item = deletingCollection()
    return item ? changePrivateCollection({ action: 'delete', id: item.id, revision: item.revision }) : false
  }

  return {
    privateOpen, privateTab, privateTools, privateBusy, privateError, privateEntries, editingNote, noteText, clipText, privateLabel,
    closePrivate, showPrivate, editPrivateNote, cancelPrivateNote, savePrivateNote, removePrivateEntry, startPrivateClip, savePrivateClip,
    storePrivateLabel, changePrivateMembership, privateCollections, collectionsOpen, collectionsBusy, collectionsError,
    collectionName, editingCollection, deletingCollection, loadPrivateCollections, clearCollectionEditor,
    editPrivateCollection, savePrivateCollection, deletePrivateCollection,
  }
}
