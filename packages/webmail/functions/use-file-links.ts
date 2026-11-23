import { state } from '@stacksjs/stx'
import type { createMailApi } from './mail-api'
import type { SharedFile } from './mail-public-links'
import { readableBytes } from './mail-utils'

interface FileLink extends SharedFile { id: string }
interface IssuedFileLink { file: SharedFile, token: string }
const endpoint = '/webmail/api/file-links'

export function useFileLinks(api: ReturnType<typeof createMailApi>, maxBytes: () => number) {
  const fileLinkOpen = state(false)
  const fileLinkFile = state<File | null>(null)
  const fileLinkLifetime = state('86400')
  const fileLinkUploading = state(false)
  const fileLinkError = state('')
  const fileLinkNotice = state('')
  const fileLinksOpen = state(false)
  const fileLinks = state<FileLink[]>([])
  const fileLinksBusy = state(false)
  const fileLinksError = state('')
  const fileLinksNotice = state('')
  const revokingFileLink = state<FileLink | null>(null)
  let uploadId = ''
  let upload: AbortController | undefined
  let manager: AbortController | undefined

  function clearFileLinkComposer() {
    upload?.abort()
    upload = undefined
    uploadId = ''
    fileLinkUploading.set(false)
    fileLinkOpen.set(false)
    fileLinkFile.set(null)
    fileLinkError.set('')
    fileLinkNotice.set('')
    fileLinkLifetime.set('86400')
  }

  function toggleFileLink() {
    if (fileLinkUploading()) return
    if (fileLinkOpen()) clearFileLinkComposer()
    else fileLinkOpen.set(true)
  }

  function selectFileLink(event: Event) {
    if (fileLinkUploading()) return
    const input = event.target as HTMLInputElement
    const file = input.files?.[0]
    if (!file) return
    fileLinkError.set('')
    fileLinkNotice.set('')
    fileLinkFile.set(null)
    if (!file.size || file.size > maxBytes()) {
      input.value = ''
      fileLinkError.set(`Choose a nonempty file of up to ${readableBytes(maxBytes())}.`)
      return
    }
    uploadId = globalThis.crypto.randomUUID().replaceAll('-', '')
    fileLinkFile.set(file)
  }

  async function uploadFileLink(): Promise<string | null> {
    const file = fileLinkFile()
    if (!file || fileLinkUploading()) return null
    const pending = new AbortController()
    upload = pending
    fileLinkUploading.set(true)
    fileLinkError.set('')
    fileLinkNotice.set('')
    try {
      const params = new URLSearchParams({ filename: file.name, uploadId, lifetime: fileLinkLifetime() })
      const issued = await api<IssuedFileLink>(`${endpoint}?${params}`, {
        method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: file, signal: pending.signal,
      })
      if (upload !== pending) return null
      const url = new URL('/file-link', globalThis.location.origin)
      url.hash = `token=${issued.token}`
      upload = undefined
      clearFileLinkComposer()
      fileLinkNotice.set('File link inserted.')
      const expiry = new Date(issued.file.expires_at * 1000).toUTCString()
      return `${issued.file.filename} (${readableBytes(issued.file.size)})\n${url.href}\nLink expires ${expiry}.`
    }
    catch (cause) {
      if (upload === pending) fileLinkError.set(cause instanceof Error ? cause.message : 'Could not upload this file.')
      return null
    }
    finally {
      if (upload === pending) {
        upload = undefined
        fileLinkUploading.set(false)
      }
    }
  }

  function closeFileLinkManager() {
    manager?.abort()
    manager = undefined
    fileLinksOpen.set(false)
    fileLinksBusy.set(false)
    fileLinks.set([])
    fileLinksError.set('')
    fileLinksNotice.set('')
    revokingFileLink.set(null)
  }

  async function manageFileLinks() {
    if (fileLinksBusy()) return
    fileLinksOpen.set(true)
    fileLinksBusy.set(true)
    fileLinksError.set('')
    const pending = new AbortController()
    manager = pending
    try {
      const result = await api<{ links: FileLink[] }>(endpoint, { signal: pending.signal })
      if (manager === pending) fileLinks.set(result.links)
    }
    catch (cause) {
      if (manager === pending) fileLinksError.set(cause instanceof Error ? cause.message : 'Could not load file links.')
    }
    finally {
      if (manager === pending) {
        manager = undefined
        fileLinksBusy.set(false)
      }
    }
  }

  async function revokeFileLink() {
    const file = revokingFileLink()
    if (!file || fileLinksBusy()) return
    const pending = new AbortController()
    manager = pending
    fileLinksBusy.set(true)
    fileLinksError.set('')
    fileLinksNotice.set('')
    try {
      await api(`${endpoint}/${file.id}`, { method: 'DELETE', signal: pending.signal })
      if (manager !== pending) return
      fileLinks.update(rows => rows.filter(link => link.id !== file.id))
      revokingFileLink.set(null)
      fileLinksNotice.set('File link revoked.')
    }
    catch (cause) {
      if (manager === pending) fileLinksError.set(cause instanceof Error ? cause.message : 'Could not revoke this link.')
    }
    finally {
      if (manager === pending) {
        manager = undefined
        fileLinksBusy.set(false)
      }
    }
  }

  return {
    fileLinkOpen, fileLinkFile, fileLinkLifetime, fileLinkUploading, fileLinkError, fileLinkNotice, toggleFileLink, selectFileLink,
    uploadFileLink, clearFileLinkComposer, fileLinksOpen, fileLinks, fileLinksBusy, fileLinksError, fileLinksNotice,
    revokingFileLink, manageFileLinks, revokeFileLink, closeFileLinkManager,
  }
}
