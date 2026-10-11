import type { ComposeAttachment, MailLimits } from './mail-types'
import { derived, state } from '@stacksjs/stx'
import { uploadAttachment } from './mail-api'
import { readableBytes } from './mail-utils'

export function useAttachments(account: () => string | undefined, limits: () => MailLimits, onError: (cause: unknown) => void, removeUpload: (id: string) => Promise<unknown>) {
  const attachments = state<ComposeAttachment[]>([])
  const dragging = state(false)
  const attachmentBytes = derived(() => attachments().reduce((sum, item) => sum + item.size, 0))
  const attachmentRemaining = derived(() => Math.max(0, limits().maxTotalBytes - attachmentBytes()))
  const attachmentPending = derived(() => attachments().some(item => item.status !== 'ready'))
  const attachmentUploading = derived(() => attachments().some(item => item.status === 'uploading'))
  const files = new Map<string, File>()
  const controllers = new Map<string, AbortController>()
  let generation = 0

  function update(key: string, values: Partial<ComposeAttachment>): void { attachments.update(items => items.map(item => item.key === key ? { ...item, ...values } : item)) }
  async function runUpload(key: string): Promise<void> {
    const file = files.get(key)
    const username = account()
    if (!file || !username) return
    const version = generation
    const controller = new AbortController()
    controllers.set(key, controller)
    update(key, { status: 'uploading', progress: 0, error: '' })
    try {
      const result = await uploadAttachment(file, username, value => { if (version === generation) update(key, { progress: value }) }, controller.signal, key)
      if (version !== generation || !attachments().some(item => item.key === key)) { void removeUpload(result.uploadId).catch(() => {}); return }
      update(key, { ...result, status: 'ready', progress: 100 })
      files.delete(key)
    }
    catch (cause) {
      if (version !== generation || !attachments().some(item => item.key === key)) return
      if (cause instanceof DOMException && cause.name === 'AbortError') return
      update(key, { status: 'failed', error: cause instanceof Error ? cause.message : 'Upload failed.' })
      onError(cause)
    }
    finally { if (controllers.get(key) === controller) controllers.delete(key) }
  }
  async function addFiles(values: FileList | File[]): Promise<void> {
    const selected = Array.from(values)
    const allowed = limits()
    if (selected.length + attachments().length > allowed.maxCount) throw new Error(`Use at most ${allowed.maxCount} attachments.`)
    let bytes = attachmentBytes()
    for (const file of selected) {
      if (file.size > allowed.maxFileBytes) throw new Error(`${file.name} exceeds the ${readableBytes(allowed.maxFileBytes)} file limit.`)
      bytes += file.size
      if (bytes > allowed.maxTotalBytes) throw new Error(`Keep attachments under ${readableBytes(allowed.maxTotalBytes)} total.`)
    }
    const keys: string[] = []
    for (const file of selected) {
      const key = crypto.randomUUID()
      files.set(key, file)
      keys.push(key)
      attachments.update(items => [...items, { key, filename: file.name, contentType: file.type || 'application/octet-stream', size: file.size, progress: 0, status: 'uploading' }])
    }
    // Sequential uploads bound server/client memory while retaining per-file progress.
    for (const key of keys) await runUpload(key)
  }
  function removeAttachment(key: string): void {
    controllers.get(key)?.abort()
    controllers.delete(key)
    files.delete(key)
    const item = attachments().find(value => value.key === key)
    attachments.update(items => items.filter(value => value.key !== key))
    if (item?.uploadId) void removeUpload(item.uploadId).catch(() => {})
  }
  async function retryAttachment(key: string): Promise<void> { await runUpload(key) }
  function restore(values: ComposeAttachment[]): void {
    generation++
    for (const controller of controllers.values()) controller.abort()
    controllers.clear()
    files.clear()
    attachments.set(values)
  }
  async function dropAttachments(event: DragEvent): Promise<void> {
    dragging.set(false)
    if (event.dataTransfer?.files.length) await addFiles(event.dataTransfer.files)
  }
  function snapshot() { return attachments().filter(item => item.status === 'ready').map(item => ({ uploadId: item.uploadId!, filename: item.filename, contentType: item.contentType, size: item.size })) }
  function destroy(): void { restore([]) }
  return { attachments, dragging, attachmentBytes, attachmentRemaining, attachmentPending, attachmentUploading, addFiles, removeAttachment, retryAttachment, restore, dropAttachments, snapshot, destroy }
}
