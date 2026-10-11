import { expect, test } from 'bun:test'
import { useAttachments } from './functions/use-attachments'

class UploadRequest {
  static requests: UploadRequest[] = []
  upload: { onprogress?: (event: { lengthComputable: boolean, loaded: number, total: number }) => void } = {}
  onload?: () => void
  onerror?: () => void
  onabort?: () => void
  ontimeout?: () => void
  status = 200
  responseText = ''
  withCredentials = false
  timeout = 0
  url = ''
  headers: Record<string, string> = {}
  open(method: string, url: string) { expect(method).toBe('POST'); this.url = url }
  setRequestHeader(name: string, value: string) { this.headers[name] = value }
  send() { UploadRequest.requests.push(this) }
  abort() { this.onabort?.() }
  complete(file: File) {
    this.responseText = JSON.stringify({ uploadId: new URL(this.url, 'http://local.test').searchParams.get('uploadId'), filename: file.name, contentType: file.type, size: file.size })
    this.onload?.()
  }
}

const limits = () => ({ maxFileBytes: 8, maxTotalBytes: 12, maxCount: 2, maxMessageBytes: 32, undoSendSeconds: 10 })

test('attachment limits reject the entire selection before starting an upload', async () => {
  const editor = useAttachments(() => 'owned@example.test', limits, () => {}, async () => {})
  try {
    await expect(editor.addFiles([new File([new Uint8Array(9)], 'oversized.bin')])).rejects.toThrow('file limit')
    await expect(editor.addFiles([new File([new Uint8Array(7)], 'first.bin'), new File([new Uint8Array(7)], 'second.bin')])).rejects.toThrow('total')
    await expect(editor.addFiles([new File([], 'a'), new File([], 'b'), new File([], 'c')])).rejects.toThrow('at most 2')
    expect(editor.attachments()).toHaveLength(0)
  }
  finally { editor.destroy() }
})

test('file drop waits for acknowledgement and a retry retains its upload identifier', async () => {
  const previous = globalThis.XMLHttpRequest
  globalThis.XMLHttpRequest = UploadRequest as unknown as typeof XMLHttpRequest
  UploadRequest.requests = []
  const errors: unknown[] = []
  const editor = useAttachments(() => 'owned@example.test', limits, cause => errors.push(cause), async () => {})
  const file = new File([new Uint8Array(8)], 'drop.bin', { type: 'application/octet-stream' })
  try {
    editor.dragging.set(true)
    const dropping = editor.dropAttachments({ dataTransfer: { files: [file] } } as unknown as DragEvent)
    const first = UploadRequest.requests[0]!
    expect(first.headers['X-Webmail-Account']).toBe('owned%40example.test')
    first.upload.onprogress?.({ lengthComputable: true, loaded: 8, total: 8 })
    expect(editor.attachmentPending()).toBe(true)
    expect(editor.attachments()[0]?.status).toBe('uploading')
    first.onerror?.()
    await dropping
    expect(editor.dragging()).toBe(false)
    expect(editor.attachments()[0]?.status).toBe('failed')
    expect(errors).toHaveLength(1)
    const key = editor.attachments()[0]!.key
    const retrying = editor.retryAttachment(key)
    const second = UploadRequest.requests[1]!
    expect(second.url).toBe(first.url)
    second.complete(file)
    await retrying
    expect(editor.attachmentPending()).toBe(false)
    expect(editor.attachments()[0]?.progress).toBe(100)
    expect(editor.snapshot()[0]?.uploadId).toBe(key)
    expect(editor.attachmentRemaining()).toBe(4)
  }
  finally { editor.destroy(); globalThis.XMLHttpRequest = previous }
})
