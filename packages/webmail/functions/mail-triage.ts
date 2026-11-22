import type { MessageRef } from './mail-types'

export const messagePageSize = 50

export function messageIdentity(message: MessageRef): string {
  return message.reference ? 'ref:' + message.reference : 'uid:' + encodeURIComponent(message.folder) + ':' + message.uid
}

export const triageShortcuts = [
  { key: 'Shift+N', label: 'Open next unread message' },
  { key: 'Shift+J', label: 'Advance in the reading batch' },
  { key: 'Shift+X', label: 'Select or deselect the open message' },
  { key: 'Shift+E', label: 'Archive the selection or open message' },
  { key: 'Shift+U', label: 'Undo the last triage action' },
  { key: 'Escape', label: 'Return to the message list' },
  { key: '?', label: 'Show keyboard shortcuts' },
]

export function isShortcutEvent(event: KeyboardEvent): boolean {
  const target = event.target
  return !event.defaultPrevented && !event.isComposing && !event.ctrlKey && !event.metaKey && !event.altKey && !event.repeat
    && !(target instanceof Element && target.closest('input, textarea, select, [contenteditable]:not([contenteditable=false]), [role=textbox], [role=combobox], dialog'))
}

interface ViewportAnchor {
  list: HTMLElement
  top: number
  row: string | undefined
  offset: number
  focused: Element | null
  focusRow: string | undefined
  control: string | undefined
}

function listRows(list: HTMLElement): HTMLElement[] {
  return Array.from(list.querySelectorAll<HTMLElement>('[data-list-row]'))
}

export function captureListViewport(list: HTMLElement | null): ViewportAnchor | null {
  if (!list?.clientHeight) return null
  const rect = list.getBoundingClientRect()
  const first = listRows(list).find(row => row.getBoundingClientRect().bottom > rect.top)
  const focused = list.contains(document.activeElement) ? document.activeElement : null
  return {
    list,
    top: list.scrollTop,
    row: first?.dataset.listRow,
    offset: first ? first.getBoundingClientRect().top - rect.top : 0,
    focused,
    focusRow: focused?.closest<HTMLElement>('[data-list-row]')?.dataset.listRow,
    control: focused?.getAttribute('data-list-control') ?? undefined,
  }
}

export function restoreListViewport(saved: ViewportAnchor | null, restoreFocus: boolean = false): void {
  if (!saved?.list.isConnected || !saved.list.clientHeight) return
  const { list } = saved
  const rows = listRows(list)
  const anchor = rows.find(row => row.dataset.listRow === saved.row)
  if (anchor && saved.top > 0) list.scrollTop += anchor.getBoundingClientRect().top - list.getBoundingClientRect().top - saved.offset
  else list.scrollTop = saved.top

  const current = document.activeElement
  if (!restoreFocus && (!saved.focused || (current !== document.body && current !== saved.focused))) return
  if (saved.focused instanceof HTMLElement && saved.focused.isConnected && list.contains(saved.focused)) {
    saved.focused.focus({ preventScroll: true })
    return
  }
  const row = rows.find(item => item.dataset.listRow === saved.focusRow) || (restoreFocus ? anchor : undefined)
  const control = Array.from(row?.querySelectorAll<HTMLElement>('[data-list-control]') ?? []).find(item => item.dataset.listControl === (saved.control || 'open'))
  const target = control || list
  target.focus({ preventScroll: true })
}
