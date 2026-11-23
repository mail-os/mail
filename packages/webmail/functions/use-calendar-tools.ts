import { derived, state } from '@stacksjs/stx'
import { allDayInstant, formatCalendarDay, zonedDay } from './calendar-dates'
import type { createMailApi } from './mail-api'
import { MailApiError } from './mail-api'

interface Item { id: string, title: string }
interface Habit extends Item { days: string[] }
interface Countdown extends Item { day: string }
interface TimeEntry extends Countdown { minutes: number }
interface JournalEntry { day: string, text: string }
interface Tools {
  version: 1
  enabled: boolean
  appearance: 'standard' | 'compact'
  habits: Habit[]
  countdowns: Countdown[]
  journal: JournalEntry[]
  time: TimeEntry[]
}
interface Snapshot { revision: number, tools: Tools }
type Section = 'countdowns' | 'habits' | 'journal' | 'time' | 'display'
type ItemSection = 'countdowns' | 'habits' | 'time'
const endpoint = '/webmail/api/calendar-tools'
const maxBytes = 512 * 1024
const sections: { id: Section, label: string }[] = [
  { id: 'countdowns', label: 'Countdowns' }, { id: 'habits', label: 'Habits' }, { id: 'journal', label: 'Journal' },
  { id: 'time', label: 'Time log' }, { id: 'display', label: 'Display & data' },
]

export function useCalendarTools(api: ReturnType<typeof createMailApi>, canView: () => boolean, focusDay: () => string, zone: () => string) {
  const snapshot = state<Snapshot | null>(null)
  const tools = derived(() => snapshot()?.tools)
  const toolsCompact = state(false)
  const toolsOpen = state(false)
  const toolsBusy = state(false)
  const toolsError = state('')
  const toolsNotice = state('')
  const toolsConflict = state(false)
  const toolSection = state<Section>('countdowns')
  const toolDate = state(focusDay())
  const editingItem = state('')
  const toolTitle = state('')
  const toolTarget = state(toolDate())
  const toolMinutes = state('')
  const journalDrafts = state(new Map<string, string>())
  const journalText = derived(() => journalDrafts().get(toolDate()) ?? tools()?.journal.find(entry => entry.day === toolDate())?.text ?? '')
  const journalDates = derived(() => (tools()?.journal ?? []).map(entry => entry.day).sort().reverse())
  const toolTimeRows = derived(() => tools()?.time.filter(entry => entry.day === toolDate()) ?? [])
  const toolTimeTotal = derived(() => toolTimeRows().reduce((total, row) => total + row.minutes, 0))
  const countdownRows = derived(() => [...(tools()?.countdowns ?? [])].sort((a, b) => a.day.localeCompare(b.day)))
  const toolNow = state(Date.now() / 1000)
  const toolToday = derived(() => zonedDay(toolNow(), zone()))
  const selectedImport = state<{ filename: string, tools: Tools } | null>(null)
  const removal = state<{ section: ItemSection | 'journal', key: string, title: string } | null>(null)
  let request: AbortController | undefined
  let displayRequest: AbortController | undefined
  let importRead = 0

  function tickTools() {
    if (toolsOpen()) toolNow.set(Date.now() / 1000)
  }

  function setSnapshot(value: Snapshot) {
    snapshot.set(value)
    toolsCompact.set(value.tools.enabled && value.tools.appearance === 'compact')
  }

  async function loadToolsDisplay() {
    if (!canView() || snapshot() || displayRequest) return
    const pending = new AbortController()
    displayRequest = pending
    try {
      const { compact } = await api<{ compact: boolean }>(`${endpoint}?display=1`, { signal: pending.signal })
      if (displayRequest === pending && !snapshot()) toolsCompact.set(compact)
    }
    catch { /* The Calendar uses its standard layout while this preference is unavailable. */ }
    finally {
      if (displayRequest === pending) displayRequest = undefined
    }
  }

  function resetItemForm() {
    editingItem.set('')
    toolTitle.set('')
    toolTarget.set(toolDate())
    toolMinutes.set('')
  }

  function closeTools() {
    toolsOpen.set(false)
    discardToolsImport()
    removal.set(null)
  }

  function clearTools() {
    request?.abort()
    displayRequest?.abort()
    request = undefined
    displayRequest = undefined
    closeTools()
    snapshot.set(null)
    journalDrafts.set(new Map())
    toolsCompact.set(false)
    toolsBusy.set(false)
    toolsConflict.set(false)
    toolsError.set('')
    toolsNotice.set('')
    resetItemForm()
  }

  async function loadTools() {
    if (!canView() || toolsBusy()) return
    if (!toolsOpen()) {
      toolDate.set(focusDay())
      resetItemForm()
    }
    toolsOpen.set(true)
    tickTools()
    toolsBusy.set(true)
    toolsError.set('')
    toolsNotice.set('')
    const pending = new AbortController()
    request = pending
    try {
      const value = await api<Snapshot>(endpoint, { signal: pending.signal })
      if (request !== pending) return
      setSnapshot(value)
      toolsConflict.set(false)
      removal.set(null)
      const section = toolSection()
      if (editingItem() && (section === 'habits' || section === 'countdowns' || section === 'time')
        && !value.tools[section].some(item => item.id === editingItem())) resetItemForm()
    }
    catch (cause) {
      if (request === pending) toolsError.set(cause instanceof Error ? cause.message : 'Could not load personal tools.')
    }
    finally {
      if (request === pending) {
        request = undefined
        toolsBusy.set(false)
      }
    }
  }

  async function saveTools(change: Partial<Tools>, message: string): Promise<boolean> {
    const previous = snapshot()
    if (!previous || !canView() || toolsBusy() || toolsConflict()) return false
    toolsBusy.set(true)
    toolsError.set('')
    toolsNotice.set('')
    const pending = new AbortController()
    request = pending
    try {
      const saved = await api<Snapshot>(endpoint, {
        method: 'PUT', body: JSON.stringify({ revision: previous.revision, tools: { ...previous.tools, ...change } }), signal: pending.signal,
      })
      if (request !== pending) return false
      setSnapshot(saved)
      toolsNotice.set(message)
      return true
    }
    catch (cause) {
      if (request === pending) {
        toolsError.set(cause instanceof Error ? cause.message : 'Could not save personal tools.')
        toolsConflict.set(cause instanceof MailApiError && cause.code === 'personal_tools_changed')
      }
      return false
    }
    finally {
      if (request === pending) {
        request = undefined
        toolsBusy.set(false)
      }
    }
  }

  function selectToolsSection(section: Section) {
    toolSection.set(section)
    resetItemForm()
    discardToolsImport()
    removal.set(null)
    if (!toolsConflict()) toolsError.set('')
    toolsNotice.set('')
  }

  function selectToolDate(day: string) {
    if (allDayInstant(day) === null) return
    toolDate.set(day)
    resetItemForm()
    removal.set(null)
    toolsNotice.set('')
  }

  function changeToolDate(event: Event) {
    const input = event.target as HTMLInputElement
    if (allDayInstant(input.value) === null) input.value = toolDate()
    else selectToolDate(input.value)
  }

  function editToolItem(item: Item & { day?: string, minutes?: number }) {
    editingItem.set(item.id)
    toolTitle.set(item.title)
    toolTarget.set(item.day ?? toolDate())
    toolMinutes.set(item.minutes ? String(item.minutes) : '')
  }

  async function saveToolItem(section: ItemSection) {
    const current = tools()
    if (!current?.enabled) return
    const title = toolTitle().trim()
    if (!title || [...title].length > 100) {
      toolsError.set('Enter a title of up to 100 characters.')
      return
    }
    const id = editingItem() || globalThis.crypto.randomUUID().replaceAll('-', '')
    const day = section === 'time' ? toolDate() : toolTarget()
    let change: Partial<Tools>
    if (section === 'habits') {
      const days = current.habits.find(habit => habit.id === id)?.days ?? []
      change = { habits: replaceItem(current.habits, { id, title, days }) }
    }
    else if (section === 'countdowns') {
      if (allDayInstant(day) === null) {
        toolsError.set('Choose a target date.')
        return
      }
      change = { countdowns: replaceItem(current.countdowns, { id, title, day }) }
    }
    else {
      const minutes = Number(toolMinutes())
      if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) {
        toolsError.set('Enter a duration between 1 and 1,440 minutes.')
        return
      }
      change = { time: replaceItem(current.time, { id, title, day, minutes }) }
    }
    if (await saveTools(change, editingItem() ? 'Changes saved.' : 'Entry added.')) resetItemForm()
  }

  function toggleHabit(habit: Habit) {
    const current = tools()
    if (!current?.enabled) return false
    const day = toolDate()
    const checked = habit.days.includes(day)
    const days = checked ? habit.days.filter(value => value !== day) : [...habit.days, day].sort()
    return saveTools({ habits: replaceItem(current.habits, { ...habit, days }) }, checked ? 'Check-in cleared.' : 'Habit checked in.')
  }

  function writeJournal(text: string) {
    journalDrafts.update(previous => new Map(previous).set(toolDate(), text))
  }

  function clearJournalDraft(day: string) {
    journalDrafts.update(previous => {
      const next = new Map(previous)
      next.delete(day)
      return next
    })
  }

  async function saveJournal() {
    const current = tools()
    if (!current?.enabled) return
    const text = journalText()
    if (!text.trim() || [...text].length > 2_000) {
      toolsError.set('Enter a journal note of up to 2,000 characters.')
      return
    }
    const day = toolDate()
    const journal = [...current.journal.filter(entry => entry.day !== day), { day, text }].sort((a, b) => a.day.localeCompare(b.day))
    if (await saveTools({ journal }, 'Journal note saved.')) clearJournalDraft(day)
  }

  async function confirmToolRemoval() {
    const current = tools()
    const target = removal()
    if (!current?.enabled || !target) return false
    const change = target.section === 'journal'
      ? { journal: current.journal.filter(entry => entry.day !== target.key) }
      : { [target.section]: current[target.section].filter(item => item.id !== target.key) }
    if (!await saveTools(change, 'Entry removed.')) return false
    if (target.section === 'journal') clearJournalDraft(target.key)
    if (editingItem() === target.key) resetItemForm()
    removal.set(null)
    return true
  }

  function discardToolsImport() {
    importRead++
    selectedImport.set(null)
  }

  async function prepareToolsImport(event: Event) {
    const input = event.target as HTMLInputElement
    const file = input.files?.[0]
    input.value = ''
    discardToolsImport()
    if (!file || !canView()) return
    toolsError.set('')
    if (file.size > maxBytes) {
      toolsError.set('Choose a Personal tools JSON file of up to 512 KiB.')
      return
    }
    const reading = importRead
    try {
      const selected: Tools = JSON.parse(await file.text())
      if (reading !== importRead || !canView()) return
      if (selected?.version !== 1 || typeof selected.enabled !== 'boolean' || !['standard', 'compact'].includes(selected.appearance)
        || ![selected.habits, selected.countdowns, selected.journal, selected.time].every(Array.isArray))
        throw new Error('Choose a version 1 Personal tools JSON file.')
      selectedImport.set({ filename: file.name, tools: selected })
    }
    catch (cause) {
      if (reading === importRead && canView()) toolsError.set(cause instanceof Error ? cause.message : 'Could not read the import file.')
    }
  }

  async function importTools() {
    const selected = selectedImport()
    if (selected && await saveTools(selected.tools, 'Personal tools imported.')) {
      discardToolsImport()
      journalDrafts.set(new Map())
      resetItemForm()
    }
  }

  async function exportTools() {
    if (!canView() || toolsBusy()) return
    toolsError.set('')
    try {
      const { tools: saved } = await api<Snapshot>(endpoint)
      if (!canView() || !toolsOpen()) return
      const file = new Blob([JSON.stringify(saved)], { type: 'application/json' })
      const url = URL.createObjectURL(file)
      const link = globalThis.document.createElement('a')
      link.href = url
      link.download = 'mail-personal-tools.json'
      globalThis.document.body.append(link)
      link.click()
      link.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    }
    catch (cause) {
      if (toolsOpen()) toolsError.set(cause instanceof Error ? cause.message : 'Could not export personal tools.')
    }
  }

  function countdownStatus(day: string): string {
    const days = (allDayInstant(day)! - allDayInstant(toolToday())!) / 86400
    if (days === 0) return 'Today'
    const length = Math.abs(days)
    return `${length} ${length === 1 ? 'day' : 'days'} ${days > 0 ? 'left' : 'ago'}`
  }

  return {
    tools, toolsOpen, toolsBusy, toolsError, toolsNotice, toolsConflict, toolsCompact, toolsSections: sections, toolSection,
    toolDate, toolTitle, toolTarget, toolMinutes, editingItem, journalText, journalDates, toolTimeRows, toolTimeTotal, countdownRows,
    selectedImport, removal, loadToolsDisplay, loadTools, closeTools, clearTools, tickTools, selectToolsSection, selectToolDate, changeToolDate,
    resetItemForm, editToolItem, saveToolItem, toggleHabit, writeJournal, saveJournal, confirmToolRemoval,
    prepareToolsImport, discardToolsImport, importTools, exportTools,
    setToolsEnabled: (enabled: boolean) => saveTools({ enabled }, enabled ? 'Personal tools enabled.' : 'Personal tools turned off.'),
    setToolsAppearance: (appearance: Tools['appearance']) => saveTools({ appearance }, 'Display preference saved.'),
    toolDateLabel: (day: string) => formatCalendarDay(day, { dateStyle: 'medium' }),
    countdownStatus,
  }
}

function replaceItem<T extends Item>(items: T[], value: T): T[] {
  return items.some(item => item.id === value.id) ? items.map(item => item.id === value.id ? value : item) : [...items, value]
}
