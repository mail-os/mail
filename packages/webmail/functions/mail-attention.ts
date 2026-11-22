import type { AttentionView } from './mail-types'

export const attentionViews: { name: AttentionView, label: string }[] = [
  { name: 'follow_up', label: 'Follow-up' },
  { name: 'saved', label: 'Saved' },
  { name: 'snoozed', label: 'Snoozed' },
  { name: 'muted', label: 'Muted' },
  { name: 'reminders', label: 'No-reply reminders' },
]

export function localDateInput(date: Date): string {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16)
}

export function localDeadline(value: string, now = Date.now()): number {
  const date = new Date(value)
  if (!Number.isFinite(date.getTime()) || localDateInput(date) !== value || date.getTime() <= now)
    throw new Error('Choose a valid local time in the future.')
  return Math.floor(date.getTime() / 1000)
}

export function deadlineLabel(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}
