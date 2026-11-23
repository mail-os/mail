import { derived, state } from '@stacksjs/stx'
import type { createMailApi } from './mail-api'
import type { MailNotificationRule, MailNotificationRules, MailNotificationScope, MessageRef } from './mail-types'

interface Settings { enabled: boolean }
type Api = ReturnType<typeof createMailApi>
const settingsPath = '/webmail/api/notifications'

export function useMailNotifications(api: Api, account: () => string | undefined) {
  const notificationEnabled = state(false)
  const notificationDevice = state<string | null>(null)
  const notificationBusy = state(false)
  const notificationError = state('')
  const notificationRuleBusy = state(false)
  const notificationRuleError = state('')
  const notificationsAvailable = typeof Notification !== 'undefined' && typeof navigator !== 'undefined' && 'serviceWorker' in navigator
  const notificationHere = derived(() => notificationEnabled() && !!account() && notificationDevice() === account())
  let registration: ServiceWorkerRegistration | null = null
  let polling = false
  const tag = (username: string) => `mail-notifications-v1:${username}`

  function savedDevice(username: string): boolean {
    try { return localStorage.getItem(tag(username)) === 'on' }
    catch { return false }
  }
  function saveDevice(username: string, enabled: boolean): void {
    try {
      if (enabled) localStorage.setItem(tag(username), 'on')
      else localStorage.removeItem(tag(username))
    }
    catch { /* In this tab, use the same explicit choice without storage. */ }
    notificationDevice.set(enabled ? username : null)
  }

  async function worker(): Promise<ServiceWorkerRegistration> {
    if (!registration?.active) {
      const installed = await navigator.serviceWorker.register('/mail-notifications.js', { updateViaCache: 'none' })
      if (installed.active) registration = installed
      else registration = await navigator.serviceWorker.ready
    }
    return registration
  }

  async function loadNotificationSettings(): Promise<void> {
    const username = account()
    if (!username || notificationBusy()) return
    const result = await api<Settings>(settingsPath)
    if (account() !== username) return
    notificationEnabled.set(result.enabled)
    if (notificationsAvailable && Notification.permission === 'granted' && savedDevice(username))
      notificationDevice.set(username)
    else if (!notificationsAvailable || Notification.permission !== 'granted')
      notificationDevice.set(null)
  }

  async function changeNotificationSettings(enabled: boolean): Promise<void> {
    const username = account()
    if (!username || notificationBusy()) return
    notificationBusy.set(true)
    notificationError.set('')
    try {
      if (enabled) {
        if (!notificationsAvailable) throw new Error('Browser notifications are unavailable here.')
        const permission = Notification.permission === 'default' ? await Notification.requestPermission() : Notification.permission
        if (permission !== 'granted') throw new Error('Allow notifications for this site in your browser to turn them on.')
        await worker()
      }
      if (account() !== username) return
      const result = await api<Settings>(settingsPath, { method: 'PUT', body: JSON.stringify({ enabled }) })
      if (account() !== username) return
      notificationEnabled.set(result.enabled)
      saveDevice(username, result.enabled)
    }
    catch (cause) {
      if (account() === username) notificationError.set(cause instanceof Error ? cause.message : 'Could not update browser notifications.')
    }
    finally { notificationBusy.set(false) }
  }

  async function pollNotifications(): Promise<void> {
    const username = account()
    if (!username || !notificationsAvailable || Notification.permission !== 'granted' || polling || notificationBusy()
      || (notificationDevice() !== username && !savedDevice(username))) return
    polling = true
    try {
      const active = await worker()
      if (account() !== username || notificationBusy() || Notification.permission !== 'granted') return
      const batch = await api<{ ids: number[], teamReplies?: number }>(`${settingsPath}/claim`, { method: 'POST' })
      if (account() !== username || notificationBusy() || Notification.permission !== 'granted') return
      if (batch.ids.length) {
        await active.showNotification('Mail', { body: 'You have new mail.', tag: `mail-${batch.ids[batch.ids.length - 1]}` })
      }
      if (batch.teamReplies && account() === username && !notificationBusy() && Notification.permission === 'granted') {
        await active.showNotification('Mail', { body: 'New replies in shared conversations.', tag: 'mail-team-replies' })
      }
    }
    catch { /* A tab can suspend or lose its session between polls. */ }
    finally { polling = false }
  }

  async function saveNotificationRule(message: MessageRef, scope: MailNotificationScope, rule: MailNotificationRule): Promise<MailNotificationRules | null> {
    if (!message.reference || !message.revision || notificationRuleBusy()) return null
    notificationRuleBusy.set(true)
    notificationRuleError.set('')
    try {
      return await api<MailNotificationRules>(`${settingsPath}/rule`, {
        method: 'PUT',
        headers: { 'If-Match': message.revision },
        body: JSON.stringify({ reference: message.reference, scope, rule }),
      })
    }
    catch (cause) {
      notificationRuleError.set(cause instanceof Error ? cause.message : 'Could not save the notification rule.')
      return null
    }
    finally { notificationRuleBusy.set(false) }
  }

  return { notificationsAvailable, notificationEnabled, notificationHere, notificationBusy, notificationError, notificationRuleBusy, notificationRuleError, loadNotificationSettings, changeNotificationSettings, pollNotifications, saveNotificationRule }
}
