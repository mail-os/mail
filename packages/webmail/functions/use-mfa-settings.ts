import type { createMailApi } from './mail-api'
import { state } from '@stacksjs/stx'

const path = '/webmail/auth/mfa'

export function useMfaSettings(api: ReturnType<typeof createMailApi>) {
  const mfaOpen = state(false)
  const mfaStatus = state<{ enabled: boolean, available: boolean } | null>(null)
  const mfaPassword = state('')
  const mfaCode = state('')
  const mfaSecret = state('')
  const mfaRecoveryCodes = state<string[]>([])
  const mfaRemoving = state(false)
  const mfaBusy = state(false)
  const mfaError = state('')
  const mfaNotice = state('')
  let generation = 0

  function closeMfaSettings() {
    generation++
    mfaOpen.set(false)
    mfaStatus.set(null)
    mfaPassword.set('')
    mfaCode.set('')
    mfaSecret.set('')
    mfaRecoveryCodes.set([])
    mfaRemoving.set(false)
    mfaBusy.set(false)
    mfaError.set('')
    mfaNotice.set('')
  }

  async function update(action: (current: () => boolean) => Promise<void>) {
    if (mfaBusy()) return
    const panel = generation
    const current = () => panel === generation
    mfaBusy.set(true)
    mfaError.set('')
    mfaNotice.set('')
    try { await action(current) }
    catch (error) {
      if (current()) mfaError.set(error instanceof Error ? error.message : 'Could not update two-step verification.')
    }
    finally { if (current()) mfaBusy.set(false) }
  }

  async function toggleMfaSettings() {
    if (mfaOpen()) {
      closeMfaSettings()
      return
    }
    mfaOpen.set(true)
    await update(async (current) => {
      const status = await api<{ enabled: boolean, available: boolean }>(path)
      if (current()) mfaStatus.set(status)
    })
  }

  async function beginMfaSetup() {
    await update(async (current) => {
      const body = JSON.stringify({ currentPassword: mfaPassword() })
      mfaPassword.set('')
      const result = await api<{ secret: string }>(path, { method: 'POST', body })
      if (current()) mfaSecret.set(result.secret)
    })
  }

  function cancelMfaSetup() {
    mfaCode.set('')
    mfaSecret.set('')
    mfaRemoving.set(false)
    mfaError.set('')
  }

  async function confirmMfaSetup() {
    await update(async (current) => {
      const body = JSON.stringify({ factor: mfaCode().trim() })
      mfaCode.set('')
      const result = await api<{ recoveryCodes: string[] }>(path, { method: 'PUT', body })
      if (!current()) return
      mfaSecret.set('')
      mfaStatus.set({ enabled: true, available: true })
      mfaRecoveryCodes.set(result.recoveryCodes)
    })
  }

  async function disableMfa() {
    await update(async (current) => {
      const body = JSON.stringify({ factor: mfaCode().trim() })
      mfaCode.set('')
      await api(path, { method: 'DELETE', body })
      if (!current()) return
      mfaRemoving.set(false)
      mfaStatus.set({ enabled: false, available: mfaStatus()?.available ?? false })
      mfaNotice.set('Two-step verification is off.')
    })
  }

  async function copyMfaCodes() {
    const codes = mfaRecoveryCodes()
    if (!codes.length) return
    try {
      await globalThis.navigator.clipboard.writeText(codes.join('\n'))
      if (mfaRecoveryCodes() === codes) mfaNotice.set('Recovery codes copied.')
    }
    catch {
      if (mfaRecoveryCodes() === codes) mfaNotice.set('Select the recovery codes to copy them.')
    }
  }

  return {
    mfaOpen, mfaStatus, mfaPassword, mfaCode, mfaSecret, mfaRecoveryCodes, mfaRemoving, mfaBusy, mfaError, mfaNotice,
    toggleMfaSettings, closeMfaSettings, beginMfaSetup, confirmMfaSetup, cancelMfaSetup, disableMfa, copyMfaCodes,
  }
}
