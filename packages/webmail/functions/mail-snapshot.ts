import { openPublicLink } from './mail-public-links'

export interface SnapshotMessage { subject: string, from: string, timestamp: number, text: string }
export interface SnapshotView { messages: SnapshotMessage[], expires_at: number }

export function openSnapshot(token: string, signal: AbortSignal) {
  return openPublicLink<SnapshotView>('/webmail/public/snapshot', token, signal)
}
