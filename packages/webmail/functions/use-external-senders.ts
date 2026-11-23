import { derived, state } from '@stacksjs/stx'
import type { createMailApi } from './mail-api'

interface ExternalAddress {
  id: string
  address: string
  state: 'unverified' | 'pending' | 'verified'
}

const endpoint = '/webmail/api/external-sender-verification'

export function useExternalSenders(api: ReturnType<typeof createMailApi>, onChange: () => void) {
  const externalAddresses = state<ExternalAddress[]>([])
  const externalAddressId = state('')
  const externalCode = state('')
  const externalAddressBusy = state(false)
  const externalAddressError = state('')
  const externalAddressNotice = state('')
  const externalAddress = derived(() => externalAddresses().find(address => address.id === externalAddressId()))
  let generation = 0

  function clearExternalAddresses() {
    generation += 1
    externalAddresses.set([])
    externalAddressId.set('')
    externalCode.set('')
    externalAddressBusy.set(false)
    externalAddressError.set('')
    externalAddressNotice.set('')
  }

  function selectExternalAddress(event: Event) {
    externalAddressId.set((event.target as HTMLSelectElement).value)
    externalCode.set('')
    externalAddressError.set('')
    externalAddressNotice.set('')
  }

  function install(addresses: ExternalAddress[]) {
    externalAddresses.set(addresses)
    if (!addresses.some(address => address.id === externalAddressId())) externalAddressId.set(addresses[0]?.id ?? '')
  }

  async function loadExternalAddresses() {
    const request = ++generation
    externalAddressError.set('')
    externalAddressBusy.set(true)
    try {
      const addresses = await api<ExternalAddress[]>(endpoint)
      if (generation === request) install(addresses)
    }
    catch (cause) {
      if (generation === request && cause instanceof Error) externalAddressError.set(cause.message)
    }
    finally {
      if (generation === request) externalAddressBusy.set(false)
    }
  }

  async function verifyExternalAddress(action: 'request' | 'confirm' | 'revoke') {
    if (!externalAddress() || externalAddressBusy()) return
    const request = ++generation
    const notice = { request: 'Verification code requested.', confirm: 'From address verified.', revoke: 'Verification removed.' }
    externalAddressBusy.set(true)
    externalAddressError.set('')
    externalAddressNotice.set('')
    try {
      const addresses = await api<ExternalAddress[]>(endpoint, {
        method: 'POST', body: JSON.stringify({ id: externalAddressId(), action, code: action === 'confirm' ? externalCode().trim() : '' }),
      })
      if (generation !== request) return
      install(addresses)
      externalCode.set('')
      externalAddressNotice.set(notice[action])
      onChange()
    }
    catch (cause) {
      if (generation === request && cause instanceof Error) externalAddressError.set(cause.message)
    }
    finally {
      if (generation === request) externalAddressBusy.set(false)
    }
  }

  return {
    externalAddresses, externalAddress, externalAddressId, externalCode, externalAddressBusy, externalAddressError, externalAddressNotice,
    selectExternalAddress, loadExternalAddresses, verifyExternalAddress, clearExternalAddresses,
  }
}
