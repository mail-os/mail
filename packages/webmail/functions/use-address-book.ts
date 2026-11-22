import { batch, derived, state } from '@stacksjs/stx'
import type { createMailApi } from './mail-api'
import type { AddressBook, AddressBookCard } from './mail-types'

const addressBookPath = '/webmail/api/address-book'
type CardKind = AddressBookCard['kind']

function cardId(value: string): string { return value.replace(/^urn:uuid:/i, '') }

function findMember(cards: AddressBookCard[], uri: string): AddressBookCard | undefined {
  if (/^mailto:/i.test(uri)) return cards.find(card => card.kind === 'contact' &&
    card.emails.some(email => email.toLowerCase() === uri.slice(7).toLowerCase()))
  const id = cardId(uri)
  const isUuid = /^[\da-f]{8}-(?:[\da-f]{4}-){3}[\da-f]{12}$/i.test(id)
  return cards.find(card => isUuid ? cardId(card.card_uid).toLowerCase() === id.toLowerCase() : cardId(card.card_uid) === id)
}

export function addressForCard(card: AddressBookCard): string {
  const email = card.emails[0] || ''
  return /[^\s@]+@[^\s@]+/.test(email) ? email : ''
}

export function useAddressBook(api: ReturnType<typeof createMailApi>) {
  const contactsOpen = state(false)
  const addressBook = state<AddressBook | null>(null)
  const contactsBusy = state(false)
  const contactsError = state('')
  const contactQuery = state('')
  const contactView = state<CardKind>('contact')
  const activeCard = state<AddressBookCard | null>(null)
  const contactDraft = state<CardKind | null>(null)
  const contactName = state('')
  const contactEmails = state('')
  const contactNote = state('')
  const memberUIDs = state<string[]>([])
  const confirmCardRemoval = state(false)
  let request = 0

  const visibleCards = derived(() => {
    const filter = contactQuery().trim().toLowerCase()
    return (addressBook()?.cards || []).filter(card => card.kind === contactView() &&
      (!filter || card.name.toLowerCase().includes(filter) || card.emails.some(email => email.toLowerCase().includes(filter))))
  })
  const memberOptions = derived(() => (addressBook()?.cards || []).filter(card => card.kind === 'contact'))
  const linkedMembers = derived(() => (activeCard()?.members || []).filter(uri => findMember(addressBook()?.cards || [], uri)?.kind !== 'contact').length)

  function setCard(card: AddressBookCard | null): void {
    const cards = addressBook()?.cards || []
    const knownMembers = card?.members.map(uri => findMember(cards, uri)).filter(item => item?.kind === 'contact').map(item => item!.uid) || []
    batch(() => {
      activeCard.set(card)
      contactDraft.set(card?.kind || null)
      contactName.set(card?.name || '')
      contactEmails.set(card?.emails.join('\n') || '')
      contactNote.set(card?.note || '')
      memberUIDs.set(knownMembers)
      confirmCardRemoval.set(false)
    })
  }

  async function loadContacts(book?: string, etag?: string): Promise<void> {
    const number = ++request
    contactsBusy.set(true)
    contactsError.set('')
    try {
      const query = book ? `?${new URLSearchParams({ book })}` : ''
      const result = await api<AddressBook>(addressBookPath + query)
      if (number !== request) return
      batch(() => {
        addressBook.set(result)
        const card = result.cards.find(item => item.etag === etag)
        setCard(card || null)
      })
    }
    catch (cause) {
      if (number === request) contactsError.set(cause instanceof Error ? cause.message : 'Could not load this address book.')
    }
    finally {
      if (number === request) contactsBusy.set(false)
    }
  }

  function closeContacts(): void {
    request += 1
    batch(() => {
      contactsOpen.set(false)
      addressBook.set(null)
      contactsBusy.set(false)
      contactsError.set('')
      contactQuery.set('')
      contactView.set('contact')
      setCard(null)
    })
  }

  function newContact(kind: CardKind): void {
    setCard(null)
    contactDraft.set(kind)
    contactView.set(kind)
  }

  function changeContactView(kind: CardKind): void {
    contactQuery.set('')
    contactView.set(kind)
    setCard(null)
  }

  function toggleContactMember(uid: string, event: Event): void {
    const input = event.target as HTMLInputElement
    memberUIDs.update(previous => input.checked ? [...new Set([...previous, uid])] : previous.filter(id => id !== uid))
  }

  async function saveContact(): Promise<void> {
    const book = addressBook()?.book
    const kind = contactDraft()
    if (!book || !kind || !contactName().trim() || contactsBusy()) return
    const card = activeCard()
    const params = new URLSearchParams({ book })
    if (card) params.set('uid', card.uid)
    const number = ++request
    contactsBusy.set(true)
    contactsError.set('')
    try {
      const saved = await api<{ etag: string }>(`${addressBookPath}?${params}`, {
        method: card ? 'PUT' : 'POST',
        headers: card ? { 'If-Match': card.etag } : undefined,
        body: JSON.stringify({
          kind, name: contactName().trim(), note: contactNote(),
          emails: kind === 'contact' ? contactEmails().split(/[\n,]+/).map(value => value.trim()).filter(Boolean) : [],
          members: kind === 'group' ? memberUIDs() : [],
        }),
      })
      if (number === request) await loadContacts(book, saved.etag)
    }
    catch (cause) {
      if (number === request) contactsError.set(cause instanceof Error ? cause.message : 'Could not save the card.')
    }
    finally {
      if (number === request) contactsBusy.set(false)
    }
  }

  async function deleteContact(): Promise<void> {
    const book = addressBook()?.book
    const card = activeCard()
    if (!book || !card || !confirmCardRemoval() || contactsBusy()) return
    const number = ++request
    contactsBusy.set(true)
    contactsError.set('')
    try {
      await api(`${addressBookPath}?${new URLSearchParams({ book, uid: card.uid })}`, { method: 'DELETE', headers: { 'If-Match': card.etag } })
      if (number === request) await loadContacts(book)
    }
    catch (cause) {
      if (number === request) contactsError.set(cause instanceof Error ? cause.message : 'Could not remove the card.')
    }
    finally {
      if (number === request) contactsBusy.set(false)
    }
  }

  function savedContactRecipients(): string[] {
    const selected = activeCard()
    if (!selected) return []
    const cards = addressBook()?.cards || []
    const pending = [selected]
    const visited = new Set<string>()
    const recipients = new Map<string, string>()
    while (pending.length) {
      const card = pending.pop()!
      if (visited.has(card.uid)) continue
      visited.add(card.uid)
      if (card.kind === 'group') {
        for (const uri of card.members.slice().reverse()) {
          const member = findMember(cards, uri)
          if (member) pending.push(member)
        }
      }
      else {
        const address = addressForCard(card)
        if (address) recipients.set(address.toLowerCase(), address)
      }
    }
    return [...recipients.values()]
  }

  return {
    contactsOpen, addressBook, contactsBusy, contactsError, contactQuery, contactView, activeCard, contactDraft,
    contactName, contactEmails, contactNote, memberUIDs, confirmCardRemoval, visibleCards, memberOptions, linkedMembers,
    setCard, loadContacts, closeContacts, newContact, changeContactView, toggleContactMember, saveContact, deleteContact,
    savedContactRecipients,
  }
}
