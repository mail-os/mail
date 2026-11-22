/* Only notification routing lives here. Mail is never cached by the worker. */
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()))
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()))
self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  event.waitUntil((async () => {
    const path = new URL('/', self.location.origin)
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    const inbox = clients.find(client => client.url === path.href)
    if (inbox) await inbox.focus()
    else await self.clients.openWindow(path.href)
  })())
})
