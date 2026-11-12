/* Service worker do Controle de Ponto: recebe notificações push com o app fechado. */

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
    let dados = {};
    try {
        dados = event.data ? event.data.json() : {};
    } catch (_) {
        dados = { corpo: event.data ? event.data.text() : '' };
    }
    const titulo = dados.titulo || 'Controle de Ponto';
    event.waitUntil(
        self.registration.showNotification(titulo, {
            body: dados.corpo || '',
            icon: '/static/icons/icon-192.png',
            badge: '/static/icons/icon-192.png',
            tag: dados.tag || 'ponto',      // um lembrete novo do mesmo tipo substitui o anterior
            renotify: true,
            data: { url: dados.url || '/' },
        })
    );
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const destino = new URL((event.notification.data && event.notification.data.url) || '/', self.location.origin).href;
    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((abertas) => {
            for (const cliente of abertas) {
                if (cliente.url.startsWith(self.location.origin) && 'focus' in cliente) {
                    cliente.navigate(destino);
                    return cliente.focus();
                }
            }
            return self.clients.openWindow(destino);
        })
    );
});
