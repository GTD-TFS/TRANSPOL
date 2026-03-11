const CACHE_NAME = "editor-compartido-v4";

const APP_ASSETS = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./icons/icon-192.png",
  "./icons/icon-512.png"
];

self.addEventListener("install", event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(APP_ASSETS))
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.map(k => (k !== CACHE_NAME ? caches.delete(k) : null))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", event => {
  const url = new URL(event.request.url);

  // ⚠️ No tocar Firebase ni Google APIs
  if (url.origin.includes("googleapis") || url.origin.includes("firebase")) {
    return;
  }

  // HTML/navegacion: intentar red primero para evitar servir versiones antiguas.
  if (event.request.mode === "navigate" || event.request.destination === "document") {
    event.respondWith(
      fetch(event.request)
        .then(resp => {
          const copy = resp.clone();
          caches.open(CACHE_NAME).then(cache => cache.put("./index.html", copy));
          return resp;
        })
        .catch(() => caches.match(event.request).then(r => r || caches.match("./index.html")))
    );
    return;
  }

  event.respondWith(
    caches.match(event.request).then(resp => {
      if (resp) return resp;
      return fetch(event.request).then(networkResp => {
        const copy = networkResp.clone();
        caches.open(CACHE_NAME).then(cache => cache.put(event.request, copy));
        return networkResp;
      });
    })
  );
});
