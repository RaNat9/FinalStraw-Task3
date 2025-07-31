// --- File: service-worker.js ---
// This service worker implements a "Network First, then Cache" strategy.

const CACHE_NAME = 'rewards-app-cache-v1';
const OFFLINE_URL = '/offline';

// List of assets to pre-cache on install
const urlsToCache = [
  '/',
  '/static/css/style.css', // Assuming you have a CSS file
  '/static/images/icon-192x192.png', // PWA icons
  '/static/images/icon-512x512.png',
  OFFLINE_URL
];

self.addEventListener('install', event => {
  // Perform installation steps
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
  );
  self.skipWaiting(); // Forces the waiting service worker to activate
});

self.addEventListener('activate', event => {
  console.log('Service Worker activating.');
  event.waitUntil(
    // Delete old caches
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.filter(cacheName => cacheName !== CACHE_NAME)
                  .map(cacheName => caches.delete(cacheName))
      );
    })
  );
  clients.claim(); // Makes the service worker take control of the page immediately
});

self.addEventListener('fetch', event => {
  // Use a "Network First, then Cache" strategy
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => {
        // If network fails, serve the offline page from the cache
        return caches.match(OFFLINE_URL);
      })
    );
  } else {
    // For other requests (e.g., CSS, JS, images), use a "Cache, then Network"
    // or simple cache strategy.
    event.respondWith(
      caches.match(event.request).then(response => {
        return response || fetch(event.request).then(fetchResponse => {
          return caches.open(CACHE_NAME).then(cache => {
            // Only cache successful responses
            if (fetchResponse.status === 200) {
              cache.put(event.request, fetchResponse.clone());
            }
            return fetchResponse;
          });
        }).catch(() => {
          // If all else fails, return the offline page.
          return caches.match(OFFLINE_URL);
        });
      })
    );
  }
});
