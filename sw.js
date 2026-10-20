const CACHE_NAME = 'private-gallery-v1';

// यहाँ उन सभी फ़ाइलों के नाम हैं जिन्हें बिना नेट के चलाना है
const ASSETS_TO_CACHE = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './argon2.js',
  './argon2.wasm',
  './manifest.json',
  './icon-512.png',
  './icon-1600.png'
];

// इंस्टॉल करते समय फ़ाइलों को सेव (cache) करना
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE);
    })
  );
});

// बिना नेट के ऐप
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request);
    })
  );
});
