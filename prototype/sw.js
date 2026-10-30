"use strict";
// DEMO-ONLY service worker. Never cache authenticated API/Windows Agent responses.
const CACHE_PREFIX = "win-remote-demo-shell-";
const CACHE_NAME = CACHE_PREFIX + "v1";
const ASSETS = Object.freeze([
  "./", "./index.html", "./styles.css", "./app.js",
  "./pwa.js", "./manifest.webmanifest", "./icons/demo.svg"
]);
const scope = self.registration.scope;
const allowed = new Map(ASSETS.map(path => {
  const url = new URL(path, scope);
  return [url.pathname, url.href];
}));

self.addEventListener("install", event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    // Atomic: if any local demo asset fails to load, install fails.
    await cache.addAll(ASSETS);
    await self.skipWaiting();
  })());
});

self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if (key.startsWith(CACHE_PREFIX) && key !== CACHE_NAME) {
        await caches.delete(key);
      }
    }
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", event => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  // Never intercept requests outside this demo's exact same-origin allowlist.
  if (url.origin !== new URL(scope).origin || !allowed.has(url.pathname)) return;
  // Queries/fragments cannot introduce new cache keys or cached API responses.
  const canonical = allowed.get(url.pathname);
  event.respondWith((async () => {
    const cached = await caches.match(canonical, { cacheName: CACHE_NAME });
    if (cached) return cached;
    // No network fallback: an incomplete install must fail rather than leak.
    return Response.error();
  })());
});
