"use strict";
// This registration is for the disconnected UI demo ONLY.
// Never register this worker from an authenticated Windows Agent origin.
(() => {
  // Keep the worker below /prototype/ even when the demo is hosted next to an Agent.
  const path = window.location.pathname;
  if (!(path.endsWith("/prototype/") || path.endsWith("/prototype/index.html"))) return;
  if (!("serviceWorker" in navigator) || !window.isSecureContext) return;
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js", { scope: "./" })
      .catch(() => {
        // The UI remains usable without offline caching. No fallback to HTTP.
        console.warn("デモのオフライン保存は利用できません。");
      });
  });
})();
