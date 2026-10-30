"use strict";
// This registration is for the disconnected UI demo ONLY.
// Never register this worker from an authenticated Windows Agent origin.
(() => {
  if (!("serviceWorker" in navigator) || !window.isSecureContext) return;
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js", { scope: "./" })
      .catch(() => {
        // The UI remains usable without offline caching. No fallback to HTTP.
        console.warn("デモのオフライン保存は利用できません。");
      });
  });
})();
