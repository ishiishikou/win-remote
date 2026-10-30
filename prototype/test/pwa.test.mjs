import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const read = name => readFileSync(new URL("../" + name, import.meta.url), "utf8");
const manifest = JSON.parse(read("manifest.webmanifest"));
const scope = "https://192.168.10.20:8443/prototype/";

function serviceWorkerHarness() {
  const handlers = {};
  const cacheAdditions = [];
  const deleted = [];
  const matches = [];
  let claimed = false;
  let skipped = false;
  let hasCache = true;
  const caches = {
    async open(name) {
      assert.equal(name, "win-remote-demo-shell-v1");
      return { async addAll(paths) { cacheAdditions.push(...paths); } };
    },
    async keys() { return ["unrelated-app", "win-remote-demo-shell-v0", "win-remote-demo-shell-v1"]; },
    async delete(name) { deleted.push(name); },
    async match(url, options) {
      matches.push({url, options});
      return hasCache ? {cached: url} : undefined;
    }
  };
  const self = {
    registration: {scope},
    addEventListener(name, callback) { handlers[name] = callback; },
    async skipWaiting() { skipped = true; },
    clients: {async claim() { claimed = true; }}
  };
  vm.runInNewContext(read("sw.js"), {self, caches, URL, Response});
  async function lifecycle(name) {
    let task;
    handlers[name]({waitUntil(promise) {task = promise;}});
    assert.ok(task, name + " must call waitUntil");
    await task;
  }
  async function request(url, method = "GET") {
    let response;
    handlers.fetch({
      request: {url, method},
      respondWith(promise) { response = promise; }
    });
    return response === undefined ? undefined : await response;
  }
  return {
    lifecycle, request, cacheAdditions, deleted, matches,
    get claimed() {return claimed;},
    get skipped() {return skipped;},
    setCache(value) {hasCache = value;}
  };
}

test("manifest is a scoped, explicitly disconnected demo", () => {
  assert.match(manifest.name, /デモ/);
  assert.equal(manifest.start_url, "./index.html");
  assert.equal(manifest.scope, "./");
  assert.equal(manifest.display, "standalone");
  assert.equal(manifest.icons.length, 1);
  assert.match(read("icons/demo.svg"), /<svg/);
  assert.ok(!JSON.stringify(manifest).includes("https://"));
});

test("CSP explicitly allows same-origin worker/manifest but forbids connections", () => {
  const html = read("index.html");
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /worker-src 'self'/);
  assert.match(html, /manifest-src 'self'/);
  assert.match(html, /href="\.\/manifest\.webmanifest"/);
  assert.match(html, /src="\.\/pwa\.js"/);
});

test("worker pre-caches only seven local demo assets and deletes only own old cache", async () => {
  const h = serviceWorkerHarness();
  await h.lifecycle("install");
  assert.deepEqual(h.cacheAdditions, [
    "./", "./index.html", "./styles.css", "./app.js",
    "./pwa.js", "./manifest.webmanifest", "./icons/demo.svg"
  ]);
  assert.ok(h.cacheAdditions.every(x => x.startsWith("./") && !x.includes("..")));
  assert.equal(h.skipped, true);
  await h.lifecycle("activate");
  assert.deepEqual(h.deleted, ["win-remote-demo-shell-v0"]);
  assert.equal(h.claimed, true);
});

test("worker serves only exact same-origin demo paths, never API, WAN or POST", async () => {
  const h = serviceWorkerHarness();
  assert.deepEqual(await h.request(scope + "index.html"), {cached:scope + "index.html"});
  assert.deepEqual(await h.request(scope + "index.html?tracking=1"), {cached:scope + "index.html"});
  assert.equal(await h.request(scope + "api/execute"), undefined);
  assert.equal(await h.request("https://example.com/prototype/index.html"), undefined);
  assert.equal(await h.request(scope + "index.html", "POST"), undefined);
  assert.equal(h.matches.length, 2);
  assert.ok(h.matches.every(x => x.options.cacheName === "win-remote-demo-shell-v1"));
});

test("worker fails closed if expected demo asset is missing", async () => {
  const h = serviceWorkerHarness();
  h.setCache(false);
  const result = await h.request(scope + "app.js");
  assert.equal(result.type, "error");
});

test("registration requires secure context and never uses remote origin", async () => {
  async function register(secure, available) {
    const listeners = {};
    const calls = [];
    const navigator = available ? {serviceWorker: {
      register(...args) {calls.push(args); return Promise.resolve();}
    }} : {};
    vm.runInNewContext(read("pwa.js"), {
      navigator,
      window: {isSecureContext: secure, addEventListener(type, callback) {listeners[type] = callback;}},
      console: {warn() {}}
    });
    if (listeners.load) listeners.load();
    await Promise.resolve();
    return calls;
  }
  assert.deepEqual(await register(false, true), []);
  assert.deepEqual(await register(true, false), []);
  assert.equal(JSON.stringify(await register(true, true)), JSON.stringify([["./sw.js", {scope:"./"}]]));
});
