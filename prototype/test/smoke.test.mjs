import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const script = readFileSync(new URL("../app.js", import.meta.url), "utf8");
const css = readFileSync(new URL("../styles.css", import.meta.url), "utf8");

test("all six documented views exist", () => {
  for (const id of ["home", "apps", "files", "terminal", "screen", "input"]) {
    assert.match(html, new RegExp('id="' + id + '"'));
  }
});

test("five primary navigation buttons exist", () => {
  for (const id of ["home", "apps", "files", "terminal", "screen"]) {
    assert.match(html, new RegExp('<button[^>]+data-view="' + id + '"'));
  }
});

test("demo is clearly labeled as disconnected", () => {
  assert.match(html, /Windowsには接続していません/);
  assert.match(html, /未接続 \/ デモ/);
  assert.match(html, /デモでは送信しません/);
});

test("prototype denies any network requests by CSP", () => {
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /default-src 'none'/);
  assert.doesNotMatch(script, /\b(fetch|WebSocket|EventSource|XMLHttpRequest)\s*\(/);
  assert.doesNotMatch(html, /<script[^>]+src="https?:/);
});

test("visible safe actions and accessibility landmarks", () => {
  assert.match(html, /role="status"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /for="draft"/);
  assert.match(css, /min-height:44px/);
  assert.match(css, /\.item\[hidden\]/);
});