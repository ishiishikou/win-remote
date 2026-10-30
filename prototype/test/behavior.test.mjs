import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const script = readFileSync(new URL("../app.js", import.meta.url), "utf8");

function harness() {
  const listeners = {};
  const classes = () => ({ toggle(name, enabled) { this[name] = !!enabled; } });
  const views = ["home", "apps", "files", "terminal", "screen", "input"]
    .map(id => ({id, hidden: id !== "home", classList: classes()}));
  const nav = ["home", "apps", "files", "terminal", "screen"]
    .map(id => ({dataset: {view:id}, classList: classes(), setAttribute(k,v){this[k]=v},removeAttribute(k){delete this[k]}}));
  const apps = ["chrome 調べもの", "メモ帳 買い物メモ", "エクスプローラー remote"]
    .map(name => ({hidden:false, getAttribute(){return name}}));
  const files = ["資料", "写真", "買い物メモ.txt", "design.md"]
    .map(name => ({hidden:false, getAttribute(){return name}}));
  const fields = {
    "#app-search": {value:"", addEventListener(type, cb){listeners.appInput=cb}},
    "#file-search": {value:"", addEventListener(type, cb){listeners.fileInput=cb}},
    "#back": {addEventListener(type, cb){listeners.back=cb}},
    "#simulate-send": {addEventListener(type, cb){listeners.send=cb}},
    "#draft": {value:""},
    "#notice": {hidden:true, textContent:""},
    "#main": {focus(){}}
  };
  const root = {
    querySelector(selector) {
      if (selector.startsWith(".view#")) return views.find(x => x.id === selector.slice(6));
      return fields[selector] || null;
    },
    querySelectorAll(selector) {
      if (selector === ".view") return views;
      if (selector === ".nav [data-view]") return nav;
      if (selector === ".app-card") return apps;
      if (selector === ".file-list .item") return files;
      return [];
    },
    contains(){return true},
    addEventListener(type, cb){listeners.click=cb}
  };
  vm.runInNewContext(script, {
    document: { querySelector(selector) { return selector === ".shell" ? root : null } },
    window: {scrollTo(){}},
    console
  }, {filename:"app.js"});
  function click(data) {
    const button={dataset:data};
    listeners.click({target:{closest(){return button}}});
  }
  const active = () => views.find(x => !x.hidden)?.id;
  return {click,active,views,nav,apps,files,fields,listeners};
}

test("navigation and input sheet return to previous view", () => {
  const h = harness();
  assert.equal(h.active(),"home");
  h.click({view:"apps"});
  assert.equal(h.active(),"apps");
  h.click({view:"input"});
  assert.equal(h.active(),"input");
  h.listeners.back();
  assert.equal(h.active(),"apps");
  h.click({view:"screen"});
  assert.equal(h.active(),"screen");
  assert.equal(h.nav.find(x=>x.dataset.view==="screen")["aria-current"],"page");
  assert.equal(h.nav.find(x=>x.dataset.view==="apps")["aria-current"],undefined);
});

test("search only filters demo data and normalizes Japanese width", () => {
  const h=harness();
  h.fields["#app-search"].value="ﾒﾓ";
  h.listeners.appInput();
  assert.deepEqual(h.apps.map(x=>x.hidden),[true,false,true]);
  h.fields["#file-search"].value="DESIGN";
  h.listeners.fileInput();
  assert.deepEqual(h.files.map(x=>x.hidden),[true,true,true,false]);
});

test("send and command buttons only show a demo message", () => {
  const h=harness();
  h.click({view:"input"});
  h.fields["#draft"].value="こんにちは世界";
  h.listeners.send();
  assert.equal(h.fields["#notice"].hidden,false);
  assert.match(h.fields["#notice"].textContent,/送信していません/);
  h.click({view:"terminal"});
  h.click({mock:"PowerShellコマンドを実行"});
  assert.match(h.fields["#notice"].textContent,/デモ表示/);
});

test("empty input is refused instead of being presented as sent", () => {
  const h=harness();
  h.fields["#draft"].value="  ";
  h.listeners.send();
  assert.match(h.fields["#notice"].textContent,/入力してください/);
});
