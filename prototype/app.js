"use strict";
(() => {
  const root = document.querySelector(".shell");
  const views = Array.from(root.querySelectorAll(".view"));
  const nav = Array.from(root.querySelectorAll(".nav [data-view]"));
  const notice = root.querySelector("#notice");
  const main = root.querySelector("#main");
  let current = "home";
  let previous = "home";

  function show(page) {
    const target = root.querySelector(".view#" + page);
    if (!target) return;
    if (page === "input" && current !== "input") previous = current;
    current = page;
    views.forEach(view => {
      const visible = view.id === page;
      view.hidden = !visible;
      view.classList.toggle("is-active", visible);
    });
    nav.forEach(button => {
      const active = button.dataset.view === page;
      button.classList.toggle("active", active);
      if (active) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    });
    notice.hidden = true;
    main.focus({preventScroll: true});
    window.scrollTo({top: 0, behavior: "instant"});
  }

  function demoOnly(action) {
    notice.textContent = "「" + action + "」はデモ表示です。Windowsには送信していません。";
    notice.hidden = false;
  }

  root.addEventListener("click", event => {
    const button = event.target.closest("button");
    if (!button || !root.contains(button)) return;
    const page = button.dataset.view;
    const mock = button.dataset.mock;
    if (page) show(page);
    else if (mock) demoOnly(mock);
  });

  root.querySelector("#back").addEventListener("click", () => show(previous));
  root.querySelector("#simulate-send").addEventListener("click", () => {
    const value = root.querySelector("#draft").value;
    if (!value.trim()) {
      notice.textContent = "送信する文字を入力してください。";
      notice.hidden = false;
      return;
    }
    demoOnly("文字を送る（" + Array.from(value).length + "文字）");
  });

  function filterItems(fieldId, selector, attribute) {
    const field = root.querySelector("#" + fieldId);
    field.addEventListener("input", () => {
      const query = field.value.normalize("NFKC").toLocaleLowerCase("ja-JP");
      root.querySelectorAll(selector).forEach(item => {
        item.hidden = !item.getAttribute(attribute).normalize("NFKC").toLocaleLowerCase("ja-JP").includes(query);
      });
    });
  }

  filterItems("app-search", ".app-card", "data-app-name");
  filterItems("file-search", ".file-list .item", "data-file-name");
})();