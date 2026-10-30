"""Chromium DOM/layout smoke checks for the disconnected UI demo.

This is intentionally NOT an HTTP/CSP/Service Worker/iOS end-to-end test:
about:blank + injected repository assets avoids all network traffic.
"""
import os
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
html = (ROOT / "index.html").read_text(encoding="utf-8")
css = (ROOT / "styles.css").read_text(encoding="utf-8")
js = (ROOT / "app.js").read_text(encoding="utf-8")
passed = []


def check(name, condition):
    assert condition, name
    passed.append(name)
    print("PASS", name)


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(
        executable_path=os.environ.get("WIN_REMOTE_CHROMIUM") or None,
        headless=True,
    )
    context = browser.new_context(
        viewport={"width": 390, "height": 844},
        is_mobile=True,
        has_touch=True,
        device_scale_factor=3,
        # Injection into about:blank cannot test the HTTP response CSP.
        bypass_csp=True,
    )
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.route("**/*", lambda route: route.abort())
    page.set_content(html)
    page.add_style_tag(content=css)
    page.evaluate(js)

    check("home", page.locator("#home").is_visible() and not page.locator("#apps").is_visible())
    check("demo banner", "Windowsには接続していません" in page.locator(".demo-banner").inner_text())
    for view in ["apps", "files", "terminal", "screen", "home"]:
        page.locator(f'.nav button[data-view="{view}"]').click()
        check("nav " + view, page.locator("#" + view).is_visible())

    page.locator('.nav button[data-view="apps"]').click()
    page.locator("#app-search").fill("ＣＨＲＯＭＥ")
    check("app search NFKC", page.locator(".app-card:visible").count() == 1)
    page.locator('.nav button[data-view="files"]').click()
    page.locator("#file-search").fill("買い物")
    check("file search Japanese", page.locator(".file-list .item:visible").count() == 1)

    page.locator('.nav button[data-view="home"]').click()
    page.locator('#home [data-view="input"]').click()
    check("input sheet", page.locator("#input").is_visible())
    page.locator("#simulate-send").click()
    check("blank reject", "送信する文字を入力" in page.locator("#notice").inner_text())
    page.locator("#draft").fill("日本語テスト🍎")
    page.locator("#simulate-send").click()
    check("demo send", "Windowsには送信していません" in page.locator("#notice").inner_text())
    page.locator("#back").click()
    check("back", page.locator("#home").is_visible())
    page.locator('.nav button[data-view="terminal"]').click()
    page.locator('#terminal button[data-mock="PowerShellコマンドを実行"]').click()
    check("terminal mock", "Windowsには送信していません" in page.locator("#notice").inner_text())

    check("no JS exception", not errors)
    for view in ["home", "apps", "files", "terminal", "screen"]:
        box = page.locator(f'.nav button[data-view="{view}"]').bounding_box()
        check("tap area " + view, box["height"] >= 44 and box["width"] >= 44)
    check("no horizontal scroll", page.evaluate("document.documentElement.scrollWidth <= innerWidth"))

    print("TOTAL", len(passed), "PASSED; Chromium", browser.version)
    browser.close()
