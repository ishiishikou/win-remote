# UI prototype (未接続デモ)

このディレクトリは [UI設計](../docs/design/mobile-ui.md) の6画面を実装した **デモ専用** プロトタイプです。現段階ではWindows Agent、RDP/VNC、HTTPS/WSS、認証、ファイル変更、PowerShell実行に**一切接続しません**。例示データだけを表示します。

## 起動（Windowsでのローカル確認のみ）

1. Pythonが使えるPCでリポジトリを取得。
2. PowerShellで**リポジトリのルート**に移動（`prototype` 内には移動しない）。
3. `python -m http.server 8765 --bind 127.0.0.1`。
4. **同じWindowsの**ブラウザで `http://127.0.0.1:8765/prototype/` を開く。画面幅を375px程度にして確認。Service Workerは `/prototype/` 以下だけに登録します。
5. 終わったらCtrl+Cでサーバー停止。

`--bind 127.0.0.1` はPC自身からしかアクセスできない設定です。**iPhoneから見たいからといって `0.0.0.0` へ変更したり、HTTPをLANへ開放したりしないでください。** iPhoneへの提供は後続のTLS/認証/LAN制限（G1〜G3）が通過してから行います。

## デモ専用PWAシェル（本接続とは完全に別）
- `manifest.webmanifest`、`pwa.js`、`sw.js` とSVGアイコンを追加。localhost/HTTPSなどのsecure contextかつURLが `/prototype/` または `/prototype/index.html` のときだけデモ用Service Workerを登録し、**このデモの固定7資産だけ**をオフライン保存します。Windows Agent/APIや外部URLをキャッシュ・中継しません。
- インストールとオフライン表示は **iPhone/Safari実機で未検証** です。SVGのみのアイコンがiOSで正しく表示されることも未保証です。実用PWAの証明書・登録・WSSは後続のG1〜G3が必要です。
- Service Workerはデモのスコープだけで使い、認証済みAgentと同じスコープに配備しないでください。後続の本接続では別のキャッシュ方針をセキュリティレビューしてから採用します。
- 開発時に古い画面が残る場合はブラウザのサイトデータからデモのService Workerとキャッシュを削除してください。通常のHTTP LAN公開でiPhoneから動作確認しないでください。

## 現在できること
- ホーム/アプリ/ファイル/端末/画面タブ、文字入力画面を画面遷移
- アプリ/ファイルの表示例に対する検索
- 日本語テキスト編集と、送信しないデモメッセージ
- 誤認防止の「未接続 / デモ」表示

## 次の実装
G1の無料・MacなしiPhone証明書/PWA・HTTPS/WSSのPoC、およびG2/G3の認証/LAN限定検証を進めます。**本デモの画面はG1や実機UXに合格したものではありません。**

## 簡易検査
Node.js があれば、リポジトリのルートで次を実行できます。

```powershell
node --check prototype/app.js
node --test prototype/test/smoke.test.mjs prototype/test/behavior.test.mjs prototype/test/pwa.test.mjs
```

2026-10-30にNode.js 24.18.0（Linux）で既存9件が成功。追加PWAテストは別途実行結果をIssue #1に記録します。モックDOM/Service Workerテストは実ブラウザE2Eの代替ではありません。**本物のSafari/Chrome上のE2E・iPhone実機動作はまだ未確認**です。

## Chromiumによる実DOM・タッチレイアウト検査（2026-10-30追加）

Playwright Python（任意の開発時依存）とChromiumが使える環境では、通信を一切行わない実ブラウザDOM検査を実行できます。Playwright/Chromiumのインストールは開発PCでのみ行い、本番Windows Agentに同梱しません。

```powershell
python -m pip install playwright
python -m playwright install chromium
python prototype/test/chromium-dom.py
```

既にChromiumが入っている場合は `WIN_REMOTE_CHROMIUM` 環境変数で実行ファイルを指定できます。このテストは`about:blank`へGitHub管理下のHTML/CSS/JSを注入し、外部要求を拒否した状態で、画面切替・検索・文字送信がデモのままであること・タップ領域（44px以上）・横スクロール・JS例外を検証します。

**検証範囲の制限:** CSPをテスト用に迂回してスクリプトを注入するため、HTTP経由のCSP、Service Worker、オフライン起動、インストール可能性、iPhone Safariの挙動は検証しません。実際の`http://127.0.0.1`での表示とPWAキャッシュは、ネットワークアクセスを許可するローカルブラウザで別途確認してください。特に`frame-ancestors`はmetaタグでは有効にならず、本番HTTPS応答ヘッダーで設定・検証する必要があります。

Linux Chromium 144.0.7559.96で、同じHTML/CSS/JSのGitHub blob SHAを照合したローカル複製に対して21件のDOM/レイアウト検査が成功しました（テストファイルのGitHub反映後のCIは未実行）。Chromiumのネットワークポリシーが`ERR_BLOCKED_BY_ADMINISTRATOR`を返したため、localhost HTTP/Service Worker検証は未実施です。**iPhone/Safari実機・G1〜G9は未合格です。**
