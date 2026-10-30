# UI prototype (未接続デモ)

このディレクトリは [UI設計](../docs/design/mobile-ui.md) の6画面を実装した **デモ専用** プロトタイプです。現段階ではWindows Agent、RDP/VNC、HTTPS/WSS、認証、ファイル変更、PowerShell実行に**一切接続しません**。例示データだけを表示します。

## 起動（Windowsでのローカル確認のみ）

1. Pythonが使えるPCでリポジトリを取得。
2. PowerShellから `cd prototype`。
3. `python -m http.server 8765 --bind 127.0.0.1`。
4. **同じWindowsの**ブラウザで `http://127.0.0.1:8765/` を開く。画面幅を375px程度にして確認。
5. 終わったらCtrl+Cでサーバー停止。

`--bind 127.0.0.1` はPC自身からしかアクセスできない設定です。**iPhoneから見たいからといって `0.0.0.0` へ変更したり、HTTPをLANへ開放したりしないでください。** iPhoneへの提供は後続のTLS/認証/LAN制限（G1〜G3）が通過してから行います。

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
node --test prototype/test/smoke.test.mjs prototype/test/behavior.test.mjs
```

2026-10-30にNode.js 24.18.0（Linux）で上記の構文チェックと9件の単体テストが成功しました。後者の4件はモックDOMで実際のUIスクリプトを実行しますが、**本物のSafari/Chrome上のE2E・iPhone実機動作はまだ未確認**です。