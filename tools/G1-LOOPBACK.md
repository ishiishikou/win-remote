# G1-L0: ローカルTLS / WebSocket Upgrade検証

`tools/g1-loopback-tls.mjs` は **G1接続方式の小さな技術検証用**であり、製品のWindows Agentでも、iPhoneから接続できるサーバーでもありません。

## 検証の目的と実行

- Node.js 22以降と OpenSSL（CLI）がある、隔離した開発環境で実行する。
- リポジトリルートから `node --check tools/g1-loopback-tls.mjs` および `node tools/g1-loopback-tls.mjs`。
- スクリプトは実行ごとに使い捨てのCA・サーバー鍵をOSの一時ディレクトリに作り、`127.0.0.1` のランダムポート **だけ**で HTTPS を起動する。成功・失敗を問わず、一時ディレクトリを削除する。
- Windows Firewall、iPhone信頼ストア、ルーター、Windowsサービス、環境変数の永続設定は変更しない。

## 実施する7確認項目

1. 受信待受けが IPv4 `127.0.0.1` に限定されている。
2. 一時CAを明示的に信頼したHTTPS要求が成功する。
3. 一時CAを信頼しないHTTPS要求は拒否される。
4. 証明書SANにないホスト名ではTLS検証が失敗する。
5. 許可Originと許可パスのWebSocket Upgrade (101) が成立する。
6. 異なるOriginのWebSocket Upgradeが403になる。
7. 意図しない操作パスのUpgradeが403になる。

**注意:** 5はWebSocketのTLS付きHTTP Upgradeのヘッダ交換だけの検証。WebSocketフレームの送受信や継続セッション、クライアント端末登録、CSRF対策等は実装・検証していない。起動してよいのはループバックのみ。WAN/LANへbindを広げないこと。PoCのCA/鍵はiPhoneに導入せず、常用しないこと。

## 実行結果（2026-10-30）

コンテナ内 Node.js v22.16.0、OpenSSL 3.5.5で構文チェック・実行を行い、**7 checks passed**。ユーザーのWindows Home/iPhone上では未実施。この結果は **G1合格ではない**。

## 次に必要な検証

- 非管理者Windows Agentの実装（.NET/Kestrel）、登録NIC/IPへの固定bind、受信Firewall制限を確認する（G3）。
- 本番用に安全にCA鍵を管理する仕組みを実装し、iPhoneで証明書の真正性・信頼設定・PWA・WSSを試す（G1）。
- 接続前に端末登録と認可／Origin／Host／CSRFを強制し、実機で拒否ケースを検証する（G2）。このPoCの無認証UpgradeをLANに流用しない。
- サーバー認証、WebSocketの実際のフレーム・クローズ、鍵更新／失効を別途検証する。

関連: [設計](../docs/design/architecture.md)、[セキュリティ](../docs/design/security.md)、[検証ゲート](../docs/design/mvp-validation.md)、[Issue #1](https://github.com/ishiishikou/win-remote/issues/1)。
