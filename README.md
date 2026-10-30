# win-remote

iPhoneから、自宅LAN上のWindows Homeを操作する個人用アプリの設計リポジトリ。

**現在は設計提案のみ。実装開始・常駐アプリ導入・ネットワーク設定変更は未承認／未実施です。**

推奨は **iPhone向けPWA + C# / .NET 10のユーザーセッション常駐エージェント**。アプリ・ファイル・入力・ターミナルを専用UIで操作し、必要な場合だけnoVNC + UltraVNCによる画面操作へ移ります。運用中のクラウド、中継サーバー、外部公開、Apple開発者有料契約を必要としない構成です。

## 設計資料

| 資料 | 内容 |
| --- | --- |
| [評価・推奨構成](docs/design/overview.md) | 結論、要件との対応、PWA／ネイティブ／OSS比較、費用と制約 |
| [アーキテクチャ](docs/design/architecture.md) | 構成図、Windows API、通信、画面操作の統合、状態管理 |
| [スマホUI](docs/design/mobile-ui.md) | 各画面、入力方法、操作フロー、エラー・再接続時の挙動 |
| [UIプレビュー](docs/design/ui-preview.html) | 実データ・通信・操作機能を持たない静的デザイン資料。ダウンロードしてブラウザで開く |
| [セキュリティ](docs/design/security.md) | 脅威モデル、LAN制限、認証・TLS、権限境界、失効・復旧 |
| [MVP・検証計画](docs/design/mvp-validation.md) | 必須範囲、将来拡張、実装承認後の検証ゲート、性能目標 |
| [判断記録](docs/decisions/pwa-local-agent.md) | 選定理由、代替案、前提、再検討条件 |
| [調査・出典](docs/design/research.md) | 一次情報、既存リポジトリ確認、実施済み／未実施の区別 |

## 判断上の重要事項

- 技術的には条件付きで実現可能。iPhone実機での証明書導入・日本語入力・復帰動作と、画面転送性能はまだ実証していません。
- 初回にiPhoneへ専用CA証明書を導入します。秘密鍵の保護と証明書更新を運用に含めます。
- 管理者として動かさず、UAC・ロック画面・管理者アプリの操作は対象外です。
- 自由なPowerShellと画面操作は、ログイン中のWindowsユーザー相当の権限を持ちます。フォルダ制限を越えられないサンドボックスとは扱いません。
- 「ポート開放しない」はルーターのWAN転送禁止を意味します。LAN通信にはWindows側の限定的な受信許可が必要です。
- 低遅延は設計目標です。既存のChromeリモートデスクトップより高速だと実測なしに保証しません。

## 作業・知識管理

設計・開発・成果物の正本は [ishiishikou/win-remote](https://github.com/ishiishikou/win-remote) です。[thoughtbaseの共通入口](https://github.com/ishiishikou/thoughtbase/blob/main/AGENTS.md) と関連ルールを参照し、理由・不確実性・再検討条件を残します。設計提案と実装決定を区別し、実装Issueは承認後に作成します。

設計調査日: 2026-10-30。詳細な参照履歴は [調査記録](docs/design/research.md) を参照してください。
