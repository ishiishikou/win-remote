---
status: active
created: 2026-10-30
updated: 2026-10-30
---

# 調査記録と一次資料

## 調査の範囲

調査日: 2026-10-30。設計案の作成に必要な公式資料・OSS一次資料の確認と、作業リポジトリ／Windows環境の読み取りを行った。文書上の対応、設計上の推論、実機未検証を区別する。

### 作業リポジトリ

- 正本: `ishiishikou/win-remote`。GitHubコネクタで直接確認した。非公開、既定ブランチは`main`。
- 調査開始時のHEAD: `d95f5b1e1270b27cd7f9e4739329ce1072313335`。
- 既存ファイルは`README.md`のみ。内容は`# win-remote`。既存実装・設計・AGENTS.mdはなかった。
- ローカルの`C:\Users\koish\win-remote`は開始時に空で、Gitチェックアウトではなかった。資料はこの作業フォルダに作成し、正式リポジトリへGitHubコネクタで保存する。
- ローカルGitHub CLIの既存認証は無効だった。認証情報の変更やトークン抽出はせず、利用可能なGitHubコネクタを用いた。

### thoughtbaseの参照

`ishiishikou/thoughtbase`のツリーを直接確認した。参照時HEADは`49cade8759110d0a73013eccf1322462ab576367`。共通入口、ルール索引、必要な本文と環境プロファイルを確認した。

| 直接読んだ文書 | この作業への適用 |
| --- | --- |
| [AGENTS.md](https://github.com/ishiishikou/thoughtbase/blob/49cade8759110d0a73013eccf1322462ab576367/AGENTS.md) | 共通入口。検索0件だけでルール不存在と判断しない |
| [AI_GUIDE.md](https://github.com/ishiishikou/thoughtbase/blob/49cade8759110d0a73013eccf1322462ab576367/AI_GUIDE.md) | 正本、理由・不確実性・再検討条件、ideaと実行Issueの区別 |
| [rules/README.md](https://github.com/ishiishikou/thoughtbase/blob/49cade8759110d0a73013eccf1322462ab576367/rules/README.md) | 該当ルールの特定 |
| [bootstrap-new-chat-from-thoughtbase.md](https://github.com/ishiishikou/thoughtbase/blob/49cade8759110d0a73013eccf1322462ab576367/rules/bootstrap-new-chat-from-thoughtbase.md) | bootstrap。既定休止中のactivity-observatoryへの記録は行わない |
| [suggest-before-writing.md](https://github.com/ishiishikou/thoughtbase/blob/49cade8759110d0a73013eccf1322462ab576367/rules/suggest-before-writing.md) | thoughtbaseへの保存は別指示が必要。今回はwin-remoteへの保存が明示されている |
| [environments/README.md](https://github.com/ishiishikou/thoughtbase/blob/49cade8759110d0a73013eccf1322462ab576367/environments/README.md)、[codex.md](https://github.com/ishiishikou/thoughtbase/blob/49cade8759110d0a73013eccf1322462ab576367/environments/codex.md) | 実行環境の実権限を確認し、モデル名で推定しない |
| [README.md](https://github.com/ishiishikou/thoughtbase/blob/49cade8759110d0a73013eccf1322462ab576367/README.md)、[projects/README.md](https://github.com/ishiishikou/thoughtbase/blob/49cade8759110d0a73013eccf1322462ab576367/projects/README.md) | プロジェクト固有資料をwin-remoteに置き、知識正本と重複させない |

直接取得したツリーにはwin-remote固有の既存ノートは見当たらなかった。thoughtbaseは更新していない。「自由シェルとGUI操作はAPIのファイル制限とは別の権限境界」という判断は将来のthoughtbase保存候補になり得るが、今回の設計資料を正本とする。

### Windows環境の読み取り

- 読み取れたレジストリ値: `EditionID=Core`、`DisplayVersion=25H2`、`CurrentBuild=26200`。`ProductName`は`Windows 10 Home`と返った。
- これらはHome系という条件を補強するが、ProductNameだけで正確なOS表記を断定しない。CIMでのOS情報・Firewallの実効設定取得は、この実行環境のアクセス制限で失敗した。
- `node`、`npm`、`python`は見つかった。`dotnet`はPATH上では見つからなかった。未インストールの断定はせず、実装時にSDKを確認する。
- 読み取り制限の解除、SDK導入、証明書登録、Firewall変更、受信ポート作成、ルーター設定変更は行っていない。

## 一次資料と設計への反映

すべて2026-10-30に参照。外部の設定項目・サポート期限・ライセンスは実装時に再確認する。最新ページは変わり得るため、実装で採用する版はlockfileや依存一覧に固定する。

| ID | 一次資料 | 確認したこと／反映 |
| --- | --- | --- |
| S01 | [Microsoft: Remote Desktop](https://support.microsoft.com/en-us/windows/experience/connectivity-networking/how-to-use-remote-desktop) | 接続先PCにProが必要。Homeを標準RDPホストとする案を除外 |
| S02 | [Apple: Personal Team](https://developer.apple.com/help/account/basics/about-your-developer-account) | 無料プロビジョニングの7日制限。自作iOSアプリの維持負担として評価 |
| S03 | [Apple: Web app on iPhone](https://support.apple.com/en-lamr/guide/iphone/iphea86e5236/ios) | Safariからホーム画面アプリにする導線 |
| S04 | [WebKit: Safari 26](https://webkit.org/blog/17333/webkit-features-in-safari-26-0/) | ホーム画面Webアプリの仕様。実機iOS版は別途確認 |
| S05 | [Apple: 手動証明書の信頼](https://support.apple.com/en-us/102390) | 証明書導入後の明示的なSSL信頼が必要 |
| S06 | [WebKit: Clipboard API](https://webkit.org/blog/10855/async-clipboard-api/) | ユーザー操作とセキュアコンテキストの制約。明示的な二段階コピーへ反映 |
| S07 | [Microsoft: CreatePseudoConsole](https://learn.microsoft.com/en-us/windows/console/createpseudoconsole) | PTY、UTF-8、仮想端末シーケンス。独自端末実装を避ける |
| S08 | [Microsoft: SendInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput) | UIPIと入力の制約。管理者アプリ対応を除外 |
| S09 | [Microsoft: SetForegroundWindow](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setforegroundwindow) | 前面化の制限。失敗を扱うUIと対象確認が必要 |
| S10 | [Microsoft: Interactive Services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services) | サービスからの直接GUI操作を避ける。ユーザーセッション内常駐を選定 |
| S11 | [Microsoft: Kestrel endpoints](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel/endpoints?view=aspnetcore-10.0) | 全IP bindや設定経路の存在。IP明示と設定不変条件に反映 |
| S12 | [Microsoft: ASP.NET Core WebSockets](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/websockets?view=aspnetcore-10.0) | WSS処理に既存基盤を利用 |
| S13 | [Microsoft: New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule) | Interface、RemoteAddress、Profile、edge traversal等による限定 |
| S14 | [Microsoft: .NET support](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core) | .NET 10 LTSを選定。掲載サポート終了日は2028-11-14 |
| S15 | [noVNC](https://novnc.com/)、[noVNC README](https://novnc.com/noVNC/) | ブラウザ側VNCとWebSocket接続、MPL-2.0 |
| S16 | [UltraVNC設定](https://uvnc.com/docs/ultravnc-server/49-ultravnc-server-configuration.html)、[ini設定](https://sc.uvnc.com/docs/ultravnc-server/69-ultravnc-ini.html) | アプリモード、ループバック限定、HTTPの別入口。実際の採用版で確認が必要 |
| S17 | [UltraVNC公式リポジトリ](https://github.com/ultravnc/UltraVNC) | Windows対応とGPL-3.0表記。外部配布時は採用版の条件を確認 |
| S18 | [websockify](https://github.com/novnc/websockify) | 既存のWebSocket/TCPブリッジ。プロトコルは自作しないが常駐依存の追加は比較 |
| S19 | [Sunshine設定](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2configuration.html) | UPnP、Web管理のアクセス範囲、LAN暗号化設定。画面性能改善時の候補 |
| S20 | [Moonlight](https://moonlight-stream.org/)、[iOS版](https://github.com/moonlight-stream/moonlight-ios) | 無料の既存iOSクライアントとSunshine連携 |
| S21 | [RustDesk advanced settings](https://rustdesk.com/docs/en/self-host/client-configuration/advanced-settings/)、[self-host](https://rustdesk.com/docs/en/self-host/) | Direct IPとID/relay機構は分けて評価する必要がある |
| S22 | [Guacamole architecture](https://guacamole.apache.org/doc/1.5.2/gug/guacamole-architecture.html)、[現行manual入口](https://guacamole.apache.org/doc/gug/introduction.html) | VNC/RDP/SSHの既存ゲートウェイ。運用する要素が多い |
| S23 | [xterm.js security](https://xtermjs.org/docs/guides/security/) | Web端末の権限とXSSの重大性。非昇格・依存削減・出力処理に反映 |
| S24 | [OWASP WebSocket security](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html) | Origin、セッション失効、認可、サイズ制限、機密をログに残さない設計 |
| S25 | [Playwright Emulation](https://playwright.dev/docs/emulation)、[Browsers](https://playwright.dev/docs/browsers) | 自動化できるブラウザ範囲と実機との差 |
| S26 | [mkcert](https://github.com/FiloSottile/mkcert) | 開発用証明書ツール。CA鍵の危険性と開発用途の注意から、常用セットアップへそのまま採用しない |
| S27 | [step certificate create](https://smallstep.com/docs/step-cli/reference/certificate/create/)、[Windows導入](https://smallstep.com/docs/step-cli/installation/)、[OSS本体](https://github.com/smallstep/cli) | オフラインCA・leaf・SANの作成とWindows実行。クラウドサービス不要のCLIを候補にする |
| S28 | [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew) | 実ハンドルの最終パス確認。文字列前方一致だけの制限を避ける |
| S29 | [Microsoft CsWin32](https://github.com/microsoft/CsWin32) | 必要なWin32 P/Invokeの生成。手書きinteropを減らす |

## 確度の整理

| 区分 | 内容 |
| --- | --- |
| 文書で確認した事実 | HomeのRDPホスト制約、Personal Teamの期限、手動CA信頼、Safariのclipboard制約、ConPTY、UIPI、noVNCの構成、UltraVNCの設定項目 |
| 設計判断 | PWA + .NET、同一オリジン、1端末、IPv4固定、短命な操作枠、画面転送の補助化、step CLIのオフライン使用 |
| 推論・価値仮説 | API中心にすれば日常操作のタップ数と待ち時間を減らせる。実測なしに高速化率は断定しない |
| 実機未検証 | CA受け渡し、実際のiOS版でのPWA認証・復帰、IME、アプリごとの入力、非昇格UltraVNC、実効Firewall、画面遅延、正確なOS表記 |

設計内のTTL・容量・遅延値はプロジェクトの初期目標であり、各製品の既定値や実測値ではない。正式なセキュリティ監査やペネトレーションテストを行ったという意味でもない。

## 今回の成果物確認

- Markdown 8ファイルのコードフェンス対応と文字化け検査に合格。
- 文書内のローカルファイルリンク22件を確認し、リンク切れ0件。
- 静的UI資料の6画面、IDの一意性をHTMLパーサーで確認。script 0件、外部asset参照0件。
- ブラウザによる目視確認は未完了。headless起動ではスクリーンショットを取得できず、利用可能なブラウザツールもローカル`file:` URLをセキュリティポリシーで拒否した。制限を回避せず、構造チェックに留めた。
- iPhone実機、アプリ動作、性能、実効セキュリティの試験は未実施。上記の資料検査を製品テストの成功として扱わない。
