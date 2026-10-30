---
status: incubating
created: 2026-10-30
updated: 2026-10-30
revisit_when: iPhone実機でHTTPS・入力・画面操作の検証に失敗したとき、または無料運用の条件が変わったとき
---

# iPhone向けWindows操作アプリ：実現可能性と推奨構成

## 評価結果

**条件付きで実現可能。PWAとWindowsの非昇格エージェントを組み合わせる構成を推奨する。** Windows画面を常時送る必要はなく、アプリ一覧・ファイル一覧・テキスト・コマンド結果をデータとして送る。既存のWindows APIとOSSを組み合わせ、独自の画面転送プロトコル、暗号方式、ターミナルエミュレーターは作らない。

現段階は一次資料と既存環境の読み取りによる評価であり、動作実証ではない。PWAの初期設定の負担、日本語入力、Windowsのフォーカス制限、noVNCの操作遅延は、実装承認後の短い検証で採否を確定する。[検証ゲート](mvp-validation.md)

## 前提と対象外

- iPhone 1台、Windows PC 1台、単一のログイン済みユーザー、自宅の同一LAN。PCは有線LANでもよい。
- 対象OSはセキュリティ更新が提供されるWindows 11 Homeを第一候補とする。Windows Homeというエディションだけで判断せず、実装時に正確なバージョンを確認する。
- iPhoneは利用端末の現行iOSを主対象とし、機種・iOSバージョンは未確認。Mac所有は前提にしない。
- PC起動済み・ユーザーログイン済み・ロック解除済みが基本。起動前、ログイン画面、UACの承認、セキュアデスクトップ、別ユーザーのデスクトップは対象外。
- オフライン運用とはアプリの実行にクラウドを必要としないこと。OS更新、依存パッケージの取得、GitHubでの設計管理は開発・保守時の作業として分ける。
- 自宅LAN内だけであっても、家族端末・IoT端末・悪意のあるWebページを信頼しない。

## 要件ごとの実現方法

| 要件 | 専用UIによる実行 | 画面転送が必要な場面 | 評価／限界 |
| --- | --- | --- | --- |
| アプリ起動 | PCで登録したアプリIDを起動 | 初回設定やアプリ固有のダイアログ | 実現可能。任意のコマンド文字列を起動APIへ渡さない |
| 切り替え | ウィンドウカード→前面化を要求 | Windowsが前面化を拒否したとき、アプリ内のタブ選択 | 条件付き。SetForegroundWindowは常に成功するAPIではない |
| 終了 | ウィンドウに通常の終了を要求 | 未保存ファイルの保存確認 | 実現可能。プロセスの強制終了とは分ける |
| ファイル操作 | 登録フォルダ内の一覧・検索・作成・移動・コピー・名前変更・ごみ箱 | 特殊なアプリで開く／編集する | 実現可能。MVPはローカル通常ファイルに限定 |
| PowerShell等 | コマンド入力欄と結果、対話用xterm.js + ConPTY | 既存のWindows Terminalウィンドウ自体を操作したいとき | 実現可能。新しいPTYセッションを作る。既存ターミナルへの接続はしない |
| 日本語・長文入力 | iPhone側で変換・編集してから確定文字列を送る | アプリがテキスト受け取りに対応しないとき | 条件付き。変換途中のキーイベントを逐次転送しない |
| コピー＆ペースト | 明示的な「PCから取得」「iPhoneにコピー」「PCへ送る」 | アプリ内の範囲選択など | 条件付き。SafariのクリップボードはHTTPSとユーザー操作に制約がある |
| デスクトップ操作 | 必要なときだけ同一PWA内のnoVNCを開く | 保存ダイアログ、細かなGUI操作、専用UI未対応アプリ | 実現可能性あり。Windows Home上のUltraVNCを通常アプリとして起動する案を検証 |
| 低遅延 | 小さいAPI要求、イベント通知、描画の局所更新 | 画像圧縮・転送・描画が必要な操作 | API中心なら改善が期待できるという推論。速度は未計測 |

根拠: [Windows HomeとRDP](https://support.microsoft.com/en-us/windows/experience/connectivity-networking/how-to-use-remote-desktop)、[前面化の制限](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setforegroundwindow)、[ConPTY](https://learn.microsoft.com/en-us/windows/console/createpseudoconsole)、[SafariのClipboard API](https://webkit.org/blog/10855/async-clipboard-api/)。

## クライアント方式の比較

| 方式 | 無料継続運用・導入 | iPhone体験 | Windows/AIによる開発・検証 | 主な弱点 | 判断 |
| --- | --- | --- | --- | --- | --- |
| PWA + Windowsエージェント | Safariからホーム画面追加。署名更新不要。ローカルHTTPSの初期設定は必要 | 大きなタップ領域、iPhoneの日本語キーボード、専用タブUI | Windowsで開発・ブラウザ自動検証可能。実機検証は別途必要 | 証明書信頼、バックグラウンド停止、クリップボード制約 | **推奨** |
| Swift等の自作ネイティブ | 通常のXcode開発経路はMacが必要。無料Personal Teamのプロビジョニングは7日で失効 | Keychain、OS連携、証明書ピン留めなどの自由度が高い | Windows中心の開発では署名・ビルド・実機自動化が複雑 | 無料で手間なく常用する条件との相性が悪い | 今回は不採用 |
| Flutter / React Native / .NET MAUI等 | iOSアプリの署名・配布制約は残る | ネイティブ相当の構成が可能 | 共通コードは増えるがiOSのビルド経路は必要 | フレームワークを替えても無料署名の課題は消えない | 今回は不採用 |
| Capacitor等のPWAラッパー | iOSネイティブのビルド・署名が必要 | ネイティブAPIへの橋渡しが可能 | Web部分は再利用できる | 単なるラップでは運用上の問題を解消しない | 後で再評価 |
| 既存リモート操作アプリのみ | 無料OSSも存在 | 画面操作の品質は高い製品もある | 開発量は小さい | Windowsの機能をスマホ用に再構成する主目的を満たさない | 補助利用を検討 |

Appleの無料アカウントには定期的な再プロビジョニングが必要である。[Apple Personal Team](https://developer.apple.com/help/account/basics/about-your-developer-account) PWAはSafariのホーム画面アプリとして利用できる。[Appleの案内](https://support.apple.com/en-lamr/guide/iphone/iphea86e5236/ios) ただしバックグラウンド常時接続や自動クリップボード同期は設計上の前提に置かない。

## 既存OSSの利用比較

| 候補 | 活用できる部分 | 今回の判断 |
| --- | --- | --- |
| noVNC + UltraVNC | ブラウザ内RFBクライアント、Windows画面取得・入力 | **MVPの補助画面操作に採用候補**。UltraVNCはアプリモード、ループバック限定。LANにVNCポートを公開しない |
| Sunshine + Moonlight | GPUエンコードと低遅延映像、無料iOSクライアント | 映像性能が足りない場合の将来候補。別アプリ・複数ポート・別認証になる。PWAにMoonlightをそのまま埋め込めるとは扱わない |
| RustDesk | Windows/iOS間の画面操作、Direct IP | 代替の画面操作候補。Direct IPの設定だけで外部IDサーバー等への通信停止・暗号化要件充足を断定しない。外向き通信の確認が必要 |
| Apache Guacamole | ブラウザ経由VNC/RDP/SSHと認証基盤 | Java Webアプリ・guacd等の運用がこの1台用途には大きい。専用アプリ・ファイルUIも別途必要 |
| xterm.js + Windows ConPTY | ターミナル描画とPTY | **再利用**。独自のANSIパーサーやシェルを作らない |
| Windows OpenSSH / SFTP | シェルとファイル転送 | SSHクライアント用途なら有効だが、ブラウザからの接続にはゲートウェイが必要。別ポート・別アカウント管理をMVPで増やさない |
| SMB | Windowsのファイル共有 | ファイルのみなら候補。専用UIと統一認証のためMVPでは公開しない |
| 標準RDP | リモートデスクトップ | Windows Homeはホストにできないため除外。非公式なRDP有効化パッチも採用しない |

参照: [noVNC](https://novnc.com/)、[UltraVNC設定](https://uvnc.com/docs/ultravnc-server/49-ultravnc-server-configuration.html)、[Moonlight](https://moonlight-stream.org/)、[Sunshine設定](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2configuration.html)、[RustDesk Direct IP](https://rustdesk.com/docs/en/self-host/client-configuration/advanced-settings/)、[Guacamole構成](https://guacamole.apache.org/doc/1.5.2/gug/guacamole-architecture.html)。

Sunshineの文書上、LANのストリーム暗号化の既定値は無効である。採用時は必須化し、iOS側との互換性を実測する。UPnP無効だけでLAN限定になるわけではない。この追加検証とネットワーク面の増加が、MVPに標準採用しない理由となる。

## 推奨スタック

| 層 | 推奨 | 理由 |
| --- | --- | --- |
| iPhone UI | React + TypeScript + ViteでビルドするPWA | 状態をテストしやすく、画面別コンポーネントを再利用できる。実行時Nodeサーバー不要 |
| Windows | C# / .NET 10 LTS + ASP.NET Core Kestrel + 小さいWinFormsトレイUI | Win32、クリップボード、プロセス、ファイルへの接続が容易。管理者常駐サービスは不要 |
| API / 通知 | 同一オリジンHTTPS + SignalR、ターミナル／画面用WSS | 普段の操作と重い画面転送を分ける |
| Windows連携 | Microsoft.Windows.CsWin32、標準.NET API、ConPTY | 手書きP/Invokeやプロトコル実装を減らす |
| 画面 | noVNC + 固定宛先の小さいWSS/TCPブリッジ + UltraVNC | 既存のRFB処理と画面取得を使う |
| 証明書 | オフラインの専用CAとサーバー証明書。作成作業はOSSのstep CLI | 公開ドメイン・ACME・常駐CAサーバー不要。暗号処理を自作しない |
| 保存 | ローカルSQLite、Windowsの鍵保護機能、NTFS ACL | 端末登録・失効・監査と設定をPC内に閉じる |

Pythonは設計・テスト補助には使えるが、本体の主言語にはしない。Node.jsバックエンドも可能だが、デスクトップAPIやConPTY用のネイティブ依存を複数管理するため、Windows専用では.NETを優先する。Electronのデスクトップレンダラーは今回不要。

.NET 10は2028-11-14までのLTSとして掲載されている。最新の修正パッチを利用し、実装時に再確認する。[.NETサポートポリシー](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core)

## 無料の範囲

ソフトウェア利用料、アプリ公開料、サーバー費用、ドメイン・公開証明書費用は不要な構成。既存のPC・iPhone・ルーターと電気・回線は前提であり、追加ハードウェア購入は要求しない。開発に使うAIサービスの料金はアプリの実行費用とは別で、既存契約や無料枠を前提にしない。アプリにAI APIを組み込まない。

React、TypeScript、.NET、xterm.js等のライセンスと、noVNC（MPL-2.0）、UltraVNC（GPL-3.0）、step CLI（Apache-2.0）は、採用版ごとにLICENSEと依存物を確認する。UltraVNCは別プロセスとして用い、外部配布へ変更するときに通知・ソース提供等の条件を確認する。無料であることと無制約で再配布できることを混同しない。

## 採否に関わる懸念

1. **ローカルHTTPSの導入負担**：iPhoneへCAを信頼登録する作業が必要。安全な証明書受け渡しと更新手順が使えなければPWA案は再検討。
2. **入力互換性**：全アプリの文字入力を統一できる保証はない。対象アプリを少数選んで評価する。
3. **画面操作の品質**：noVNCは補助操作向け。動画・ゲーム・長時間の画面操作が主体ならMoonlight等を再評価。
4. **権限の広さ**：シェルと画面操作は現在のWindowsユーザー相当。限定的なファイルAPIだけの安全性とは区別する。
5. **LAN限定の限界**：誤設定への多層防御はできるが、管理者によるファイアウォール無効化・中継導入や、信頼済みユーザーによるトンネル構築をアプリだけで完全には禁止できない。

関連: [詳細構成](architecture.md) / [UI](mobile-ui.md) / [セキュリティ](security.md) / [MVP](mvp-validation.md)
