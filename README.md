# scan.py — IMAP メールボックス rspamd 連携スキャナ

IMAPアカウントの受信トレイを巡回し、rspamd でスパム判定・学習を行うスクリプトです。
systemd タイマーや cron での定期実行を想定しています。

## 動作環境

| 項目 | バージョン |
|---|---|
| Python | 3.9 以上 |
| imap-tools | 1.13.0 |
| rspamd / rspamc | サーバにインストール済みであること |

```bash
python -m venv venv
source venv/bin/activate
pip install imap-tools==1.13.0
```

## ファイル構成

```
.
├── scan.py          # 本スクリプト
├── config.json      # アカウント設定（要作成）
└── state/           # 処理済みウォーターマーク（自動生成）
    └── state_user_at_example.com.json
```

## 設定ファイル (config.json)

```json
{
  "accounts": [
    {
      "user": "user@example.com",
      "password": "secret",
      "host": "imap.example.com",
      "port": 993,
      "enabled": true,

      "inbox_folder":   "INBOX",
      "junk_folder":    "Junk E-mail",
      "ham_folder":     "Learned-Ham",
      "spam_folder":    "Junk E-mail",
      "notspam_folder": "Not-Spam",

      "imap_timeout":   60,
      "rspamc_timeout": 30
    }
  ]
}
```

### アカウント設定キー一覧

| キー | 必須 | デフォルト | 説明 |
|---|---|---|---|
| `user` | ✓ | — | IMAPログインユーザー名 |
| `password` | ✓ | — | IMAPパスワード |
| `host` | ✓ | — | IMAPサーバホスト名 |
| `port` | | `993` | IMAPポート（IMAPS） |
| `enabled` | | `true` | `false` にするとそのアカウントをスキップ |
| `inbox_folder` | | `INBOX` | スキャン対象の受信トレイ |
| `junk_folder` | | `Junk` | SPAM判定メールの移動先 |
| `ham_folder` | | なし | HAM判定メールの移動先。未設定時はINBOXに残す |
| `spam_folder` | | なし | 手動でSPAMを入れるフォルダ。設定時に `learn_spam` を実行する |
| `notspam_folder` | | なし | 手動でHAMを入れるフォルダ。設定時に `learn_ham` を実行し `ham_folder` へ移動する。`ham_folder` 未指定時は `inbox_folder` へ移動する |
| `imap_timeout` | | `60` | IMAP接続・操作のタイムアウト秒数 |
| `rspamc_timeout` | | `30` | rspamc コマンドのタイムアウト秒数 |

## 処理フロー

```
起動
 └─ アカウントごとに処理
     │
     ├─ [INBOX スキャン]
     │   UID SEARCH で last_uid 以降の新着UID一覧を取得
     │   ↓ 1通ずつフェッチ
     │   rspamd でスコアリング
     │   ├─ reject / soft reject  → junk_folder へ移動 → learn_spam
     │   ├─ ham / greylist / no action → ham_folder へ移動 → learn_ham
     │   └─ その他              → INBOX に残す（ログのみ）
     │   処理のたびに last_uid を保存
     │
     ├─ [notspam_folder スキャン] ※設定時のみ
     │   last_notspam_uid 以降のUID一覧を取得
     │   ↓ 1通ずつフェッチ
     │   learn_ham → ham_folder（または INBOX）へ移動
     │   処理のたびに last_notspam_uid を保存
     │
     └─ [spam_folder スキャン] ※設定時のみ
         last_spam_uid 以降のUID一覧を取得
         ↓ 1通ずつフェッチ
         learn_spam（フォルダ移動なし）
         処理のたびに last_spam_uid を保存
```

### rspamd アクションと振る舞いの対応

| rspamd action | 振る舞い |
|---|---|
| `reject` | junk_folder へ移動 → `learn_spam` |
| `soft reject` | junk_folder へ移動 → `learn_spam` |
| `ham` | ham_folder へ移動 → `learn_ham` |
| `greylist` | ham_folder へ移動 → `learn_ham` |
| `no action` | ham_folder へ移動 → `learn_ham` |
| その他 | INBOX に残す（ログのみ） |

## 実行方法

```bash
# 通常実行
python scan.py

# 設定ファイルを指定
python scan.py --config /etc/rspamd/scan_config.json

# ドライラン（移動・学習・state保存を行わない）
python scan.py --dry-run
```

## ステートファイル

`state/state_<user>.json` にアカウントごとのウォーターマークを保存します。

```json
{
  "last_uid": 5385680,
  "last_spam_uid": 142,
  "last_notspam_uid": 0
}
```

| キー | 説明 |
|---|---|
| `last_uid` | INBOX で最後に処理した UID |
| `last_spam_uid` | spam_folder で最後に処理した UID |
| `last_notspam_uid` | notspam_folder で最後に処理した UID |

処理は1通完了するたびにウォーターマークを更新・保存します。
途中でクラッシュしても次回起動時に続きから再開します。

### ウォーターマーク方式が成立する理由

IMAPでメールをフォルダ間 move すると、移動先で新しい UID が採番されます。
UID はフォルダ内で単調増加するため、「放り込んだ順 ＝ UID の昇順」が保証されます。
これにより全件スキャン不要で、ウォーターマーク方式でも漏れは発生しません。

なお `list_uids` は RFC 3501 の仕様（`X:*` 検索が X 未満の最大 UID を返すことがある）に対応するため、取得 UID を `>= start_uid` でフィルタしています。

## systemd タイマー設定例

```ini
# /etc/systemd/system/rspamd-scan.service
[Unit]
Description=rspamd IMAP scanner

[Service]
Type=oneshot
WorkingDirectory=/opt/rspamd
ExecStart=/opt/rspamd/venv/bin/python scan.py --config config.json
```

```ini
# /etc/systemd/system/rspamd-scan.timer
[Unit]
Description=rspamd IMAP scanner timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now rspamd-scan.timer
```

## エラーハンドリング

- **IMAP タイムアウト**: 最大 3 回まで自動再接続してリトライします。
- **rspamc タイムアウト**: 該当メールをスキップし、ウォーターマークを進めます（次回実行での再処理はしません）。
- **フォルダ move 失敗**: エラーログを出力し、次のメールへ進みます。
- **アカウント単位の致命的エラー**: そのアカウントをスキップし、次のアカウントの処理を続けます。

ログは systemd journal に対応したフォーマット（`scan[PID]: LEVEL: message`）で標準エラーに出力します。
