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
└── state/           # 処理状態（自動生成。カレントディレクトリ直下）
    └── state_user_at_example.com.json
```

> `state/` は相対パス（`Path("state")`）で作成されます。cron や systemd から実行する場合は、
> 実行時のカレントディレクトリ（systemd なら `WorkingDirectory`）を固定してください。
> 実行場所が変わると別の `state/` が作られ、ウォーターマークや送信元リストが引き継がれません。

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
| `ham_folder` | | なし | HAM判定メール・`notspam_senders` 該当メールの移動先。未設定時はINBOXに残す |
| `spam_folder` | | なし | 手動でSPAMを入れるフォルダ。設定時に `learn_spam` を実行し、送信元を `notspam_senders` から取り消す |
| `notspam_folder` | | なし | 手動でHAMを入れるフォルダ。設定時に `learn_ham` を実行し、送信元を `notspam_senders` に登録して `ham_folder` へ移動する。`ham_folder` 未指定時は `inbox_folder` へ移動する |
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
     │   ├─ From が notspam_senders に含まれる
     │   │     → rspamd スキャン・学習なし
     │   │     → ham_folder があれば移動 / なければ INBOX に残す
     │   └─ それ以外 → rspamd でスコアリング
     │       ├─ reject / soft reject       → junk_folder へ移動 → learn_spam
     │       ├─ ham / greylist / no action → ham_folder へ移動（learn_ham はしない）
     │       └─ その他                     → INBOX に残す（ログのみ）
     │   処理のたびに last_uid を保存
     │
     ├─ [notspam_folder スキャン] ※設定時のみ
     │   last_notspam_uid 以降のUID一覧を取得
     │   ↓ 1通ずつフェッチ
     │   learn_ham → From を notspam_senders に登録 → ham_folder（または INBOX）へ移動
     │   処理のたびに last_notspam_uid を保存
     │
     └─ [spam_folder スキャン] ※設定時のみ
         last_spam_uid 以降のUID一覧を取得
         ↓ 1通ずつフェッチ
         learn_spam → From を notspam_senders から取り消し → junk_folder へ移動
         処理のたびに last_spam_uid を保存
```

### rspamd アクションと振る舞いの対応（INBOX）

| rspamd action | 振る舞い |
|---|---|
| `reject` | junk_folder へ移動 → `learn_spam` |
| `soft reject` | junk_folder へ移動 → `learn_spam` |
| `ham` | ham_folder へ移動（学習なし） |
| `greylist` | ham_folder へ移動（学習なし） |
| `no action` | ham_folder へ移動（学習なし） |
| その他 | INBOX に残す（ログのみ） |

`learn_ham` を実行するのは **notspam_folder のメールだけ**です。
INBOX で HAM 判定されたメールを学習すると rspamd の誤判定がそのまま強化されるため、
人が確認して notspam_folder に入れたメールのみを HAM 学習の対象にしています。
`ham_folder` が未設定の場合、HAM 判定メールは移動されず INBOX に残ります（警告ログのみ）。

## 送信元リスト (notspam_senders)

notspam_folder に入れたメールの送信元を記録し、以降はその送信元のメールを
rspamd にかけずに通すための仕組みです。

| 契機 | 動作 |
|---|---|
| notspam_folder のメールを処理 | `learn_ham` 後、From アドレスを `notspam_senders` に登録 |
| INBOX のメールの From が登録済み | スキャン・学習をスキップし、`ham_folder` があれば移動、なければ INBOX に残す。`last_uid` は進める |
| spam_folder のメールを処理 | `learn_spam` 後、From アドレスが登録済みなら `notspam_senders` から取り消す |

- アドレスは小文字化・前後空白除去した **完全一致**で照合します（ドメイン単位ではありません）。
- From を取得できないメールは登録も照合もしません。
- 登録・取り消しの反映は次回以降の INBOX スキャンからです。
  同じ実行内では INBOX の処理が先に終わるため、その回の INBOX には反映されません。
- 同じ実行内で notspam_folder と spam_folder の両方に同じ送信元がある場合は、
  spam_folder の処理が後なので取り消しが勝ちます。
- 手動で除外したい場合は、stateファイルの `notspam_senders` から該当アドレスを削除してください。
- この機能の導入前に処理済みのメールの送信元は、さかのぼっては登録されません
  （`last_notspam_uid` が進んでおり、メールも notspam_folder から移動済みのため）。

## 実行方法

```bash
# 通常実行
python scan.py

# 設定ファイルを指定
python scan.py --config /etc/rspamd/scan_config.json

# ドライラン
python scan.py --dry-run
```

### ドライランの挙動

`--dry-run` では、メールの移動・rspamd への学習・state の保存をいずれも行いません。
ログ出力と、読み取りのみの rspamd スキャン（`rspamc -j symbols`）だけを実行します。

| 操作 | dry-run 時 |
|---|---|
| メールの移動（`junk_folder` / `ham_folder` / notspam_folder の移動先） | 行わない |
| `learn_spam` / `learn_ham` | 行わない |
| state の保存（ウォーターマーク・`notspam_senders`） | 行わない |
| rspamd スキャン（判定のみ・ログ出力用） | 行う |

dry-run 中に送信元の登録・取り消しが発生しても、メモリ上だけの変更で state には保存されません。

## ステートファイル

`state/state_<user>.json` にアカウントごとの状態を保存します。
`user` の `@` は `_at_`、`/` と `\` は `_` に置換されます。

```json
{
  "last_uid": 5385680,
  "last_spam_uid": 142,
  "last_notspam_uid": 0,
  "notspam_senders": [
    "info@example.org",
    "newsletter@example.com"
  ]
}
```

| キー | 説明 |
|---|---|
| `last_uid` | INBOX で最後に処理した UID |
| `last_spam_uid` | spam_folder で最後に処理した UID |
| `last_notspam_uid` | notspam_folder で最後に処理した UID |
| `notspam_senders` | notspam_folder で学習した送信元アドレス（小文字・重複なし・ソート済み） |

`notspam_senders` キーがない既存の stateファイルは、空リストとして読み込まれるのでそのまま使えます。

処理は1通完了するたびに state を更新・保存します。
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
- **フェッチ失敗**: 該当UIDをスキップし、ウォーターマークを進めます。
- **learn_spam / learn_ham の失敗**: 警告ログを出力して処理を続けます（学習済みメールはエラーになりません）。
- **フォルダ move 失敗**: INBOX・notspam_folder・spam_folder のいずれの処理でも、
  エラーログを出力して次のメールへ進みます（ウォーターマークは進めるため、そのメールは自動では再試行されません）。
  失敗したメールは元のフォルダに残るので、必要に応じて手動で対応してください。
- **アカウント単位の致命的エラー**: そのアカウントをスキップし、次のアカウントの処理を続けます。

ログは systemd journal に対応したフォーマット（`scan[PID]: LEVEL: message`）で標準エラーに出力します。
