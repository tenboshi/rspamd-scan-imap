#!/usr/bin/env python3
"""IMAP mailbox scanner with rspamd SPAM classification.

概要:
  IMAPサーバーからメールをフェッチし、rspamd(rspamc)でスパム判定・学習を行う。
  実行ごとにstate_fileにlast_uidなどのwatermark（水標）を記録し、
  次に実行した際には未処理のメッセージのみを処理する。

動作フロー (per account):
  1. state_fileから前回のlast_spam / last_notspam / last_uidを読み込む。
  2. inboxフォルダのUID > last_spamかつUID > last_notspam のメッセージを検出。
  3. 各メッセージをrspamdでスキャン → actionが "reject"/"soft reject" ならスパムとしてJunkへ移動 + learn_spam、
     "ham"/"greylist" あるいは "no action" ならHAMとして指定フォルダへ移動 + learn_ham。
  4. notspam_folder / spam_folderが設定されていれば、それらも同様に処理する。
     notspam_folder は HAM学習用（手動で「スパムでない」とマークされたメール）、
     spam_folder は SPAM学習用（手動で「スパム」とマークされたメール → learn_spam 後、Junkへ移動）。

state_file の設計:
  user@domain → state/state_state__at_domain_.json に保存。
  記録するのは watermark だけ。learned_spam_uids / processed_uids などの
  ルーピング状態は過去に保持していたが、メモリ負荷の理由で削除された。

注意:
  - UIDはIMAPサーバーによって払い出される番号。moveしても旧UIDは残り得るが、
    ここでは watermark = max(last, uid) を毎メッセージ書き出すので重複回避できる。
  - rspamd の "no action" は INBOX に残す（何もしない）。
"""

import argparse
import json
import logging
import socket
import subprocess
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# グローバル定数
# ---------------------------------------------------------------------------

#: IMAP接続のデフォルトタイムアウト秒数。サーバーが応答しない場合のリトライ判定にも使われる。
DEFAULT_IMAP_TIMEOUT = 60

#: rspamc コマンドのデフォルトタイムアウト秒数（ただし現在はサブプロセス側で有効になっていない）。
DEFAULT_RSPAMC_TIMEOUT = 30

#: 設定ファイルから上書きされるバッチサイズ。現在は unused の可能性あり。
DEFAULT_BATCH_SIZE = 100

#: IMAPコネクションのリトライ最大回数。タイムアウト時のみリトライする。
MAX_IMAP_RETRIES = 3

#: state ファイルを保存するディレクトリ。初回実行時にmkdir(exist_ok=True)で自動作成される。
STATE_DIR = Path("state")
STATE_DIR.mkdir(exist_ok=True)

#: rspamd の action で SPAM と判定される値のセット。これらのアクションが来たら Junk フォルダへ移動する。
SPAM_ACTIONS = {"reject", "soft reject"}

#: SPAMアクションの別名（コピペ）。rspamd から返ってくる文字列と一致させる。
ACTIONS_SPAM = SPAM_ACTIONS

#: rspamd の action で HAM と判定される値のセット。これらのアクションが来たら ham_folder へ移動する。
ACTIONS_HAM = {"ham", "greylist"}


# ---------------------------------------------------------------------------
# ユーティリティ関数
# ---------------------------------------------------------------------------


def _safe_filename(user):
    """メールアドレスなどをファイル名として安全な文字列に変換する。

    IMAPユーザー名の '@', '/', '\\' を '_at_' や '_' に置換し、
    OSのファイルシステムで問題を起こさないようにする。
    例: user@example.com → user_at_example.com
    """
    return (
        user.replace("@", "_at_")
            .replace("/", "_")
            .replace("\\", "_")
    )


def state_file_path(user):
    """userごとのstateファイルのパスを返す。

    例: state/state_state_user_at_example.com.json
    """
    return STATE_DIR / ("state_" + _safe_filename(user) + ".json")


def load_state(user):
    """ユーザーごとのstateファイルを読み込む（または新規辞書を返す）。

    戻り値の辞書には必ず以下のキーが存在する:
        last_uid        : INBOXで最後に処理したUIDの最大値。次回のSCAN起点となる。
        last_spam_uid   : spam_folder で最後に処理したスパムメールのUID最大値。
        last_notspam_uid: notspam_folder で最後に処理した HAM メール のUID最大値。

    過去に保持していた learned_spam_uids / processed_uids は削除された（メモリ削減のため）。
    setdefault() でキー欠落時のフォールバックも行う。
    """
    path = state_file_path(user)
    if not path.exists():
        return {"last_uid": 0, "last_spam_uid": 0, "last_notspam_uid": 0}
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    # 古いキーを無視して削除（後方互換）
    data.pop("processed_uids", None)
    data.pop("learned_spam_uids", None)
    data.pop("learned_ham_uids", None)
    # キーが存在しない場合のデフォルト値
    data.setdefault("last_uid", 0)
    data.setdefault("last_spam_uid", 0)
    data.setdefault("last_notspam_uid", 0)
    return data


def save_state(user, state):
    """watermark（last_uid / last_spam_uid / last_notspam_uid）だけをstate_fileに書き出す。

    注意: learned_spam_uids や learned_ham_uids はこの関数では保存されない。
    UIDリストではなく watermark 方式なので、ファイルサイズが膨らまない。
    """
    path = state_file_path(user)
    # 必要キーだけ書き出す（ループ状態を含まない）
    payload = {
        "last_uid": state.get("last_uid", 0),
        "last_spam_uid": state.get("last_spam_uid", 0),
        "last_notspam_uid": state.get("last_notspam_uid", 0),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def setup_logging():
    """ロギングを設定し、systemd journal にも出力可能なloggerを返す。

    - ロガー名: "scan"
    - フォーマット: scan[PID]: LEVEL: message
    - ハンドラは重複追加されない（if not logger.handlers）
    - レベル: INFO（WARNING以上は warning() で出す）
    """
    logger = logging.getLogger("scan")
    if not logger.handlers:
        handler = logging.StreamHandler()
        fmt_str = "scan[%(process)d]: %(levelname)s: %(message)s"
        formatter = logging.Formatter(fmt_str)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def _is_timeout_error(exc):
    """例外の内容がネットワークタイムアウト由来かどうかをチェックする。

    タイムアウト文字列を小文字にして部分一致で判定:
      - "timed out"  /  "timeout"  /  "socket timed out"
    rspamdスキャンのsubprocess.TimeoutExpired は含まれない（rspamc側でkillされるため）。
    """
    text = str(exc).lower()
    return "timed out" in text or "timeout" in text or "socket timed out" in text


# ---------------------------------------------------------------------------
# IMAP クラス — _MailboxHandle / MailboxFetcher
# ---------------------------------------------------------------------------


class _MailboxHandle:
    """imap_tools.MailBox の薄いラッパークラス。タイムアウト時に再接続可能。

    内部状態:
        _mb     : imap_tools.MailBox インスタンス（None で未接続状態）
        _user   : ログインユーザー名（reconnect 用）
        _pw     : パスワード（reconnect 用）
        _folder : 最後のフォルダ名（reconnect 時に再選択するため保持）

    public属性:
        host / port / timeout : open() で設定された接続情報。reconnect でも再利用される。

    注意:
        connect() / reconnect() / close() はすべて socket.setdefaulttimeout() を呼ぶ。
        これは imap_tools が内部でソケットを使用するために必要。
    """

    def __init__(self, host, port, timeout):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._mb = None  # MailBox インスタンス（None = 未接続）
        self._user = None
        self._pw = None
        self._folder = None

    @property
    def mailbox(self):
        """現在の MailBox インスタンスを返す。未接続なら None。"""
        return self._mb

    def connect(self, user, password, folder):
        """IMAPサーバーに接続し、folder をオープンする。

        1. socket.setdefaulttimeout() でグローバルタイムアウトを設定
        2. MailBox.login() で認証 + initial_folder 指定
        3. _user / _pw / _folder に後続 reconnect 用のクレデンシャルを保存
        """
        socket.setdefaulttimeout(self.timeout)
        from imap_tools import MailBox
        self._user = user
        self._pw = password
        self._folder = folder
        self._mb = MailBox(self.host, self.port).login(
            user, password, initial_folder=folder
        )

    def reconnect(self):
        """現在の接続を切断 → 再接続する。

        フロー:
          1. _mb.logout() でクリーンアップ（失敗しても無視）
          2. _mb = None で未接続状態に戻す
          3. MailBox.login() で同じクレデンシャルで再接続

        エラー:
            logout() が例外を投げてくる可能性がある（既に切断されているなど）。
            必ず except/パス で飲み込む。
        """
        if self._mb:
            try:
                self._mb.logout()
            except Exception:
                pass
            self._mb = None
        socket.setdefaulttimeout(self.timeout)
        from imap_tools import MailBox
        self._mb = MailBox(self.host, self.port).login(
            self._user, self._pw, initial_folder=self._folder
        )

    def close(self):
        """IMAPセッションをlogout() で切断し、_mb を None にする。"""
        if self._mb:
            try:
                self._mb.logout()
            except Exception:
                pass
            self._mb = None


class MailboxFetcher:
    """逐次 IMAPフェッチャ。タイムアウト時に per-UID で再接続重试する。

    このクラスは _MailboxHandle をカプセル化し、検索・取得・移動の一連のIMAP操作を
    タイムアウト耐性付きで提供する。

    主なメソッド:
        open()          : IMAP接続確立（リトライあり）
        list_uids()     : UID SEARCH で未処理UID一覧を取得（本文ダウンロードなし）
        fetch_uid()     : 指定UIDのメッセージをフェッチ（本文付き）
        move()          : メッセージを指定フォルダへ移動
        set_folder()    : 作業対象フォルダを変更（INBOX ↔ notspam_folder / spam_folder）
        close()         : セッション終了
    """

    def __init__(self, logger, max_retries=MAX_IMAP_RETRIES):
        self.logger = logger
        self.max_retries = max_retries
        self._handle = None   # _MailboxHandle インスタンス
        self._retry_delay = 1  #再接続間の待機秒（固定）

    def open(self, host, port, user, password, folder, timeout):
        """IMAP接続を開く。成功したら True、超时で False を返す。

        retry フロー:
          1. _handle.connect() で接続を試みる
          2. socket.timeout / TimeoutError / OSError が起きたら _is_timeout_error() チェック
          3. タイムアウトなら _retry_delay 秒待機して再試行（最大 max_retries 回）
          4. タイムアウト以外なら即 raise
          5. max_retries を超えたら False

        NOTE:
            socket.timeout や TimeoutError が発生しないエラー（認証失敗など）は
            _is_timeout_error() で false なので、そのまま raise される。
        """
        self._handle = _MailboxHandle(host, port, timeout)
        attempts = 0
        while attempts < self.max_retries:
            try:
                self._handle.connect(user, password, folder)
                return True
            except (socket.timeout, TimeoutError, OSError) as exc:
                if not _is_timeout_error(exc):
                    raise
                attempts += 1
                self.logger.warning(
                    "IMAP connect timeout on %s attempt %d/%d",
                    host, attempts, self.max_retries,
                )
                if attempts < self.max_retries:
                    time.sleep(self._retry_delay)
        return False

    def list_uids(self, start_uid):
        """現在のフォルダ内で start_uid 以上の UID をソート済みリストで返す。

        IMAPのUID SEARCHを使用して、メッセージ本文をダウンロードせずに
        UIDのみを取得する（効率的）。

        Args:
            start_uid : これ以上のUIDを対象とする。0 を指定すると全UIDになる。

        Returns:
            int のソート済みリスト。接続 unavailable の場合は []。

        注意 (RFC 3501):
            "X:*" は「largest existing UID」を返す可能性があるため、
            start_uid より小さい UID が混入する場合がある。それをフィルタリングする。
        """
        if self._handle is None or self._handle.mailbox is None:
            return []

        for attempt in range(self.max_retries):
            try:
                imap = self._handle.mailbox.client
                _typ, data = imap.uid("SEARCH", None, "UID", "%d:*" % start_uid)
                if _typ != "OK" or not data or not data[0]:
                    return []
                # RFC 3501: "X:*" may return the largest existing UID even
                # when it is less than X. Filter to ensure UIDs >= start_uid.
                return sorted(int(u) for u in data[0].split() if int(u) >= start_uid)
            except Exception as exc:
                if _is_timeout_error(exc) and attempt < self.max_retries - 1:
                    self.logger.warning(
                        "IMAP timeout during UID SEARCH (%d/%d), reconnecting",
                        attempt + 1, self.max_retries,
                    )
                    try:
                        self._handle.reconnect()
                        time.sleep(self._retry_delay)
                    except Exception as reexc:
                        self.logger.error("Reconnect failed: %s", reexc)
                        return []
                else:
                    raise
        return []

    def fetch_uid(self, uid):
        """指定UIDのメッセージをフェッチする。

        戻り値:
            imap_tools.Message オブジェクト、またはフェッチ失敗時に None。

        mark_seen=False を指定しているので、既読フラグは変わらない。

        エラーハンドリング:
            タイムアウト時のみ再接続 + retry。それ以外の例外は即 raise。
            reconnect() が失敗したら None を返す（永久的な失敗とみなす）。
        """
        if self._handle is None or self._handle.mailbox is None:
            return None

        for attempt in range(self.max_retries):
            try:
                msgs = list(
                    self._handle.mailbox.fetch(
                        criteria="UID %d" % uid,
                        mark_seen=False,
                    )
                )
                return msgs[0] if msgs else None
            except Exception as exc:
                if _is_timeout_error(exc) and attempt < self.max_retries - 1:
                    self.logger.warning(
                        "IMAP timeout fetching UID=%d (%d/%d), reconnecting",
                        uid, attempt + 1, self.max_retries,
                    )
                    try:
                        self._handle.reconnect()
                        time.sleep(self._retry_delay)
                    except Exception as reexc:
                        self.logger.error("Reconnect failed: %s", reexc)
                        return None
                else:
                    raise
        return None

    def move(self, uid, folder):
        """メッセージを指定フォルダへ移動する（タイムアウト耐性なし）"""
        self._handle.mailbox.move(uid, folder)

    def get_folder(self):
        """現在の作業フォルダ名を返す。未接続時は None。"""
        if self._handle and self._handle.mailbox:
            return self._handle.mailbox.folder.get()
        return None

    def set_folder(self, folder):
        """作業フォルダを変更する（INBOX ↔ notspam_folder / spam_folder の切り替え用）。"""
        self._handle.mailbox.folder.set(folder)

    def close(self):
        """内部の _MailboxHandle.close() を呼び、セッションを終了する。"""
        if self._handle:
            self._handle.close()


# ---------------------------------------------------------------------------
# rspamd 連携関数
# ---------------------------------------------------------------------------


def run_rspamc(command, message_bytes, timeout, ignore_already_learned=False):
    """rspamc コマンドを実行する。

    Args:
        command             : rspamc のサブコマンドリスト（例: ["-j", "symbols"]）
        message_bytes       : メール本文の bytes。stdin に渡される。
        timeout             : タイムアウト秒数（現在、subprocess.run() で有効になっていない）
        ignore_already_learned: True なら "already learned as ..." の stdout を無視する。

    Returns:
        subprocess.CompletedProcess オブジェクト。

    エラー処理:
        returncode != 0 なら RuntimeError を raise（stdout/stderr付き）。
        ignore_already_learned=True で "already learned" メッセージが含まれる場合は、
        returncode != 0 でも例外を投げる代わりに result を返す。

    NOTE:
        timeout パラメータが subprocess.run() に渡されていない（コメントアウト済み）。
        rspamc がフリーズした場合はプロセスが残り続けるので注意。
    """
    result = subprocess.run(
        ["rspamc"] + command,
        input=message_bytes,
        capture_output=True,
        #timeout=timeout,
    )
    stdout = result.stdout.decode(errors="ignore")
    stderr = result.stderr.decode(errors="ignore")

    if ignore_already_learned:
        lo = stdout.lower()
        if "already learned as spam" in lo or "already learned as ham" in lo:
            return result

    if result.returncode != 0:
        raise RuntimeError(
            "rspamc failed rc=%d\nstdout=%s\nstderr=%s"
            % (result.returncode, stdout, stderr)
        )
    return result


def rspamd_scan(message_bytes, timeout):
    """メッセージを rspamd でスキャンする。

    rspamc "-j symbols" を実行し、JSON結果から以下を抽出:
        score           : 現在のスパムスコア（高いほどスパム可能性大）
        required_score  : スパムと判定される閾値
        action          : rspamd のアクション ("reject", "soft reject", "ham", "greylist", "no action" など)

    Returns:
        dict {"score": float, "required_score": float, "action": str}
    """
    result = run_rspamc(["-j", "symbols"], message_bytes, timeout)
    data = json.loads(result.stdout.decode())
    return {
        "score": float(data["score"]),
        "required_score": float(data["required_score"]),
        "action": data["action"],
    }


def learn_spam(message_bytes, timeout):
    """メッセージを rspamd にスパムとして学習させる。

    ignore_already_learned=True なので、すでに学習済みなら何もしない（エラーにもならない）。
    """
    run_rspamc(["learn_spam"], message_bytes, timeout, ignore_already_learned=True)


def learn_ham(message_bytes, timeout):
    """メッセージを rspamd にハム（正常メール）として学習させる。

    learn_spam() と同じく ignore_already_learned=True。
    """
    run_rspamc(["learn_ham"], message_bytes, timeout, ignore_already_learned=True)


def process_account(account, logger, dry_run=False):
    """1つのIMAPアカウントを処理する。

    フロー:
      1. config から接続情報を抽出（host, port, user, password, フォルダ名）。
         enabled=false のアカウントはスキップ。
      2. state_file から last_uid / last_spam_uid / last_notspam_uid を読み込み。
      3. INBOX で未処理UID (max(last_uid)+1 ~ ) を list_uids() で検索 → フェッチ → スキャン。
         - action ∈ SPAM_ACTIONS  → Junk フォルダへ移動 + learn_spam
         - action ∈ HAM_ACTIONS / "no action" → ham_folder へ移動 + learn_ham
         - それ以外 → INBOX にそのまま
      4. notspam_folder が設定されていたら、そこに溜まったメッセージを learn_ham。
      5. spam_folder が設定されていたら、そこに溜まったメッセージを learn_spam。

    dry_run=True の場合:
        メールは移動されない（状態ファイルも更新されない）。ログのみ出力される。

    state_file に記録される key:
        last_uid       : INBOX で最後に処理した UID の最大値
        last_spam_uid  : spam_folder で最後に処理したメッセージの UID 最大値
        last_notspam_uid: notspam_folder で最後に処理したメッセージの UID 最大値

    NOTE:
        watermark = max(current, uid) を毎メッセージ書き出す。これで UIDが飛び番でも安全。
        spam_folder / notspam_folder で move するとサーバーが新しい UID を割り振るが、
        その場合は watermark が進んでいるので再取得されない。
    """
    # アカウントが無効化されていたら処理をスキップ（デフォルトは有効）
    if not account.get("enabled", True):
        return

    logger.info("Processing account %s", account["user"])

    # ---- 接続情報＆フォルダ設定を抽出 ----
    host = account["host"]
    port = account.get("port", 993)         # デフォルトは IMAPS(993)
    user = account["user"]
    password = account["password"]

    # フォルダ名。None の場合その機能が無効になる。
    inbox_folder   = account.get("inbox_folder", "INBOX")     # 通常受信トレイ
    junk_folder    = account.get("junk_folder", "Junk")       # SPAM移動先（デフォルト）
    ham_folder     = account.get("ham_folder")                # HAM移動先（任意、Noneで無効）
    notspam_folder = account.get("notspam_folder")            # 手動HAM学習用フォルダ（任意）
    spam_folder    = account.get("spam_folder")               # 手動SPAM学習用フォルダ（任意）

    # タイムアウト設定（アカウント毎にオーバーライド可能）
    rspamc_timeout = int(account.get("rspamc_timeout", DEFAULT_RSPAMC_TIMEOUT))
    imap_timeout   = int(account.get("imap_timeout", DEFAULT_IMAP_TIMEOUT))

    # ---- 状態の読み込みとフェッチャの準備 ----
    state = load_state(user)
    fetcher = MailboxFetcher(logger)

    # IMAP接続。失敗したら即 return（reconnect は中側で担当）
    if not fetcher.open(host, port, user, password, inbox_folder, imap_timeout):
        logger.error("Cannot connect to %s", host)
        return

    # ---- 全アカウントの処理を try/finally で囲む ----
    # finally: fetcher.close() でセッションを確実に切断する。
    #          except Exception で fatal エラーもログ出力する。
    try:
        max_uid = state.get("last_uid", 0)   # watermarker起点（前回の最大UID）
        fetched_count = 0                      # INBOX 処理件数カウンター
        fetcher.set_folder(inbox_folder)       # 作業対象を INBOX に設定

        # ==== 1. INBOX の未処理メッセージを処理 ====
        # list_uids() は UID SEARCH で本文下载なし。効率的。
        uid_list = fetcher.list_uids(max_uid + 1)
        logger.info("Found %d UID(s) to process in %s", len(uid_list), inbox_folder)

        for uid in uid_list:
            msg = fetcher.fetch_uid(uid)       # UID で個別フェッチ（本文あり）
            if msg is None:
                logger.warning("UID=%d could not be fetched, skipping", uid)
                # フェッチ失敗時: watermark を進めて再試行ループを防ぐ。
                max_uid = max(max_uid, uid)
                if not dry_run:
                    state["last_uid"] = max_uid
                    save_state(user, state)
                continue

            fetched_count += 1

            # rspamd スキャン（msg.obj.as_bytes() でメール全文をbytes化）
            try:
                scan = rspamd_scan(msg.obj.as_bytes(), rspamc_timeout)
            except subprocess.TimeoutExpired:
                logger.warning("UID=%d RSPAMC TIMEOUT (score unknown)", uid)
                max_uid = max(max_uid, uid)
                if not dry_run:
                    state["last_uid"] = max_uid
                    save_state(user, state)
                continue

            score = scan["score"]
            action = scan["action"]

            # ==== SPAM パス (reject / soft reject) ====
            if action in ACTIONS_SPAM:
                logger.info(
                    "UID=%d SCORE=%.2f ACTION=%s SUBJECT=%s -> SPAM (to Junk)",
                    uid, score, action, msg.subject or "",
                )
                try:
                    fetcher.move(msg.uid, junk_folder)
                except Exception as move_exc:
                    logger.error(
                        "UID=%d move to %s failed: %s",
                        uid, junk_folder, move_exc,
                    )

                try:
                    learn_spam(msg.obj.as_bytes(), rspamc_timeout)
                except Exception as learn_exc:
                    logger.warning("UID=%d learn_spam failed: %s", uid, learn_exc)

            # ==== HAM パス (ham / greylist / no action) ====
            elif action in ACTIONS_HAM or action == "no action":
                if not dry_run and ham_folder:
                    logger.info(
                        "UID=%d SCORE=%.2f ACTION=%s SUBJECT=%s -> HAM (to %s)",
                        uid, score, action, msg.subject or "", ham_folder,
                    )
                    try:
                        fetcher.move(msg.uid, ham_folder)
                    except Exception as move_exc:
                        logger.error(
                            "UID=%d move to %s failed: %s",
                            uid, ham_folder, move_exc,
                        )
                elif not dry_run and not ham_folder:
                    logger.warning(
                        "UID=%d HAM but no ham_folder configured -> skip move", uid,
                    )

                try:
                    learn_ham(msg.obj.as_bytes(), rspamc_timeout)
                except Exception:
                    pass   # 学習失敗は無視（すでに学習済みなど）

            # ==== 未知のアクション ====
            else:
                logger.info(
                    "UID=%d SCORE=%.2f ACTION=%s SUBJECT=%s -> kept in INBOX",
                    uid, score, action, msg.subject or "",
                )

            # watermark を毎メッセージ更新して永続化。dry_run=False のみ state_file が更新される。
            max_uid = max(max_uid, uid)
            if not dry_run:
                state["last_uid"] = max_uid
                save_state(user, state)

        logger.info(
            "Inbox done: %d message(s), max UID=%d", fetched_count, max_uid
        )

        # ==== 2. notspam_folder の処理（手動HAM学習用） ====
        # notspam_folder に溜まったメールを learn_ham する。
        # フォルダ移動後にサーバーが新UIDを割り振るが、watermark = max(prev, uid) なので安全。
        if notspam_folder:
            logger.info("Processing notspam_folder: %s", notspam_folder)

            # move先: ham_folder があればそこへ、なければ INBOX のまま
            dest = ham_folder if ham_folder else inbox_folder
            if not dry_run and not ham_folder:
                logger.warning(
                    "HAM target folder not set. Messages remain in INBOX."
                )

            fetcher.set_folder(notspam_folder)       # 作業フォルダを切り替え

            notspam_max = state.get("last_notspam_uid", 0)   # notspam の watermark 起点
            notspam_uids = fetcher.list_uids(notspam_max + 1)
            logger.info(
                "Found %d UID(s) to process in %s",
                len(notspam_uids), notspam_folder,
            )

            notspam_fetched = 0
            for nuid in notspam_uids:
                msg = fetcher.fetch_uid(nuid)              # このフォルダからフェッチ
                if msg is None:
                    logger.warning(
                        "LEARN_HAM UID=%d could not be fetched, skipping", nuid
                    )
                    notspam_max = max(notspam_max, nuid)    # watermark を進む（再試行防止）
                    if not dry_run:
                        state["last_notspam_uid"] = notspam_max
                        save_state(user, state)
                    continue

                notspam_fetched += 1
                logger.info(
                    "LEARN_HAM UID=%d SUBJECT=%s (from %s)",
                    nuid, msg.subject or "", notspam_folder,
                )

                try:
                    learn_ham(msg.obj.as_bytes(), rspamc_timeout)   # rspamd に HAM 学習させる
                except Exception as le:
                    logger.warning("LEARN_HAM UID=%d failed: %s", nuid, le)

                if not dry_run:
                    fetcher.move(msg.uid, dest)             # move先へ移動（dry_runならなし）

                notspam_max = max(notspam_max, nuid)
                if not dry_run:
                    state["last_notspam_uid"] = notspam_max
                    save_state(user, state)

            logger.info("notspam done: %d message(s)", notspam_fetched)


        # ==== 3. spam_folder の処理（手動SPAM学習用） ====
        # spam_folder に溜まったメールを learn_spam した後、junk_folder へ移動する。
        # これにより spam_folder が空になり、次回再取得されない。
        # notspam_folder と同じく watermark = max(prev, uid) で安全に再取得回避。
        if spam_folder:
            logger.info("Processing spam_folder: %s", spam_folder)

            fetcher.set_folder(spam_folder)       # フォルダを切り替え

            spam_max = state.get("last_spam_uid", 0)   # spam の watermark 起点
            spam_uids = fetcher.list_uids(spam_max + 1)
            logger.info(
                "Found %d UID(s) to process in %s",
                len(spam_uids), spam_folder,
            )

            spam_fetched = 0
            for suid in spam_uids:
                msg = fetcher.fetch_uid(suid)
                if msg is None:
                    logger.warning(
                        "LEARN_SPAM UID=%d could not be fetched, skipping", suid
                    )
                    spam_max = max(spam_max, suid)            # watermark を進む（再試行防止）
                    if not dry_run:
                        state["last_spam_uid"] = spam_max
                        save_state(user, state)
                    continue

                spam_fetched += 1
                logger.info(
                    "LEARN_SPAM UID=%d SUBJECT=%s (from %s)",
                    suid, msg.subject or "", spam_folder,
                )

                # rspamd にスパムとして学習
                try:
                    learn_spam(msg.obj.as_bytes(), rspamc_timeout)
                except Exception as le:
                    logger.warning("LEARN_SPAM UID=%d failed: %s", suid, le)

                # 学習済み → junk_folder へ移動（spam_folder は空にする）
                if not dry_run and junk_folder:
                    try:
                        fetcher.move(msg.uid, junk_folder)
                    except Exception as move_exc:
                        logger.error(
                            "LEARN_SPAM UID=%d move to %s failed: %s",
                            suid, junk_folder, move_exc,
                        )

                spam_max = max(spam_max, suid)
                if not dry_run:
                    state["last_spam_uid"] = spam_max
                    save_state(user, state)

            logger.info("spam_folder done: %d message(s)", spam_fetched)
        if not dry_run:
            logger.info("State saved: last_uid=%d", max_uid)

    # fatal エラー時はログ出力（continue する）
    except Exception as exc:
        logger.error("Fatal error processing %s: %s", user, exc)
    # 必ずセッションを切断
    finally:
        fetcher.close()


def main():
    """CLIのエントリポイント。

    フロー:
      1. argparse で引数処理（--config, --dry-run, --batch-size）
      2. config.json からアカウント一覧を読み込み
      3. アカウントごとに process_account() を逐次実行
         - socket.timeout は個別にキャッチしてログ出力（残りのアカウントは continue）
         - その他の例外もキャッチ（process_account 内での try/except + finally も併用）

    NOTE:
        --batch-size が globals()["DEFAULT_BATCH_SIZE"] に書き込まれるが、
        process_account() では使われていない。unused parameter の可能性あり。
        socket.timeout は process_account 外でもキャッチしているが、
        fetcher.open() で True/False を返すため、ここでは不要な場合が多い。
    """
    parser = argparse.ArgumentParser(
        description="IMAP mailbox scanner with rspamd classification"
    )
    parser.add_argument("--config", default="config.json")       # 設定ファイルパス
    parser.add_argument("--dry-run", action="store_true")         # ドライランフラグ（移動なし）
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)  # バッチサイズ（unused）
    args = parser.parse_args()

    # グローバル定数の上書き（現在は unused な可能性あり）
    globals()["DEFAULT_BATCH_SIZE"] = args.batch_size

    logger = setup_logging()

    # config.json を読み込み
    with open(args.config, encoding="utf-8") as fh:
        config = json.load(fh)

    # accounts キーがない場合は終了
    if "accounts" not in config:
        logger.error("No accounts found in config")
        return

    # アカウントごとに逐次処理（並列ではない）
    for account in config["accounts"]:
        try:
            process_account(account, logger, args.dry_run)
        except socket.timeout:
            # IMAP接続のタイムアウト。このアカウントをスキップして次へ。
            logger.error("%s IMAP TIMEOUT", account.get("user", "unknown"))
        except Exception as exc:
            # それ以外のエラーもキャッチ。repr() でフル情報 logged
            logger.error(
                "%s ERROR: %s",
                account.get("user", "unknown"), repr(exc),
            )


if __name__ == "__main__":
    main()
