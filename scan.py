#!/usr/bin/env python3
"""IMAP mailbox scanner with rspamd SPAM classification."""

import argparse
import json
import logging
import socket
import subprocess
import time
from pathlib import Path


DEFAULT_IMAP_TIMEOUT = 60
DEFAULT_RSPAMC_TIMEOUT = 30
DEFAULT_BATCH_SIZE = 100
MAX_IMAP_RETRIES = 3

STATE_DIR = Path("state")
STATE_DIR.mkdir(exist_ok=True)

SPAM_ACTIONS = {"reject", "soft reject"}

ACTIONS_SPAM = SPAM_ACTIONS
ACTIONS_HAM = {"ham", "greylist"}


def _safe_filename(user):
    """Convert a user identifier into a safe state-file name."""
    return (
        user.replace("@", "_at_")
            .replace("/", "_")
            .replace("\\", "_")
    )


def state_file_path(user):
    return STATE_DIR / ("state_" + _safe_filename(user) + ".json")


def load_state(user):
    path = state_file_path(user)
    if not path.exists():
        return {"last_uid": 0, "last_spam_uid": 0, "last_notspam_uid": 0}
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    data.pop("processed_uids", None)
    data.pop("learned_spam_uids", None)
    data.pop("learned_ham_uids", None)
    data.setdefault("last_uid", 0)
    data.setdefault("last_spam_uid", 0)
    data.setdefault("last_notspam_uid", 0)
    return data


def save_state(user, state):
    path = state_file_path(user)
    # 必要キーだけ書き出す
    payload = {
        "last_uid": state.get("last_uid", 0),
        "last_spam_uid": state.get("last_spam_uid", 0),
        "last_notspam_uid": state.get("last_notspam_uid", 0),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def setup_logging():
    """Configure logging suitable for systemd journal."""
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
    """Check if an exception indicates a network timeout."""
    text = str(exc).lower()
    return "timed out" in text or "timeout" in text or "socket timed out" in text


class _MailboxHandle:
    """Thin wrapper around imap_tools MailBox with reconnect on timeout."""

    def __init__(self, host, port, timeout):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._mb = None
        self._user = None
        self._pw = None
        self._folder = None

    @property
    def mailbox(self):
        return self._mb

    def connect(self, user, password, folder):
        socket.setdefaulttimeout(self.timeout)
        from imap_tools import MailBox
        self._user = user
        self._pw = password
        self._folder = folder
        self._mb = MailBox(self.host, self.port).login(
            user, password, initial_folder=folder
        )

    def reconnect(self):
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
        if self._mb:
            try:
                self._mb.logout()
            except Exception:
                pass
            self._mb = None


class MailboxFetcher:
    """Sequential IMAP fetcher with per-UID reconnect on timeout."""

    def __init__(self, logger, max_retries=MAX_IMAP_RETRIES):
        self.logger = logger
        self.max_retries = max_retries
        self._handle = None
        self._retry_delay = 1

    def open(self, host, port, user, password, folder, timeout):
        """Open the IMAP connection.  Returns True on success."""
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
        """Return sorted list of UIDs >= start_uid in the current folder.

        Uses IMAP UID SEARCH so no message body is downloaded.
        Returns empty list if the connection is unavailable.
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
        """Fetch a single message by UID.

        Returns the message object, or None on permanent failure.
        Retries with reconnect on timeout.
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
        self._handle.mailbox.move(uid, folder)

    def get_folder(self):
        if self._handle and self._handle.mailbox:
            return self._handle.mailbox.folder.get()
        return None

    def set_folder(self, folder):
        self._handle.mailbox.folder.set(folder)

    def close(self):
        if self._handle:
            self._handle.close()


def run_rspamc(command, message_bytes, timeout, ignore_already_learned=False):
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
    """Scan a message with rspamd.

    Returns dict  {score, required_score, action}.
    """
    result = run_rspamc(["-j", "symbols"], message_bytes, timeout)
    data = json.loads(result.stdout.decode())
    return {
        "score": float(data["score"]),
        "required_score": float(data["required_score"]),
        "action": data["action"],
    }


def learn_spam(message_bytes, timeout):
    run_rspamc(["learn_spam"], message_bytes, timeout, ignore_already_learned=True)


def learn_ham(message_bytes, timeout):
    run_rspamc(["learn_ham"], message_bytes, timeout, ignore_already_learned=True)


def process_account(account, logger, dry_run=False):
    """Process a single IMAP account.

    - Lists UIDs > last_uid via IMAP SEARCH (no body download)
    - Fetches and classifies each message one by one
    - SPAM -> move to Junk then learn_spam
    - HAM / greylist -> move to ham_folder then learn_ham
    - Persists only last_uid / last_notspam_uid (no processed_uids list)
    """
    if not account.get("enabled", True):
        return

    logger.info("Processing account %s", account["user"])

    host = account["host"]
    port = account.get("port", 993)
    user = account["user"]
    password = account["password"]
    inbox_folder = account.get("inbox_folder", "INBOX")
    junk_folder = account.get("junk_folder", "Junk")
    ham_folder = account.get("ham_folder")
    notspam_folder = account.get("notspam_folder")
    spam_folder = account.get("spam_folder")

    rspamc_timeout = int(account.get("rspamc_timeout", DEFAULT_RSPAMC_TIMEOUT))
    imap_timeout = int(account.get("imap_timeout", DEFAULT_IMAP_TIMEOUT))

    state = load_state(user)
    fetcher = MailboxFetcher(logger)

    if not fetcher.open(host, port, user, password, inbox_folder, imap_timeout):
        logger.error("Cannot connect to %s", host)
        return

    try:
        max_uid = state.get("last_uid", 0)
        fetched_count = 0
        fetcher.set_folder(inbox_folder)

        # ---- process inbox: list UIDs first, then fetch one by one ----
        uid_list = fetcher.list_uids(max_uid + 1)
        logger.info("Found %d UID(s) to process in %s", len(uid_list), inbox_folder)

        for uid in uid_list:
            msg = fetcher.fetch_uid(uid)
            if msg is None:
                logger.warning("UID=%d could not be fetched, skipping", uid)
                # advance past this UID so we don't retry forever
                max_uid = max(max_uid, uid)
                if not dry_run:
                    state["last_uid"] = max_uid
                    save_state(user, state)
                continue

            fetched_count += 1

            # rspamd scan
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

            # ---- SPAM path ----
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

            # ---- HAM path (includes greylist) ----
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
                    pass

            # ---- unknown action ----
            else:
                logger.info(
                    "UID=%d SCORE=%.2f ACTION=%s SUBJECT=%s -> kept in INBOX",
                    uid, score, action, msg.subject or "",
                )

            # Advance the watermark and persist after every message
            max_uid = max(max_uid, uid)
            if not dry_run:
                state["last_uid"] = max_uid
                save_state(user, state)

        logger.info(
            "Inbox done: %d message(s), max UID=%d", fetched_count, max_uid
        )

        # ---- learn_ham from notspam_folder (if configured) ----
        # move先で新UIDが採番されるのでUID順は保証される → watermark方式で十分
        if notspam_folder:
            logger.info("Processing notspam_folder: %s", notspam_folder)

            dest = ham_folder if ham_folder else inbox_folder
            if not dry_run and not ham_folder:
                logger.warning(
                    "HAM target folder not set. Messages remain in INBOX."
                )

            fetcher.set_folder(notspam_folder)

            notspam_max = state.get("last_notspam_uid", 0)
            notspam_uids = fetcher.list_uids(notspam_max + 1)
            logger.info(
                "Found %d UID(s) to process in %s",
                len(notspam_uids), notspam_folder,
            )

            notspam_fetched = 0
            for nuid in notspam_uids:
                msg = fetcher.fetch_uid(nuid)
                if msg is None:
                    logger.warning(
                        "LEARN_HAM UID=%d could not be fetched, skipping", nuid
                    )
                    notspam_max = max(notspam_max, nuid)
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
                    learn_ham(msg.obj.as_bytes(), rspamc_timeout)
                except Exception as le:
                    logger.warning("LEARN_HAM UID=%d failed: %s", nuid, le)

                if not dry_run:
                    fetcher.move(msg.uid, dest)

                notspam_max = max(notspam_max, nuid)
                if not dry_run:
                    state["last_notspam_uid"] = notspam_max
                    save_state(user, state)

            logger.info("notspam done: %d message(s)", notspam_fetched)


        # ---- learn_spam from spam_folder (manually sorted spam) ----
        # move先で新UIDが採番されるのでUID順は保証される → watermark方式で十分
        if spam_folder:
            logger.info("Processing spam_folder: %s", spam_folder)

            fetcher.set_folder(spam_folder)

            spam_max = state.get("last_spam_uid", 0)
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
                    spam_max = max(spam_max, suid)
                    if not dry_run:
                        state["last_spam_uid"] = spam_max
                        save_state(user, state)
                    continue

                spam_fetched += 1
                logger.info(
                    "LEARN_SPAM UID=%d SUBJECT=%s (from %s)",
                    suid, msg.subject or "", spam_folder,
                )

                try:
                    learn_spam(msg.obj.as_bytes(), rspamc_timeout)
                except Exception as le:
                    logger.warning("LEARN_SPAM UID=%d failed: %s", suid, le)

                spam_max = max(spam_max, suid)
                if not dry_run:
                    state["last_spam_uid"] = spam_max
                    save_state(user, state)

            logger.info("spam_folder done: %d message(s)", spam_fetched)
        if not dry_run:
            logger.info("State saved: last_uid=%d", max_uid)

    except Exception as exc:
        logger.error("Fatal error processing %s: %s", user, exc)
    finally:
        fetcher.close()


def main():
    parser = argparse.ArgumentParser(
        description="IMAP mailbox scanner with rspamd classification"
    )
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    args = parser.parse_args()

    globals()["DEFAULT_BATCH_SIZE"] = args.batch_size

    logger = setup_logging()

    with open(args.config, encoding="utf-8") as fh:
        config = json.load(fh)

    if "accounts" not in config:
        logger.error("No accounts found in config")
        return

    for account in config["accounts"]:
        try:
            process_account(account, logger, args.dry_run)
        except socket.timeout:
            logger.error("%s IMAP TIMEOUT", account.get("user", "unknown"))
        except Exception as exc:
            logger.error(
                "%s ERROR: %s",
                account.get("user", "unknown"), repr(exc),
            )


if __name__ == "__main__":
    main()
