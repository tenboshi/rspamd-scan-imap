#!/usr/bin/env python3
import argparse
import json
import sys
import tty
import termios
from imap_tools import MailBox


def load_config(config_path):
    with open(config_path, encoding="utf-8") as f:
        return json.load(f)


def find_account(config, account_name):
    for account in config["accounts"]:
        if not account.get("enabled", True):
            continue
        if account["user"] == account_name:
            return account
    return None


def get_enabled_accounts(config):
    return [a for a in config["accounts"] if a.get("enabled", True)]


def move_to_line(row):
    """1-origin の絶対行へ移動（カーソル位置ESCシーケンス）"""
    sys.stdout.write(f"\033[{row};1H")


def render_line(row, label, selected):
    """指定行だけを書き直す"""
    move_to_line(row)
    sys.stdout.write("\033[2K")          # 行クリア
    if selected:
        sys.stdout.write(f"\033[7m > {label}\033[0m")
    else:
        sys.stdout.write(f"   {label}")
    sys.stdout.flush()


def pick_account_interactive(accounts):
    if not sys.stdin.isatty():
        print("Error: no TTY available for interactive selection", file=sys.stderr)
        sys.exit(1)

    total = len(accounts)
    labels = [f"{i+1:2}. {a['user']}" for i, a in enumerate(accounts)]

    # ヘッダ2行 + アカウント行を一括描画してカーソル位置を固定
    sys.stdout.write("\033[2J\033[H")    # 画面クリア・ホーム
    sys.stdout.write("Select account  (↑↓ or number, Enter / q to quit)\n")
    sys.stdout.write("---------------------------------------------------\n")
    for i, label in enumerate(labels):
        if i == 0:
            sys.stdout.write(f"\033[7m > {label}\033[0m\n")
        else:
            sys.stdout.write(f"   {label}\n")
    sys.stdout.flush()

    HEADER = 3   # ヘッダ行数（1行目: タイトル、2行目: 区切り、3行目〜: アカウント）

    selected = 0
    number_buf = ""

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)

            if ch in ("q", "Q", "\x03"):
                sys.stdout.write("\033[?25h")
                # 画面下へ移動してから終了
                move_to_line(HEADER + total + 1)
                sys.stdout.write("\n")
                sys.stdout.flush()
                sys.exit(0)

            if ch in ("\r", "\n"):
                if number_buf:
                    n = int(number_buf) - 1
                    if 0 <= n < total:
                        selected = n
                    number_buf = ""
                break

            if ch == "\x1b":
                seq = sys.stdin.read(2)
                prev = selected
                if seq == "[A":    # ↑
                    selected = (selected - 1) % total
                elif seq == "[B":  # ↓
                    selected = (selected + 1) % total
                else:
                    continue
                number_buf = ""
                render_line(HEADER + prev,     labels[prev],    False)
                render_line(HEADER + selected, labels[selected], True)
                continue

            if ch.isdigit():
                number_buf += ch
                n = int(number_buf) - 1
                if 0 <= n < total:
                    prev = selected
                    selected = n
                    render_line(HEADER + prev,     labels[prev],    False)
                    render_line(HEADER + selected, labels[selected], True)
                if int(number_buf) > total:
                    number_buf = ""
                continue

            number_buf = ""

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write("\033[?25h")
        move_to_line(HEADER + total + 1)
        sys.stdout.write("\n")
        sys.stdout.flush()

    return accounts[selected]


def show_folders(account):
    host = account["host"]
    user = account["user"]
    password = account["password"]

    print(f"Connecting to {host}")
    print(f"User: {user}")
    print()

    with MailBox(host).login(username=user, password=password) as mailbox:
        folders = mailbox.folder.list()
        print("IMAP folders:")
        print("-------------")
        for folder in folders:
            flags = ""
            if folder.flags:
                flags = " [" + ", ".join(folder.flags) + "]"
            print(f"{folder.name}{flags}")


def main():
    parser = argparse.ArgumentParser(
        description="List IMAP folders for configured account"
    )
    parser.add_argument(
        "account",
        nargs="?",
        help="mail address defined in config.json (省略時は対話選択)"
    )
    parser.add_argument(
        "--config",
        default="config.json",
        help="config file path"
    )
    args = parser.parse_args()

    config = load_config(args.config)

    if args.account is None:
        accounts = get_enabled_accounts(config)
        if not accounts:
            print("No enabled accounts found in config.", file=sys.stderr)
            sys.exit(1)
        account = pick_account_interactive(accounts)
    else:
        account = find_account(config, args.account)
        if account is None:
            print(f"Account not found or disabled: {args.account}", file=sys.stderr)
            sys.exit(1)

    show_folders(account)


if __name__ == "__main__":
    main()
