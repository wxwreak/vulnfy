import os

import requests


def send_telegram(
    vuln_count: int, report_summary: str, report_fpath: str | None = None
):
    bot = os.getenv("TELEGRAM_BOT_TOKEN")
    chat = os.getenv("TELEGRAM_CHAT_ID")

    if not bot or not chat:
        print("[!] Telegram Error: Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")
        return False

    base_url = f"https://api.telegram.org/bot{bot}"

    if vuln_count > 0:
        emoji = "⚠️"
        text = f"Found {vuln_count} vulnerabilities"
    else:
        return

    payload = (
        f"{emoji} *Vulnfy Security Scan Results*\n"
        f"*Status:* {text}\n\n"
        f"*Summary:*\n{report_summary}"
    )

    try:
        text_url = f"{base_url}/sendMessage"
        requests.post(
            text_url, json={"chat_id": chat, "text": payload, "parse_mode": "Markdown"}
        )

        if report_fpath and os.path.exists(report_fpath):
            doc_url = f"{base_url}/sendDocument"
            with open(report_fpath, "rb") as f:
                requests.post(doc_url, data={"chat_id": chat}, files={"document": f})
        return True
    except Exception as e:
        print(f"[!] Telegram Error: {e}")
        return False
