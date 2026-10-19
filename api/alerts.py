# guardrail/api/alerts.py

import os
import requests
from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

celery_app = Celery("guardrail", broker=REDIS_URL, backend=REDIS_URL)


@celery_app.task
def send_telegram_alert(title: str, message: str, severity: str = "high"):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return {"status": "skipped", "reason": "no_telegram_config"}

    emoji = {"high": "🚨", "medium": "⚠️", "low": "ℹ️"}.get(severity, "🔔")
    text = f"{emoji} *{title}*\n\n{message}"

    r = requests.post(
        f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
        json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "Markdown",
        },
        timeout=5,
    )
    return {"status": r.status_code}