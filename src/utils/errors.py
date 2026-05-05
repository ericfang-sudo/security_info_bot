import requests

from src.config import MATTERMOST_OPS_WEBHOOK
from src.utils.logging import log


class TwcertLoginError(Exception):
    pass


class GeminiQuotaExhausted(Exception):
    pass


def send_ops_alert(title: str, detail: str) -> None:
    if not MATTERMOST_OPS_WEBHOOK:
        log.warning("MATTERMOST_OPS_WEBHOOK not set, skipping ops alert: %s", title)
        return

    payload = {
        "username": "SecurityBot-OPS",
        "icon_emoji": ":warning:",
        "text": f"### :warning: {title}\n\n{detail}",
    }
    try:
        resp = requests.post(MATTERMOST_OPS_WEBHOOK, json=payload, timeout=10)
        resp.raise_for_status()
        log.info("Ops alert sent: %s", title)
    except requests.RequestException as e:
        log.error("Failed to send ops alert: %s", e)
