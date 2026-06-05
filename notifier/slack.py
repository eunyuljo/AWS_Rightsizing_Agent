"""Slack 웹훅 알림"""
import json
import urllib.request
from config import config

SEVERITY_EMOJI = {
    "critical": "🔴",
    "warning": "🟡",
    "info": "🔵",
}


def send(text: str, blocks: list = None):
    if not config.slack_webhook_url:
        print(f"[Slack 미설정] {text}")
        return

    payload = {"text": text}
    if blocks:
        payload["blocks"] = blocks

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        config.slack_webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read()


def send_alert(alert: dict, explanation: str):
    emoji = SEVERITY_EMOJI.get(alert.get("severity", "info"), "⚪")
    severity_label = {"critical": "긴급", "warning": "주의", "info": "참고"}.get(
        alert.get("severity", "info"), ""
    )

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} [{severity_label}] {alert.get('title', '알림')}",
            },
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": explanation},
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"*유형:* `{alert.get('alert_type', '')}` | *시각:* {alert.get('ts', '')}"},
            ],
        },
        {"type": "divider"},
    ]
    send(f"{emoji} {alert.get('title', '알림')}", blocks=blocks)


def send_daily_summary(alerts: list[dict], summary_text: str):
    critical = sum(1 for a in alerts if a.get("severity") == "critical")
    warning = sum(1 for a in alerts if a.get("severity") == "warning")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "☁️ AWS 인프라 일일 리포트"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*🔴 긴급:* {critical}건"},
                {"type": "mrkdwn", "text": f"*🟡 주의:* {warning}건"},
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": summary_text},
        },
    ]
    send("AWS 인프라 일일 리포트", blocks=blocks)
