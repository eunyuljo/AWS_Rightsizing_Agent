"""Slack 웹훅 알림"""
import json
import urllib.request
from config import config

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
}

SEVERITY_LABEL = {
    "critical": "심각",
    "high":     "높음",
    "medium":   "보통",
    "low":      "낮음",
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


def send_violation(violation: dict, explanation: str):
    """
    규정 위반 항목 하나를 Slack으로 전송.
    violation 은 Violation.to_dict() 형태.
    """
    sev = violation.get("severity", "low")
    emoji = SEVERITY_EMOJI.get(sev, "⚪")
    label = SEVERITY_LABEL.get(sev, "")
    framework = violation.get("framework", "")
    rule_id = violation.get("rule_id", "")
    resource = violation.get("resource_id", "")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} [{label}] {violation.get('title', '위반 감지')}",
            },
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": explanation},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*프레임워크:* {framework}"},
                {"type": "mrkdwn", "text": f"*룰 ID:* `{rule_id}`"},
                {"type": "mrkdwn", "text": f"*리소스:* `{resource}`"},
                {"type": "mrkdwn", "text": f"*카테고리:* {violation.get('category', '')}"},
            ],
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*조치:* {violation.get('remediation', '')}",
                }
            ],
        },
        {"type": "divider"},
    ]
    send(f"{emoji} {violation.get('title', '위반 감지')}", blocks=blocks)


def send_daily_summary(violations: list[dict], summary_text: str):
    critical = sum(1 for v in violations if v.get("severity") == "critical")
    high = sum(1 for v in violations if v.get("severity") == "high")
    medium = sum(1 for v in violations if v.get("severity") == "medium")
    low = sum(1 for v in violations if v.get("severity") == "low")

    by_cat: dict[str, int] = {}
    for v in violations:
        cat = v.get("category", "기타")
        by_cat[cat] = by_cat.get(cat, 0) + 1

    cat_text = " | ".join(f"{k}: {n}건" for k, n in by_cat.items())

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "☁️ AWS 인프라 일일 컴플라이언스 리포트"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*🔴 심각:* {critical}건"},
                {"type": "mrkdwn", "text": f"*🟠 높음:* {high}건"},
                {"type": "mrkdwn", "text": f"*🟡 보통:* {medium}건"},
                {"type": "mrkdwn", "text": f"*🔵 낮음:* {low}건"},
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*카테고리별:* {cat_text}"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": summary_text},
        },
    ]
    send(f"AWS 일일 리포트 — 총 {len(violations)}건", blocks=blocks)
