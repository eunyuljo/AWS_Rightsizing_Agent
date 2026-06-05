import os
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

# .env 파일이 있으면 자동 로드 (없어도 무시)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env", override=False)
except ImportError:
    pass


@dataclass
class Config:
    # AWS
    aws_region: str = os.getenv("AWS_REGION", "ap-northeast-2")
    aws_access_key_id: Optional[str] = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = os.getenv("AWS_SECRET_ACCESS_KEY")
    aws_session_token: Optional[str] = os.getenv("AWS_SESSION_TOKEN")

    # Claude
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    claude_model: str = "claude-sonnet-4-6"

    # Slack
    slack_webhook_url: Optional[str] = os.getenv("SLACK_WEBHOOK_URL")
    slack_channel: str = os.getenv("SLACK_CHANNEL", "#aws-alerts")

    # Detection thresholds
    cost_spike_pct: float = float(os.getenv("COST_SPIKE_PCT", "50"))   # % 증가 시 알림
    cpu_idle_pct: float = float(os.getenv("CPU_IDLE_PCT", "5"))         # % 이하 → 유휴
    cpu_idle_hours: int = int(os.getenv("CPU_IDLE_HOURS", "24"))

    # Scheduler (seconds)
    collect_interval: int = int(os.getenv("COLLECT_INTERVAL", "900"))   # 15분
    security_interval: int = int(os.getenv("SECURITY_INTERVAL", "3600")) # 1시간

    # DB
    db_path: str = os.getenv("DB_PATH", "infrachat.db")


config = Config()
