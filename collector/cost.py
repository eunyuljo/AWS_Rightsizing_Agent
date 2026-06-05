"""Cost Explorer 기반 시간당/서비스별 비용 수집"""
import boto3
from datetime import datetime, timedelta, timezone
from config import config


def _client():
    return boto3.client(
        "ce",
        region_name="us-east-1",  # Cost Explorer는 us-east-1 고정
        aws_access_key_id=config.aws_access_key_id,
        aws_secret_access_key=config.aws_secret_access_key,
        aws_session_token=config.aws_session_token,
    )


def get_daily_cost_by_service(days: int = 30) -> list[dict]:
    """최근 N일간 서비스별 일별 비용"""
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=days)

    resp = _client().get_cost_and_usage(
        TimePeriod={"Start": str(start), "End": str(end)},
        Granularity="DAILY",
        Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )

    results = []
    for period in resp["ResultsByTime"]:
        date = period["TimePeriod"]["Start"]
        for group in period["Groups"]:
            service = group["Keys"][0]
            amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
            if amount > 0:
                results.append({"date": date, "service": service, "amount": amount})
    return results


def get_hourly_cost(hours: int = 48) -> list[dict]:
    """최근 N시간 시간별 총 비용 (이상 감지용)"""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    resp = _client().get_cost_and_usage(
        TimePeriod={
            "Start": start.strftime("%Y-%m-%dT%H:00:00Z"),
            "End": end.strftime("%Y-%m-%dT%H:00:00Z"),
        },
        Granularity="HOURLY",
        Metrics=["UnblendedCost"],
    )

    results = []
    for period in resp["ResultsByTime"]:
        ts = period["TimePeriod"]["Start"]
        amount = float(period["Total"]["UnblendedCost"]["Amount"])
        results.append({"ts": ts, "amount": amount})
    return results


def get_mtd_cost_by_service() -> list[dict]:
    """이번 달 누계 서비스별 비용"""
    today = datetime.now(timezone.utc).date()
    start = today.replace(day=1)

    resp = _client().get_cost_and_usage(
        TimePeriod={"Start": str(start), "End": str(today)},
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )

    results = []
    if resp["ResultsByTime"]:
        for group in resp["ResultsByTime"][0]["Groups"]:
            service = group["Keys"][0]
            amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
            if amount > 0.01:
                results.append({"service": service, "amount": amount})
    return sorted(results, key=lambda x: x["amount"], reverse=True)
