"""주기적 수집 + 감지 + 알림 스케줄러"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from collector.cost import get_hourly_cost
from collector.resources import (
    list_running_ec2, list_security_groups,
    list_rds_instances, list_iam_users_no_mfa,
)
from collector.metrics import get_all_ec2_cpu
from detector.rules import (
    detect_cost_spike, detect_new_public_ec2,
    detect_open_security_groups, detect_idle_instances,
    detect_iam_no_mfa, detect_missing_tags,
)
from explainer.llm import explain_alert, explain_alerts_summary
from notifier.slack import send_alert, send_daily_summary
from store.memory import (
    save_cost_snapshot, save_resource_snapshot,
    get_unnotified_alerts, mark_notified, get_recent_alerts,
)
from config import config

log = logging.getLogger(__name__)


def run_cost_check():
    """비용 수집 + 이상 감지"""
    log.info("비용 수집 시작")
    try:
        hourly = get_hourly_cost(hours=48)
        for h in hourly:
            save_cost_snapshot("total", h["amount"])

        alerts = detect_cost_spike(hourly)
        _notify_alerts(alerts)
    except Exception as e:
        log.error(f"비용 수집 실패: {e}")


def run_resource_check():
    """리소스 수집 + 보안/유휴/태그 감지"""
    log.info("리소스 수집 시작")
    try:
        instances = list_running_ec2()
        for inst in instances:
            save_resource_snapshot(inst["instance_id"], "ec2", inst)
            if inst.get("public_ip"):
                save_resource_snapshot(inst["instance_id"], "ec2_public", inst)

        sgs = list_security_groups()

        # CPU 수집 (유휴 감지용)
        iids = [i["instance_id"] for i in instances]
        cpu_stats = get_all_ec2_cpu(iids, hours=config.cpu_idle_hours) if iids else {}

        # 감지
        alerts = []
        alerts += detect_new_public_ec2(instances)
        alerts += detect_open_security_groups(sgs)
        alerts += detect_idle_instances(cpu_stats, instances)
        alerts += detect_missing_tags(instances)

        _notify_alerts(alerts)
    except Exception as e:
        log.error(f"리소스 수집 실패: {e}")


def run_security_check():
    """IAM 보안 점검"""
    log.info("IAM 보안 점검 시작")
    try:
        no_mfa = list_iam_users_no_mfa()
        alerts = detect_iam_no_mfa(no_mfa)
        _notify_alerts(alerts)
    except Exception as e:
        log.error(f"IAM 점검 실패: {e}")


def run_daily_summary():
    """하루 요약 슬랙 전송"""
    log.info("일일 요약 생성")
    try:
        alerts = get_recent_alerts(hours=24)
        if not alerts:
            return
        summary = explain_alerts_summary(alerts)
        send_daily_summary(alerts, summary)
    except Exception as e:
        log.error(f"일일 요약 실패: {e}")


def _notify_alerts(alerts: list[dict]):
    """새 알림을 LLM 설명 + 슬랙 전송"""
    for alert in alerts:
        try:
            explanation = explain_alert(alert)
            send_alert(alert, explanation)
            mark_notified(alert["id"])
        except Exception as e:
            log.error(f"알림 전송 실패 (id={alert.get('id')}): {e}")


def start_scheduler() -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="Asia/Seoul")

    scheduler.add_job(
        run_cost_check,
        IntervalTrigger(seconds=config.collect_interval),
        id="cost_check",
        next_run_time=None,  # 즉시 실행 원하면 제거
    )
    scheduler.add_job(
        run_resource_check,
        IntervalTrigger(seconds=config.collect_interval),
        id="resource_check",
    )
    scheduler.add_job(
        run_security_check,
        IntervalTrigger(seconds=config.security_interval),
        id="security_check",
    )
    scheduler.add_job(
        run_daily_summary,
        "cron",
        hour=9,
        minute=0,
        id="daily_summary",
    )

    scheduler.start()
    log.info("스케줄러 시작")
    return scheduler
