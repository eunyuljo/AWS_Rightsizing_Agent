"""주기적 수집 + 감지 + 알림 스케줄러"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from rules.engine import run_category, run_all
from explainer.llm import explain_violation, explain_violations_summary
from notifier.slack import send_violation, send_daily_summary
from store.memory import (
    save_alert, get_recent_alerts,
)
from config import config

log = logging.getLogger(__name__)


def _save_and_notify(violations: list[dict]):
    """위반 항목을 DB 저장 + Slack 전송"""
    for v in violations:
        try:
            alert_id = save_alert(
                alert_type=v["rule_id"],
                title=v["title"],
                severity=v["severity"],
                detail=v["detail"],
                resource_id=v.get("resource_id", ""),
            )
            explanation = explain_violation(v)
            send_violation(v, explanation)
        except Exception as e:
            log.error(f"알림 처리 실패 ({v.get('title')}): {e}")


def run_security_check():
    """CIS + ISMS-P 보안 룰 전체 점검"""
    log.info("보안 룰 점검 시작")
    try:
        result = run_category("security")
        violations = [v.to_dict() for v in result]
        _save_and_notify(violations)
        log.info(f"보안 점검 완료: {len(violations)}건")
    except Exception as e:
        log.error(f"보안 점검 실패: {e}")


def run_reliability_check():
    """안정성 룰 점검"""
    log.info("안정성 룰 점검 시작")
    try:
        result = run_category("reliability")
        violations = [v.to_dict() for v in result]
        _save_and_notify(violations)
        log.info(f"안정성 점검 완료: {len(violations)}건")
    except Exception as e:
        log.error(f"안정성 점검 실패: {e}")


def run_cost_check():
    """비용 최적화 룰 점검"""
    log.info("비용 룰 점검 시작")
    try:
        result = run_category("cost")
        violations = [v.to_dict() for v in result]
        _save_and_notify(violations)
        log.info(f"비용 점검 완료: {len(violations)}건")
    except Exception as e:
        log.error(f"비용 점검 실패: {e}")


def run_full_scan():
    """전체 룰 일괄 실행 (수동 트리거용)"""
    log.info("전체 룰 스캔 시작")
    try:
        result = run_all()
        _save_and_notify(result["violations"])
        log.info(
            f"전체 스캔 완료: {result['summary']['total']}건 "
            f"(critical={result['summary']['critical']}, "
            f"high={result['summary']['high']})"
        )
        return result
    except Exception as e:
        log.error(f"전체 스캔 실패: {e}")
        return {"violations": [], "summary": {}, "errors": [str(e)]}


def run_daily_summary():
    """하루 요약 슬랙 전송"""
    log.info("일일 요약 생성")
    try:
        alerts = get_recent_alerts(hours=24)
        if not alerts:
            return
        summary = explain_violations_summary(alerts)
        send_daily_summary(alerts, summary)
    except Exception as e:
        log.error(f"일일 요약 실패: {e}")


def start_scheduler() -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="Asia/Seoul")

    scheduler.add_job(
        run_cost_check,
        IntervalTrigger(seconds=config.collect_interval),
        id="cost_check",
    )
    scheduler.add_job(
        run_reliability_check,
        IntervalTrigger(seconds=config.collect_interval),
        id="reliability_check",
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
