"""Rule-based 이상 감지 — 단순하고 신뢰할 수 있는 규칙만"""
import json
from datetime import datetime, timezone
from store.memory import (
    get_cost_snapshots, get_baseline, set_baseline,
    get_latest_resource_ids, get_previous_resource_ids,
    save_alert,
)
from config import config


# ── 비용 이상 감지 ─────────────────────────────────────────────────────────────

def detect_cost_spike(hourly_costs: list[dict]) -> list[dict]:
    """
    최근 1시간 비용이 직전 7일 동일 시간대 평균의 N% 초과 시 알림
    """
    if len(hourly_costs) < 2:
        return []

    alerts = []
    recent = hourly_costs[-1]["amount"]

    # 직전 24시간 평균을 베이스라인으로 사용
    baseline_amounts = [h["amount"] for h in hourly_costs[:-1]]
    if not baseline_amounts:
        return []

    baseline_avg = sum(baseline_amounts) / len(baseline_amounts)
    if baseline_avg < 0.01:  # 거의 0이면 스킵
        return []

    spike_pct = ((recent - baseline_avg) / baseline_avg) * 100

    if spike_pct >= config.cost_spike_pct:
        alert_id = save_alert(
            alert_type="cost_spike",
            severity="critical" if spike_pct >= 100 else "warning",
            title=f"비용 급증 감지 (+{spike_pct:.0f}%)",
            detail=(
                f"최근 1시간 비용 ${recent:.2f}이 "
                f"직전 평균 ${baseline_avg:.2f} 대비 {spike_pct:.0f}% 증가했습니다."
            ),
            raw_data={"recent": recent, "baseline": baseline_avg, "spike_pct": spike_pct},
        )
        alerts.append({
            "id": alert_id,
            "type": "cost_spike",
            "severity": "critical" if spike_pct >= 100 else "warning",
            "spike_pct": round(spike_pct, 1),
            "recent_usd": recent,
            "baseline_usd": baseline_avg,
        })
    return alerts


# ── 신규 퍼블릭 리소스 감지 ───────────────────────────────────────────────────

def detect_new_public_ec2(current_instances: list[dict]) -> list[dict]:
    """이전에 없던 퍼블릭 IP 가진 EC2 신규 감지"""
    current_public = {
        i["instance_id"]: i
        for i in current_instances
        if i.get("public_ip")
    }
    prev_ids = get_previous_resource_ids("ec2_public")

    alerts = []
    for iid, inst in current_public.items():
        if iid not in prev_ids:
            alert_id = save_alert(
                alert_type="new_public_ec2",
                severity="warning",
                title=f"신규 퍼블릭 EC2 감지: {inst['name'] or iid}",
                detail=(
                    f"인스턴스 {iid} ({inst['instance_type']})이 "
                    f"퍼블릭 IP {inst['public_ip']}로 실행 중입니다."
                ),
                raw_data=inst,
            )
            alerts.append({"id": alert_id, "type": "new_public_ec2", "instance": inst})
    return alerts


# ── 과도한 보안그룹 감지 ──────────────────────────────────────────────────────

def detect_open_security_groups(security_groups: list[dict]) -> list[dict]:
    """0.0.0.0/0 허용 보안그룹 + 이전과 비교해서 새로 생긴 것"""
    baseline = get_baseline("open_sg_ids") or []
    baseline_set = set(baseline)

    alerts = []
    current_open_ids = []

    for sg in security_groups:
        if not sg["open_to_world"]:
            continue
        current_open_ids.append(sg["group_id"])

        # 새로 발견된 경우만 알림
        if sg["group_id"] not in baseline_set:
            # 전체 포트 개방 (port_from=None or 0, port_to=None or 65535) → critical
            all_ports_open = any(
                r.get("port_from") in (None, 0, -1) or r.get("protocol") == "-1"
                for r in sg["open_to_world"]
            )
            severity = "critical" if all_ports_open else "warning"
            alert_id = save_alert(
                alert_type="open_security_group",
                severity=severity,
                title=f"보안그룹 인터넷 개방: {sg['group_name']}",
                detail=(
                    f"보안그룹 {sg['group_id']} ({sg['group_name']})이 "
                    f"0.0.0.0/0 허용 규칙을 포함합니다. "
                    f"개방 규칙: {len(sg['open_to_world'])}개"
                ),
                raw_data=sg,
            )
            alerts.append({"id": alert_id, "type": "open_security_group", "sg": sg, "severity": severity})

    # 베이스라인 업데이트
    set_baseline("open_sg_ids", current_open_ids)
    return alerts


# ── 유휴 인스턴스 감지 ────────────────────────────────────────────────────────

def detect_idle_instances(cpu_stats: dict[str, dict], instances: list[dict]) -> list[dict]:
    """CPU 평균 N% 이하 × N시간 지속"""
    inst_map = {i["instance_id"]: i for i in instances}
    alerts = []

    for iid, stats in cpu_stats.items():
        avg = stats.get("avg")
        if avg is None or stats.get("points", 0) < 12:  # 데이터 부족 스킵
            continue
        if avg <= config.cpu_idle_pct:
            inst = inst_map.get(iid, {})
            alert_id = save_alert(
                alert_type="idle_instance",
                severity="warning",
                title=f"유휴 EC2 감지: {inst.get('name') or iid}",
                detail=(
                    f"인스턴스 {iid} ({inst.get('instance_type', '?')})의 "
                    f"{config.cpu_idle_hours}시간 CPU 평균이 {avg:.1f}%입니다. "
                    f"다운사이즈 또는 종료를 검토하세요."
                ),
                raw_data={**inst, "cpu_avg": avg, "cpu_max": stats.get("max")},
            )
            alerts.append({"id": alert_id, "type": "idle_instance", "instance_id": iid, "cpu_avg": avg})
    return alerts


# ── MFA 미설정 감지 ───────────────────────────────────────────────────────────

def detect_iam_no_mfa(users_no_mfa: list[dict]) -> list[dict]:
    baseline = get_baseline("no_mfa_users") or []
    baseline_set = set(baseline)
    alerts = []
    current = [u["username"] for u in users_no_mfa]

    for u in users_no_mfa:
        if u["username"] not in baseline_set:
            alert_id = save_alert(
                alert_type="iam_no_mfa",
                severity="warning",
                title=f"MFA 미설정 IAM 사용자: {u['username']}",
                detail=f"사용자 {u['username']}가 MFA 없이 콘솔 접근 가능합니다.",
                raw_data=u,
            )
            alerts.append({"id": alert_id, "type": "iam_no_mfa", "user": u})

    set_baseline("no_mfa_users", current)
    return alerts


# ── 태그 누락 감지 ────────────────────────────────────────────────────────────

REQUIRED_TAGS = ["Name", "Env", "Owner"]


def detect_missing_tags(instances: list[dict]) -> list[dict]:
    alerts = []
    for inst in instances:
        missing = [t for t in REQUIRED_TAGS if not inst.get("tags", {}).get(t)]
        if missing:
            alert_id = save_alert(
                alert_type="missing_tags",
                severity="info",
                title=f"태그 누락: {inst.get('name') or inst['instance_id']}",
                detail=f"필수 태그 {missing} 누락. 비용 배분 및 거버넌스에 영향을 줍니다.",
                raw_data={**inst, "missing_tags": missing},
            )
            alerts.append({"id": alert_id, "type": "missing_tags", "instance_id": inst["instance_id"], "missing": missing})
    return alerts
