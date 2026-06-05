"""
비용 최적화 룰 — AWS Well-Architected Cost Optimization Pillar

낭비 리소스 및 rightsizing 필요 항목 감지
"""
import boto3
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from config import config
from rules.base import Violation, Severity, Framework


def _ec2():
    return boto3.client("ec2", region_name=config.aws_region,
                        aws_access_key_id=config.aws_access_key_id,
                        aws_secret_access_key=config.aws_secret_access_key,
                        aws_session_token=config.aws_session_token)

def _cw():
    return boto3.client("cloudwatch", region_name=config.aws_region,
                        aws_access_key_id=config.aws_access_key_id,
                        aws_secret_access_key=config.aws_secret_access_key,
                        aws_session_token=config.aws_session_token)

def _elb():
    return boto3.client("elbv2", region_name=config.aws_region,
                        aws_access_key_id=config.aws_access_key_id,
                        aws_secret_access_key=config.aws_secret_access_key,
                        aws_session_token=config.aws_session_token)


def _get_pricing() -> dict:
    pricing_file = Path(__file__).parent.parent / "ec2_pricing.json"
    if pricing_file.exists():
        with open(pricing_file) as f:
            return json.load(f)
    return {}


def _estimate_monthly(instance_type: str) -> float | None:
    pricing = _get_pricing()
    parts = instance_type.split(".")
    if len(parts) != 2:
        return None
    family, size = parts[0], parts[1]
    hourly = pricing.get(family, {}).get(size)
    return round(hourly * 720, 2) if hourly else None


def check_unattached_ebs() -> list[Violation]:
    """미연결 EBS 볼륨 (비용 낭비)"""
    violations = []
    vols = _ec2().describe_volumes(
        Filters=[{"Name": "status", "Values": ["available"]}]
    )["Volumes"]

    for v in vols:
        age_days = (datetime.now(timezone.utc) - v["CreateTime"]).days
        name = next((t["Value"] for t in v.get("Tags", []) if t["Key"] == "Name"), v["VolumeId"])
        monthly_cost = round(v["Size"] * 0.08, 2)  # gp2 기준 $0.08/GB

        violations.append(Violation(
            rule_id="AWS-BP/Cost",
            framework=Framework.AWS_BP,
            category="cost",
            title=f"미연결 EBS 볼륨: {name}",
            severity=Severity.MEDIUM,
            resource_id=v["VolumeId"],
            resource_type="EC2/Volume",
            detail=(
                f"EBS 볼륨 {v['VolumeId']} ({v['Size']}GB, {v['VolumeType']})이 "
                f"{age_days}일째 어떤 인스턴스에도 연결되지 않았습니다. "
                f"예상 낭비 비용: ${monthly_cost}/월"
            ),
            remediation="사용 중인 볼륨인지 확인 후 스냅샷 생성 → 삭제하세요. 필요하다면 인스턴스에 연결하세요.",
            raw={"size_gb": v["Size"], "monthly_cost": monthly_cost, "age_days": age_days},
        ))
    return violations


def check_unassociated_eip() -> list[Violation]:
    """미할당 Elastic IP (월 $3.6 낭비)"""
    violations = []
    addrs = _ec2().describe_addresses()["Addresses"]
    for a in addrs:
        if "AssociationId" not in a:
            violations.append(Violation(
                rule_id="AWS-BP/Cost",
                framework=Framework.AWS_BP,
                category="cost",
                title=f"미할당 Elastic IP: {a['PublicIp']}",
                severity=Severity.LOW,
                resource_id=a.get("AllocationId", a["PublicIp"]),
                resource_type="EC2/ElasticIP",
                detail=f"Elastic IP {a['PublicIp']}가 어떤 리소스에도 연결되지 않아 월 $3.6의 비용이 발생합니다.",
                remediation="EC2 콘솔 → Elastic IP → 릴리스. 필요하다면 인스턴스 또는 NAT Gateway에 연결하세요.",
            ))
    return violations


def check_idle_ec2() -> list[Violation]:
    """
    30일 CPU 평균 5% 이하 유휴 EC2
    CloudWatch get_metric_statistics 사용
    """
    violations = []
    ec2 = _ec2()
    cw = _cw()

    resp = ec2.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    )
    instances = [
        i for r in resp["Reservations"] for i in r["Instances"]
    ]

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=30)

    for inst in instances:
        iid = inst["InstanceId"]
        name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), iid)
        env = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Env"), "")

        stats = cw.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": iid}],
            StartTime=start,
            EndTime=end,
            Period=86400,
            Statistics=["Average"],
        )["Datapoints"]

        if not stats or len(stats) < 7:  # 데이터 부족 스킵
            continue

        avg_cpu = sum(p["Average"] for p in stats) / len(stats)

        if avg_cpu <= 5.0:
            monthly = _estimate_monthly(inst["InstanceType"])
            cost_str = f"${monthly}/월" if monthly else "비용 미확인"
            violations.append(Violation(
                rule_id="AWS-BP/Cost",
                framework=Framework.AWS_BP,
                category="cost",
                title=f"유휴 EC2: {name} (CPU {avg_cpu:.1f}%)",
                severity=Severity.HIGH if (monthly or 0) > 100 else Severity.MEDIUM,
                resource_id=iid,
                resource_type="EC2/Instance",
                detail=(
                    f"인스턴스 {iid} ({inst['InstanceType']})의 30일 평균 CPU가 {avg_cpu:.1f}%입니다. "
                    f"현재 비용: {cost_str}. 다운사이즈 또는 종료를 검토하세요."
                ),
                remediation="용도 확인 후 불필요하면 종료, 필요하면 더 작은 인스턴스 타입으로 변경하세요.",
                raw={"cpu_avg": round(avg_cpu, 2), "instance_type": inst["InstanceType"], "monthly_cost": monthly},
            ))
    return violations


def check_unused_elb() -> list[Violation]:
    """타겟이 없거나 healthy 타겟 0개인 로드밸런서"""
    violations = []
    elb = _elb()
    lbs = elb.describe_load_balancers()["LoadBalancers"]

    for lb in lbs:
        tgs = elb.describe_target_groups(LoadBalancerArn=lb["LoadBalancerArn"])["TargetGroups"]
        healthy = 0
        for tg in tgs:
            health = elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
            healthy += sum(
                1 for t in health["TargetHealthDescriptions"]
                if t["TargetHealth"]["State"] == "healthy"
            )

        if healthy == 0:
            violations.append(Violation(
                rule_id="AWS-BP/Cost",
                framework=Framework.AWS_BP,
                category="cost",
                title=f"Healthy 타겟 없는 로드밸런서: {lb['LoadBalancerName']}",
                severity=Severity.MEDIUM,
                resource_id=lb["LoadBalancerArn"],
                resource_type="ELB/LoadBalancer",
                detail=(
                    f"로드밸런서 {lb['LoadBalancerName']}에 Healthy 상태의 타겟이 없습니다. "
                    "비용만 발생하고 트래픽을 처리하지 않는 상태입니다."
                ),
                remediation="타겟 그룹에 정상 인스턴스를 등록하거나, 불필요한 경우 로드밸런서를 삭제하세요.",
            ))
    return violations


def check_old_snapshots() -> list[Violation]:
    """90일 이상 된 수동 스냅샷"""
    violations = []
    ec2 = _ec2()
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)

    snaps = ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]
    old = [s for s in snaps if s["StartTime"] < cutoff]

    if len(old) > 5:  # 5개 이상일 때만 알림
        total_gb = sum(s["VolumeSize"] for s in old)
        monthly_cost = round(total_gb * 0.05, 2)  # $0.05/GB
        violations.append(Violation(
            rule_id="AWS-BP/Cost",
            framework=Framework.AWS_BP,
            category="cost",
            title=f"오래된 스냅샷 {len(old)}개 ({total_gb}GB)",
            severity=Severity.LOW,
            resource_id="snapshots",
            resource_type="EC2/Snapshot",
            detail=(
                f"90일 이상 된 수동 스냅샷이 {len(old)}개 ({total_gb}GB) 있습니다. "
                f"예상 월 비용: ${monthly_cost}"
            ),
            remediation="사용하지 않는 오래된 스냅샷을 정리하거나, DLM 정책으로 자동 만료를 설정하세요.",
            raw={"count": len(old), "total_gb": total_gb, "monthly_cost": monthly_cost},
        ))
    return violations


COST_RULES = [
    check_unattached_ebs,
    check_unassociated_eip,
    check_idle_ec2,
    check_unused_elb,
    check_old_snapshots,
]
