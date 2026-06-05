"""
안정성 룰 — AWS Well-Architected Reliability Pillar + ISMS-P 2.11

백업, 고가용성, 단일 장애점(SPOF) 검사
"""
import boto3
from config import config
from rules.base import Violation, Severity, Framework


def _rds():
    return boto3.client("rds", region_name=config.aws_region,
                        aws_access_key_id=config.aws_access_key_id,
                        aws_secret_access_key=config.aws_secret_access_key,
                        aws_session_token=config.aws_session_token)

def _ec2():
    return boto3.client("ec2", region_name=config.aws_region,
                        aws_access_key_id=config.aws_access_key_id,
                        aws_secret_access_key=config.aws_secret_access_key,
                        aws_session_token=config.aws_session_token)

def _elb():
    return boto3.client("elbv2", region_name=config.aws_region,
                        aws_access_key_id=config.aws_access_key_id,
                        aws_secret_access_key=config.aws_secret_access_key,
                        aws_session_token=config.aws_session_token)


def check_rds_multi_az() -> list[Violation]:
    """
    AWS-BP / ISMS-P 2.11.1
    RDS Multi-AZ 미설정 (단일 AZ → 장애 시 다운타임)
    """
    violations = []
    dbs = _rds().describe_db_instances()["DBInstances"]
    for db in dbs:
        if db.get("DBInstanceStatus") != "available":
            continue
        if not db.get("MultiAZ"):
            violations.append(Violation(
                rule_id="AWS-BP / ISMS-P-2.11.1",
                framework=Framework.AWS_BP,
                category="reliability",
                title=f"RDS Multi-AZ 미설정: {db['DBInstanceIdentifier']}",
                severity=Severity.HIGH,
                resource_id=db["DBInstanceIdentifier"],
                resource_type="RDS/DBInstance",
                detail=(
                    f"데이터베이스 {db['DBInstanceIdentifier']} ({db['Engine']})이 단일 가용영역으로 운영 중입니다. "
                    "하드웨어 장애 또는 AZ 장애 시 수분~수십분의 다운타임이 발생합니다."
                ),
                remediation="RDS 콘솔 → 인스턴스 수정 → 다중 AZ 배포 활성화 (운영 중 변경 가능, 재시작 발생)",
            ))
    return violations


def check_rds_backup() -> list[Violation]:
    """
    AWS-BP / ISMS-P 2.11.1
    RDS 자동 백업 미설정 (보존 기간 0일)
    """
    violations = []
    dbs = _rds().describe_db_instances()["DBInstances"]
    for db in dbs:
        retention = db.get("BackupRetentionPeriod", 0)
        if retention == 0:
            violations.append(Violation(
                rule_id="AWS-BP / ISMS-P-2.11.1",
                framework=Framework.AWS_BP,
                category="reliability",
                title=f"RDS 자동 백업 비활성화: {db['DBInstanceIdentifier']}",
                severity=Severity.CRITICAL,
                resource_id=db["DBInstanceIdentifier"],
                resource_type="RDS/DBInstance",
                detail=(
                    f"데이터베이스 {db['DBInstanceIdentifier']}의 자동 백업이 비활성화되어 있습니다. "
                    "데이터 손실 발생 시 복구가 불가능합니다."
                ),
                remediation="RDS 콘솔 → 인스턴스 수정 → 백업 보존 기간을 최소 7일 이상으로 설정",
            ))
        elif retention < 7:
            violations.append(Violation(
                rule_id="AWS-BP / ISMS-P-2.11.1",
                framework=Framework.AWS_BP,
                category="reliability",
                title=f"RDS 백업 보존 기간 부족: {db['DBInstanceIdentifier']}",
                severity=Severity.MEDIUM,
                resource_id=db["DBInstanceIdentifier"],
                resource_type="RDS/DBInstance",
                detail=f"데이터베이스 {db['DBInstanceIdentifier']}의 백업 보존 기간이 {retention}일입니다. 최소 7일 권고.",
                remediation="RDS 콘솔 → 인스턴스 수정 → 백업 보존 기간 7일 이상으로 수정",
            ))
    return violations


def check_ec2_single_az() -> list[Violation]:
    """
    AWS-BP
    로드밸런서 없이 단일 인스턴스로 운영 중인 EC2 (SPOF)
    """
    violations = []

    # ELB 타겟 그룹에 등록된 인스턴스 수집
    elb_instance_ids = set()
    try:
        tgs = _elb().describe_target_groups()["TargetGroups"]
        for tg in tgs:
            health = _elb().describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
            for t in health["TargetHealthDescriptions"]:
                elb_instance_ids.add(t["Target"]["Id"])
    except Exception:
        pass

    resp = _ec2().describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    )
    for r in resp["Reservations"]:
        for i in r["Instances"]:
            iid = i["InstanceId"]
            name = next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), iid)
            env = next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Env"), "")

            # dev/staging 환경은 스킵
            if env.lower() in ("dev", "staging", "test"):
                continue

            if iid not in elb_instance_ids and i.get("PublicIpAddress"):
                violations.append(Violation(
                    rule_id="AWS-BP",
                    framework=Framework.AWS_BP,
                    category="reliability",
                    title=f"로드밸런서 없는 단독 EC2: {name}",
                    severity=Severity.MEDIUM,
                    resource_id=iid,
                    resource_type="EC2/Instance",
                    detail=(
                        f"인스턴스 {iid} ({name})이 로드밸런서 없이 직접 노출되어 있습니다. "
                        "장애 시 자동 복구가 되지 않습니다."
                    ),
                    remediation="ALB + Auto Scaling Group 구성으로 고가용성을 확보하거나, 최소 인스턴스 수를 2개 이상으로 유지하세요.",
                ))
    return violations


def check_ebs_snapshot() -> list[Violation]:
    """
    AWS-BP
    최근 30일 내 스냅샷 없는 EBS 볼륨
    """
    violations = []
    ec2 = _ec2()
    vols = ec2.describe_volumes(
        Filters=[{"Name": "status", "Values": ["in-use"]}]
    )["Volumes"]

    for vol in vols:
        snaps = ec2.describe_snapshots(
            Filters=[{"Name": "volume-id", "Values": [vol["VolumeId"]]}],
            OwnerIds=["self"],
        )["Snapshots"]

        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        recent = [s for s in snaps if s["StartTime"] > cutoff]

        if not recent:
            name = next((t["Value"] for t in vol.get("Tags", []) if t["Key"] == "Name"), vol["VolumeId"])
            violations.append(Violation(
                rule_id="AWS-BP",
                framework=Framework.AWS_BP,
                category="reliability",
                title=f"EBS 스냅샷 없음 (30일): {name}",
                severity=Severity.MEDIUM,
                resource_id=vol["VolumeId"],
                resource_type="EC2/Volume",
                detail=f"EBS 볼륨 {vol['VolumeId']} ({vol['Size']}GB)의 최근 30일 내 스냅샷이 없습니다.",
                remediation="AWS Backup 또는 Data Lifecycle Manager(DLM)로 자동 스냅샷을 설정하세요.",
            ))
    return violations


RELIABILITY_RULES = [
    check_rds_multi_az,
    check_rds_backup,
    check_ec2_single_az,
    check_ebs_snapshot,
]
