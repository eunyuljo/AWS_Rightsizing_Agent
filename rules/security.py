"""
보안 룰 — CIS AWS Foundations Benchmark + ISMS-P

CIS 매핑:  https://www.cisecurity.org/benchmark/amazon_web_services
ISMS-P 매핑: 정보보호 및 개인정보보호 관리체계 인증기준 (KISA)
"""
import boto3
from datetime import datetime, timezone, timedelta
from config import config
from rules.base import Violation, Severity, Framework


def _ec2():
    return boto3.client("ec2", region_name=config.aws_region,
                        aws_access_key_id=config.aws_access_key_id,
                        aws_secret_access_key=config.aws_secret_access_key,
                        aws_session_token=config.aws_session_token)

def _iam():
    return boto3.client("iam",
                        aws_access_key_id=config.aws_access_key_id,
                        aws_secret_access_key=config.aws_secret_access_key,
                        aws_session_token=config.aws_session_token)

def _s3():
    return boto3.client("s3",
                        aws_access_key_id=config.aws_access_key_id,
                        aws_secret_access_key=config.aws_secret_access_key,
                        aws_session_token=config.aws_session_token)

def _rds():
    return boto3.client("rds", region_name=config.aws_region,
                        aws_access_key_id=config.aws_access_key_id,
                        aws_secret_access_key=config.aws_secret_access_key,
                        aws_session_token=config.aws_session_token)

def _ct():
    return boto3.client("cloudtrail", region_name=config.aws_region,
                        aws_access_key_id=config.aws_access_key_id,
                        aws_secret_access_key=config.aws_secret_access_key,
                        aws_session_token=config.aws_session_token)

def _cw():
    return boto3.client("cloudwatch", region_name=config.aws_region,
                        aws_access_key_id=config.aws_access_key_id,
                        aws_secret_access_key=config.aws_secret_access_key,
                        aws_session_token=config.aws_session_token)


# ── IAM ───────────────────────────────────────────────────────────────────────

def check_root_mfa() -> list[Violation]:
    """
    CIS 1.5 / ISMS-P 2.6.2
    루트 계정 MFA 활성화 여부
    """
    violations = []
    summary = _iam().get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) == 0:
        violations.append(Violation(
            rule_id="CIS-1.5 / ISMS-P-2.6.2",
            framework=Framework.ISMS_P,
            category="security",
            title="루트 계정 MFA 미설정",
            severity=Severity.CRITICAL,
            resource_id="root",
            resource_type="IAM/Root",
            detail="루트 계정에 MFA(다단계 인증)가 설정되어 있지 않습니다. 비밀번호 유출 시 계정 전체가 탈취될 수 있습니다.",
            remediation="AWS 콘솔 → 우측 상단 계정명 → 보안 자격증명 → MFA 활성화",
        ))
    return violations


def check_root_access_key() -> list[Violation]:
    """
    CIS 1.4 / ISMS-P 2.6.2
    루트 계정 Access Key 존재 여부
    """
    violations = []
    summary = _iam().get_account_summary()["SummaryMap"]
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        violations.append(Violation(
            rule_id="CIS-1.4 / ISMS-P-2.6.2",
            framework=Framework.ISMS_P,
            category="security",
            title="루트 계정 Access Key 존재",
            severity=Severity.CRITICAL,
            resource_id="root",
            resource_type="IAM/Root",
            detail="루트 계정에 Access Key가 발급되어 있습니다. 유출 시 모든 AWS 리소스에 접근 가능합니다.",
            remediation="IAM 콘솔 → 보안 자격증명 → Access Key 삭제. 루트 계정 키는 어떤 용도로도 사용하지 않아야 합니다.",
        ))
    return violations


def check_iam_mfa() -> list[Violation]:
    """
    CIS 1.10 / ISMS-P 2.6.2
    콘솔 접근 가능 IAM 사용자 MFA 미설정
    """
    violations = []
    iam = _iam()
    users = iam.list_users()["Users"]
    for user in users:
        # 콘솔 로그인 프로필 없으면 스킵 (프로그래밍 방식 전용)
        try:
            iam.get_login_profile(UserName=user["UserName"])
        except iam.exceptions.NoSuchEntityException:
            continue

        mfa = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
        if not mfa:
            violations.append(Violation(
                rule_id="CIS-1.10 / ISMS-P-2.6.2",
                framework=Framework.ISMS_P,
                category="security",
                title=f"IAM 사용자 MFA 미설정: {user['UserName']}",
                severity=Severity.HIGH,
                resource_id=user["UserName"],
                resource_type="IAM/User",
                detail=f"사용자 {user['UserName']}가 MFA 없이 AWS 콘솔에 로그인할 수 있습니다.",
                remediation=f"IAM 콘솔 → 사용자 {user['UserName']} → 보안 자격증명 → MFA 디바이스 할당",
            ))
    return violations


def check_access_key_rotation() -> list[Violation]:
    """
    CIS 1.14 / ISMS-P 2.6.2
    90일 이상 미갱신 Access Key
    """
    violations = []
    iam = _iam()
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)

    for user in iam.list_users()["Users"]:
        keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
        for key in keys:
            if key["Status"] != "Active":
                continue
            age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
            if key["CreateDate"] < cutoff:
                violations.append(Violation(
                    rule_id="CIS-1.14 / ISMS-P-2.6.2",
                    framework=Framework.ISMS_P,
                    category="security",
                    title=f"Access Key 장기 미교체: {user['UserName']}",
                    severity=Severity.HIGH,
                    resource_id=key["AccessKeyId"],
                    resource_type="IAM/AccessKey",
                    detail=f"사용자 {user['UserName']}의 Access Key가 {age_days}일째 교체되지 않았습니다.",
                    remediation=f"IAM 콘솔 → 사용자 {user['UserName']} → 보안 자격증명 → 새 키 발급 후 기존 키 비활성화",
                    raw={"age_days": age_days},
                ))
    return violations


def check_iam_password_policy() -> list[Violation]:
    """
    CIS 1.8~1.11 / ISMS-P 2.5.4
    IAM 패스워드 정책 미흡
    """
    violations = []
    try:
        policy = _iam().get_account_password_policy()["PasswordPolicy"]
    except Exception:
        violations.append(Violation(
            rule_id="CIS-1.8 / ISMS-P-2.5.4",
            framework=Framework.ISMS_P,
            category="security",
            title="IAM 패스워드 정책 미설정",
            severity=Severity.HIGH,
            resource_id="account",
            resource_type="IAM/PasswordPolicy",
            detail="계정 수준의 패스워드 정책이 설정되어 있지 않습니다. 취약한 비밀번호 사용이 허용됩니다.",
            remediation="IAM 콘솔 → 계정 설정 → 패스워드 정책: 최소 14자, 대소문자+숫자+특수문자, 90일 만료 설정",
        ))
        return violations

    issues = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        issues.append(f"최소 길이 {policy.get('MinimumPasswordLength')}자 (권고: 14자 이상)")
    if not policy.get("RequireUppercaseCharacters"):
        issues.append("대문자 미요구")
    if not policy.get("RequireNumbers"):
        issues.append("숫자 미요구")
    if not policy.get("RequireSymbols"):
        issues.append("특수문자 미요구")
    if not policy.get("MaxPasswordAge") or policy.get("MaxPasswordAge", 999) > 90:
        issues.append("비밀번호 만료 기간 미설정 또는 90일 초과")

    if issues:
        violations.append(Violation(
            rule_id="CIS-1.8~1.11 / ISMS-P-2.5.4",
            framework=Framework.ISMS_P,
            category="security",
            title="IAM 패스워드 정책 미흡",
            severity=Severity.MEDIUM,
            resource_id="account",
            resource_type="IAM/PasswordPolicy",
            detail=f"패스워드 정책이 기준에 미달합니다: {', '.join(issues)}",
            remediation="IAM 콘솔 → 계정 설정 → 패스워드 정책 강화",
        ))
    return violations


# ── 네트워크 보안 ─────────────────────────────────────────────────────────────

def check_sg_ssh_open() -> list[Violation]:
    """
    CIS 5.2 / ISMS-P 2.6.1
    SSH 포트(22) 인터넷 개방
    """
    violations = []
    sgs = _ec2().describe_security_groups()["SecurityGroups"]
    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            port_from = rule.get("FromPort", 0)
            port_to = rule.get("ToPort", 65535)
            proto = rule.get("IpProtocol", "")
            if proto == "-1" or (port_from <= 22 <= port_to):
                for ipv4 in rule.get("IpRanges", []):
                    if ipv4.get("CidrIp") == "0.0.0.0/0":
                        violations.append(Violation(
                            rule_id="CIS-5.2 / ISMS-P-2.6.1",
                            framework=Framework.ISMS_P,
                            category="security",
                            title=f"SSH 포트 인터넷 개방: {sg['GroupName']}",
                            severity=Severity.CRITICAL,
                            resource_id=sg["GroupId"],
                            resource_type="EC2/SecurityGroup",
                            detail=f"보안그룹 {sg['GroupId']} ({sg['GroupName']})이 전체 인터넷(0.0.0.0/0)에서 SSH(22) 접속을 허용합니다.",
                            remediation="보안그룹에서 SSH 소스 IP를 사무실/VPN IP로 제한하거나, Bastion Host + Session Manager로 대체하세요.",
                        ))
    return violations


def check_sg_rdp_open() -> list[Violation]:
    """
    CIS 5.3 / ISMS-P 2.6.1
    RDP 포트(3389) 인터넷 개방
    """
    violations = []
    sgs = _ec2().describe_security_groups()["SecurityGroups"]
    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            port_from = rule.get("FromPort", 0)
            port_to = rule.get("ToPort", 65535)
            proto = rule.get("IpProtocol", "")
            if proto == "-1" or (port_from <= 3389 <= port_to):
                for ipv4 in rule.get("IpRanges", []):
                    if ipv4.get("CidrIp") == "0.0.0.0/0":
                        violations.append(Violation(
                            rule_id="CIS-5.3 / ISMS-P-2.6.1",
                            framework=Framework.ISMS_P,
                            category="security",
                            title=f"RDP 포트 인터넷 개방: {sg['GroupName']}",
                            severity=Severity.CRITICAL,
                            resource_id=sg["GroupId"],
                            resource_type="EC2/SecurityGroup",
                            detail=f"보안그룹 {sg['GroupId']} ({sg['GroupName']})이 전체 인터넷에서 RDP(3389) 접속을 허용합니다.",
                            remediation="RDP 소스 IP를 제한하거나 AWS Systems Manager Session Manager로 교체하세요.",
                        ))
    return violations


def check_sg_all_open() -> list[Violation]:
    """
    ISMS-P 2.6.1
    모든 포트 인터넷 개방 (프로토콜 -1)
    """
    violations = []
    sgs = _ec2().describe_security_groups()["SecurityGroups"]
    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            if rule.get("IpProtocol") == "-1":
                for ipv4 in rule.get("IpRanges", []):
                    if ipv4.get("CidrIp") == "0.0.0.0/0":
                        violations.append(Violation(
                            rule_id="ISMS-P-2.6.1",
                            framework=Framework.ISMS_P,
                            category="security",
                            title=f"전체 포트 인터넷 개방: {sg['GroupName']}",
                            severity=Severity.CRITICAL,
                            resource_id=sg["GroupId"],
                            resource_type="EC2/SecurityGroup",
                            detail=f"보안그룹 {sg['GroupId']}이 모든 포트를 인터넷에 개방합니다. 즉각적인 보안 위협입니다.",
                            remediation="필요한 포트만 최소 개방하고 소스 IP를 제한하세요. 사용 중인 리소스라면 즉시 검토가 필요합니다.",
                        ))
    return violations


# ── 암호화 ────────────────────────────────────────────────────────────────────

def check_ebs_encryption() -> list[Violation]:
    """
    AWS-BP / ISMS-P 2.7.1
    EBS 볼륨 암호화 미적용
    """
    violations = []
    vols = _ec2().describe_volumes()["Volumes"]
    for v in vols:
        if not v.get("Encrypted"):
            name = next((t["Value"] for t in v.get("Tags", []) if t["Key"] == "Name"), v["VolumeId"])
            violations.append(Violation(
                rule_id="AWS-BP / ISMS-P-2.7.1",
                framework=Framework.ISMS_P,
                category="security",
                title=f"EBS 암호화 미적용: {name}",
                severity=Severity.HIGH,
                resource_id=v["VolumeId"],
                resource_type="EC2/Volume",
                detail=f"EBS 볼륨 {v['VolumeId']} ({v['Size']}GB)이 암호화되지 않았습니다. 스토리지 탈취 시 데이터가 노출됩니다.",
                remediation="새 암호화 스냅샷으로 복원하거나, EC2 기본 설정에서 EBS 기본 암호화를 활성화하세요.",
            ))
    return violations


def check_rds_encryption() -> list[Violation]:
    """
    AWS-BP / ISMS-P 2.7.1
    RDS 암호화 미적용
    """
    violations = []
    dbs = _rds().describe_db_instances()["DBInstances"]
    for db in dbs:
        if not db.get("StorageEncrypted"):
            violations.append(Violation(
                rule_id="AWS-BP / ISMS-P-2.7.1",
                framework=Framework.ISMS_P,
                category="security",
                title=f"RDS 암호화 미적용: {db['DBInstanceIdentifier']}",
                severity=Severity.HIGH,
                resource_id=db["DBInstanceIdentifier"],
                resource_type="RDS/DBInstance",
                detail=f"RDS 인스턴스 {db['DBInstanceIdentifier']} ({db['Engine']} {db['EngineVersion']})이 암호화되지 않았습니다.",
                remediation="스냅샷 생성 → 암호화 옵션으로 복원 (RDS는 생성 후 암호화 변경 불가).",
            ))
    return violations


def check_rds_public() -> list[Violation]:
    """
    ISMS-P 2.6.4
    RDS 퍼블릭 접근 허용
    """
    violations = []
    dbs = _rds().describe_db_instances()["DBInstances"]
    for db in dbs:
        if db.get("PubliclyAccessible"):
            violations.append(Violation(
                rule_id="ISMS-P-2.6.4",
                framework=Framework.ISMS_P,
                category="security",
                title=f"RDS 퍼블릭 접근 허용: {db['DBInstanceIdentifier']}",
                severity=Severity.CRITICAL,
                resource_id=db["DBInstanceIdentifier"],
                resource_type="RDS/DBInstance",
                detail=f"데이터베이스 {db['DBInstanceIdentifier']}이 인터넷에서 직접 접근 가능합니다.",
                remediation="RDS 수정 → 퍼블릭 액세스 비활성화. 애플리케이션은 VPC 내부에서만 접근해야 합니다.",
            ))
    return violations


def check_s3_public() -> list[Violation]:
    """
    AWS-BP / ISMS-P 2.6.1
    S3 퍼블릭 버킷
    """
    violations = []
    s3 = _s3()
    buckets = s3.list_buckets()["Buckets"]
    for bucket in buckets:
        name = bucket["Name"]
        try:
            block = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all([
                block.get("BlockPublicAcls"),
                block.get("IgnorePublicAcls"),
                block.get("BlockPublicPolicy"),
                block.get("RestrictPublicBuckets"),
            ]):
                violations.append(Violation(
                    rule_id="AWS-BP / ISMS-P-2.6.1",
                    framework=Framework.ISMS_P,
                    category="security",
                    title=f"S3 퍼블릭 접근 차단 미설정: {name}",
                    severity=Severity.HIGH,
                    resource_id=name,
                    resource_type="S3/Bucket",
                    detail=f"S3 버킷 {name}의 퍼블릭 액세스 차단이 완전히 활성화되지 않았습니다.",
                    remediation="S3 콘솔 → 버킷 → 권한 → 퍼블릭 액세스 차단 4개 항목 모두 활성화",
                ))
        except Exception:
            pass
    return violations


# ── 로깅 ──────────────────────────────────────────────────────────────────────

def check_cloudtrail() -> list[Violation]:
    """
    CIS 3.1 / ISMS-P 2.9.4
    CloudTrail 미활성화 또는 멀티리전 미설정
    """
    violations = []
    trails = _ct().describe_trails(includeShadowTrails=False).get("trailList", [])

    if not trails:
        violations.append(Violation(
            rule_id="CIS-3.1 / ISMS-P-2.9.4",
            framework=Framework.ISMS_P,
            category="security",
            title="CloudTrail 미활성화",
            severity=Severity.CRITICAL,
            resource_id="account",
            resource_type="CloudTrail",
            detail="CloudTrail이 설정되어 있지 않습니다. AWS 계정의 모든 API 활동이 기록되지 않아 감사 추적이 불가능합니다.",
            remediation="CloudTrail 콘솔 → 추적 생성 → 모든 리전 적용, S3 로그 저장 활성화",
        ))
        return violations

    multi_region = any(t.get("IsMultiRegionTrail") for t in trails)
    if not multi_region:
        violations.append(Violation(
            rule_id="CIS-3.1 / ISMS-P-2.9.4",
            framework=Framework.ISMS_P,
            category="security",
            title="CloudTrail 멀티리전 미설정",
            severity=Severity.HIGH,
            resource_id=trails[0].get("TrailARN", ""),
            resource_type="CloudTrail",
            detail="CloudTrail이 모든 리전을 커버하지 않습니다. 일부 리전의 API 활동이 기록되지 않을 수 있습니다.",
            remediation="CloudTrail → 추적 수정 → '모든 리전에 적용' 활성화",
        ))
    return violations


def check_cloudwatch_alarms() -> list[Violation]:
    """
    ISMS-P 2.11.1
    CloudWatch 알람 미설정 (기본 모니터링 부재)
    """
    violations = []
    alarms = _cw().describe_alarms()["MetricAlarms"]
    if len(alarms) == 0:
        violations.append(Violation(
            rule_id="ISMS-P-2.11.1",
            framework=Framework.ISMS_P,
            category="security",
            title="CloudWatch 알람 미설정",
            severity=Severity.MEDIUM,
            resource_id="account",
            resource_type="CloudWatch",
            detail="CloudWatch 알람이 하나도 설정되어 있지 않습니다. 장애, 보안 이벤트 발생 시 즉각적인 인지가 어렵습니다.",
            remediation="CloudWatch → 알람 생성: CPU, 비용 이상, 루트 로그인 이벤트 등 최소한의 알람을 설정하세요.",
        ))
    return violations


# ── 전체 보안 룰 실행 ─────────────────────────────────────────────────────────

SECURITY_RULES = [
    check_root_mfa,
    check_root_access_key,
    check_iam_mfa,
    check_access_key_rotation,
    check_iam_password_policy,
    check_sg_ssh_open,
    check_sg_rdp_open,
    check_sg_all_open,
    check_ebs_encryption,
    check_rds_encryption,
    check_rds_public,
    check_s3_public,
    check_cloudtrail,
    check_cloudwatch_alarms,
]
