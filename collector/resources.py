"""EC2, RDS, 보안그룹 등 리소스 현황 수집"""
import boto3
import json
from config import config


def _ec2():
    return boto3.client(
        "ec2",
        region_name=config.aws_region,
        aws_access_key_id=config.aws_access_key_id,
        aws_secret_access_key=config.aws_secret_access_key,
        aws_session_token=config.aws_session_token,
    )


def _rds():
    return boto3.client(
        "rds",
        region_name=config.aws_region,
        aws_access_key_id=config.aws_access_key_id,
        aws_secret_access_key=config.aws_secret_access_key,
        aws_session_token=config.aws_session_token,
    )


def _iam():
    return boto3.client(
        "iam",
        aws_access_key_id=config.aws_access_key_id,
        aws_secret_access_key=config.aws_secret_access_key,
        aws_session_token=config.aws_session_token,
    )


def _tag(tags: list, key: str) -> str:
    for t in (tags or []):
        if t["Key"] == key:
            return t["Value"]
    return ""


def list_running_ec2() -> list[dict]:
    resp = _ec2().describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    )
    instances = []
    for r in resp["Reservations"]:
        for i in r["Instances"]:
            instances.append({
                "instance_id": i["InstanceId"],
                "instance_type": i["InstanceType"],
                "name": _tag(i.get("Tags", []), "Name"),
                "public_ip": i.get("PublicIpAddress"),
                "private_ip": i.get("PrivateIpAddress"),
                "launch_time": i["LaunchTime"].isoformat(),
                "subnet_id": i.get("SubnetId"),
                "vpc_id": i.get("VpcId"),
                "security_groups": [sg["GroupId"] for sg in i.get("SecurityGroups", [])],
                "tags": {t["Key"]: t["Value"] for t in i.get("Tags", [])},
            })
    return instances


def list_security_groups() -> list[dict]:
    resp = _ec2().describe_security_groups()
    groups = []
    for sg in resp["SecurityGroups"]:
        open_ingress = []
        for rule in sg.get("IpPermissions", []):
            for ipv4 in rule.get("IpRanges", []):
                if ipv4.get("CidrIp") == "0.0.0.0/0":
                    open_ingress.append({
                        "port_from": rule.get("FromPort"),
                        "port_to": rule.get("ToPort"),
                        "protocol": rule.get("IpProtocol"),
                    })
        groups.append({
            "group_id": sg["GroupId"],
            "group_name": sg["GroupName"],
            "vpc_id": sg.get("VpcId"),
            "open_to_world": open_ingress,
            "description": sg.get("Description", ""),
        })
    return groups


def list_rds_instances() -> list[dict]:
    resp = _rds().describe_db_instances()
    instances = []
    for db in resp["DBInstances"]:
        instances.append({
            "identifier": db["DBInstanceIdentifier"],
            "engine": db["Engine"],
            "engine_version": db["EngineVersion"],
            "instance_class": db["DBInstanceClass"],
            "status": db["DBInstanceStatus"],
            "multi_az": db["MultiAZ"],
            "storage_encrypted": db["StorageEncrypted"],
            "publicly_accessible": db["PubliclyAccessible"],
            "backup_retention": db["BackupRetentionPeriod"],
        })
    return instances


def list_unattached_ebs() -> list[dict]:
    resp = _ec2().describe_volumes(
        Filters=[{"Name": "status", "Values": ["available"]}]
    )
    volumes = []
    for v in resp["Volumes"]:
        volumes.append({
            "volume_id": v["VolumeId"],
            "size_gb": v["Size"],
            "volume_type": v["VolumeType"],
            "create_time": v["CreateTime"].isoformat(),
            "name": _tag(v.get("Tags", []), "Name"),
        })
    return volumes


def list_unassociated_eips() -> list[dict]:
    resp = _ec2().describe_addresses()
    return [
        {
            "allocation_id": a.get("AllocationId"),
            "public_ip": a["PublicIp"],
            "name": _tag(a.get("Tags", []), "Name"),
        }
        for a in resp["Addresses"]
        if "AssociationId" not in a
    ]


def list_iam_users_no_mfa() -> list[dict]:
    iam = _iam()
    users = iam.list_users()["Users"]
    no_mfa = []
    for u in users:
        mfa = iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]
        if not mfa:
            no_mfa.append({
                "username": u["UserName"],
                "created": u["CreateDate"].isoformat(),
                "password_last_used": u.get("PasswordLastUsed", "never").isoformat()
                    if hasattr(u.get("PasswordLastUsed"), "isoformat") else "never",
            })
    return no_mfa
