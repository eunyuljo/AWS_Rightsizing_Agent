"""CloudWatch 메트릭 수집"""
import boto3
from datetime import datetime, timedelta, timezone
from config import config


def _cw():
    return boto3.client(
        "cloudwatch",
        region_name=config.aws_region,
        aws_access_key_id=config.aws_access_key_id,
        aws_secret_access_key=config.aws_secret_access_key,
        aws_session_token=config.aws_session_token,
    )


def get_ec2_cpu_stats(instance_id: str, hours: int = 24) -> dict:
    """EC2 CPU 통계 (avg, max, p99)"""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    resp = _cw().get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=start,
        EndTime=end,
        Period=3600,
        Statistics=["Average", "Maximum"],
    )

    points = resp.get("Datapoints", [])
    if not points:
        return {"avg": None, "max": None, "points": 0}

    avgs = [p["Average"] for p in points]
    maxs = [p["Maximum"] for p in points]
    return {
        "avg": round(sum(avgs) / len(avgs), 2),
        "max": round(max(maxs), 2),
        "points": len(points),
    }


def get_all_ec2_cpu(instance_ids: list[str], hours: int = 24) -> dict[str, dict]:
    """여러 인스턴스 CPU 일괄 수집"""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    queries = []
    for i, iid in enumerate(instance_ids):
        queries.append({
            "Id": f"cpu_{i}",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/EC2",
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": iid}],
                },
                "Period": 3600,
                "Stat": "Average",
            },
        })

    if not queries:
        return {}

    resp = _cw().get_metric_data(
        MetricDataQueries=queries,
        StartTime=start,
        EndTime=end,
    )

    result = {}
    for metric in resp["MetricDataResults"]:
        idx = int(metric["Id"].split("_")[1])
        iid = instance_ids[idx]
        values = metric.get("Values", [])
        if values:
            result[iid] = {
                "avg": round(sum(values) / len(values), 2),
                "max": round(max(values), 2),
                "points": len(values),
            }
        else:
            result[iid] = {"avg": None, "max": None, "points": 0}
    return result
