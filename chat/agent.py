"""채팅 조사 에이전트 — 알림 받은 뒤 파고들 때 사용"""
from collector.resources import list_running_ec2, list_security_groups, list_rds_instances
from collector.cost import get_mtd_cost_by_service, get_daily_cost_by_service
from collector.metrics import get_ec2_cpu_stats
from store.memory import get_recent_alerts
from explainer.llm import answer_question
import json


TOOL_REGISTRY = {
    "list_ec2": {
        "description": "실행 중인 EC2 인스턴스 목록",
        "fn": list_running_ec2,
    },
    "list_security_groups": {
        "description": "보안그룹 및 인터넷 개방 현황",
        "fn": list_security_groups,
    },
    "list_rds": {
        "description": "RDS 인스턴스 목록",
        "fn": list_rds_instances,
    },
    "get_monthly_cost": {
        "description": "이번 달 서비스별 비용",
        "fn": get_mtd_cost_by_service,
    },
    "get_recent_alerts": {
        "description": "최근 24시간 감지된 이상 목록",
        "fn": lambda: get_recent_alerts(hours=24),
    },
}


def _detect_tools(question: str) -> list[str]:
    """질문에서 필요한 tool 목록을 키워드로 추론"""
    q = question.lower()
    tools = []

    if any(k in q for k in ["비용", "cost", "얼마", "요금", "청구"]):
        tools.append("get_monthly_cost")
    if any(k in q for k in ["ec2", "서버", "인스턴스", "cpu", "메모리"]):
        tools.append("list_ec2")
    if any(k in q for k in ["보안", "security", "포트", "sg", "노출"]):
        tools.append("list_security_groups")
    if any(k in q for k in ["rds", "데이터베이스", "db", "mysql", "postgres"]):
        tools.append("list_rds")
    if any(k in q for k in ["알림", "alert", "이상", "감지", "최근"]):
        tools.append("get_recent_alerts")

    # 아무 키워드도 없으면 기본 조회
    if not tools:
        tools = ["list_ec2", "get_monthly_cost"]

    return list(dict.fromkeys(tools))  # 중복 제거, 순서 유지


def chat(question: str, conversation_history: list[dict] = None) -> dict:
    """
    질문 → tool 실행 → LLM 응답
    반환: { style, summary, answer, key_numbers, actions, data, tool_used }
    """
    # 1. 필요한 tool 결정
    tools_needed = _detect_tools(question)

    # 2. 데이터 수집
    context = {}
    for tool_name in tools_needed:
        tool = TOOL_REGISTRY.get(tool_name)
        if tool:
            try:
                context[tool_name] = tool["fn"]()
            except Exception as e:
                context[tool_name] = {"error": str(e)}

    # 3. LLM으로 응답 생성
    response = answer_question(question, context)
    response["tool_used"] = tools_needed
    response["raw_data"] = context

    return response
