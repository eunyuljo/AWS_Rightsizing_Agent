"""채팅 조사 에이전트 — 알림 수신 후 자연어로 후속 조사"""
from collector.resources import list_running_ec2, list_security_groups, list_rds_instances
from collector.cost import get_mtd_cost_by_service
from store.memory import get_recent_alerts
from explainer.llm import answer_question
import logging

log = logging.getLogger(__name__)


def _get_recent_violations(hours: int = 24) -> list[dict]:
    return get_recent_alerts(hours=hours, limit=30)


def _get_live_violations(category: str = None) -> dict:
    """룰 엔진을 즉시 실행해 현재 위반 항목 반환 (Slack 발송 없이)"""
    try:
        from rules.engine import run_all, run_category
        if category:
            violations = [v.to_dict() for v in run_category(category)]
            return {"violations": violations, "total": len(violations)}
        return run_all()
    except Exception as e:
        log.warning(f"live scan 실패: {e}")
        return {"violations": [], "total": 0, "error": str(e)}


TOOL_REGISTRY = {
    "list_ec2": {
        "description": "실행 중인 EC2 인스턴스 목록",
        "fn": list_running_ec2,
        "keywords": ["ec2", "서버", "인스턴스", "cpu", "메모리", "리소스"],
    },
    "list_security_groups": {
        "description": "보안그룹 및 인터넷 개방 현황",
        "fn": list_security_groups,
        "keywords": ["보안그룹", "sg", "포트", "노출", "방화벽", "security group"],
    },
    "list_rds": {
        "description": "RDS 인스턴스 목록",
        "fn": list_rds_instances,
        "keywords": ["rds", "데이터베이스", "db", "mysql", "postgres", "aurora"],
    },
    "get_monthly_cost": {
        "description": "이번 달 서비스별 비용",
        "fn": get_mtd_cost_by_service,
        "keywords": ["비용", "cost", "얼마", "요금", "청구", "절감", "낭비"],
    },
    "get_recent_alerts": {
        "description": "최근 24시간 DB에 저장된 알림 이력",
        "fn": lambda: _get_recent_violations(hours=24),
        "keywords": ["알림", "alert", "감지", "최근", "이력"],
    },
    "get_live_violations": {
        "description": "현재 시점 CIS+ISMS-P 위반 항목 전체 스캔",
        "fn": _get_live_violations,
        "keywords": ["위반", "compliance", "컴플라이언스", "isms", "cis", "점검", "진단", "보안이슈"],
    },
    "get_security_violations": {
        "description": "보안 카테고리 위반만 실시간 스캔",
        "fn": lambda: _get_live_violations("security"),
        "keywords": ["보안위반", "보안점검", "보안진단", "취약점", "루트", "mfa", "암호화"],
    },
    "get_cost_violations": {
        "description": "비용 낭비 항목 실시간 스캔",
        "fn": lambda: _get_live_violations("cost"),
        "keywords": ["낭비", "유휴", "eip", "ebs 미연결", "idle", "미사용"],
    },
}


def _detect_tools(question: str) -> list[str]:
    """질문 키워드 기반 필요한 tool 추론"""
    q = question.lower()
    matched = []

    for tool_name, tool in TOOL_REGISTRY.items():
        if any(k in q for k in tool["keywords"]):
            matched.append(tool_name)

    # 겹치는 tool 정리: live_violations가 있으면 recent_alerts 제거
    if "get_live_violations" in matched:
        matched = [t for t in matched if t != "get_recent_alerts"]
    if "get_security_violations" in matched and "get_live_violations" in matched:
        matched = [t for t in matched if t != "get_security_violations"]

    # 아무 키워드도 없으면 기본 조회
    if not matched:
        matched = ["list_ec2", "get_monthly_cost"]

    return list(dict.fromkeys(matched))  # 중복 제거, 순서 유지


def chat(question: str, conversation_history: list[dict] = None) -> dict:
    """
    질문 → tool 실행 → LLM 응답

    반환:
        { style, summary, answer, key_numbers, actions, tool_used, raw_data }
    """
    tools_needed = _detect_tools(question)

    # 데이터 수집
    context: dict = {}
    for tool_name in tools_needed:
        tool = TOOL_REGISTRY.get(tool_name)
        if tool:
            try:
                context[tool_name] = tool["fn"]()
            except Exception as e:
                context[tool_name] = {"error": str(e)}

    # LLM 응답 생성 (대화 히스토리 전달)
    response = answer_question(question, context, history=conversation_history or [])
    response["tool_used"] = tools_needed
    response["raw_data"] = context

    return response
