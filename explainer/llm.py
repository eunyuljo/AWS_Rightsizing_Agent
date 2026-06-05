"""Claude API로 이상 감지 결과를 자연어로 설명"""
import anthropic
import json
from config import config

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=config.anthropic_api_key)
    return _client


def explain_violation(violation: dict) -> str:
    """
    규칙 위반 한 건을 비즈니스 언어로 설명.
    violation 은 Violation.to_dict() 형태의 dict.
    """
    severity_kr = {
        "critical": "심각", "high": "높음", "medium": "보통", "low": "낮음",
    }.get(violation.get("severity", ""), "")

    prompt = f"""당신은 AWS 인프라 전문가입니다.
아래 규정 위반 감지 결과를 비기술직 담당자도 이해할 수 있는 한국어로 2~4문장으로 설명하세요.
- 무슨 문제가 발견됐는지
- 왜 위험한지 (보안/비용/가용성 관점)
- 즉시 취해야 할 조치

위반 데이터:
{json.dumps(violation, ensure_ascii=False, indent=2)}

설명 (한국어, {severity_kr} 심각도):"""

    resp = _get_client().messages.create(
        model=config.claude_model,
        max_tokens=300,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text.strip()


def explain_violations_summary(violations: list[dict]) -> str:
    """여러 위반 항목을 Slack용 요약 메시지로"""
    if not violations:
        return "현재 감지된 위반 없음."

    prompt = f"""당신은 AWS MSP 엔지니어입니다.
아래 {len(violations)}개의 규정 위반 결과를 운영팀에 전달할 슬랙 메시지로 작성하세요.

형식:
- 첫 줄: 전체 상황 한 줄 요약
- 심각도별 이슈 한 줄씩 (이모지 포함)
- 마지막 줄: 권고 액션

위반 목록:
{json.dumps(violations, ensure_ascii=False, indent=2)}

슬랙 메시지 (한국어, 마크다운):"""

    resp = _get_client().messages.create(
        model=config.claude_model,
        max_tokens=600,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text.strip()


def answer_question(question: str, context_data: dict, history: list[dict] = None) -> dict:
    """
    채팅 질문에 답변 — 응답 스타일(biz/tech)을 LLM이 자동 판단.
    history: [{"role": "user"|"assistant", "content": "..."}, ...]
    """
    system = """당신은 AWS 인프라 어시스턴트입니다.
질문의 성격을 판단해서 응답 스타일을 결정하세요:
- 비즈니스 질문 (비용, 절감, 왜, 얼마, 요약) → 비즈니스 언어, 숫자 강조, SQL 숨김
- 기술 질문 (인스턴스 ID, SQL, 목록, 메트릭, 위반 상세) → 기술 언어, 데이터 상세
- 컴플라이언스 질문 (위반, ISMS, CIS, 보안이슈) → 위험도 강조, 조치 방법 포함

반드시 JSON으로만 응답하세요:
{
  "style": "biz" | "tech",
  "summary": "한 줄 요약",
  "answer": "상세 설명 (2~4문장)",
  "key_numbers": [{"label": "...", "value": "..."}],
  "actions": ["권고 액션 1", "권고 액션 2"],
  "needs_more_data": false
}"""

    # 대화 히스토리 + 현재 질문으로 messages 구성
    messages: list[dict] = []
    for h in (history or []):
        role = h.get("role", "user")
        content = h.get("content", "")
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})

    user_msg = f"""질문: {question}

현재 인프라 데이터:
{json.dumps(context_data, ensure_ascii=False, indent=2, default=str)}"""

    messages.append({"role": "user", "content": user_msg})

    resp = _get_client().messages.create(
        model=config.claude_model,
        max_tokens=800,
        system=system,
        messages=messages,
    )

    text = resp.content[0].text.strip()
    try:
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        return json.loads(text)
    except Exception:
        return {
            "style": "biz",
            "summary": "조회 완료",
            "answer": text,
            "key_numbers": [],
            "actions": [],
            "needs_more_data": False,
        }
