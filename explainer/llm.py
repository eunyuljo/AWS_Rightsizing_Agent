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


def explain_alert(alert: dict) -> str:
    """알림 하나를 비즈니스 언어로 설명"""
    prompt = f"""
당신은 AWS 인프라 전문가입니다.
아래 이상 감지 결과를 비기술직 담당자도 이해할 수 있는 언어로 2~4문장으로 설명하세요.
- 무슨 일이 생겼는지
- 왜 중요한지 (비용/보안/가용성 관점)
- 다음에 무엇을 확인해야 하는지

알림 데이터:
{json.dumps(alert, ensure_ascii=False, indent=2)}

설명 (한국어):
"""
    resp = _get_client().messages.create(
        model=config.claude_model,
        max_tokens=300,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text.strip()


def explain_alerts_summary(alerts: list[dict]) -> str:
    """여러 알림을 하나의 요약으로"""
    if not alerts:
        return "현재 감지된 이상 없음."

    prompt = f"""
당신은 AWS MSP 엔지니어입니다.
아래 {len(alerts)}개의 이상 감지 결과를 운영팀에 전달할 슬랙 메시지로 작성하세요.

형식:
- 첫 줄: 전체 상황 한 줄 요약
- 이슈별 한 줄씩 (심각도 이모지 포함)
- 마지막 줄: 권고 액션

이상 목록:
{json.dumps(alerts, ensure_ascii=False, indent=2)}

슬랙 메시지 (한국어, 마크다운 사용):
"""
    resp = _get_client().messages.create(
        model=config.claude_model,
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text.strip()


def answer_question(question: str, context_data: dict) -> dict:
    """
    채팅 질문에 답변 — 응답 스타일(biz/tech)을 LLM이 자동 판단
    """
    system = """당신은 AWS 인프라 어시스턴트입니다.
질문의 성격을 판단해서 응답 스타일을 결정하세요:
- 비즈니스 질문 (비용, 절감, 왜, 얼마) → 비즈니스 언어, 숫자 강조, SQL 숨김
- 기술 질문 (인스턴스 ID, SQL, 목록, 메트릭) → 기술 언어, 데이터 상세

반드시 JSON으로만 응답하세요:
{
  "style": "biz" | "tech",
  "summary": "한 줄 요약",
  "answer": "상세 설명 (2~4문장)",
  "key_numbers": [{"label": "...", "value": "..."}],
  "actions": ["권고 액션 1", "권고 액션 2"],
  "needs_more_data": false
}"""

    user_msg = f"""
질문: {question}

현재 인프라 데이터:
{json.dumps(context_data, ensure_ascii=False, indent=2, default=str)}
"""
    resp = _get_client().messages.create(
        model=config.claude_model,
        max_tokens=800,
        system=system,
        messages=[{"role": "user", "content": user_msg}],
    )

    text = resp.content[0].text.strip()
    # JSON 파싱 시도, 실패 시 fallback
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
