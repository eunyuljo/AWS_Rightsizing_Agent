"""
규칙 엔진 — 모든 룰을 실행하고 Violation 목록을 반환
"""
import logging
import traceback
from typing import Optional

from rules.base import Violation, Severity
from rules.security import SECURITY_RULES
from rules.reliability import RELIABILITY_RULES
from rules.cost import COST_RULES

log = logging.getLogger(__name__)

CATEGORY_MAP = {
    "security": SECURITY_RULES,
    "reliability": RELIABILITY_RULES,
    "cost": COST_RULES,
}


def run_category(category: str) -> list[Violation]:
    """특정 카테고리 룰만 실행"""
    rules = CATEGORY_MAP.get(category, [])
    violations: list[Violation] = []
    for rule_fn in rules:
        try:
            result = rule_fn()
            violations.extend(result)
        except Exception:
            log.warning(f"[{category}] {rule_fn.__name__} 실패:\n{traceback.format_exc()}")
    return violations


def run_all(
    categories: Optional[list[str]] = None,
    min_severity: Optional[Severity] = None,
) -> dict:
    """
    모든 룰 실행 후 요약 반환

    Returns:
        {
          "violations": [...],   # Violation.to_dict() 목록
          "summary": {
              "total": N,
              "critical": N, "high": N, "medium": N, "low": N,
              "by_category": {"security": N, "reliability": N, "cost": N},
          },
          "errors": [],          # 실패한 룰 이름 목록
        }
    """
    cats = categories or list(CATEGORY_MAP.keys())
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    min_idx = severity_order.index(min_severity) if min_severity else len(severity_order)

    all_violations: list[Violation] = []
    errors: list[str] = []
    by_category: dict[str, int] = {}

    for cat in cats:
        rules = CATEGORY_MAP.get(cat, [])
        cat_count = 0
        for rule_fn in rules:
            try:
                result = rule_fn()
                for v in result:
                    if min_severity is None or severity_order.index(v.severity) <= min_idx:
                        all_violations.append(v)
                        cat_count += 1
            except Exception:
                log.warning(f"[{cat}] {rule_fn.__name__} 실패:\n{traceback.format_exc()}")
                errors.append(f"{cat}.{rule_fn.__name__}")
        by_category[cat] = cat_count

    severity_counts = {s.value: 0 for s in Severity}
    for v in all_violations:
        severity_counts[v.severity.value] += 1

    return {
        "violations": [v.to_dict() for v in all_violations],
        "summary": {
            "total": len(all_violations),
            **severity_counts,
            "by_category": by_category,
        },
        "errors": errors,
    }
