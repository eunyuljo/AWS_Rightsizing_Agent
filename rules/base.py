"""룰 엔진 기반 클래스 및 결과 타입"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class Framework(str, Enum):
    CIS     = "CIS AWS Foundations Benchmark"
    ISMS_P  = "ISMS-P"
    AWS_BP  = "AWS Best Practice"


@dataclass
class Violation:
    rule_id:       str
    framework:     Framework
    category:      str          # security / reliability / cost
    title:         str
    severity:      Severity
    resource_id:   str
    resource_type: str
    detail:        str          # 기술적 설명
    remediation:   str          # 교정 방법
    raw:           dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id":       self.rule_id,
            "framework":     self.framework.value,
            "category":      self.category,
            "title":         self.title,
            "severity":      self.severity.value,
            "resource_id":   self.resource_id,
            "resource_type": self.resource_type,
            "detail":        self.detail,
            "remediation":   self.remediation,
        }
