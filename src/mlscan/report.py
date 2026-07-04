from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    severity: Severity
    rule_id: str
    message: str
    location: str

    def __str__(self) -> str:
        return f"[{self.severity.value}] {self.rule_id}: {self.message} ({self.location})"

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "message": self.message,
            "location": self.location,
        }
