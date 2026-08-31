"""
Risk level definitions and helpers.
"""

from enum import Enum


class RiskLevel(Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def get_risk_level(score: int) -> RiskLevel:
    if score <= 19:
        return RiskLevel.SAFE
    elif score <= 39:
        return RiskLevel.LOW
    elif score <= 59:
        return RiskLevel.MEDIUM
    elif score <= 79:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL