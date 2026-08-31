"""
Risk result model.
"""

from dataclasses import dataclass, field
from typing import List
from mal_cli.analyzer.risk import RiskLevel


@dataclass
class RiskResult:
    package_name: str
    score: int
    level: RiskLevel
    label: str = ""
    explanation: str = ""
    indicators: List[str] = field(default_factory=list)