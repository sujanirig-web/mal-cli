"""
Main analyzer combining rules, signatures, and behavior.
"""

from typing import Optional
from mal_cli.database.database import Database
from mal_cli.models.package import Package
from mal_cli.models.result import RiskResult
from mal_cli.analyzer.rules import apply_rules
from mal_cli.analyzer.signatures import check_signatures
from mal_cli.analyzer.behavior import analyze_behavior
from mal_cli.analyzer.risk import RiskLevel, get_risk_level


class Analyzer:
    def __init__(self, db: Database):
        self.db = db

    def evaluate_package(self, pkg: Package, dynamic_data: dict = None) -> RiskResult:
        """Evaluate static and dynamic evidence to produce risk result."""
        total_score = 0
        indicators = []
        explanation_parts = []

        # 1. Static rules
        static_score, static_indicators, static_expl = apply_rules(pkg)
        total_score += static_score
        indicators.extend(static_indicators)
        if static_expl:
            explanation_parts.append(static_expl)

        # 2. Signature/hash check
        sig_score, sig_indicators, sig_expl = check_signatures(pkg)
        total_score += sig_score
        indicators.extend(sig_indicators)
        if sig_expl:
            explanation_parts.append(sig_expl)

        # 3. Behavioral (if dynamic data provided)
        if dynamic_data:
            beh_score, beh_indicators, beh_expl = analyze_behavior(pkg, dynamic_data)
            total_score += beh_score
            indicators.extend(beh_indicators)
            if beh_expl:
                explanation_parts.append(beh_expl)

        # Cap at 100
        total_score = min(100, total_score)
        level = get_risk_level(total_score)
        label = "MALICIOUS" if level == RiskLevel.CRITICAL and total_score >= 90 else ""

        explanation = "; ".join(explanation_parts) if explanation_parts else "No specific indicators"

        return RiskResult(
            package_name=pkg.name,
            score=total_score,
            level=level,
            label=label,
            explanation=explanation,
            indicators=indicators,
        )