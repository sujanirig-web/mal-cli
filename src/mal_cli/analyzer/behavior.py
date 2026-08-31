"""
Behavioral analysis based on dynamic data.
"""

from typing import Dict, List, Tuple
from mal_cli.models.package import Package


def analyze_behavior(pkg: Package, dynamic: Dict) -> Tuple[int, List[str], str]:
    """
    Analyze dynamic behavior and return (score, indicators, explanation).
    """
    score = 0
    indicators = []
    parts = []

    # Example: if package has high CPU usage (not implemented)
    # For now, placeholders
    if dynamic.get("background_processes", 0) > 2:
        score += 10
        indicators.append("Multiple background processes")
        parts.append("Multiple background processes")

    if dynamic.get("foreground_time", 0) < 10:  # rarely in foreground
        score += 5
        indicators.append("Rarely in foreground")
        parts.append("Rarely in foreground")

    # Network usage
    if dynamic.get("network_total", 0) > 10 * 1024 * 1024:  # >10MB
        score += 8
        indicators.append("High network usage")
        parts.append("High network usage")

    return min(score, 50), indicators, "; ".join(parts) if parts else ""