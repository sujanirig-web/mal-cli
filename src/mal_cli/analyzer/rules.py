"""
Static rules for risk scoring.
"""

from typing import List, Tuple
from mal_cli.models.package import Package

# Basic risk weights
PERMISSION_WEIGHTS = {
    "android.permission.READ_SMS": 15,
    "android.permission.RECORD_AUDIO": 12,
    "android.permission.CAMERA": 10,
    "android.permission.ACCESS_FINE_LOCATION": 10,
    "android.permission.READ_CONTACTS": 8,
    "android.permission.READ_PHONE_STATE": 8,
    "android.permission.SEND_SMS": 15,
    "android.permission.INTERNET": 5,
    "android.permission.WRITE_EXTERNAL_STORAGE": 5,
    "android.permission.READ_EXTERNAL_STORAGE": 3,
    "android.permission.ACCESS_COARSE_LOCATION": 7,
    "android.permission.SYSTEM_ALERT_WINDOW": 10,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 20,
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": 10,
}

SERVICE_WEIGHT = 5
EXPORTED_SERVICE_WEIGHT = 10
BACKGROUND_SERVICE_WEIGHT = 8


def apply_rules(pkg: Package) -> Tuple[int, List[str], str]:
    """
    Apply static rules and return (score, indicators, explanation).
    """
    score = 0
    indicators = []
    parts = []

    # Permissions
    perm_score = 0
    for perm in pkg.permissions:
        weight = PERMISSION_WEIGHTS.get(perm, 0)
        if weight:
            perm_score += weight
            indicators.append(f"Permission: {perm}")
    if perm_score:
        score += perm_score
        parts.append(f"Permissions contributing {perm_score} points")

    # Services
    for svc in pkg.services:
        score += SERVICE_WEIGHT
        indicators.append(f"Service: {svc}")
        # Check if exported (simplified: assume all are exported unless we parse manifest)
        # For demo, we just add extra if service contains ".service"
        if "service" in svc.lower():
            score += EXPORTED_SERVICE_WEIGHT
            indicators.append(f"Exported service: {svc}")
    if pkg.services:
        parts.append(f"Services contributing {len(pkg.services)*SERVICE_WEIGHT} points")

    # Check for background services (based on name)
    for svc in pkg.services:
        if "background" in svc.lower() or "sync" in svc.lower():
            score += BACKGROUND_SERVICE_WEIGHT
            indicators.append(f"Background service: {svc}")

    # Check target SDK (low target may indicate legacy app)
    if pkg.target_sdk < 26:  # Android 8.0
        score += 5
        indicators.append(f"Target SDK < 26 ({pkg.target_sdk})")
        parts.append("Low target SDK")

    return min(score, 50), indicators, "; ".join(parts) if parts else ""