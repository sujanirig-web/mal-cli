"""
Security event model.
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityEvent:
    timestamp: datetime
    package_name: str
    event_type: str
    description: str
    old_score: int = None
    new_score: int = None