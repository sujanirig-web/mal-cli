"""
Device model.
"""

from dataclasses import dataclass


@dataclass
class Device:
    serial: str
    model: str
    android_version: str
    sdk_version: int
    is_online: bool