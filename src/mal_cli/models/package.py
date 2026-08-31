"""
Package model.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Package:
    name: str
    version: str = ""
    installer: str = ""
    target_sdk: int = 0
    min_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    apk_hash: Optional[str] = None
    signer_info: Optional[str] = None