"""
Track packages and their state over time.
"""

import time
from typing import Dict, List, Optional
from mal_cli.database.database import Database
from mal_cli.models.package import Package
from mal_cli.models.result import RiskResult


class PackageTracker:
    def __init__(self, db: Database):
        self.db = db
        self.packages: Dict[str, dict] = {}  # name -> state

    def update_package(self, pkg: Package, risk: Optional[RiskResult] = None):
        """Update or add package state."""
        state = self.packages.get(pkg.name, {
            "first_seen": time.time(),
            "last_seen": 0,
            "risk_history": [],
            "indicators": set(),
            "events": [],
            "remediation_state": "none",
        })
        state["last_seen"] = time.time()
        if risk:
            state["risk_history"].append((time.time(), risk.score, getattr(risk.level, "value", risk.level)))
            # Trim history
            if len(state["risk_history"]) > 100:
                state["risk_history"] = state["risk_history"][-100:]
        # Store indicators from risk
        if risk and risk.indicators:
            state["indicators"].update(risk.indicators)
        # Save to DB
        self.db.upsert_package(
            name=pkg.name,
            first_seen=state["first_seen"],
            last_seen=state["last_seen"],
            apk_hash=pkg.apk_hash,
            signer=pkg.signer_info,
            remediation_state=state["remediation_state"],
            version=pkg.version,
            installer=pkg.installer,
        )
        if risk:
            self.db.save_risk(pkg.name, risk.score, risk.level, risk.explanation)
        self.packages[pkg.name] = state

    def get_package_state(self, name: str) -> Optional[dict]:
        return self.packages.get(name)

    def get_all_packages(self) -> List[dict]:
        return list(self.packages.values())

    def add_event(self, package: str, event_type: str, description: str, old_score: int = None, new_score: int = None):
        self.db.add_event(package, event_type, description, old_score, new_score)
        if package in self.packages:
            self.packages[package]["events"].append((time.time(), event_type, description))