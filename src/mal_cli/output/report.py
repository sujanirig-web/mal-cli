"""
Report generation.
"""

from typing import Dict, Any, List
from mal_cli.database.database import Database


class ReportGenerator:
    def __init__(self, db: Database):
        self.db = db

    def generate(self) -> Dict[str, Any]:
        """Generate a full report as dict."""
        packages = self.db.get_all_package_summaries()
        report = {
            "timestamp": __import__("time").time(),
            "packages": []
        }
        for pkg in packages:
            info = self.db.get_package(pkg["name"])
            risk = self.db.get_latest_risk(pkg["name"])
            events = self.db.get_events(pkg["name"], limit=10)
            report["packages"].append({
                "name": pkg["name"],
                "version": info.get("version", ""),
                "installer": info.get("installer", ""),
                "first_seen": pkg["first_seen"],
                "last_seen": pkg["last_seen"],
                "remediation_state": info.get("remediation_state", "none"),
                "current_risk": risk,
                "recent_events": events
            })
        return report

    def text_report(self) -> str:
        """Generate a plain text report."""
        data = self.generate()
        lines = ["mal-cli Report", "=" * 40, ""]
        for pkg in data["packages"]:
            lines.append(f"Package: {pkg['name']}")
            lines.append(f"  Version: {pkg['version']}")
            lines.append(f"  State: {pkg['remediation_state']}")
            risk = pkg.get("current_risk")
            if risk:
                lines.append(f"  Risk: {risk.get('level', 'N/A')} ({risk.get('score', '?')})")
            lines.append("")
        return "\n".join(lines)