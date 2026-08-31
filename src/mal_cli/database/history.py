"""
History query helpers.
"""

from mal_cli.database.database import Database


class History:
    def __init__(self, db: Database):
        self.db = db

    def get_package_timeline(self, package: str):
        return self.db.get_risk_history(package)