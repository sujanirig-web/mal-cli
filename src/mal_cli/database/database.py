"""
SQLite database for persistent storage.
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
import os


class Database:
    def __init__(self, db_path: str = None):
        if db_path is None:
            home = os.path.expanduser("~")
            db_dir = os.path.join(home, ".mal_cli")
            os.makedirs(db_dir, exist_ok=True)
            db_path = os.path.join(db_dir, "mal_cli.db")
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS packages (
                    name TEXT PRIMARY KEY,
                    first_seen INTEGER,
                    last_seen INTEGER,
                    apk_hash TEXT,
                    signer TEXT,
                    remediation_state TEXT,
                    version TEXT,
                    installer TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS risk_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_name TEXT REFERENCES packages(name),
                    timestamp INTEGER,
                    score INTEGER,
                    level TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_name TEXT REFERENCES packages(name),
                    timestamp INTEGER,
                    event_type TEXT,
                    description TEXT,
                    old_score INTEGER,
                    new_score INTEGER
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS static_data (
                    package_name TEXT PRIMARY KEY REFERENCES packages(name),
                    permissions TEXT,
                    services TEXT,
                    target_sdk INTEGER,
                    min_sdk INTEGER
                )
            """)
            conn.commit()

    def upsert_package(self, name: str, first_seen: float, last_seen: float,
                       apk_hash: str = None, signer: str = None,
                       remediation_state: str = "none",
                       version: str = "", installer: str = ""):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO packages
                (name, first_seen, last_seen, apk_hash, signer, remediation_state, version, installer)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, int(first_seen), int(last_seen), apk_hash, signer, remediation_state, version, installer))
            conn.commit()

    def save_risk(self, package: str, score: int, level: str, explanation: str = ""):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO risk_history (package_name, timestamp, score, level)
                VALUES (?, ?, ?, ?)
            """, (package, int(datetime.now().timestamp()), score, level))
            conn.commit()
            # Update last_seen in packages
            cur.execute("UPDATE packages SET last_seen = ? WHERE name = ?",
                        (int(datetime.now().timestamp()), package))
            conn.commit()

    def add_event(self, package: str, event_type: str, description: str,
                  old_score: int = None, new_score: int = None):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO security_events
                (package_name, timestamp, event_type, description, old_score, new_score)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (package, int(datetime.now().timestamp()), event_type, description, old_score, new_score))
            conn.commit()

    def get_package(self, name: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM packages WHERE name = ?", (name,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_latest_risk(self, package: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("""
                SELECT score, level FROM risk_history
                WHERE package_name = ?
                ORDER BY timestamp DESC LIMIT 1
            """, (package,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_risk_history(self, package: str, limit: int = 20) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("""
                SELECT timestamp, score, level FROM risk_history
                WHERE package_name = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (package, limit))
            rows = cur.fetchall()
            return [dict(row) for row in rows]

    def get_events(self, package: str = None, limit: int = 20) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            if package:
                cur.execute("""
                    SELECT * FROM security_events
                    WHERE package_name = ?
                    ORDER BY timestamp DESC LIMIT ?
                """, (package, limit))
            else:
                cur.execute("""
                    SELECT * FROM security_events
                    ORDER BY timestamp DESC LIMIT ?
                """, (limit,))
            rows = cur.fetchall()
            return [dict(row) for row in rows]

    def get_all_package_summaries(self) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("""
                SELECT p.name, p.first_seen, p.last_seen,
                       (SELECT level FROM risk_history WHERE package_name = p.name ORDER BY timestamp DESC LIMIT 1) as current_level
                FROM packages p
            """)
            rows = cur.fetchall()
            return [dict(row) for row in rows]

    def update_remediation_state(self, package: str, state: str):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("UPDATE packages SET remediation_state = ? WHERE name = ?", (state, package))
            conn.commit()

    def get_permissions(self, package: str) -> Optional[List[str]]:
        # Could be stored in static_data
        return None

    def get_services(self, package: str) -> Optional[List[str]]:
        return None