"""
Main monitoring loop.
"""

import time
import threading
from typing import Dict, List, Optional
from mal_cli.adb.client import ADBClient
from mal_cli.adb.commands import ADBCommands
from mal_cli.models.device import Device
from mal_cli.database.database import Database
from mal_cli.analyzer.analyzer import Analyzer
from mal_cli.monitor.package_tracker import PackageTracker
from mal_cli.monitor.processes import ProcessMonitor
from mal_cli.monitor.foreground import ForegroundMonitor
from mal_cli.monitor.network import NetworkMonitor
from mal_cli.monitor.logs import LogMonitor
from mal_cli.monitor.activity import ActivityMonitor
from mal_cli.monitor.events import EventQueue
from mal_cli.output.monitor_ui import MonitorUI


class Monitor:
    def __init__(self, client: ADBClient, device: Device, db: Database,
                 analyzer: Analyzer, interval: float = 2.0):
        self.client = client
        self.device = device
        self.db = db
        self.analyzer = analyzer
        self.interval = interval
        self.cmds = ADBCommands(client, device.serial)
        self.tracker = PackageTracker(db)
        self.event_queue = EventQueue()
        self.running = False
        self.threads = []
        self.ui = MonitorUI()
        self.activity = ActivityMonitor(client, device.serial)

    def start(self):
        self.running = True
        # Live logcat tail for app launches / activity starts
        self.activity.start()
        # Start background monitors
        self.process_monitor = ProcessMonitor(self.cmds, self.tracker, self.event_queue)
        self.foreground_monitor = ForegroundMonitor(self.cmds, self.tracker, self.event_queue)
        self.network_monitor = NetworkMonitor(self.cmds, self.tracker, self.event_queue)
        self.log_monitor = LogMonitor(self.cmds, self.tracker, self.event_queue)
        for monitor in (self.process_monitor, self.foreground_monitor,
                        self.network_monitor, self.log_monitor):
            self._start_monitor(monitor)

        # Main loop for UI
        self.ui.start()
        while self.running:
            # Update UI with currently running packages, events and live activity
            packages = self._current_packages()
            events = self.event_queue.get_recent()
            activity = self.activity.get_recent(12)
            self.ui.render(packages, events, activity)

            # Run periodic risk re-evaluation
            # (In real implementation, we would trigger re-evaluation on change)
            self._evaluate_packages()

            time.sleep(self.interval)

    def _current_packages(self) -> List[Dict]:
        """Build a table of packages that are running right now."""
        try:
            snapshot = self.process_monitor.snapshot()
        except Exception:
            snapshot = {}
        try:
            fg = self.foreground_monitor.foreground or ""
        except Exception:
            fg = ""
        packages = []
        for name, info in sorted(snapshot.items()):
            state = {
                "name": name,
                "status": "FOREGROUND" if fg == name else "RUNNING",
                "processes": len(info["pids"]),
                "risk": "NOT SCANNED",
            }
            try:
                risk = self.db.get_latest_risk(name)
                if risk:
                    state["risk"] = f"{risk.get('level', '?')} ({risk.get('score', '?')})"
            except Exception:
                pass
            packages.append(state)
        return packages

    def stop(self):
        self.running = False
        self.activity.stop()
        self.ui.stop()
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=1)

    def _start_monitor(self, monitor):
        """Start a monitor thread."""
        t = threading.Thread(target=self._run_monitor, args=(monitor,), daemon=True)
        t.start()
        self.threads.append(t)

    def _run_monitor(self, monitor):
        """Run a monitor in loop."""
        while self.running:
            try:
                monitor.update()
            except Exception:
                pass
            time.sleep(self.interval)

    def _evaluate_packages(self):
        """Re-evaluate risk for packages that have changed."""
        for pkg in self.tracker.get_all_packages():
            # Get current static info from DB
            # For simplicity, we only re-evaluate if we have new events
            # In real implementation, we would compare states
            pass