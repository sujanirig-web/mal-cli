"""
Main monitoring loop.
"""

import time
import threading
from typing import Optional
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

    def start(self):
        self.running = True
        # Start background monitors
        self._start_monitor(ProcessMonitor, self.cmds, self.tracker, self.event_queue)
        self._start_monitor(ForegroundMonitor, self.cmds, self.tracker, self.event_queue)
        self._start_monitor(NetworkMonitor, self.cmds, self.tracker, self.event_queue)
        self._start_monitor(LogMonitor, self.cmds, self.tracker, self.event_queue)

        # Main loop for UI
        self.ui.start()
        while self.running:
            # Update UI with tracker data and events
            packages = self.tracker.get_all_packages()
            events = self.event_queue.get_recent()
            self.ui.update(packages, events)

            # Run periodic risk re-evaluation
            # (In real implementation, we would trigger re-evaluation on change)
            self._evaluate_packages()

            time.sleep(self.interval)

    def stop(self):
        self.running = False
        self.ui.stop()
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=1)

    def _start_monitor(self, monitor_cls, *args):
        """Start a monitor thread."""
        t = threading.Thread(target=self._run_monitor, args=(monitor_cls, *args), daemon=True)
        t.start()
        self.threads.append(t)

    def _run_monitor(self, monitor_cls, *args):
        """Run a monitor in loop."""
        monitor = monitor_cls(*args)
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