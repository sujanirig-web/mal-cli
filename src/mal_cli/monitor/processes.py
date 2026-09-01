"""
Monitor process changes.
"""

import time
from typing import Dict
from mal_cli.adb.commands import ADBCommands
from mal_cli.monitor.package_tracker import PackageTracker
from mal_cli.monitor.events import EventQueue


class ProcessMonitor:
    def __init__(self, cmds: ADBCommands, tracker: PackageTracker, event_queue: EventQueue):
        self.cmds = cmds
        self.tracker = tracker
        self.events = event_queue
        self.last_processes = set()
        self.current: Dict[str, list] = {}

    def update(self):
        processes = self.cmds.get_running_processes()
        current = {}
        for proc in processes:
            name = proc["name"]
            if name.startswith("["):
                # Kernel threads (e.g. [kworker/0:1]) - not user processes
                continue
            if '/' in name:
                pkg = name.split('/')[0]
            else:
                pkg = name
            current.setdefault(pkg, []).append(proc["pid"])
        self.current = current
        current_set = set()
        for pkg, pids in current.items():
            for pid in pids:
                current_set.add((pkg, pid))
        # Detect new processes
        new = current_set - self.last_processes
        for pkg, pid in new:
            self.events.put({
                "type": "PROCESS_STARTED",
                "package": pkg,
                "description": f"Process {pid} started"
            })
        # Detect terminated processes
        terminated = self.last_processes - current_set
        for pkg, pid in terminated:
            self.events.put({
                "type": "PROCESS_TERMINATED",
                "package": pkg,
                "description": f"Process {pid} terminated"
            })
        self.last_processes = current_set

    def snapshot(self) -> Dict[str, dict]:
        """Return currently running packages mapped to their PIDs."""
        return {pkg: {"pids": list(pids)} for pkg, pids in self.current.items()}