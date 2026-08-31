"""
Monitor process changes.
"""

import time
from mal_cli.adb.commands import ADBCommands
from mal_cli.monitor.package_tracker import PackageTracker
from mal_cli.monitor.events import EventQueue


class ProcessMonitor:
    def __init__(self, cmds: ADBCommands, tracker: PackageTracker, event_queue: EventQueue):
        self.cmds = cmds
        self.tracker = tracker
        self.events = event_queue
        self.last_processes = set()

    def update(self):
        processes = self.cmds.get_running_processes()
        current = set()
        for proc in processes:
            # Associate process name to package (simplified)
            name = proc["name"]
            if '/' in name:
                pkg = name.split('/')[0]
            else:
                pkg = name
            current.add((pkg, proc["pid"]))
        # Detect new processes
        new = current - self.last_processes
        for pkg, pid in new:
            self.events.put({
                "type": "PROCESS_STARTED",
                "package": pkg,
                "description": f"Process {pid} started"
            })
        # Detect terminated processes
        terminated = self.last_processes - current
        for pkg, pid in terminated:
            self.events.put({
                "type": "PROCESS_TERMINATED",
                "package": pkg,
                "description": f"Process {pid} terminated"
            })
        self.last_processes = current