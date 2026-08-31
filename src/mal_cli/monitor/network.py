"""
Monitor network usage.
"""

import time
from mal_cli.adb.commands import ADBCommands
from mal_cli.monitor.package_tracker import PackageTracker
from mal_cli.monitor.events import EventQueue


class NetworkMonitor:
    def __init__(self, cmds: ADBCommands, tracker: PackageTracker, event_queue: EventQueue):
        self.cmds = cmds
        self.tracker = tracker
        self.events = event_queue
        self.last_stats = {}

    def update(self):
        stats = self.cmds.get_network_stats()
        # Check for high usage
        for uid, total in stats.items():
            if uid in self.last_stats:
                diff = total - self.last_stats[uid]
                if diff > 1024 * 1024:  # > 1MB since last check
                    # Try to map uid to package
                    # We can use pm list packages but we'll skip for now
                    self.events.put({
                        "type": "HIGH_NETWORK",
                        "package": f"uid:{uid}",
                        "description": f"High network traffic: {diff} bytes"
                    })
        self.last_stats = stats