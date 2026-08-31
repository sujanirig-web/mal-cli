"""
Monitor foreground app.
"""

import time
from mal_cli.adb.commands import ADBCommands
from mal_cli.monitor.package_tracker import PackageTracker
from mal_cli.monitor.events import EventQueue


class ForegroundMonitor:
    def __init__(self, cmds: ADBCommands, tracker: PackageTracker, event_queue: EventQueue):
        self.cmds = cmds
        self.tracker = tracker
        self.events = event_queue
        self.last_foreground = None

    def update(self):
        fg = self.cmds.get_foreground_activity()
        if fg != self.last_foreground:
            if fg:
                self.events.put({
                    "type": "FOREGROUND_CHANGED",
                    "package": fg,
                    "description": f"App {fg} came to foreground"
                })
            self.last_foreground = fg