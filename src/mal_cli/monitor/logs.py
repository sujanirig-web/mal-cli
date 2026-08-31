"""
Monitor logcat for security-relevant messages.
"""

import re
from mal_cli.adb.commands import ADBCommands
from mal_cli.monitor.package_tracker import PackageTracker
from mal_cli.monitor.events import EventQueue


class LogMonitor:
    def __init__(self, cmds: ADBCommands, tracker: PackageTracker, event_queue: EventQueue):
        self.cmds = cmds
        self.tracker = tracker
        self.events = event_queue
        self.last_log_count = 0

    def update(self):
        logs = self.cmds.get_logcat()
        # Process new logs (naive: just take latest N)
        new_logs = logs[self.last_log_count:]
        self.last_log_count = len(logs)
        for line in new_logs:
            # Look for error/warning patterns
            if "E/" in line or "W/" in line:
                # Try to extract package name (e.g., from activity manager)
                pkg_match = re.search(r'([a-zA-Z0-9_.]+)\s*:\s*', line)
                if pkg_match:
                    pkg = pkg_match.group(1)
                    if '.' in pkg:  # likely a package
                        self.events.put({
                            "type": "LOG_WARNING",
                            "package": pkg,
                            "description": line[:100]
                        })