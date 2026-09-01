"""
Live monitoring UI: a clean ANSI frame rendered on each refresh.

The Monitor loop owns the timing; this class only draws a full frame
(move-to-home + clear) every cycle, so it never blocks.
"""

import sys
import time
from typing import Dict, List

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
RED = "\x1b[31m"
CYAN = "\x1b[36m"


def _risk_color(risk: str) -> str:
    up = risk.upper()
    if "CRITICAL" in up or "HIGH" in up:
        return RED
    if "MEDIUM" in up:
        return YELLOW
    if "SAFE" in up:
        return GREEN
    return CYAN


class MonitorUI:
    def __init__(self):
        self.running = False
        self.packages: List[Dict] = []
        self.events: List[Dict] = []
        self.activity: List[tuple] = []

    def start(self):
        """Hide the cursor and draw an initial frame. Returns immediately."""
        self.running = True
        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()
        self.render([], [])

    def render(self, packages: List[Dict], events: List[Dict],
               activity: List[tuple] = None):
        """Redraw the whole frame at home position."""
        if not self.running:
            return
        self.packages = packages
        self.events = events
        self.activity = activity or []
        now = time.strftime("%H:%M:%S")
        out = ["\x1b[H\x1b[J"]
        out.append(BOLD + GREEN + "  mal-cli MONITOR" + RESET + DIM
                   + "   [Ctrl+C to return to shell]  " + now + RESET + "\n")
        out.append("\n")
        header = f"{'PACKAGE':<30}{'PIDS':>5}  {'STATUS':<14}{'RISK'}"
        out.append(BOLD + header + RESET + "\n")
        out.append(DIM + "-" * len(header) + RESET + "\n")
        if not packages:
            out.append(DIM + "  Collecting data from device..." + RESET + "\n")
        for p in packages:
            name = p.get("name", "?")[:29]
            pids = p.get("processes", "")
            status = p.get("status", "UNKNOWN")
            risk = p.get("risk", "NOT SCANNED")
            fmt_status = (GREEN + f"{status:<14}" + RESET
                          if status == "FOREGROUND" else f"{status:<14}")
            fmt_risk = _risk_color(risk) + f"{risk:<18}" + RESET
            out.append(f"  {name:<28}{pids:>5}  {fmt_status}{fmt_risk}\n")
        out.append("\n" + BOLD + "LIVE ACTIVITY" + RESET + DIM
                   + "  (ActivityManager / ActivityTaskManager)" + RESET + "\n")
        out.append(DIM + "-" * len(header) + RESET + "\n")
        if not self.activity:
            out.append(DIM + "  Waiting for activity log..." + RESET + "\n")
        for item in self.activity[-8:]:
            t, tag, msg = item
            out.append(f"  {GREEN}{t}{RESET} [{DIM}{tag}{RESET}] {msg[:100]}\n")
        out.append("\n" + BOLD + "EVENTS" + RESET + "\n")
        out.append(DIM + "-" * len(header) + RESET + "\n")
        if not events:
            out.append(DIM + "  No events recorded yet." + RESET + "\n")
        for evt in events[-6:]:
            ts = time.strftime("%H:%M:%S", time.localtime(evt.get("timestamp", 0)))
            pkg = evt.get("package", "?")
            desc = evt.get("description", "")
            out.append(DIM + f"  {ts} " + RESET + f"{pkg:<30} {desc}\n")
        sys.stdout.write("".join(out))
        sys.stdout.flush()

    def stop(self):
        self.running = False
        sys.stdout.write("\x1b[?25h\n")
        sys.stdout.flush()