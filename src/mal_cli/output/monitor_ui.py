"""
Live monitoring UI using curses or simple print.
"""

import sys
import time
import threading
from typing import List, Dict

try:
    import curses
    HAS_CURSES = True
except ImportError:
    HAS_CURSES = False


class MonitorUI:
    def __init__(self):
        self.running = False
        self.packages = []
        self.events = []
        self.lock = threading.Lock()

    def start(self):
        if HAS_CURSES:
            self._start_curses()
        else:
            self._start_simple()

    def _start_curses(self):
        # Simplified curses loop – we'll use wrapper
        curses.wrapper(self._curses_loop)

    def _curses_loop(self, stdscr):
        curses.curs_set(0)
        stdscr.nodelay(1)
        self.running = True
        while self.running:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            # Header
            stdscr.addstr(0, 0, "mal-cli Monitor", curses.A_BOLD)
            stdscr.addstr(1, 0, "Press 'q' to quit")
            # Package list
            y = 3
            stdscr.addstr(y, 0, "PACKAGE".ljust(25) + "STATUS".ljust(15) + "RISK")
            y += 1
            with self.lock:
                for pkg in self.packages[-height+5:]:
                    name = pkg.get("name", "")[:24]
                    status = pkg.get("status", "UNKNOWN")[:14]
                    risk = pkg.get("risk", "")
                    color = curses.COLOR_WHITE
                    if "CRITICAL" in risk:
                        color = curses.COLOR_RED
                    elif "HIGH" in risk:
                        color = curses.COLOR_YELLOW
                    elif "MEDIUM" in risk:
                        color = curses.COLOR_MAGENTA
                    elif "SAFE" in risk:
                        color = curses.COLOR_GREEN
                    if y < height - 2:
                        stdscr.addstr(y, 0, name.ljust(25), curses.color_pair(color))
                        stdscr.addstr(y, 25, status.ljust(15))
                        stdscr.addstr(y, 40, risk)
                        y += 1
                # Events
                y += 1
                stdscr.addstr(y, 0, "EVENTS:", curses.A_BOLD)
                y += 1
                for evt in self.events[-10:]:
                    if y < height - 1:
                        stdscr.addstr(y, 0, f"{evt.get('timestamp', '')} {evt.get('package', '')}: {evt.get('description', '')[:50]}")
                        y += 1
            stdscr.refresh()
            time.sleep(0.5)
            c = stdscr.getch()
            if c == ord('q'):
                self.running = False
                break

    def _start_simple(self):
        # Simple scrolling text
        self.running = True
        while self.running:
            # Clear screen (ANSI)
            print("\033[2J\033[H", end="")
            print("mal-cli Monitor (press Ctrl+C to exit)")
            print("=" * 50)
            with self.lock:
                print("PACKAGE".ljust(25) + "STATUS".ljust(15) + "RISK")
                for pkg in self.packages:
                    name = pkg.get("name", "")[:24]
                    status = pkg.get("status", "UNKNOWN")[:14]
                    risk = pkg.get("risk", "")
                    print(f"{name.ljust(25)}{status.ljust(15)}{risk}")
                print("\nRecent Events:")
                for evt in self.events[-5:]:
                    print(f"{evt.get('timestamp', '')} {evt.get('package', '')}: {evt.get('description', '')[:60]}")
            time.sleep(2)

    def stop(self):
        self.running = False

    def update(self, packages: List[Dict], events: List[Dict]):
        with self.lock:
            self.packages = packages
            self.events = events