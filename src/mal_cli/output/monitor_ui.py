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
        # Professional dark scheme with green accents
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)       # header / prompt
            curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_GREEN)  # online badge
            curses.init_pair(3, curses.COLOR_YELLOW, -1)      # high risk
            curses.init_pair(4, curses.COLOR_RED, -1)         # critical risk
            curses.init_pair(5, curses.COLOR_MAGENTA, -1)     # medium risk
            curses.init_pair(6, curses.COLOR_CYAN, -1)        # info / labels
            curses.init_pair(7, curses.COLOR_WHITE, -1)       # normal
        self.running = True
        while self.running:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            # Header bar
            title = "  ◆ mal-cli MONITOR  "
            stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(0, 0, title.ljust(width))
            stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(1, 0, "  [q] quit   |   Ctrl+C to return", curses.color_pair(6))
            # Divider
            stdscr.addstr(2, 0, "─" * width, curses.color_pair(6))
            # Package table header
            y = 4
            label = "PACKAGE".ljust(25) + "STATUS".ljust(15) + "RISK"
            stdscr.addstr(y, 0, label, curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(y + 1, 0, "─" * width, curses.color_pair(6))
            y += 2
            with self.lock:
                for pkg in self.packages[-height+10:]:
                    name = pkg.get("name", "")[:24]
                    status = pkg.get("status", "UNKNOWN")[:14]
                    risk = pkg.get("risk", "")
                    if "CRITICAL" in risk:
                        c = curses.color_pair(4) | curses.A_BOLD
                    elif "HIGH" in risk:
                        c = curses.color_pair(3)
                    elif "MEDIUM" in risk:
                        c = curses.color_pair(5)
                    elif "SAFE" in risk:
                        c = curses.color_pair(1)
                    else:
                        c = curses.color_pair(7)
                    if y < height - 2:
                        stdscr.addstr(y, 0, name.ljust(25), curses.color_pair(7))
                        stdscr.addstr(y, 25, status.ljust(15), curses.color_pair(7))
                        stdscr.addstr(y, 40, risk, c)
                        y += 1
                # Events section
                y += 1
                if y < height:
                    stdscr.addstr(y, 0, "EVENTS", curses.color_pair(1) | curses.A_BOLD)
                y += 1
                for evt in self.events[-8:]:
                    if y < height - 1:
                        line = f"{evt.get('timestamp', '')} {evt.get('package', '')}: {evt.get('description', '')[:50]}"
                        stdscr.addstr(y, 0, line[:width], curses.color_pair(7))
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