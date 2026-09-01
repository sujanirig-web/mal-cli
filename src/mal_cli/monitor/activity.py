"""
Live tail of ActivityTaskManager / ActivityManager logcat lines.

Mirrors the shell command:
    adb logcat -v time ActivityTaskManager:I ActivityManager:I *:S
      | findstr /i "START Launched"

Runs `adb logcat` as a streaming subprocess and keeps the last N
interesting lines (START / Launch / Displayed) in a thread-safe buffer.
"""

import re
import subprocess
import threading
from collections import deque
from typing import List, Optional, Tuple

_AM_RE = re.compile(
    r"^\d{2}-\d{2} (\d\d:\d\d:\d\d)\.\d+\s+\d+\s+\d+\s+([VDIWEF]) (\S+): (.*)$"
)


def _interesting(line: str) -> bool:
    m = _AM_RE.match(line)
    if not m:
        return False
    return bool(re.search(r"start|launch|displayed", m.group(4), re.IGNORECASE))


def _clean(line: str) -> Optional[Tuple[str, str, str]]:
    m = _AM_RE.match(line)
    if not m:
        return None
    t, _sev, tag, msg = m.groups()
    return (t, tag, msg)


class ActivityMonitor:
    def __init__(self, client, serial: str, maxlen: int = 120):
        self.client = client
        self.serial = serial
        self._buffer: deque = deque(maxlen=maxlen)
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self):
        cmd = [self.client.adb_path, "-s", self.serial, "logcat", "-v", "time",
               "ActivityTaskManager:I", "ActivityManager:I", "*:S"]
        self._stop.clear()
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    def _read(self):
        try:
            while not self._stop.is_set() and self._proc and self._proc.stdout:
                line = self._proc.stdout.readline()
                if not line:
                    break
                line = line.rstrip("\r\n")
                if not _interesting(line):
                    continue
                cleaned = _clean(line)
                if cleaned:
                    self._buffer.append(cleaned)
        except Exception:
            pass

    def get_recent(self, limit: int = 20) -> List[Tuple[str, str, str]]:
        return list(self._buffer)[-limit:]

    def stop(self):
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
            try:
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        if self._thread:
            self._thread.join(timeout=2)