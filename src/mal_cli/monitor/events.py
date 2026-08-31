"""
Event queue for passing events between monitors and UI.
"""

from collections import deque
import threading
import time


class EventQueue:
    def __init__(self, maxlen=100):
        self.queue = deque(maxlen=maxlen)
        self.lock = threading.Lock()

    def put(self, event):
        event["timestamp"] = time.time()
        with self.lock:
            self.queue.append(event)

    def get_recent(self, limit=50):
        with self.lock:
            return list(self.queue)[-limit:]

    def clear(self):
        with self.lock:
            self.queue.clear()