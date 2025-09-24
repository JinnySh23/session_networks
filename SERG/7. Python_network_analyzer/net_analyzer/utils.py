# utils.py
from collections import deque
import time

class SlidingWindow:
    """
    Хранит временную последовательность timestamp -> value.
    Позволяет быстро получать события только за последние window_seconds.
    """
    def __init__(self, window_seconds):
        self.window = deque()
        self.window_seconds = window_seconds

    def add(self, item_timestamp, item):
        self.window.append((item_timestamp, item))
        self._trim()

    def _trim(self):
        cutoff = time.time() - self.window_seconds
        while self.window and self.window[0][0] < cutoff:
            self.window.popleft()

    def items(self):
        self._trim()
        return list(self.window)

    def count(self):
        self._trim()
        return len(self.window)
