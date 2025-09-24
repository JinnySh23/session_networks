# alerts.py
import time
from collections import defaultdict

class AlertManager:
    def __init__(self, cooldown=10):
        self.last_alert = defaultdict(lambda: 0)
        self.cooldown = cooldown

    def send(self, key, message):
        now = time.time()
        if now - self.last_alert[key] < self.cooldown:
            return
        self.last_alert[key] = now
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        print(f"[ALERT {ts}] {message}")
