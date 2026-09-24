from datetime import datetime

from detection.rules.base import DetectionRule


class BruteForceRule(DetectionRule):
    name = "brute_force"

    def __init__(self, threshold=5, window_seconds=10):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.failures_by_ip = {}

    def evaluate(self, event: dict) -> dict | None:
        if event.get("metadata", {}).get("success") is not False:
            return None

        ip = event["source_ip"]
        timestamp = datetime.fromisoformat(event["timestamp"])

        history = self.failures_by_ip.setdefault(ip, [])
        history.append(timestamp)

        cutoff = timestamp.timestamp() - self.window_seconds

        self.failures_by_ip[ip] = [
            t for t in history
            if t.timestamp() > cutoff
        ]

        if len(self.failures_by_ip[ip]) >= self.threshold:
            return {
                "rule": self.name,
                "source_ip": ip,
                "count": len(self.failures_by_ip[ip]),
                "window_seconds": self.window_seconds,
                "timestamp": event["timestamp"],
            }

        return None