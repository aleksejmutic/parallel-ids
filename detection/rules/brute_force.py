from detection.rules.base import DetectionRule


class BruteForceRule(DetectionRule):
    name = "ssh_brute_force"

    def __init__(self, threshold=5, window_seconds=10):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.failures_by_ip = {}  # local to this worker/process, no sharing needed

    def evaluate(self, event: dict) -> dict | None:
        if event.get("source_type") != "ssh" or event.get("outcome") != "failure":
            return None

        ip = event["source_ip"]
        ts = event["timestamp"]

        history = self.failures_by_ip.setdefault(ip, [])
        history.append(ts)
        # drop anything outside the window
        self.failures_by_ip[ip] = [t for t in history if t > ts - self.window_seconds]

        if len(self.failures_by_ip[ip]) >= self.threshold:
            return {
                "rule": self.name,
                "source_ip": ip,
                "count": len(self.failures_by_ip[ip]),
                "window_seconds": self.window_seconds,
                "timestamp": ts,
            }
        return None
