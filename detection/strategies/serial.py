from detection.strategies.base import DetectionStrategy


class SerialStrategy(DetectionStrategy):
    """Baseline: one thread, one process, events handled strictly in order.
    Everything else gets measured against this."""

    name = "serial"

    def __init__(self, rule_specs):
        self.rules = [
            cls(**kwargs)
            for cls, kwargs in rule_specs
        ]

    def process(self, events):
        alerts = []

        for event in events:
            for rule in self.rules:
                alert = rule.evaluate(event)

                if alert:
                    alerts.append(alert)

        return alerts