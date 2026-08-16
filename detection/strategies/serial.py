from detection.strategies.base import DetectionStrategy


class SerialStrategy(DetectionStrategy):
    """Baseline: one thread, one process, events handled strictly in order.
    Everything else gets measured against this."""

    name = "serial"

    def process(self, events, rule_specs):
        rules = [cls(**kwargs) for cls, kwargs in rule_specs]
        alerts = []
        for event in events:
            for rule in rules:
                alert = rule.evaluate(event)
                if alert:
                    alerts.append(alert)
        return alerts
