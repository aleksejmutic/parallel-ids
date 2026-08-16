from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

from detection.strategies.base import DetectionStrategy


def _process_partition(events: list[dict], rule_specs) -> list[dict]:
    """Runs inside a worker process. Builds fresh rule instances so this
    partition's state never touches any other partition's state."""
    rules = [cls(**kwargs) for cls, kwargs in rule_specs]
    alerts = []
    for event in events:
        for rule in rules:
            alert = rule.evaluate(event)
            if alert:
                alerts.append(alert)
    return alerts


class BatchStrategy(DetectionStrategy):
    """Partitions the active IP space into num_workers groups. Every rule
    runs against every partition, but each partition only ever sees its
    own slice of IPs, so no cross-worker state sharing is needed."""

    name = "batch"

    def __init__(self, num_workers: int = 4):
        self.num_workers = num_workers

    def process(self, events, rule_specs):
        partitions: dict[int, list[dict]] = defaultdict(list)
        for event in events:
            partition_id = hash(event["source_ip"]) % self.num_workers
            partitions[partition_id].append(event)

        alerts = []
        with ProcessPoolExecutor(max_workers=self.num_workers) as pool:
            futures = [
                pool.submit(_process_partition, part, rule_specs)
                for part in partitions.values()
            ]
            for future in futures:
                alerts.extend(future.result())
        return alerts
