import zlib
from collections import defaultdict

from detection.strategies.base import PooledStrategy


def _process_partition(events: list[dict], rule_specs) -> list[dict]:
    """Runs inside a worker process. Builds fresh rule instances so this
    partition's state never touches any other partition's state -- and so
    reusing the pool across calls can't leak state between them either."""
    rules = [cls(**kwargs) for cls, kwargs in rule_specs]
    alerts = []
    for event in events:
        for rule in rules:
            alert = rule.evaluate(event)
            if alert:
                alerts.append(alert)
    return alerts


def _stable_bucket(source_ip: str, num_workers: int) -> int:
    """Deterministic partition assignment.

    The builtin hash() salts string hashing per interpreter (PYTHONHASHSEED),
    so hash(ip) gives different buckets in different processes/runs. That's
    invisible while results happen to be correct, but it makes partitioning
    non-reproducible. crc32 is stable across processes and runs.
    """
    return zlib.crc32(source_ip.encode("utf-8")) % num_workers


class BatchStrategy(PooledStrategy):
    """Partitions the active IP space into num_workers groups. Every rule
    runs against every partition, but each partition only ever sees its
    own slice of IPs, so no cross-worker state sharing is needed.

    The pool is owned by PooledStrategy: created once, reused across calls,
    warmed via warmup() before timing.
    """

    name = "batch"

    def process(self, events, rule_specs):
        pool = self._ensure_pool()

        partitions: dict[int, list[dict]] = defaultdict(list)
        for event in events:
            partition_id = _stable_bucket(event["source_ip"], self.num_workers)
            partitions[partition_id].append(event)

        alerts = []
        futures = [
            pool.submit(_process_partition, part, rule_specs)
            for part in partitions.values()
        ]
        for future in futures:
            alerts.extend(future.result())
        return alerts