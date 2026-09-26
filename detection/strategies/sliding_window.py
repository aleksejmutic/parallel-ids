from collections import defaultdict
from datetime import datetime

from detection.strategies.base import PooledStrategy
from detection.strategies.batch import _process_partition  # same worker fn, different partitioning


class SlidingWindowStrategy(PooledStrategy):
    """Slices the event timeline into fixed-size, non-overlapping windows
    and processes each window independently. (Technically a "tumbling"
    window, not an overlapping sliding one -- windows don't share events,
    which is what makes them independent and safe to parallelize without
    coordination. An attack that straddles a window boundary can be split
    across two windows and under-counted; that's a real limitation worth
    discussing in the writeup, not a bug to silently fix.)

    The pool is owned by PooledStrategy: created once, reused across calls,
    warmed via warmup() before timing.
    """

    name = "sliding_window"

    def __init__(self, window_seconds: int = 30, num_workers: int = 4):
        super().__init__(num_workers=num_workers)
        self.window_seconds = window_seconds

    @staticmethod
    def _epoch(event: dict) -> float:
        # Events carry ISO-8601 string timestamps (see core/event_factory.py),
        # so convert to epoch seconds before bucketing into windows.
        return datetime.fromisoformat(event["timestamp"]).timestamp()

    def process(self, events, rule_specs):
        pool = self._ensure_pool()

        windows: dict[int, list[dict]] = defaultdict(list)
        for event in events:
            window_id = int(self._epoch(event) // self.window_seconds)
            windows[window_id].append(event)

        alerts = []
        futures = [
            pool.submit(_process_partition, window_events, rule_specs)
            for window_events in windows.values()
        ]
        for future in futures:
            alerts.extend(future.result())
        return alerts