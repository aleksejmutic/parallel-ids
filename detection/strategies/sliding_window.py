from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

from detection.strategies.base import DetectionStrategy
from detection.strategies.batch import _process_partition  # same worker fn, different partitioning


class SlidingWindowStrategy(DetectionStrategy):
    """Slices the event timeline into fixed-size, non-overlapping windows
    and processes each window independently. (This is technically a
    "tumbling" window, not an overlapping sliding one — windows don't
    share events, which is exactly what makes them independent and safe
    to parallelize without coordination. An attack that straddles a
    window boundary can get split across two windows and under-counted;
    that's a real limitation worth discussing in your writeup, not a bug
    to silently fix.)"""

    name = "sliding_window"

    def __init__(self, window_seconds: int = 30, num_workers: int = 4):
        self.window_seconds = window_seconds
        self.num_workers = num_workers

    def process(self, events, rule_specs):
        windows: dict[int, list[dict]] = defaultdict(list)
        for event in events:
            window_id = int(event["timestamp"] // self.window_seconds)
            windows[window_id].append(event)

        alerts = []
        with ProcessPoolExecutor(max_workers=self.num_workers) as pool:
            futures = [
                pool.submit(_process_partition, window_events, rule_specs)
                for window_events in windows.values()
            ]
            for future in futures:
                alerts.extend(future.result())
        return alerts
