"""
Runs all three strategies against the same synthetic corpus at each
volume level, and prints/logs throughput + alert counts.

This is your evidence for the "where does parallelism actually pay off"
argument in the abstract. Run it as-is:

    python -m detection.benchmark

Expect batch/sliding_window to LOSE to serial at low volumes (process
pool startup overhead dominates) and win at high volumes — that
crossover point is itself a result worth reporting, not a bug to hide.
"""
import json
import time
from pathlib import Path

from detection.alert_logger import log_alerts
from detection.rules.brute_force import BruteForceRule
from detection.strategies.batch import BatchStrategy
from detection.strategies.serial import SerialStrategy
from detection.strategies.sliding_window import SlidingWindowStrategy
from detection.synthetic_events import generate_synthetic_events

RULE_SPECS = [(BruteForceRule, {"threshold": 5, "window_seconds": 60})]

STRATEGIES = [
    SerialStrategy(),
    BatchStrategy(num_workers=4),
    SlidingWindowStrategy(window_seconds=30, num_workers=4),
]

VOLUMES = [1_000, 5_000, 10_000, 50_000, 100_000]

RESULTS_PATH = Path("logs/benchmark_results.jsonl")


def run_benchmark():
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    results = []

    for volume in VOLUMES:
        # same corpus (same seed) reused across all three strategies at
        # this volume, so the comparison is apples-to-apples
        events = generate_synthetic_events(volume, seed=42)

        for strategy in STRATEGIES:
            start = time.perf_counter()
            alerts = strategy.process(events, RULE_SPECS)
            elapsed = time.perf_counter() - start

            log_alerts(alerts, strategy.name)

            result = {
                "strategy": strategy.name,
                "volume": volume,
                "elapsed_seconds": elapsed,
                "events_per_second": (volume / elapsed) if elapsed > 0 else None,
                "alert_count": len(alerts),
            }
            results.append(result)

            print(
                f"[{strategy.name:15s}] volume={volume:>7} "
                f"time={elapsed:.4f}s  alerts={len(alerts):>4}  "
                f"throughput={result['events_per_second']:.1f} ev/s"
            )

            with RESULTS_PATH.open("a") as f:
                f.write(json.dumps(result) + "\n")

    return results


if __name__ == "__main__":
    run_benchmark()
