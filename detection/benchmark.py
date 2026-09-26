"""
Runs the detection strategies against the same synthetic corpus at each
volume level and reports throughput + alert counts.

This is the evidence for the "where does parallelism actually pay off"
argument: expect batch/sliding_window to LOSE to serial at low volumes
(per-event work is cheaper than the cost of shipping events to workers)
and to win at higher volumes on a multi-core machine. That crossover point
is a result worth reporting, not a bug to hide.

Two things make the comparison fair rather than accidentally rigged:

  - The process pools are created ONCE and reused across volumes (see
    PooledStrategy), not rebuilt inside every process() call. Rebuilding
    per call charges worker-spawn cost to every measurement and buries the
    parallel strategies at low volume.
  - warmup() spawns those workers before the timed loop, so the one-off
    fork/import cost lands outside every measured region.

Note: parallelism needs multiple cores. On a single-core host batch and
sliding_window cannot beat serial no matter what -- there's nothing to run
in parallel, only pool overhead to pay. Run this on the real multi-core
box to see the crossover.

Run it standalone:

    python -m detection.benchmark
"""
import json
import time
from pathlib import Path

from detection.alert_logger import log_alerts
from detection.rules.ssh.brute_force import BruteForceRule
from detection.strategies.batch import BatchStrategy
from detection.strategies.serial import SerialStrategy
from detection.strategies.sliding_window import SlidingWindowStrategy
from detection.synthetic_events import generate_synthetic_events

RULE_SPECS = [(BruteForceRule, {"threshold": 5, "window_seconds": 60})]

VOLUMES = [1_000, 5_000, 10_000, 50_000, 100_000]

RESULTS_PATH = Path("logs/benchmark_results.jsonl")


def run_benchmark(on_result=None):
    """Run every strategy at every volume.

    on_result: optional callback invoked with each result dict as soon as
    it is measured. The web dashboard uses this to stream progress; the CLI
    leaves it None.
    """
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    results = []

    # Parallel strategies are stateless across calls (they build fresh rules
    # inside each partition), so they are created ONCE and reused for every
    # volume. Their pools are warmed here so no single volume pays the
    # one-off worker-spawn cost inside its timed region.
    batch = BatchStrategy(num_workers=4).warmup()
    window = SlidingWindowStrategy(window_seconds=30, num_workers=4).warmup()

    try:
        for volume in VOLUMES:
            # same corpus (same seed) reused across all strategies at this
            # volume, so the comparison is apples-to-apples
            events = generate_synthetic_events(volume, seed=42)

            # SerialStrategy is stateful (per-IP failure history), so rebuild
            # it fresh each volume to keep volume levels independent. It's
            # constructed WITH the specs and its process() takes only events,
            # matching the live pipeline (orchestration/detection.py).
            serial = SerialStrategy(RULE_SPECS)

            runners = [
                ("serial", lambda events, s=serial: s.process(events)),
                ("batch", lambda events, s=batch: s.process(events, RULE_SPECS)),
                ("sliding_window", lambda events, s=window: s.process(events, RULE_SPECS)),
            ]

            for name, run in runners:
                start = time.perf_counter()
                alerts = run(events)
                elapsed = time.perf_counter() - start

                log_alerts(alerts, name)

                result = {
                    "strategy": name,
                    "volume": volume,
                    "elapsed_seconds": elapsed,
                    "events_per_second": (volume / elapsed) if elapsed > 0 else None,
                    "alert_count": len(alerts),
                }
                results.append(result)

                print(
                    f"[{name:15s}] volume={volume:>7} "
                    f"time={elapsed:.4f}s  alerts={len(alerts):>5}  "
                    f"throughput={result['events_per_second']:.1f} ev/s"
                )

                with RESULTS_PATH.open("a") as f:
                    f.write(json.dumps(result) + "\n")

                if on_result is not None:
                    on_result(result)
    finally:
        # shut the worker processes down cleanly even if a run raises
        batch.close()
        window.close()

    return results


if __name__ == "__main__":
    run_benchmark()