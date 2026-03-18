"""
Parallel detector — Layer 2: batch splitting within each rule type.

Events are grouped by IP, then those IP groups are split into
equal-sized batches. Each batch runs on a separate worker process.
Results from all batches are merged at the end.

Architecture (example with 4 workers, brute force rule):
    100 IPs total → split into 4 batches of 25 IPs each
    [IPs  1-25 → worker 1] ─┐
    [IPs 26-50 → worker 2]  ├→ merge → deduplicate → alerts
    [IPs 51-75 → worker 3]  │
    [IPs 76-100→ worker 4] ─┘

This is applied to ALL rules simultaneously, so the full matrix is:
    6 rules × 4 batches = 24 concurrent tasks

Physical cores on i5-11320H: 4
Optimal workers: 4 (one per physical core)
"""

import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional

from serial_detector import (
    apply_all_rules, group_by_ip, BenchmarkResult
)

WORKERS = 4   # matches physical core count on i5-11320H


# ── Batch worker (module-level for pickling) ──────────────────────────────────

def process_ip_batch(args):
    """
    Process one batch: a subset of IPs, all rules applied.
    Returns a list of alert dicts.
    This runs in its own OS process.
    """
    ip_batch, scenario_id = args
    alerts = []
    for ip, ip_events in ip_batch:
        alerts.extend(apply_all_rules(ip, ip_events, scenario_id))
    return alerts


def _split_into_batches(ip_items: list, n_batches: int) -> list:
    """
    Split a list of (ip, events) tuples into n_batches equal chunks.
    Last batch gets any remainder.
    """
    total     = len(ip_items)
    size      = max(1, total // n_batches)
    batches   = []
    for i in range(0, total, size):
        batches.append(ip_items[i : i + size])
    return batches


def run_parallel_batch(
    events: list,
    scenario_id: Optional[str] = None,
    n_workers: int = WORKERS,
) -> BenchmarkResult:
    """
    Layer 2 parallel: IP groups split into batches, each batch on its own process.
    All batches run simultaneously using ProcessPoolExecutor.

    Steps:
      1. Group all 5000 events by source IP
      2. Split IP groups into n_workers equal batches
      3. Submit each batch to the process pool
      4. Collect and merge results from all workers
    """
    start    = time.perf_counter()
    by_ip    = group_by_ip(events)
    ip_items = list(by_ip.items())   # [(ip, [events...]), ...]

    batches   = _split_into_batches(ip_items, n_workers)
    all_alerts = []

    print(f"  [batch] {len(ip_items)} IPs → {len(batches)} batches "
          f"(~{len(batches[0])} IPs/batch) across {n_workers} workers")

    with ProcessPoolExecutor(max_workers=n_workers) as pool:
        futures = [
            pool.submit(process_ip_batch, (batch, scenario_id))
            for batch in batches
        ]
        for future in as_completed(futures):
            batch_alerts = future.result()
            all_alerts.extend(batch_alerts)

    elapsed = time.perf_counter() - start

    alerts_by_rule = defaultdict(int)
    for a in all_alerts:
        alerts_by_rule[a["rule_name"]] += 1

    return BenchmarkResult(
        mode              = f"parallel_batch_{n_workers}w",
        total_events      = len(events),
        total_alerts      = len(all_alerts),
        elapsed_seconds   = elapsed,
        events_per_second = len(events) / elapsed if elapsed > 0 else 0,
        alerts_by_rule    = dict(alerts_by_rule),
    )


def run_parallel_batch_scaling(
    events: list,
    scenario_id: Optional[str] = None,
) -> list:
    """
    Run batch mode with 2, 4 workers to show scaling curve.
    Returns a list of BenchmarkResults — one per worker count.
    """
    results = []
    for n in [2, 4]:
        print(f"\n  Testing {n} workers...")
        r = run_parallel_batch(events, scenario_id, n_workers=n)
        results.append(r)
    return results


if __name__ == "__main__":
    from detector.benchmark import generate_events
    events = generate_events(5000)
    for result in run_parallel_batch_scaling(events):
        print(f"[{result.mode}] {result.total_events} events → "
              f"{result.total_alerts} alerts in {result.elapsed_seconds:.4f}s "
              f"({result.events_per_second:.0f} events/sec)")
