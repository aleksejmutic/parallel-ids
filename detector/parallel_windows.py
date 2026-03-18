"""
Parallel detector — Layer 3: time window parallelism.

The full event timeline is divided into fixed-size time windows.
Each window is processed independently and simultaneously by a worker process.
Results from all windows are merged and deduplicated at the end.

Architecture (example: 60 minutes of events, 10-minute windows):
    [window 00:00-10:00 → worker 1] ─┐
    [window 10:00-20:00 → worker 2]  ├→ merge → deduplicate → alerts
    [window 20:00-30:00 → worker 3]  │
    [window 30:00-40:00 → worker 4] ─┘
    (windows 40-60 processed in next round)

Why this matters: in a real streaming IDS, new events arrive constantly.
Time window parallelism means you don't wait for window N to finish
before starting window N+1.

Deduplication: the same attack can span multiple windows. An IP that
brute-forces across a window boundary would fire alerts in both windows.
We deduplicate by (ip, rule_name) keeping the alert with the highest event count.
"""

import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import Optional

from serial_detector import apply_all_rules, group_by_ip, BenchmarkResult

WORKERS        = 4    # physical cores on i5-11320H
WINDOW_MINUTES = 5    # size of each time window


# ── Window worker (module-level for pickling) ─────────────────────────────────

def process_window(args):
    """
    Process one time window: filter events to the window,
    group by IP, apply all rules.
    Returns (window_label, alerts_list).
    """
    window_start, window_end, all_events, scenario_id = args

    # Filter events belonging to this window
    window_events = []
    for e in all_events:
        try:
            ts = datetime.fromisoformat(e["timestamp"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if window_start <= ts < window_end:
                window_events.append(e)
        except Exception:
            pass

    if not window_events:
        return (window_start.isoformat(), [])

    by_ip  = group_by_ip(window_events)
    alerts = []
    for ip, ip_events in by_ip.items():
        alerts.extend(apply_all_rules(ip, ip_events, scenario_id))

    label = f"{window_start.strftime('%H:%M')}-{window_end.strftime('%H:%M')}"
    return (label, alerts)


def _build_windows(events: list, window_minutes: int) -> list:
    """
    Scan events to find the earliest and latest timestamps,
    then build a list of (start, end) window tuples covering that range.
    """
    timestamps = []
    for e in events:
        try:
            ts = datetime.fromisoformat(e["timestamp"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            timestamps.append(ts)
        except Exception:
            pass

    if not timestamps:
        return []

    earliest = min(timestamps)
    latest   = max(timestamps)
    delta    = timedelta(minutes=window_minutes)

    # Round earliest down to the nearest window boundary
    epoch    = datetime(1970, 1, 1, tzinfo=timezone.utc)
    seconds  = int((earliest - epoch).total_seconds())
    boundary = epoch + timedelta(seconds=(seconds // (window_minutes * 60)) * window_minutes * 60)

    windows = []
    current = boundary
    while current <= latest:
        windows.append((current, current + delta))
        current += delta

    return windows


def _deduplicate_alerts(all_alerts: list) -> list:
    """
    Remove duplicate alerts for the same (ip, rule_name).
    When an attack spans a window boundary it will fire in both windows —
    keep the one with the highest event count as it has more context.
    """
    best = {}   # (ip, rule_name) → alert
    for alert in all_alerts:
        key = (alert["source_ip"], alert["rule_name"])
        if key not in best or alert["event_count"] > best[key]["event_count"]:
            best[key] = alert
    return list(best.values())


def run_parallel_windows(
    events: list,
    scenario_id: Optional[str] = None,
    window_minutes: int = WINDOW_MINUTES,
    n_workers: int = WORKERS,
) -> BenchmarkResult:
    """
    Layer 3 parallel: time windows processed simultaneously.

    Steps:
      1. Scan events to determine the full time range
      2. Divide that range into window_minutes-sized windows
      3. Submit each window to the process pool
      4. Collect results, deduplicate cross-window alerts
    """
    start   = time.perf_counter()
    windows = _build_windows(events, window_minutes)

    if not windows:
        return BenchmarkResult("parallel_windows", len(events), 0, 0, 0, {})

    print(f"  [windows] {len(windows)} windows of {window_minutes}min "
          f"across {n_workers} workers")

    raw_alerts    = []
    window_counts = defaultdict(int)

    with ProcessPoolExecutor(max_workers=n_workers) as pool:
        futures = [
            pool.submit(process_window, (w_start, w_end, events, scenario_id))
            for w_start, w_end in windows
        ]
        for future in as_completed(futures):
            label, w_alerts = future.result()
            raw_alerts.extend(w_alerts)
            window_counts[label] = len(w_alerts)

    # Deduplicate alerts that fired in multiple windows
    deduped = _deduplicate_alerts(raw_alerts)

    elapsed = time.perf_counter() - start

    alerts_by_rule = defaultdict(int)
    for a in deduped:
        alerts_by_rule[a["rule_name"]] += 1

    return BenchmarkResult(
        mode              = f"parallel_windows_{window_minutes}min",
        total_events      = len(events),
        total_alerts      = len(deduped),
        elapsed_seconds   = elapsed,
        events_per_second = len(events) / elapsed if elapsed > 0 else 0,
        alerts_by_rule    = dict(alerts_by_rule),
    )


if __name__ == "__main__":
    from detector.benchmark import generate_events
    events = generate_events(5000)
    result = run_parallel_windows(events)
    print(f"[parallel_windows] {result.total_events} events → "
          f"{result.total_alerts} alerts in {result.elapsed_seconds:.4f}s "
          f"({result.events_per_second:.0f} events/sec)")
