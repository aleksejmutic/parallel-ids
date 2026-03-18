"""
Pipeline detector — bridge between run.py and the parallel detectors.
Reads events from ids_data.db, runs all four detection modes,
saves comparison to pipeline_results.json for the Flask dashboard.

Called automatically by Flask after run.py finishes.
Can also be run standalone: python3 pipeline_detector.py
"""

import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "detector"))

from storage.db import get_events, init_db
from detector.serial_detector    import run_serial
from detector.parallel_type      import run_parallel_by_type
from detector.parallel_batch     import run_parallel_batch
from detector.parallel_windows   import run_parallel_windows


def load_events_from_db(limit: int = 50000) -> list:
    """Load all events saved by run.py from SQLite."""
    return get_events(limit=limit)


def run_all_modes(events: list) -> list:
    """Run all four detection modes on the same event set and return results."""
    results = []

    print(f"[pipeline] {len(events)} events loaded from DB")
    print(f"[pipeline] {len(set(e['source_ip'] for e in events))} unique IPs\n")

    print("[1/4] Serial detector (no parallelism — baseline)...")
    r = run_serial(events)
    results.append(r)
    print(f"      {r.total_alerts} alerts in {r.elapsed_seconds:.4f}s "
          f"({r.events_per_second:.0f} evt/sec)\n")

    print("[2/4] Parallel by intrusion type (one worker per rule)...")
    r = run_parallel_by_type(events)
    results.append(r)
    print(f"      {r.total_alerts} alerts in {r.elapsed_seconds:.4f}s "
          f"({r.events_per_second:.0f} evt/sec)\n")

    print("[3/4] Parallel batch — 4 workers (IP groups split across cores)...")
    r = run_parallel_batch(events, n_workers=4)
    results.append(r)
    print(f"      {r.total_alerts} alerts in {r.elapsed_seconds:.4f}s "
          f"({r.events_per_second:.0f} evt/sec)\n")

    print("[4/4] Parallel time windows (5-min slices processed simultaneously)...")
    r = run_parallel_windows(events)
    results.append(r)
    print(f"      {r.total_alerts} alerts in {r.elapsed_seconds:.4f}s "
          f"({r.events_per_second:.0f} evt/sec)\n")

    return results


def save_results(results: list, path: str = "pipeline_results.json"):
    serial_time = next(r.elapsed_seconds for r in results if r.mode == "serial")
    data = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "event_source": "run.py simulation (real SSH attack scenarios)",
        "results": [
            {
                "mode":              r.mode,
                "label":             {
                    "serial":                  "Serial (no parallelism)",
                    "parallel_by_type":        "Parallel by rule type",
                    "parallel_batch_4w":       "Parallel batch (4 workers)",
                    "parallel_windows_5min":   "Parallel time windows",
                }.get(r.mode, r.mode),
                "total_events":      r.total_events,
                "total_alerts":      r.total_alerts,
                "elapsed_seconds":   round(r.elapsed_seconds, 6),
                "events_per_second": round(r.events_per_second, 1),
                "speedup":           round(serial_time / r.elapsed_seconds, 3),
                "alerts_by_rule":    r.alerts_by_rule,
            }
            for r in results
        ],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[pipeline] Results saved to {path}")
    return data


def run_pipeline(event_limit: int = 50000) -> dict:
    init_db()
    events  = load_events_from_db(limit=event_limit)
    if not events:
        print("[pipeline] No events in DB — run the simulation first.")
        return {}
    results = run_all_modes(events)
    return save_results(results)


if __name__ == "__main__":
    run_pipeline()
