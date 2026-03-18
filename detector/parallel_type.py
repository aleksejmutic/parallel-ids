"""
Parallel detector — Layer 1: parallelism by intrusion type.

Each rule type runs as a completely independent process simultaneously.
All workers receive the same full event set but each applies only its own rule.

Architecture:
    events → [BruteForce worker]      ─┐
           → [SlowBruteForce worker]   ├→ merge → alerts
           → [UserEnum worker]         │
           → [SuccessAfterFail worker] │
           → [PortScan worker]         │
           → [AuthLimit worker]       ─┘

Worker count: 6 (one per rule type)
Each worker runs on a separate OS process — true parallelism, bypasses GIL.
"""

import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional

from serial_detector import (
    apply_all_rules, group_by_ip, BenchmarkResult, events_in_window
)
import json


# ── Individual rule workers (each runs in its own process) ────────────────────
# These must be module-level functions — pickle requirement for multiprocessing.

def worker_brute_force(args):
    ip, ip_events, scenario_id = args
    w = events_in_window(ip_events, 1)
    failures = [e for e in w if e["event_type"] in ("auth_failure", "auth_invalid_user")]
    if len(failures) >= 5:
        return {"rule_name": "brute_force", "severity": "high",
                "source_ip": ip, "event_count": len(failures),
                "description": f"{len(failures)} failures in 60s from {ip}",
                "scenario_id": scenario_id}
    return None


def worker_slow_brute(args):
    ip, ip_events, scenario_id = args
    w = events_in_window(ip_events, 10)
    failures = [e for e in w if e["event_type"] in ("auth_failure", "auth_invalid_user")]
    if len(failures) >= 10:
        return {"rule_name": "slow_brute_force", "severity": "medium",
                "source_ip": ip, "event_count": len(failures),
                "description": f"{len(failures)} failures in 10min from {ip}",
                "scenario_id": scenario_id}
    return None


def worker_user_enum(args):
    ip, ip_events, scenario_id = args
    w = events_in_window(ip_events, 5)
    invalids = [e for e in w if e["event_type"] == "auth_invalid_user"]
    users = set()
    for e in invalids:
        try:
            meta = json.loads(e.get("metadata") or "{}")
            if meta.get("user"):
                users.add(meta["user"])
        except Exception:
            pass
    if len(invalids) >= 8 and len(users) >= 5:
        return {"rule_name": "user_enumeration", "severity": "medium",
                "source_ip": ip, "event_count": len(invalids),
                "description": f"{len(invalids)} invalid users from {ip}",
                "scenario_id": scenario_id}
    return None


def worker_success_after_fail(args):
    ip, ip_events, scenario_id = args
    w = events_in_window(ip_events, 10)
    failures  = [e for e in w if e["event_type"] in ("auth_failure", "auth_invalid_user")]
    successes = [e for e in w if e["event_type"] == "auth_success"]
    if len(failures) >= 3 and len(successes) >= 1:
        return {"rule_name": "success_after_failure", "severity": "critical",
                "source_ip": ip, "event_count": len(failures) + len(successes),
                "description": f"Login after {len(failures)} failures from {ip}",
                "scenario_id": scenario_id}
    return None


def worker_port_scan(args):
    ip, ip_events, scenario_id = args
    w = events_in_window(ip_events, 2)
    probes = [e for e in w if e["event_type"] in
              ("connection_attempt", "invalid_packet", "connection_closed")]
    if len(probes) >= 15:
        return {"rule_name": "port_scan_probe", "severity": "medium",
                "source_ip": ip, "event_count": len(probes),
                "description": f"{len(probes)} probes from {ip}",
                "scenario_id": scenario_id}
    return None


def worker_auth_limit(args):
    ip, ip_events, scenario_id = args
    w = events_in_window(ip_events, 5)
    too_many = [e for e in w if e["event_type"] == "auth_too_many"]
    if too_many:
        return {"rule_name": "server_auth_limit_hit", "severity": "high",
                "source_ip": ip, "event_count": len(too_many),
                "description": f"Server auth limit hit from {ip}",
                "scenario_id": scenario_id}
    return None


# All rule workers as a list for the executor to map over
RULE_WORKERS = [
    worker_brute_force,
    worker_slow_brute,
    worker_user_enum,
    worker_success_after_fail,
    worker_port_scan,
    worker_auth_limit,
]


def _run_rule_on_all_ips(rule_fn, by_ip: dict, scenario_id: Optional[str]) -> list:
    """
    Run one rule function across all IPs using a process pool.
    Each IP is a separate task submitted to the pool.
    """
    args    = [(ip, events, scenario_id) for ip, events in by_ip.items()]
    alerts  = []
    # Use 4 workers (matches physical core count on i5-11320H)
    with ProcessPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(rule_fn, arg) for arg in args]
        for future in as_completed(futures):
            result = future.result()
            if result:
                alerts.append(result)
    return alerts


def run_parallel_by_type(
    events: list,
    scenario_id: Optional[str] = None,
) -> BenchmarkResult:
    """
    Layer 1 parallel: all rule types run simultaneously.
    Uses ProcessPoolExecutor — one process per rule type,
    all running concurrently on the same event set.
    """
    start = time.perf_counter()
    by_ip = group_by_ip(events)

    all_alerts = []

    # Submit all rule types simultaneously — each gets its own process pool
    with ProcessPoolExecutor(max_workers=len(RULE_WORKERS)) as outer_pool:
        futures = {
            outer_pool.submit(_run_rule_on_all_ips, rule_fn, by_ip, scenario_id): rule_fn.__name__
            for rule_fn in RULE_WORKERS
        }
        for future in as_completed(futures):
            rule_alerts = future.result()
            all_alerts.extend(rule_alerts)

    elapsed = time.perf_counter() - start

    alerts_by_rule = defaultdict(int)
    for a in all_alerts:
        alerts_by_rule[a["rule_name"]] += 1

    return BenchmarkResult(
        mode              = "parallel_by_type",
        total_events      = len(events),
        total_alerts      = len(all_alerts),
        elapsed_seconds   = elapsed,
        events_per_second = len(events) / elapsed if elapsed > 0 else 0,
        alerts_by_rule    = dict(alerts_by_rule),
    )


if __name__ == "__main__":
    from detector.benchmark import generate_events
    events = generate_events(5000)
    result = run_parallel_by_type(events)
    print(f"[parallel_type] {result.total_events} events → {result.total_alerts} alerts "
          f"in {result.elapsed_seconds:.4f}s "
          f"({result.events_per_second:.0f} events/sec)")
