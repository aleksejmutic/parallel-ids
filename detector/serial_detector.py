"""
Serial detector — baseline, no parallelism.
Processes all rules sequentially, one rule at a time, one IP at a time.
Used as the comparison baseline for all parallel implementations.
"""

import time
import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional
from dataclasses import dataclass


@dataclass
class BenchmarkResult:
    mode:             str
    total_events:     int
    total_alerts:     int
    elapsed_seconds:  float
    events_per_second: float
    alerts_by_rule:   dict


# ── Shared rule logic (imported by all three parallel files too) ──────────────

def events_in_window(events: list, minutes: int) -> list:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    result = []
    for e in events:
        try:
            ts = datetime.fromisoformat(e["timestamp"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= cutoff:
                result.append(e)
        except Exception:
            pass
    return result


def apply_all_rules(ip: str, ip_events: list, scenario_id: Optional[str]) -> list:
    """
    Apply every detection rule to one IP's events.
    Returns a list of alert dicts (may be empty).
    This function is intentionally pure — no DB writes, no side effects.
    Used by serial AND all parallel implementations.
    """
    alerts = []

    # Rule 1 — brute force (60s window, 5+ failures)
    w = events_in_window(ip_events, 1)
    failures = [e for e in w if e["event_type"] in ("auth_failure", "auth_invalid_user")]
    if len(failures) >= 5:
        alerts.append({
            "rule_name":   "brute_force",
            "severity":    "high",
            "source_ip":   ip,
            "event_count": len(failures),
            "description": f"{len(failures)} failures in 60s from {ip}",
            "scenario_id": scenario_id,
        })

    # Rule 2 — slow brute force (10min window, 10+ failures)
    w = events_in_window(ip_events, 10)
    failures = [e for e in w if e["event_type"] in ("auth_failure", "auth_invalid_user")]
    if len(failures) >= 10:
        alerts.append({
            "rule_name":   "slow_brute_force",
            "severity":    "medium",
            "source_ip":   ip,
            "event_count": len(failures),
            "description": f"{len(failures)} failures in 10min from {ip}",
            "scenario_id": scenario_id,
        })

    # Rule 3 — user enumeration (5min window, 8+ invalid users, 5+ distinct)
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
        alerts.append({
            "rule_name":   "user_enumeration",
            "severity":    "medium",
            "source_ip":   ip,
            "event_count": len(invalids),
            "description": f"{len(invalids)} invalid users ({len(users)} distinct) from {ip}",
            "scenario_id": scenario_id,
        })

    # Rule 4 — success after failure (10min, 3+ failures then a success)
    w = events_in_window(ip_events, 10)
    failures  = [e for e in w if e["event_type"] in ("auth_failure", "auth_invalid_user")]
    successes = [e for e in w if e["event_type"] == "auth_success"]
    if len(failures) >= 3 and len(successes) >= 1:
        alerts.append({
            "rule_name":   "success_after_failure",
            "severity":    "critical",
            "source_ip":   ip,
            "event_count": len(failures) + len(successes),
            "description": f"Login after {len(failures)} failures from {ip}",
            "scenario_id": scenario_id,
        })

    # Rule 5 — port scan (2min window, 15+ probes)
    w = events_in_window(ip_events, 2)
    probes = [e for e in w if e["event_type"] in
              ("connection_attempt", "invalid_packet", "connection_closed")]
    if len(probes) >= 15:
        alerts.append({
            "rule_name":   "port_scan_probe",
            "severity":    "medium",
            "source_ip":   ip,
            "event_count": len(probes),
            "description": f"{len(probes)} probes in 2min from {ip}",
            "scenario_id": scenario_id,
        })

    # Rule 6 — server auth limit (any auth_too_many in 5min)
    w = events_in_window(ip_events, 5)
    too_many = [e for e in w if e["event_type"] == "auth_too_many"]
    if too_many:
        alerts.append({
            "rule_name":   "server_auth_limit_hit",
            "severity":    "high",
            "source_ip":   ip,
            "event_count": len(too_many),
            "description": f"Server auth limit hit from {ip}",
            "scenario_id": scenario_id,
        })

    return alerts


def group_by_ip(events: list) -> dict:
    groups = defaultdict(list)
    for e in events:
        groups[e["source_ip"]].append(e)
    return dict(groups)


# ── Serial implementation ─────────────────────────────────────────────────────

def run_serial(events: list, scenario_id: Optional[str] = None) -> BenchmarkResult:
    """
    Pure sequential processing.
    One IP at a time, one rule at a time, single thread.
    """
    start     = time.perf_counter()
    by_ip     = group_by_ip(events)
    all_alerts = []

    for ip, ip_events in by_ip.items():
        alerts = apply_all_rules(ip, ip_events, scenario_id)
        all_alerts.extend(alerts)

    elapsed = time.perf_counter() - start

    alerts_by_rule = defaultdict(int)
    for a in all_alerts:
        alerts_by_rule[a["rule_name"]] += 1

    return BenchmarkResult(
        mode              = "serial",
        total_events      = len(events),
        total_alerts      = len(all_alerts),
        elapsed_seconds   = elapsed,
        events_per_second = len(events) / elapsed if elapsed > 0 else 0,
        alerts_by_rule    = dict(alerts_by_rule),
    )


if __name__ == "__main__":
    from detector.benchmark import generate_events
    events = generate_events(5000)
    result = run_serial(events)
    print(f"[serial] {result.total_events} events → {result.total_alerts} alerts "
          f"in {result.elapsed_seconds:.4f}s "
          f"({result.events_per_second:.0f} events/sec)")
