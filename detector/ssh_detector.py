"""
SSH detection engine.
Reads events from SQLite and applies detection rules using sliding time windows.
Can run as a one-shot analysis or in continuous watch mode.

Usage:
    python detector.py              # analyze all events in DB
    python detector.py --watch      # continuous mode, checks every 5s
    python detector.py --scenario brute_force  # analyze one scenario only
"""

import argparse
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.schema import EventType, Severity
from storage.db import init_db, get_events, insert_alert, get_alerts


# ── Time window helpers ───────────────────────────────────────────────────────

def events_in_window(events: list[dict], minutes: int) -> list[dict]:
    """Filter events to only those within the last N minutes."""
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


def group_by_ip(events: list[dict]) -> dict[str, list[dict]]:
    groups = defaultdict(list)
    for e in events:
        groups[e["source_ip"]].append(e)
    return dict(groups)


# ── Individual detection rules ────────────────────────────────────────────────

class DetectionRule:
    name     = "base_rule"
    severity = Severity.LOW

    def check(self, ip: str, events: list[dict],
              scenario_id: Optional[str]) -> Optional[dict]:
        """
        Examine events for a single IP. Return an alert dict if triggered,
        None otherwise.
        """
        raise NotImplementedError


class BruteForceRule(DetectionRule):
    """
    5+ authentication failures from the same IP within 60 seconds.
    Classic brute force signature.
    """
    name            = "brute_force"
    severity        = Severity.HIGH
    THRESHOLD       = 5
    WINDOW_MINUTES  = 1

    def check(self, ip, events, scenario_id):
        window   = events_in_window(events, self.WINDOW_MINUTES)
        failures = [e for e in window if e["event_type"] in (
            EventType.AUTH_FAILURE, EventType.AUTH_INVALID_USER
        )]
        if len(failures) >= self.THRESHOLD:
            return {
                "rule_name":    self.name,
                "description":  f"{len(failures)} auth failures from {ip} in {self.WINDOW_MINUTES}min window",
                "severity":     self.severity,
                "event_count":  len(failures),
                "event_ids":    [e["event_id"] for e in failures],
                "scenario_id":  scenario_id,
            }
        return None


class SlowBruteForceRule(DetectionRule):
    """
    10+ failures from same IP over a longer 10-minute window.
    Catches slow attackers who stay under the 1-minute threshold.
    """
    name            = "slow_brute_force"
    severity        = Severity.MEDIUM
    THRESHOLD       = 10
    WINDOW_MINUTES  = 10

    def check(self, ip, events, scenario_id):
        window   = events_in_window(events, self.WINDOW_MINUTES)
        failures = [e for e in window if e["event_type"] in (
            EventType.AUTH_FAILURE, EventType.AUTH_INVALID_USER
        )]
        if len(failures) >= self.THRESHOLD:
            return {
                "rule_name":    self.name,
                "description":  f"{len(failures)} auth failures from {ip} over {self.WINDOW_MINUTES}min (slow attack)",
                "severity":     self.severity,
                "event_count":  len(failures),
                "event_ids":    [e["event_id"] for e in failures],
                "scenario_id":  scenario_id,
            }
        return None


class UserEnumerationRule(DetectionRule):
    """
    8+ invalid user attempts from the same IP within 5 minutes.
    Indicates username enumeration / scanning.
    """
    name            = "user_enumeration"
    severity        = Severity.MEDIUM
    THRESHOLD       = 8
    WINDOW_MINUTES  = 5

    def check(self, ip, events, scenario_id):
        window   = events_in_window(events, self.WINDOW_MINUTES)
        invalids = [e for e in window if e["event_type"] == EventType.AUTH_INVALID_USER]

        # Count distinct usernames attempted
        users    = set()
        for e in invalids:
            import json
            try:
                meta = json.loads(e.get("metadata") or "{}")
                if meta.get("user"):
                    users.add(meta["user"])
            except Exception:
                pass

        if len(invalids) >= self.THRESHOLD and len(users) >= 5:
            return {
                "rule_name":    self.name,
                "description":  f"{len(invalids)} invalid user attempts ({len(users)} distinct users) from {ip}",
                "severity":     self.severity,
                "event_count":  len(invalids),
                "event_ids":    [e["event_id"] for e in invalids],
                "scenario_id":  scenario_id,
            }
        return None


class SuccessAfterFailureRule(DetectionRule):
    """
    Successful login preceded by 3+ failures from the same IP in 10 minutes.
    Strong indicator of a successful brute force.
    """
    name            = "success_after_failure"
    severity        = Severity.CRITICAL
    FAILURE_MIN     = 3
    WINDOW_MINUTES  = 10

    def check(self, ip, events, scenario_id):
        window    = events_in_window(events, self.WINDOW_MINUTES)
        failures  = [e for e in window if e["event_type"] in (
            EventType.AUTH_FAILURE, EventType.AUTH_INVALID_USER
        )]
        successes = [e for e in window if e["event_type"] == EventType.AUTH_SUCCESS]

        if len(failures) >= self.FAILURE_MIN and len(successes) >= 1:
            return {
                "rule_name":    self.name,
                "description":  f"Successful login after {len(failures)} failures from {ip} — possible compromise",
                "severity":     self.severity,
                "event_count":  len(failures) + len(successes),
                "event_ids":    [e["event_id"] for e in failures + successes],
                "scenario_id":  scenario_id,
            }
        return None


class PortScanProbeRule(DetectionRule):
    """
    15+ connection attempts or invalid packets from the same IP in 2 minutes.
    Indicates automated scanning.
    """
    name            = "port_scan_probe"
    severity        = Severity.MEDIUM
    THRESHOLD       = 15
    WINDOW_MINUTES  = 2

    def check(self, ip, events, scenario_id):
        window = events_in_window(events, self.WINDOW_MINUTES)
        probes = [e for e in window if e["event_type"] in (
            EventType.CONNECTION_ATTEMPT,
            EventType.INVALID_PACKET,
            EventType.CONNECTION_CLOSED,
        )]
        if len(probes) >= self.THRESHOLD:
            return {
                "rule_name":    self.name,
                "description":  f"{len(probes)} connection probes from {ip} in {self.WINDOW_MINUTES}min",
                "severity":     self.severity,
                "event_count":  len(probes),
                "event_ids":    [e["event_id"] for e in probes],
                "scenario_id":  scenario_id,
            }
        return None


class TooManyAuthTriggeredRule(DetectionRule):
    """
    SSH server itself reported 'Too many authentication failures'.
    This is a high-confidence signal — no threshold needed.
    """
    name            = "server_auth_limit_hit"
    severity        = Severity.HIGH
    WINDOW_MINUTES  = 5

    def check(self, ip, events, scenario_id):
        window    = events_in_window(events, self.WINDOW_MINUTES)
        triggered = [e for e in window if e["event_type"] == EventType.AUTH_TOO_MANY_AUTH]
        if triggered:
            return {
                "rule_name":    self.name,
                "description":  f"SSH server hit auth limit for {ip} — server-confirmed brute force",
                "severity":     self.severity,
                "event_count":  len(triggered),
                "event_ids":    [e["event_id"] for e in triggered],
                "scenario_id":  scenario_id,
            }
        return None


# ── Distributed attack rule (cross-IP) ───────────────────────────────────────

def check_distributed_attack(
    all_events: list[dict],
    scenario_id: Optional[str],
    window_minutes: int = 5,
    ip_threshold: int = 6,
    total_threshold: int = 20,
) -> Optional[dict]:
    """
    Many different IPs each contributing a small number of failures.
    Looks at the fleet as a whole, not per-IP.
    """
    window   = events_in_window(all_events, window_minutes)
    failures = [e for e in window if e["event_type"] in (
        EventType.AUTH_FAILURE, EventType.AUTH_INVALID_USER
    )]

    attacker_ips = defaultdict(int)
    for e in failures:
        attacker_ips[e["source_ip"]] += 1

    # Only count IPs that contributed at least 2 failures
    contributing = {ip: c for ip, c in attacker_ips.items() if c >= 2}

    if len(contributing) >= ip_threshold and len(failures) >= total_threshold:
        return {
            "rule_name":    "distributed_attack",
            "description":  (
                f"Distributed attack: {len(contributing)} IPs, "
                f"{len(failures)} total failures in {window_minutes}min window"
            ),
            "severity":     Severity.CRITICAL,
            "source_ip":    "multiple",
            "source_host":  "multiple",
            "event_count":  len(failures),
            "event_ids":    [e["event_id"] for e in failures],
            "scenario_id":  scenario_id,
        }
    return None


# ── Detection engine ──────────────────────────────────────────────────────────

PER_IP_RULES = [
    BruteForceRule(),
    SlowBruteForceRule(),
    UserEnumerationRule(),
    SuccessAfterFailureRule(),
    PortScanProbeRule(),
    TooManyAuthTriggeredRule(),
]

# Track which (ip, rule) pairs have already fired to avoid duplicate alerts
_fired: set[tuple] = set()


def run_detection(scenario_id: Optional[str] = None, verbose: bool = True) -> list[dict]:
    """
    Run all rules against events in the database.
    Returns list of new alerts generated.
    """
    events    = get_events(scenario_id=scenario_id, limit=5000)
    by_ip     = group_by_ip(events)
    new_alerts = []

    if verbose:
        print(f"\n[detector] Analyzing {len(events)} events from {len(by_ip)} IPs...")

    # Per-IP rules
    for ip, ip_events in by_ip.items():
        for rule in PER_IP_RULES:
            dedup_key = (ip, rule.name, _window_bucket(minutes=1))
            if dedup_key in _fired:
                continue

            alert = rule.check(ip, ip_events, scenario_id)
            if alert:
                _fired.add(dedup_key)
                host = ip_events[0].get("source_host", "unknown") if ip_events else "unknown"
                alert_id = insert_alert(
                    rule_name         = alert["rule_name"],
                    description       = alert["description"],
                    severity          = alert["severity"],
                    source_ip         = ip,
                    source_host       = host,
                    event_count       = alert["event_count"],
                    related_event_ids = alert["event_ids"],
                    scenario_id       = alert.get("scenario_id"),
                )
                new_alerts.append(alert)
                _print_alert(alert, ip)

    # Fleet-wide distributed attack check
    dist_alert = check_distributed_attack(events, scenario_id)
    if dist_alert:
        dedup_key = ("multiple", "distributed_attack", _window_bucket(minutes=5))
        if dedup_key not in _fired:
            _fired.add(dedup_key)
            insert_alert(
                rule_name         = dist_alert["rule_name"],
                description       = dist_alert["description"],
                severity          = dist_alert["severity"],
                source_ip         = dist_alert["source_ip"],
                source_host       = dist_alert["source_host"],
                event_count       = dist_alert["event_count"],
                related_event_ids = dist_alert["event_ids"],
                scenario_id       = dist_alert.get("scenario_id"),
            )
            new_alerts.append(dist_alert)
            _print_alert(dist_alert, "multiple IPs")

    if verbose and not new_alerts:
        print("[detector] No new alerts.")

    return new_alerts


def _window_bucket(minutes: int) -> int:
    """Returns current time truncated to N-minute buckets for deduplication."""
    ts = datetime.now(timezone.utc)
    return int(ts.timestamp() // (minutes * 60))


def _print_alert(alert: dict, ip: str):
    sev_color = {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH:     "HIGH    ",
        Severity.MEDIUM:   "MEDIUM  ",
        Severity.LOW:      "LOW     ",
    }.get(alert["severity"], alert["severity"])

    print(f"  [!] [{sev_color}] {alert['rule_name']:<28} {ip:<18} {alert['description']}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IDS SSH detection engine")
    parser.add_argument("--watch",    action="store_true", help="Continuous watch mode")
    parser.add_argument("--interval", type=int, default=5,  help="Watch interval in seconds")
    parser.add_argument("--scenario", help="Analyze specific scenario only")
    parser.add_argument("--summary",  action="store_true", help="Print alert summary after run")
    args = parser.parse_args()

    init_db()

    if args.watch:
        print(f"[detector] Watch mode — checking every {args.interval}s. Press Ctrl+C to stop.\n")
        try:
            while True:
                run_detection(scenario_id=args.scenario)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[detector] Stopped.")
    else:
        run_detection(scenario_id=args.scenario, verbose=True)

    if args.summary:
        alerts = get_alerts(scenario_id=args.scenario)
        print(f"\n── Alert summary ({len(alerts)} total) ──")
        for a in alerts:
            print(f"  {a['severity']:<10} {a['rule_name']:<28} {a['source_ip']:<18} {a['description'][:60]}")


if __name__ == "__main__":
    main()
