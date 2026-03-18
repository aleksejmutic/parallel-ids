"""
Benchmark — runs all four detection modes on the same event dataset
and prints a full comparison table with speedup ratios.

Usage:
    python3 benchmark.py                      # full benchmark, 5000 events
    python3 benchmark.py --events 100000      # custom event count
    python3 benchmark.py --quick              # serial + one parallel mode only
    python3 benchmark.py --events 50000 --save  # saves to benchmark_50000.json
"""

import argparse
import json
import random
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Synthetic event generator ─────────────────────────────────────────────────

ATTACKER_IPS = [f"10.{i}.{j}.{k}" for i in range(1,5)
                for j in range(1,10) for k in range(2,12)]
LEGIT_IPS    = [f"192.168.{i}.{j}" for i in range(1,10)
                for j in range(10,50)]
USERNAMES    = ["root", "admin", "ubuntu", "pi", "deploy", "git",
                "postgres", "test", "jenkins", "nagios", "hadoop"]
LEGIT_USERS  = ["alice", "bob", "carol", "dave", "eve", "frank"]
HOSTS        = ["web-01", "web-02", "db-01", "bastion", "api-01"]

EVENT_TYPES_NORMAL = [
    ("auth_success",       60),
    ("auth_failure",       20),
    ("disconnect",         15),
    ("connection_attempt",  5),
]


def _ts(offset_seconds: float = 0) -> str:
    t = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
    return t.isoformat()


def _make_event(event_type, source_ip, host, scenario_id=None, user=None):
    return {
        "event_id":    str(uuid4()),
        "timestamp":   _ts(random.uniform(0, 600)),
        "event_type":  event_type,
        "source_type": "ssh",
        "source_ip":   source_ip,
        "source_host": host,
        "severity":    "low",
        "scenario_id": scenario_id,
        "raw":         f"sshd: {event_type} from {source_ip}",
        "metadata":    json.dumps({"user": user or random.choice(USERNAMES),
                                   "port": random.randint(49152, 65535)}),
    }


def generate_events(total: int = 5000) -> list:
    events = []
    random.seed(42)

    n_normal = int(total * 0.60)
    n_brute  = int(total * 0.25)
    n_scan   = int(total * 0.10)
    n_enum   = total - n_normal - n_brute - n_scan

    types, weights = zip(*EVENT_TYPES_NORMAL)
    for _ in range(n_normal):
        etype = random.choices(types, weights=weights)[0]
        events.append(_make_event(etype, random.choice(LEGIT_IPS),
                                  random.choice(HOSTS), "background",
                                  random.choice(LEGIT_USERS)))

    attacker_pool = random.sample(ATTACKER_IPS, min(200, len(ATTACKER_IPS)))
    for _ in range(n_brute):
        ip    = random.choice(attacker_pool)
        etype = random.choices(["auth_failure","auth_too_many","auth_success"],
                               weights=[85, 10, 5])[0]
        events.append(_make_event(etype, ip, random.choice(HOSTS), "brute_force", "root"))

    scan_ips = random.sample(ATTACKER_IPS, min(50, len(ATTACKER_IPS)))
    for _ in range(n_scan):
        ip    = random.choice(scan_ips)
        etype = random.choices(["connection_attempt","invalid_packet","connection_closed"],
                               weights=[40, 35, 25])[0]
        events.append(_make_event(etype, ip, random.choice(HOSTS), "port_scan"))

    enum_ips = random.sample(ATTACKER_IPS, min(30, len(ATTACKER_IPS)))
    for _ in range(n_enum):
        ip = random.choice(enum_ips)
        events.append(_make_event("auth_invalid_user", ip, random.choice(HOSTS),
                                  "enum", random.choice(USERNAMES)))

    random.shuffle(events)
    return events


# ── Result formatting ─────────────────────────────────────────────────────────

def print_results(results: list, serial_time: float):
    w = 26
    print("\n" + "═" * 78)
    print(f"  {'MODE':<{w}} {'EVENTS':>8}  {'ALERTS':>7}  {'TIME':>9}  {'EVT/SEC':>9}  {'SPEEDUP':>8}")
    print("─" * 78)
    for r in results:
        speedup = serial_time / r.elapsed_seconds if r.elapsed_seconds > 0 else 0
        marker  = "  (baseline)" if r.mode == "serial" else f"  ×{speedup:.2f} faster"
        print(f"  {r.mode:<{w}} {r.total_events:>8}  {r.total_alerts:>7}  "
              f"{r.elapsed_seconds:>8.4f}s  {r.events_per_second:>8.0f}  {marker}")
    print("═" * 78)

    print("\n  Alerts by rule:")
    all_rules = sorted(set(k for r in results for k in r.alerts_by_rule))
    rule_w, col_w = 28, 12
    print(f"  {'Rule':<{rule_w}}" + "".join(f"{r.mode[:col_w]:>{col_w}}" for r in results))
    print("  " + "─" * (rule_w + col_w * len(results)))
    for rule in all_rules:
        row = f"  {rule:<{rule_w}}"
        for r in results:
            row += f"{r.alerts_by_rule.get(rule, 0):>{col_w}}"
        print(row)
    print()


def save_results(results: list):
    """
    Saves to benchmark_<total_events>.json so each scale gets its own file.
    The Flask /api/scaling route reads all these files automatically.
    """
    total = results[0].total_events
    path  = f"benchmark_{total}.json"

    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu":       "Intel i5-11320H (4 cores / 8 threads)",
        "results": [
            {
                "mode":              r.mode,
                "total_events":      r.total_events,
                "total_alerts":      r.total_alerts,
                "elapsed_seconds":   round(r.elapsed_seconds, 6),
                "events_per_second": round(r.events_per_second, 1),
                "alerts_by_rule":    r.alerts_by_rule,
            }
            for r in results
        ],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Results saved to {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IDS parallelism benchmark")
    parser.add_argument("--quick",  action="store_true",
                        help="Run serial + parallel_type only")
    parser.add_argument("--save",   action="store_true",
                        help="Save results to benchmark_<N>.json")
    parser.add_argument("--events", type=int, default=5000,
                        help="Number of events to generate")
    args = parser.parse_args()

    print(f"\n[benchmark] Generating {args.events} events...")
    events = generate_events(args.events)
    print(f"[benchmark] Dataset ready — {len(events)} events across "
          f"{len(set(e['source_ip'] for e in events))} unique IPs\n")

    from serial_detector   import run_serial
    from parallel_type     import run_parallel_by_type
    from parallel_batch    import run_parallel_batch, run_parallel_batch_scaling
    from parallel_windows  import run_parallel_windows

    all_results = []

    print("[1/4] Running serial (baseline)...")
    r_serial = run_serial(events)
    all_results.append(r_serial)
    serial_time = r_serial.elapsed_seconds
    print(f"      Done — {r_serial.elapsed_seconds:.4f}s\n")

    if args.quick:
        print("[2/4] Running parallel by type...")
        r_type = run_parallel_by_type(events)
        all_results.append(r_type)
        print(f"      Done — {r_type.elapsed_seconds:.4f}s\n")
    else:
        print("[2/4] Running parallel by intrusion type...")
        r_type = run_parallel_by_type(events)
        all_results.append(r_type)
        print(f"      Done — {r_type.elapsed_seconds:.4f}s\n")

        print("[3/4] Running parallel batch (scaling 2→4 workers)...")
        batch_results = run_parallel_batch_scaling(events)
        all_results.extend(batch_results)
        print(f"      Done\n")

        print("[4/4] Running parallel time windows (5-min slices)...")
        r_windows = run_parallel_windows(events)
        all_results.append(r_windows)
        print(f"      Done — {r_windows.elapsed_seconds:.4f}s\n")

    print_results(all_results, serial_time)

    if args.save:
        save_results(all_results)


if __name__ == "__main__":
    main()