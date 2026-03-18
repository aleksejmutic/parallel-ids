"""
IDS Project — Quick start runner.
Runs the full pipeline: simulator → detector → summary.

Usage:
    python run.py                    # full demo (all scenarios)
    python run.py --scenario brute_force
    python run.py --watch            # live mode: simulate + detect continuously
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from storage.db import init_db, get_alerts, get_all_profiles
from simulator.ssh_simulator import SCENARIOS, scenario_normal_background
from detector.ssh_detector import run_detection


def print_summary():
    print("\n" + "="*60)
    print("DETECTION SUMMARY")
    print("="*60)

    alerts = get_alerts(limit=50)
    if alerts:
        print(f"\nAlerts fired: {len(alerts)}")
        for a in alerts:
            print(f"  [{a['severity'].upper():<8}] {a['rule_name']:<28} {a['source_ip']:<18}")
            print(f"           {a['description']}")
    else:
        print("No alerts fired.")

    print("\nIP Profiles (flagged):")
    profiles = get_all_profiles(flagged_only=True)
    if profiles:
        for p in profiles:
            print(f"  {p['source_ip']:<18} failures={p['auth_failures']:<5} "
                  f"alerts={p['alert_count']:<3} risk={p['risk_score']:.2f}")
    else:
        print("  No flagged IPs.")


def main():
    parser = argparse.ArgumentParser(description="IDS pipeline runner")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()),
                        help="Run one specific scenario")
    parser.add_argument("--watch", action="store_true",
                        help="Run simulator + detector in continuous loop")
    parser.add_argument("--detect-only", action="store_true",
                        help="Skip simulation, only run detector on existing DB data")
    args = parser.parse_args()

    init_db()

    if args.detect_only:
        run_detection(verbose=True)
        print_summary()
        return

    if args.watch:
        print("[IDS] Live watch mode. Press Ctrl+C to stop.\n")
        try:
            while True:
                scenario_normal_background(count=5, scenario_id="live_background")
                run_detection(scenario_id=None)
                time.sleep(3)
        except KeyboardInterrupt:
            print("\n[IDS] Stopped.")
            print_summary()
        return

    if args.scenario:
        print(f"[IDS] Running scenario: {args.scenario}\n")
        SCENARIOS[args.scenario](scenario_id=args.scenario)
        time.sleep(0.5)
        run_detection(scenario_id=args.scenario, verbose=True)
    else:
        print("[IDS] Running full demo pipeline...\n")
        # Background first to establish normal traffic
        scenario_normal_background(count=15, scenario_id="background")
        time.sleep(0.3)

        # Then each attack scenario
        attack_scenarios = [k for k in SCENARIOS if k != "background"]
        for name in attack_scenarios:
            print(f"\n{'─'*50}")
            SCENARIOS[name](scenario_id=name)
            time.sleep(0.3)
            run_detection(scenario_id=name, verbose=True)

    print_summary()


if __name__ == "__main__":
    main()
