"""
Real SSH attacker using paramiko.
Makes actual SSH connections to the Docker container on localhost:2222,
generating real OpenSSH log events for the IDS to detect.

Install: pip3 install paramiko
Usage:   python3 real_ssh_attacker.py

Run this alongside log_tailer.py to see real events flow into the IDS.
"""

import random
import time
import sys
import paramiko
from pathlib import Path

TARGET_HOST = "localhost"
TARGET_PORT = 2222

VALID_USERS  = ["testuser", "alice"]
VALID_PASS   = {"testuser": "testpass123", "alice": "alicepass"}
ATTACK_USERS = ["root", "admin", "ubuntu", "pi", "deploy",
                "git", "postgres", "jenkins", "nagios"]
WRONG_PASSWORDS = ["password", "123456", "admin", "root",
                   "letmein", "qwerty", "abc123", "pass"]


def _try_ssh(username: str, password: str, timeout: float = 3.0) -> bool:
    """Attempt one SSH login. Returns True if successful."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            TARGET_HOST, port=TARGET_PORT,
            username=username, password=password,
            timeout=timeout, allow_agent=False, look_for_keys=False,
        )
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return False


def scenario_brute_force():
    """Rapid repeated failures against root then a success."""
    print("\n[attacker] Brute force scenario")
    for i in range(12):
        result = _try_ssh("root", random.choice(WRONG_PASSWORDS))
        print(f"  attempt {i+1:>2}: root / wrong_password → {'OK' if result else 'FAIL'}")
        time.sleep(random.uniform(0.1, 0.4))

    result = _try_ssh("testuser", "testpass123")
    print(f"  final:     testuser / correct → {'OK' if result else 'FAIL'}")


def scenario_invalid_user_scan():
    """Try many non-existent usernames."""
    print("\n[attacker] Invalid user scan")
    fake_users = ["deploy", "jenkins", "nagios", "zabbix", "postgres",
                  "tomcat", "hadoop", "elastic", "kibana", "vagrant"]
    for user in fake_users:
        _try_ssh(user, "password123")
        print(f"  tried invalid user: {user}")
        time.sleep(random.uniform(0.1, 0.3))


def scenario_credential_stuffing():
    """Try known username/password combinations."""
    print("\n[attacker] Credential stuffing")
    combos = [
        ("alice",    "wrongpass"),
        ("testuser", "letmein"),
        ("alice",    "password"),
        ("testuser", "123456"),
        ("alice",    "alicepass"),   # this one succeeds
    ]
    for user, pw in combos:
        result = _try_ssh(user, pw)
        print(f"  {user:<12} / {pw:<15} → {'SUCCESS' if result else 'fail'}")
        time.sleep(random.uniform(0.5, 1.5))


def scenario_slow_and_low():
    """Very slow attempts designed to evade rate-based rules."""
    print("\n[attacker] Slow-and-low (one attempt every 3-5 seconds)")
    users = ["root", "admin", "ubuntu", "pi", "git", "deploy"]
    for user in users:
        _try_ssh(user, random.choice(WRONG_PASSWORDS))
        print(f"  slow attempt: {user}")
        time.sleep(random.uniform(3.0, 5.0))


def scenario_distributed(n_ips: int = 8):
    """
    Simulates distributed attack by making rapid bursts
    then pausing — mimics multiple source IPs timing-wise.
    """
    print(f"\n[attacker] Distributed pattern ({n_ips} simulated sources)")
    for i in range(n_ips):
        attempts = random.randint(1, 3)
        user = random.choice(ATTACK_USERS)
        for _ in range(attempts):
            _try_ssh(user, random.choice(WRONG_PASSWORDS))
        print(f"  source {i+1}: {attempts} attempt(s) as {user}")
        time.sleep(random.uniform(0.3, 1.0))


SCENARIOS = {
    "brute_force":        scenario_brute_force,
    "invalid_user_scan":  scenario_invalid_user_scan,
    "credential_stuffing":scenario_credential_stuffing,
    "slow_and_low":       scenario_slow_and_low,
    "distributed":        scenario_distributed,
}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Real SSH IDS attacker")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()),
                        help="Run one specific scenario")
    parser.add_argument("--all", action="store_true",
                        help="Run all scenarios in sequence")
    parser.add_argument("--list", action="store_true",
                        help="List available scenarios")
    args = parser.parse_args()

    if args.list:
        for name in SCENARIOS:
            print(f"  {name}")
        return

    print(f"[attacker] Target: {TARGET_HOST}:{TARGET_PORT}")
    print("[attacker] Make sure log_tailer.py is running in another terminal.\n")

    if args.scenario:
        SCENARIOS[args.scenario]()
    else:
        for name, fn in SCENARIOS.items():
            if name == "slow_and_low":
                continue   # skip slow one in full run
            fn()
            time.sleep(1)

    print("\n[attacker] Done. Check the IDS dashboard for alerts.")


if __name__ == "__main__":
    main()
