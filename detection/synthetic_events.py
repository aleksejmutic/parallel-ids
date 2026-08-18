"""
Generates a synthetic corpus of SSH auth events for benchmarking.

This is deliberately NOT wired to sources/ssh/attacks/*.py. Those scripts
drive real sshpass subprocesses at real network speed (with a 1-second
sleep between attempts).
"""
import random
import time


def generate_synthetic_events(
    num_events: int,
    num_attacker_ips: int = 5,
    num_normal_ips: int = 50,
    attack_ratio: float = 0.3,
    seed: int | None = None,
) -> list[dict]:
    """
    ~attack_ratio of events are rapid-fire failures from a small pool of
    "attacker" IPs (should trip BruteForceRule). The rest are occasional
    failures/successes from a larger pool of "normal" IPs (should stay
    under threshold and establish what your abstract calls the baseline
    background-traffic scenario).
    """
    rng = random.Random(seed)
    attacker_ips = [f"10.0.0.{i}" for i in range(1, num_attacker_ips + 1)]
    normal_ips = [f"192.168.1.{i}" for i in range(1, num_normal_ips + 1)]

    events = []
    base_ts = time.time()
    for i in range(num_events):
        if rng.random() < attack_ratio:
            ip = rng.choice(attacker_ips)
            ts = base_ts + i * 0.05  # rapid-fire: ~20 attempts/sec
            outcome = "failure"
        else:
            ip = rng.choice(normal_ips)
            ts = base_ts + i * 2.0  # sparse: normal login pace
            outcome = rng.choice(["failure", "success"])

        events.append({
            "source_type": "ssh",
            "source_ip": ip,
            "outcome": outcome,
            "timestamp": ts,
        })

    events.sort(key=lambda e: e["timestamp"])
    return events
