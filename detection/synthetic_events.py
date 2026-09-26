"""
Generates a synthetic corpus of SSH auth events for benchmarking.

Events here are emitted in the SAME shape the live pipeline produces
(see core/event_factory.py) so the real detection rules run against them
unchanged:
  - "timestamp" is an ISO-8601 string (BruteForceRule calls
    datetime.fromisoformat on it), not a raw float.
  - failure/success is carried in metadata.success (a bool), which is what
    BruteForceRule checks, rather than a separate "outcome" string.
"""
import random
from datetime import datetime, timezone

# Fixed reference epoch (2023-11-14T22:13:20Z) so the corpus is FULLY
# determined by `seed`. Using time.time() here would leave the absolute
# timestamps -- and therefore the tumbling-window boundaries the
# sliding_window strategy buckets on -- different every run, making its
# alert count wobble between runs even at the same seed. serial/batch don't
# care about absolute time, so only sliding_window was affected, which is
# exactly the kind of non-reproducibility that makes a benchmark untrustworthy.
_BASE_EPOCH = 1_700_000_000.0


def generate_synthetic_events(
    num_events: int,
    num_attacker_ips: int = 5,
    num_normal_ips: int = 50,
    attack_ratio: float = 0.3,
    seed: int | None = None,
) -> list[dict]:
    rng = random.Random(seed)
    attacker_ips = [f"10.0.0.{i}" for i in range(1, num_attacker_ips + 1)]
    normal_ips = [f"192.168.1.{i}" for i in range(1, num_normal_ips + 1)]

    base_ts = _BASE_EPOCH
    raw = []
    for i in range(num_events):
        if rng.random() < attack_ratio:
            ip = rng.choice(attacker_ips)
            ts = base_ts + i * 0.05
            outcome = "failure"
        else:
            ip = rng.choice(normal_ips)
            ts = base_ts + i * 2.0
            outcome = rng.choice(["failure", "success"])
        raw.append((ts, ip, outcome))

    raw.sort(key=lambda r: r[0])

    events = []
    for ts, ip, outcome in raw:
        events.append({
            "source_type": "ssh",
            "source_ip": ip,
            "timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
            "metadata": {
                "attack_type": "brute_force",
                "success": outcome == "success",
            },
        })
    return events