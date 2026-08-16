"""
Base class for detection rules.

A rule instance is intentionally never shared across workers/processes.
Each partition (batch worker, window worker) constructs its own fresh
rule instance, so per-IP state (like BruteForceRule.failures_by_ip)
never needs to be synchronized between workers. This is *why* you
don't need Redis or any other shared cache for batch/sliding-window
parallelism: each worker owns a disjoint slice of events (a set of
IPs, or a time window), so no two workers ever touch the same state.
"""
from abc import ABC, abstractmethod


class DetectionRule(ABC):
    name: str

    @abstractmethod
    def evaluate(self, event: dict) -> dict | None:
        """Return an alert dict if this event triggers the rule, else None."""
        ...
