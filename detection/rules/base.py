"""
Base class for detection rules.

A rule instance is intentionally never shared across workers/processes.
Each partition (batch worker, window worker) constructs its own fresh
rule instance, so per-IP state (like BruteForceRule.failures_by_ip)
never needs to be synchronized between workers.
"""
from abc import ABC, abstractmethod


class DetectionRule(ABC):
    name: str

    @abstractmethod
    def evaluate(self, event: dict) -> dict | None:
        """Return an alert dict if this event triggers the rule, else None."""
        ...
