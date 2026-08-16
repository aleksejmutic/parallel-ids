"""
Base class for detection strategies.

Rules are passed as "specs" rather than live instances:
    RuleSpec = (RuleClass, kwargs_dict)
    e.g. (BruteForceRule, {"threshold": 5, "window_seconds": 60})

This matters for the parallel strategies specifically: ProcessPoolExecutor
pickles whatever you hand it and sends it to a subprocess. Classes and
plain dicts pickle cleanly; a constructed rule instance would too, but
handing every worker the *same* instance can trick you into thinking
state is being shared when it isn't (each subprocess actually gets an
independent pickled copy). Passing (class, kwargs) instead makes it
explicit and unambiguous: each worker always builds its own fresh rule.
"""
from abc import ABC, abstractmethod
from typing import Type

from detection.rules.base import DetectionRule

RuleSpec = tuple[Type[DetectionRule], dict]


class DetectionStrategy(ABC):
    name: str

    @abstractmethod
    def process(self, events: list[dict], rule_specs: list[RuleSpec]) -> list[dict]:
        """Run all rules over all events, return a list of alert dicts."""
        ...
