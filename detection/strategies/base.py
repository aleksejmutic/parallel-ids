"""
Base classes for detection strategies.

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
from concurrent.futures import ProcessPoolExecutor
from typing import Type

from detection.rules.base import DetectionRule

RuleSpec = tuple[Type[DetectionRule], dict]


class DetectionStrategy(ABC):
    name: str

    @abstractmethod
    def process(self, events: list[dict], rule_specs: list[RuleSpec]) -> list[dict]:
        """Run all rules over all events, return a list of alert dicts."""
        ...


def _pool_noop(_):
    return None


class PooledStrategy(DetectionStrategy):
    """A strategy that fans work out to a ProcessPoolExecutor.

    The pool is created ONCE and reused across process() calls, instead of
    being built and torn down inside every call.

    Why this matters for the benchmark: creating a pool forks num_workers
    subprocesses and re-imports the module tree in each one. That is a
    fixed cost. If it is paid on every process() call it gets charged to
    every measurement, dominates the timing at small volumes, and makes
    the parallel strategies look far worse than they actually are -- you
    end up timing process creation instead of detection. Creating the pool
    once and reusing it removes that per-call cost; calling warmup() before
    the timed loop spawns the workers up front so the one-off spawn lands
    outside the measured region entirely.

    Use as a context manager (`with BatchStrategy() as s: ...`) or call
    close() when done so the worker processes are shut down cleanly.
    """

    def __init__(self, num_workers: int = 4):
        self.num_workers = num_workers
        self._pool: ProcessPoolExecutor | None = None

    def _ensure_pool(self) -> ProcessPoolExecutor:
        if self._pool is None:
            self._pool = ProcessPoolExecutor(max_workers=self.num_workers)
        return self._pool

    def warmup(self):
        """Spawn the worker processes now so the first timed process() call
        doesn't pay the one-off fork/import cost. Returns self so it can be
        chained: `batch = BatchStrategy().warmup()`."""
        pool = self._ensure_pool()
        list(pool.map(_pool_noop, range(self.num_workers)))
        return self

    def close(self):
        if self._pool is not None:
            self._pool.shutdown(wait=True)
            self._pool = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()