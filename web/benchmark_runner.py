"""
Runs detection.benchmark.run_benchmark in a background thread and streams
each result onto the Hub as it is measured. Only one run is allowed at a
time.
"""
import threading

from detection.benchmark import run_benchmark


class BenchmarkRunner:
    def __init__(self, hub):
        self.hub = hub
        self._lock = threading.Lock()
        self._running = False

    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    def start(self) -> bool:
        with self._lock:
            if self._running:
                return False
            self._running = True
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def _run(self):
        try:
            self.hub.publish({"channel": "benchmark", "data": {"event": "start"}})
            run_benchmark(on_result=self._on_result)
            self.hub.publish({"channel": "benchmark", "data": {"event": "done"}})
        except Exception as exc:  # noqa: BLE001
            self.hub.publish(
                {"channel": "benchmark", "data": {"event": "error", "message": str(exc)}}
            )
        finally:
            with self._lock:
                self._running = False

    def _on_result(self, result):
        self.hub.publish({"channel": "benchmark", "data": {"event": "result", "result": result}})