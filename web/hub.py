"""
In-process pub/sub used to fan a single stream of messages out to every
connected browser (each SSE client) plus decouple the producers (the Kafka
consumer thread and the benchmark thread) from the consumers.

Each subscriber gets its own bounded queue. If a browser falls behind, we
drop that subscriber's oldest message rather than block the producer -- a
live dashboard should stay live, not stall the whole system for one slow tab.
"""
import queue
import threading


class Hub:
    def __init__(self, max_queue: int = 2000):
        self._subscribers: set[queue.Queue] = set()
        self._lock = threading.Lock()
        self._max_queue = max_queue

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=self._max_queue)
        with self._lock:
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            self._subscribers.discard(q)

    def publish(self, message: dict) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(message)
            except queue.Full:
                # slow consumer: drop oldest, keep the stream current
                try:
                    q.get_nowait()
                    q.put_nowait(message)
                except queue.Empty:
                    pass