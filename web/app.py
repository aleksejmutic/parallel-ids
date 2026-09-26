"""
Flask dashboard for the IDS.

  GET  /                 dashboard page
  GET  /stream           Server-Sent Events: live attack events + benchmark
                         progress, multiplexed onto one connection
  POST /benchmark/start  kick off a benchmark run (streams back over /stream)

One SSE connection carries everything; the browser routes each message by its
"channel" field into the right console pane or chart.
"""
import json
import queue

from flask import Flask, Response, jsonify, render_template

from web.hub import Hub
from web.kafka_stream import start_kafka_stream
from web.benchmark_runner import BenchmarkRunner

app = Flask(__name__)

hub = Hub()
benchmark_runner = BenchmarkRunner(hub)
start_kafka_stream(hub)


def _sse(message: dict) -> str:
    return f"data: {json.dumps(message)}\n\n"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/stream")
def stream():
    def gen():
        q = hub.subscribe()
        yield _sse({"channel": "system", "data": {"status": "connected"}})
        try:
            while True:
                try:
                    message = q.get(timeout=15)
                except queue.Empty:
                    yield ": keepalive\n\n"  # comment frame keeps the socket open
                    continue
                yield _sse(message)
        finally:
            hub.unsubscribe(q)

    return Response(
        gen(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/benchmark/start", methods=["POST"])
def benchmark_start():
    started = benchmark_runner.start()
    return jsonify({"started": started, "running": benchmark_runner.running})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)