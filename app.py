"""
IDS Dashboard — Flask app.
Place in IDS SYSTEM/ root (same level as run.py, detector/, etc.)

Install:  pip3 install flask
Run:      python3 app.py
Open:     http://localhost:5000
"""

import glob
import json
import subprocess
import sys
from pathlib import Path
from flask import Flask, Response, jsonify, render_template, stream_with_context

app = Flask(__name__)
BASE = Path(__file__).parent


def _stream_script(cmd: list, cwd: Path):
    """Generator: runs a subprocess and yields each output line as SSE."""
    proc = subprocess.Popen(
        cmd, cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    for line in proc.stdout:
        yield f"data: {line.rstrip()}\n\n"
    proc.wait()
    code = proc.returncode
    yield f"data: __EXIT__{code}\n\n"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/results")
def api_results():
    """Return pipeline_results.json to the dashboard."""
    path = BASE / "pipeline_results.json"
    if not path.exists():
        return jsonify({"error": "No results yet — run the pipeline first."})
    return jsonify(json.loads(path.read_text()))


@app.route("/api/scaling")
def api_scaling():
    """
    Reads all benchmark_<N>.json files from detector/ and builds
    the scaling dataset dynamically. No hardcoded numbers.
    Run benchmark.py --events N --save for each scale you want to appear.
    """
    detector_dir = BASE / "detector"
    files = sorted(glob.glob(str(detector_dir / "benchmark_*.json")))

    if not files:
        return jsonify({"error": "No benchmark files found — run benchmark.py --save first."})

    scales = {}
    label_order = []

    for path in files:
        data = json.loads(Path(path).read_text())
        total = data["results"][0]["total_events"]
        label = f"{total // 1000}K" if total >= 1000 else str(total)
        label_order.append(label)

        for r in data["results"]:
            mode = r["mode"]
            if mode not in scales:
                scales[mode] = {"values": [], "elapsed": []}
            scales[mode]["values"].append(round(r["events_per_second"], 1))
            scales[mode]["elapsed"].append(round(r["elapsed_seconds"] * 1000, 1))

    def get_values(mode):
        return scales.get(mode, {}).get("values", [None] * len(label_order))

    def get_elapsed(mode):
        return scales.get(mode, {}).get("elapsed", [None] * len(label_order))

    return jsonify({
        "labels":          label_order,
        "serial":          get_values("serial"),
        "parallel_type":   get_values("parallel_by_type"),
        "batch_2w":        get_values("parallel_batch_2w"),
        "batch_4w":        get_values("parallel_batch_4w"),
        "windows":         get_values("parallel_windows_5min"),
        "elapsed_serial":  get_elapsed("serial"),
        "elapsed_batch4w": get_elapsed("parallel_batch_4w"),
    })


@app.route("/run/benchmark")
def run_benchmark():
    """Stream benchmark.py at all five scales, then signal done."""
    detector_dir = BASE / "detector"
    scales = [1000, 5000, 20000, 50000, 100000]

    def generate():
        yield "data: === Running benchmark at all scales — this takes a few minutes ===\n\n"
        for n in scales:
            yield f"data: \n\n"
            yield f"data: --- Scale: {n:,} events ---\n\n"
            yield from _stream_script(
                [sys.executable, "benchmark.py", "--events", str(n), "--save"],
                detector_dir,
            )
        yield "data: \n\n"
        yield "data: === All benchmark files generated ===\n\n"
        yield "data: __BENCH_DONE__\n\n"

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/run/simulation")
def run_simulation():
    """Stream run.py output live, then automatically run pipeline_detector."""
    def generate():
        yield "data: === Starting IDS simulation (all SSH attack scenarios) ===\n\n"
        yield from _stream_script([sys.executable, "run.py"], BASE)
        yield "data: \n\n"
        yield "data: === Simulation done — running parallel detector comparison ===\n\n"
        yield from _stream_script([sys.executable, "pipeline_detector.py"], BASE)
        yield "data: __DONE__\n\n"
    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)