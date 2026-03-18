"""
IDS Dashboard — Flask app.
Place in IDS SYSTEM/ root (same level as run.py, detector/, etc.)

Install:  pip3 install flask
Run:      python3 app.py
Open:     http://localhost:5000
"""

import json
import os
import subprocess
import sys
import time
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
    """Static scaling data from your benchmark runs."""
    return jsonify({
        "labels": ["1K", "5K", "20K", "50K", "100K"],
        "serial":        [218221, 319790, 250155, 342190, 399002],
        "parallel_type": [11314,  27545,  42971,  42318,  47970],
        "batch_2w":      [59071,  142988, 196503, 193918, 220811],
        "batch_4w":      [47290,  127004, 195190, 271938, 270672],
        "windows":       [35884,  65244,  79131,  94849,  87657],
        "elapsed_serial":   [4.6,  15.6,  80.0,  146.1, 250.6],
        "elapsed_batch4w":  [21.1, 39.4,  102.5, 183.9, 369.5],
    })


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
