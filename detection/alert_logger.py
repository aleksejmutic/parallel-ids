"""
Alert logging.

Alerts are written as JSON Lines (one flat JSON object per line) to
logs/alerts.jsonl, e.g.:

    {"logged_at": 1755321000.1, "strategy": "batch", "rule": "ssh_brute_force", "source_ip": "10.0.0.3", "count": 6, "window_seconds": 60, "timestamp": 1755321000.05}
    {"logged_at": 1755321000.4, "strategy": "batch", "rule": "ssh_brute_force", "source_ip": "10.0.0.1", "count": 5, "window_seconds": 60, "timestamp": 1755321000.38}

WHY FLAT, NOT NESTED:

Nested logs (an "attack" object containing an array of "events" containing
nested "metadata"...) feel natural to write but are painful to read back.
Every consumer of the log — a grep/jq one-liner, a pandas dataframe for
your benchmark report, an Elasticsearch index later — wants one record
per line with predictable top-level keys. Nesting forces every one of
those consumers to write tree-walking code just to answer "how many
alerts fired against this IP." Flat records answer that with one jq
filter: `jq 'select(.source_ip=="10.0.0.3")' logs/alerts.jsonl`.

WHY JSON LINES, NOT ONE BIG JSON ARRAY:

A JSON array requires the whole file to be valid JSON at all times —
you'd have to read the entire file, deserialize it, append, and
rewrite the whole thing for every single alert, which gets slow and is
fragile if the process dies mid-write (you can corrupt the whole log).
JSON Lines lets you open the file in append mode and just write one
more line, forever. Multiple strategy runs (serial, batch, window) can
all append to the same file without stepping on each other.

IF YOU LATER WANT STRUCTURE (e.g. grouping alerts into "attack
sessions" spanning multiple IPs or a timeline view for the dashboard):
build that as a *derived* view computed from these flat records
(a query/aggregation step), rather than changing the raw log format
itself. Keep the source-of-truth log flat; nest only in memory, for
display.
"""
import json
import time
from pathlib import Path

LOG_PATH = Path("logs/alerts.jsonl")


def log_alerts(alerts: list[dict], strategy_name: str) -> None:
    if not alerts:
        return
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a") as f:
        for alert in alerts:
            record = {
                "logged_at": time.time(),
                "strategy": strategy_name,
                **alert,
            }
            f.write(json.dumps(record) + "\n")
