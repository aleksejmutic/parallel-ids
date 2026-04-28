"""
Real SSH log tailer.
Watches the Docker SSH container logs in real time and feeds
each line into the existing normalizer + SQLite pipeline.

Usage:
    python3 log_tailer.py

Requires the Docker SSH container to be running:
    docker-compose up -d
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from normalizer.ssh_normalizer import SSHNormalizer
from storage.db import init_db, insert_event

normalizer = SSHNormalizer()


def process_line(line: str):
    line = line.strip()
    if not line:
        return
    event = normalizer.parse(line, source_host="ids-ssh-server", scenario_id=None)
    if event:
        insert_event(event)
        print(f"[live] {event.event_type:<22} {event.source_ip:<16} {line[-70:]}")


def tail_docker(container: str = "ids-ssh-server"):
    print(f"[tailer] Watching Docker container: {container}")
    print(f"[tailer] Make SSH connections to localhost:2222 to see them appear.")
    print(f"[tailer] Press Ctrl+C to stop.\n")

    try:
        proc = subprocess.Popen(
            ["docker", "logs", "-f", "--tail", "0", container],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            process_line(line)
    except KeyboardInterrupt:
        proc.terminate()
        print("\n[tailer] Stopped.")
    except FileNotFoundError:
        print("[tailer] ERROR: docker command not found.")


if __name__ == "__main__":
    init_db()
    print("[tailer] Database ready.\n")
    tail_docker()
