import subprocess
import json
from core.event_factory import create_event


"""This script runs an SSH command, captures its output, 
converts it into a structured IDS event using the event factory, and prints it as formatted JSON."""
result = subprocess.run(
    ["ssh", "alexei@localhost", "echo Connected"],
    capture_output=True,
    text=True
)

event = create_event(
    source_type="ssh",
    result=result,
    context={
        "command": "ssh localhost echo Connected",
        "dest_port": 22,
        "source_ip": "127.0.0.1"
    }
)
"""Just prints out the event log as a json format."""
print(json.dumps(event, indent=2))