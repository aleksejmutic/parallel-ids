import subprocess
import json
from core.event_factory import create_event
from config import SSH_USER, SSH_HOST, SSH_PORT

"""This script runs an SSH command, captures its output, 
converts it into a structured IDS event using the event factory, and prints it as formatted JSON."""
command = f"{SSH_USER}@{SSH_HOST}"

result = subprocess.run(
    ["ssh", command, "echo Connected"],
    capture_output=True,
    text=True
)

event = create_event(
    source_type="ssh",
    result=result,
    context={
        "command": "ssh localhost echo Connected",
        "dest_port": SSH_PORT,
        "source_ip": "127.0.0.1"
    }
)
"""Just prints out the event log as a json format."""
print(json.dumps(event, indent=2))