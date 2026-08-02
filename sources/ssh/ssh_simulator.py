"""
SSH Event Collector Module

This module simulates SSH activity and converts the execution result into a
normalized IDS security event.

It acts as a data source component in the IDS pipeline:
- Executes an SSH command against a target SSH service.
- Captures the command execution result.
- Passes the raw result and connection context to the event factory.
- Returns a structured event that can later be stored, analyzed, or forwarded
  to monitoring systems such as Elasticsearch and Kibana.

This module represents the SSH telemetry source of the IDS environment.
In the full system, similar collectors can exist for HTTP traffic, Linux
system calls, Windows system calls, and other event sources.
"""

import subprocess

from core.event_factory import create_event
from config import SSH_USER, SSH_HOST, SSH_PORT


def collect():
    """
    Executes an SSH command and returns a normalized IDS event.

    The function represents an SSH activity source inside the IDS lab
    environment. It performs the request, captures the execution output,
    and converts the result into a common event format.
    """

    ssh_target = f"{SSH_USER}@{SSH_HOST}"

    ssh_command = [
    "ssh",
    "-p",
    str(SSH_PORT),
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    ssh_target,
    "echo",
    "Connected"
]

    result = subprocess.run(
        ssh_command,
        capture_output=True,
        text=True,
        timeout=10
    )

    event = create_event(
        source_type="ssh",
        result=result,
        context={
            "command": " ".join(ssh_command),
            "dest_port": SSH_PORT,
            "source_ip": "127.0.0.1"
        }
    )

    return event