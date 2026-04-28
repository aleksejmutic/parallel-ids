"""
Event Factory Module

This module is responsible for converting raw execution results
(from SSH, HTTP, and system call simulators) into a unified
structured security event format.

It acts as the normalization layer in the IDS pipeline, ensuring
all data sources produce consistent event objects that can be
stored, analyzed, and forwarded to systems like ELK (Elasticsearch,
Logstash, Kibana).
"""

from datetime import datetime, timezone
import uuid
from core.event_schema import EVENT_FORMAT


def create_event(source_type: str, result, context: dict = None, simulated: bool = True):
    """
    Creates a normalized IDS event from raw execution output.

    This function serves as a generic event factory for all data sources
    (SSH, HTTP, Linux syscalls, Windows syscalls).

    It takes raw process execution results and converts them into a
    structured event format defined by EVENT_FORMAT.

    Parameters:
        source_type (str):
            Type of the source generating the event.
            Examples: "ssh", "http", "sys_linux", "sys_windows"

        result:
            Execution result object (typically subprocess result)
            Expected to contain:
                - stdout
                - stderr
                - returncode

        context (dict, optional):
            Additional metadata about the event.
            Can include:
                - source_ip
                - source_host
                - dest_ip
                - dest_port
                - severity
                - command
                - extra (custom fields)

    Returns:
        dict:
            A normalized security event containing:
                - unique event_id
                - timestamp (UTC ISO format)
                - classification fields
                - network/system metadata
                - raw execution output
                - structured metadata

    Purpose in IDS pipeline:
        This function acts as the central normalization layer before
        events are stored in the database or forwarded to ELK stack
        for analysis and visualization.
    """

    if context is None:
        context = {}

    event = dict(EVENT_FORMAT)

    event.update({
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": source_type.upper(),
        "source_type": source_type,

        "source_ip": context.get("source_ip", "127.0.0.1"),
        "source_host": context.get("source_host", "localhost"),
        "dest_ip": context.get("dest_ip", "127.0.0.1"),
        "dest_port": context.get("dest_port"),

        "severity": context.get("severity", "low"),

        "raw_stdout": getattr(result, "stdout", "").strip(),
        "raw_stderr": getattr(result, "stderr", "").strip(),
        "exit_code": getattr(result, "returncode", None),

        "metadata": {
            "command": context.get("command"),
            "success": getattr(result, "returncode", 0) == 0,
            "simulated": simulated,
            **context.get("extra", {})
        }
    })

    return event