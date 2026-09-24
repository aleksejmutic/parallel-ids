"""
Event Factory Module

This module provides the central normalization layer for the IDS pipeline.

It converts raw execution results from different data sources such as SSH,
HTTP requests, and system call collectors into a unified security event format.

Each generated event contains common fields like:
- unique event identifier
- timestamp
- event source information
- network metadata
- execution output
- additional context

The purpose of this module is to ensure that all IDS data sources produce
consistent structured events that can later be stored, analyzed, batched, or
forwarded to monitoring systems such as Elasticsearch, Logstash, and Kibana.
"""

import copy
import uuid
from datetime import datetime, timezone

from core.event_schema import EVENT_FORMAT
from core.normalizers.ssh import normalize as normalize_ssh
from core.normalizers.http import normalize as normalize_http


NORMALIZERS = {
    "ssh": normalize_ssh,
    "http": normalize_http,
}


def create_event(
    source_type: str,
    result,
    context: dict | None = None,
    simulated: bool = True
):
    if context is None:
        context = {}

    normalizer = NORMALIZERS[source_type]
    normalized = normalizer(result)

    event = copy.deepcopy(EVENT_FORMAT)

    event.update({
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "event_type": source_type.upper(),
        "source_type": source_type,

        "source_ip": context.get("source_ip"),
        "source_host": context.get("source_host"),

        "dest_ip": context.get("dest_ip"),
        "dest_port": context.get("dest_port"),

        "severity": context.get("severity", "low"),

        "raw_stdout": normalized["raw_stdout"],
        "raw_stderr": normalized["raw_stderr"],
        "exit_code": normalized["exit_code"],

        "metadata": {
            "command": context.get("command"),
            "attack_type": context.get("attack_type"),
            "success": normalized["success"],
            "simulated": simulated,
        }
    })

    return event