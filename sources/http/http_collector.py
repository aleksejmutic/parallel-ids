"""
HTTP Event Collector Module

This module simulates HTTP activity and converts the HTTP request result into a
normalized IDS security event.

It acts as a data source component in the IDS pipeline:
- Receives the result of an HTTP request against a target HTTP service.
- Captures the request result.
- Passes the raw result and connection context to the event factory.
- Returns a structured event that can later be stored, analyzed, or forwarded
  to monitoring systems such as Elasticsearch and Kibana.

This module represents the HTTP telemetry source of the IDS environment.
"""

from core.event_factory import create_event
from config import HTTP_HOST, HTTP_PORT


def collect(result, attack_type):
    """
    Converts an HTTP request result into a normalized IDS event.
    """

    event = create_event(
        source_type="http",
        result=result,
        context={
            "command": "HTTP authentication attempt",
            "source_ip": "127.0.0.1",
            "source_host": "attacker",
            "dest_ip": HTTP_HOST,
            "dest_port": HTTP_PORT,
            "attack_type": attack_type,
        }
    )

    print("NORMALIZED HTTP EVENT:")
    print(event)

    return event