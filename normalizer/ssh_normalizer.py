"""
SSH log normalizer.
Parses raw auth.log lines (both simulated and real) into unified Event objects.
This is the single source of truth for SSH log parsing — used by both
the simulator and the real log tailer.
"""

import re
from datetime import datetime, timezone
from typing import Optional
from shared.schema import Event, EventType, Severity, SourceType


# ── Regex patterns matching real OpenSSH sshd log lines ──────────────────────

PATTERNS = [
    # Failed password for root from 1.2.3.4 port 54321 ssh2
    (re.compile(
        r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) "
        r"from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ), "_parse_failed_password"),

    # Invalid user bob from 1.2.3.4 port 54321
    (re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ), "_parse_invalid_user"),

    # Accepted password for alice from 1.2.3.4 port 54321 ssh2
    # Accepted publickey for alice from 1.2.3.4 port 54321 ssh2
    (re.compile(
        r"Accepted (?P<method>password|publickey) for (?P<user>\S+) "
        r"from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ), "_parse_accepted"),

    # Connection closed by 1.2.3.4 port 54321
    (re.compile(
        r"Connection closed by (?:invalid user \S+ )?(?P<ip>[\d.]+) port (?P<port>\d+)"
    ), "_parse_connection_closed"),

    # Disconnected from 1.2.3.4 port 54321
    (re.compile(
        r"Disconnected from (?:invalid user \S+ )?(?P<ip>[\d.]+) port (?P<port>\d+)"
    ), "_parse_disconnect"),

    # Too many authentication failures for root from 1.2.3.4 port 54321
    (re.compile(
        r"Too many authentication failures for (?P<user>\S+) "
        r"from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ), "_parse_too_many_auth"),

    # Connection from 1.2.3.4 port 54321
    (re.compile(
        r"Connection from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ), "_parse_connection_attempt"),

    # Bad packet length / SSH packet not finished / protocol mismatch
    (re.compile(
        r"(?P<msg>Bad packet length|Did not receive identification string|"
        r"Protocol mismatch|Invalid SSH identification string)"
        r".*from (?P<ip>[\d.]+)"
    ), "_parse_invalid_packet"),
]


class SSHNormalizer:

    def parse(self, raw_line: str, source_host: str = "unknown",
              scenario_id: Optional[str] = None) -> Optional[Event]:
        """
        Given a raw auth.log line, return a normalized Event or None
        if the line is not SSH-related or not recognized.
        """
        # Only process sshd lines
        if "sshd" not in raw_line:
            return None

        for pattern, method_name in PATTERNS:
            match = pattern.search(raw_line)
            if match:
                method = getattr(self, method_name)
                event = method(match, raw_line, source_host, scenario_id)
                return event

        return None  # unrecognized sshd line

    # ── Individual parsers ────────────────────────────────────────────────────

    def _parse_failed_password(self, m, raw, host, scenario_id):
        is_invalid = bool(m.group("invalid"))
        return Event(
            event_type   = EventType.AUTH_INVALID_USER if is_invalid else EventType.AUTH_FAILURE,
            source_type  = SourceType.SSH,
            source_ip    = m.group("ip"),
            source_host  = host,
            severity     = Severity.LOW,
            scenario_id  = scenario_id,
            raw          = raw.strip(),
            dest_port    = 22,
            metadata     = {
                "user":   m.group("user"),
                "port":   int(m.group("port")),
                "method": "password",
                "invalid_user": is_invalid,
            },
        )

    def _parse_invalid_user(self, m, raw, host, scenario_id):
        return Event(
            event_type  = EventType.AUTH_INVALID_USER,
            source_type = SourceType.SSH,
            source_ip   = m.group("ip"),
            source_host = host,
            severity    = Severity.LOW,
            scenario_id = scenario_id,
            raw         = raw.strip(),
            dest_port   = 22,
            metadata    = {
                "user": m.group("user"),
                "port": int(m.group("port")),
            },
        )

    def _parse_accepted(self, m, raw, host, scenario_id):
        return Event(
            event_type  = EventType.AUTH_SUCCESS,
            source_type = SourceType.SSH,
            source_ip   = m.group("ip"),
            source_host = host,
            severity    = Severity.INFO,
            scenario_id = scenario_id,
            raw         = raw.strip(),
            dest_port   = 22,
            metadata    = {
                "user":   m.group("user"),
                "port":   int(m.group("port")),
                "method": m.group("method"),
            },
        )

    def _parse_connection_closed(self, m, raw, host, scenario_id):
        return Event(
            event_type  = EventType.CONNECTION_CLOSED,
            source_type = SourceType.SSH,
            source_ip   = m.group("ip"),
            source_host = host,
            severity    = Severity.INFO,
            scenario_id = scenario_id,
            raw         = raw.strip(),
            dest_port   = 22,
            metadata    = {"port": int(m.group("port"))},
        )

    def _parse_disconnect(self, m, raw, host, scenario_id):
        return Event(
            event_type  = EventType.DISCONNECT,
            source_type = SourceType.SSH,
            source_ip   = m.group("ip"),
            source_host = host,
            severity    = Severity.INFO,
            scenario_id = scenario_id,
            raw         = raw.strip(),
            dest_port   = 22,
            metadata    = {"port": int(m.group("port"))},
        )

    def _parse_too_many_auth(self, m, raw, host, scenario_id):
        return Event(
            event_type  = EventType.AUTH_TOO_MANY_AUTH,
            source_type = SourceType.SSH,
            source_ip   = m.group("ip"),
            source_host = host,
            severity    = Severity.MEDIUM,
            scenario_id = scenario_id,
            raw         = raw.strip(),
            dest_port   = 22,
            metadata    = {
                "user": m.group("user"),
                "port": int(m.group("port")),
            },
        )

    def _parse_connection_attempt(self, m, raw, host, scenario_id):
        return Event(
            event_type  = EventType.CONNECTION_ATTEMPT,
            source_type = SourceType.SSH,
            source_ip   = m.group("ip"),
            source_host = host,
            severity    = Severity.INFO,
            scenario_id = scenario_id,
            raw         = raw.strip(),
            dest_port   = 22,
            metadata    = {"port": int(m.group("port"))},
        )

    def _parse_invalid_packet(self, m, raw, host, scenario_id):
        return Event(
            event_type  = EventType.INVALID_PACKET,
            source_type = SourceType.SSH,
            source_ip   = m.group("ip"),
            source_host = host,
            severity    = Severity.MEDIUM,
            scenario_id = scenario_id,
            raw         = raw.strip(),
            dest_port   = 22,
            metadata    = {"message": m.group("msg")},
        )
