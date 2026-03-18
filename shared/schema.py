"""
Unified event schema for the IDS pipeline.
Every event — simulated or real — must conform to this structure
before being passed to Kafka or SQLite.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
import uuid
import json


# ── Event types (normalized vocabulary, source-agnostic) ─────────────────────
class EventType:
    AUTH_FAILURE         = "auth_failure"          # wrong password / bad key
    AUTH_SUCCESS         = "auth_success"           # successful login
    AUTH_INVALID_USER    = "auth_invalid_user"      # username does not exist
    AUTH_TOO_MANY_AUTH   = "auth_too_many"          # too many auth attempts (server-side)
    CONNECTION_CLOSED    = "connection_closed"      # connection dropped / reset
    CONNECTION_ATTEMPT   = "connection_attempt"     # new inbound connection
    DISCONNECT           = "disconnect"             # clean disconnect
    INVALID_PACKET       = "invalid_packet"         # malformed SSH packet
    PORT_SCAN            = "port_scan"              # detected by detector, not raw log
    BRUTE_FORCE          = "brute_force"            # detected by detector
    CREDENTIAL_STUFFING  = "credential_stuffing"    # detected by detector
    DISTRIBUTED_ATTACK   = "distributed_attack"     # detected by detector


# ── Severity levels ───────────────────────────────────────────────────────────
class Severity:
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


# ── Source types ──────────────────────────────────────────────────────────────
class SourceType:
    SSH     = "ssh"
    HTTP    = "http"
    NETFLOW = "netflow"
    WINDOWS = "windows"
    LINUX   = "linux"


@dataclass
class Event:
    """
    The single unified event schema used throughout the entire pipeline.
    Every component reads and writes this structure.
    """
    event_type:   str
    source_type:  str
    source_ip:    str
    source_host:  str

    # Optional fields with sensible defaults
    event_id:     str                  = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:    str                  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    dest_ip:      Optional[str]        = None
    dest_port:    Optional[int]        = None
    severity:     str                  = Severity.LOW
    scenario_id:  Optional[str]        = None   # set by simulator; null for real traffic
    raw:          Optional[str]        = None   # original log line
    metadata:     dict                 = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @staticmethod
    def from_dict(d: dict) -> "Event":
        return Event(**d)

    @staticmethod
    def from_json(s: str) -> "Event":
        return Event.from_dict(json.loads(s))
