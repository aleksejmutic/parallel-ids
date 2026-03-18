"""
SQLite storage layer.
Handles all database operations for events, alerts, and IP profiles.
"""

import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from shared.schema import Event


DB_PATH = Path("ids_data.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # allows concurrent reads during writes
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables if they don't exist. Safe to call multiple times."""
    conn = get_connection()
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id      TEXT UNIQUE NOT NULL,
                timestamp     TEXT NOT NULL,
                event_type    TEXT NOT NULL,
                source_type   TEXT NOT NULL,
                source_ip     TEXT NOT NULL,
                source_host   TEXT NOT NULL,
                dest_ip       TEXT,
                dest_port     INTEGER,
                severity      TEXT NOT NULL DEFAULT 'low',
                scenario_id   TEXT,
                raw           TEXT,
                metadata      TEXT         -- stored as JSON string
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id       TEXT UNIQUE NOT NULL,
                timestamp      TEXT NOT NULL,
                rule_name      TEXT NOT NULL,
                description    TEXT NOT NULL,
                severity       TEXT NOT NULL,
                source_ip      TEXT NOT NULL,
                source_host    TEXT NOT NULL,
                event_count    INTEGER DEFAULT 1,
                scenario_id    TEXT,
                related_events TEXT         -- JSON array of event_ids
            );

            CREATE TABLE IF NOT EXISTS ip_profiles (
                source_ip          TEXT PRIMARY KEY,
                first_seen         TEXT NOT NULL,
                last_seen          TEXT NOT NULL,
                total_events       INTEGER DEFAULT 0,
                auth_failures      INTEGER DEFAULT 0,
                auth_successes     INTEGER DEFAULT 0,
                invalid_users      INTEGER DEFAULT 0,
                connection_count   INTEGER DEFAULT 0,
                alert_count        INTEGER DEFAULT 0,
                risk_score         REAL DEFAULT 0.0,
                is_flagged         INTEGER DEFAULT 0,  -- boolean
                metadata           TEXT                -- JSON
            );

            CREATE INDEX IF NOT EXISTS idx_events_source_ip  ON events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type       ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_scenario   ON events(scenario_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_source_ip  ON alerts(source_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON alerts(timestamp);
        """)
    conn.close()
    print(f"[DB] Initialized database at {DB_PATH.resolve()}")


# ── Events ────────────────────────────────────────────────────────────────────

def insert_event(event: Event):
    conn = get_connection()
    with conn:
        conn.execute("""
            INSERT OR IGNORE INTO events
                (event_id, timestamp, event_type, source_type, source_ip,
                 source_host, dest_ip, dest_port, severity, scenario_id, raw, metadata)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            event.event_id,
            event.timestamp,
            event.event_type,
            event.source_type,
            event.source_ip,
            event.source_host,
            event.dest_ip,
            event.dest_port,
            event.severity,
            event.scenario_id,
            event.raw,
            json.dumps(event.metadata),
        ))
    conn.close()
    _update_ip_profile(event)


def get_events(
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    scenario_id: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 200,
) -> list[dict]:
    conn = get_connection()
    query = "SELECT * FROM events WHERE 1=1"
    params = []
    if source_ip:
        query += " AND source_ip = ?"
        params.append(source_ip)
    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if scenario_id:
        query += " AND scenario_id = ?"
        params.append(scenario_id)
    if since:
        query += " AND timestamp >= ?"
        params.append(since)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = [dict(r) for r in conn.execute(query, params).fetchall()]
    conn.close()
    return rows


# ── Alerts ────────────────────────────────────────────────────────────────────

def insert_alert(
    rule_name: str,
    description: str,
    severity: str,
    source_ip: str,
    source_host: str,
    event_count: int,
    related_event_ids: list[str],
    scenario_id: Optional[str] = None,
) -> str:
    import uuid
    alert_id  = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    with conn:
        conn.execute("""
            INSERT INTO alerts
                (alert_id, timestamp, rule_name, description, severity,
                 source_ip, source_host, event_count, scenario_id, related_events)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            alert_id, timestamp, rule_name, description, severity,
            source_ip, source_host, event_count, scenario_id,
            json.dumps(related_event_ids),
        ))
    conn.close()
    # bump alert count on the IP profile
    conn = get_connection()
    with conn:
        conn.execute("""
            UPDATE ip_profiles
            SET alert_count = alert_count + 1,
                is_flagged  = 1,
                last_seen   = ?
            WHERE source_ip = ?
        """, (timestamp, source_ip))
    conn.close()
    return alert_id


def get_alerts(limit: int = 100, scenario_id: Optional[str] = None) -> list[dict]:
    conn = get_connection()
    query = "SELECT * FROM alerts"
    params = []
    if scenario_id:
        query += " WHERE scenario_id = ?"
        params.append(scenario_id)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = [dict(r) for r in conn.execute(query, params).fetchall()]
    conn.close()
    return rows


# ── IP Profiles ───────────────────────────────────────────────────────────────

def _update_ip_profile(event: Event):
    """Called automatically after every insert_event."""
    now = event.timestamp
    conn = get_connection()
    with conn:
        existing = conn.execute(
            "SELECT * FROM ip_profiles WHERE source_ip = ?", (event.source_ip,)
        ).fetchone()

        from shared.schema import EventType
        if existing is None:
            conn.execute("""
                INSERT INTO ip_profiles
                    (source_ip, first_seen, last_seen, total_events,
                     auth_failures, auth_successes, invalid_users, connection_count)
                VALUES (?,?,?,1,?,?,?,?)
            """, (
                event.source_ip, now, now,
                1 if event.event_type == EventType.AUTH_FAILURE      else 0,
                1 if event.event_type == EventType.AUTH_SUCCESS       else 0,
                1 if event.event_type == EventType.AUTH_INVALID_USER  else 0,
                1 if event.event_type == EventType.CONNECTION_ATTEMPT else 0,
            ))
        else:
            conn.execute("""
                UPDATE ip_profiles SET
                    last_seen          = ?,
                    total_events       = total_events + 1,
                    auth_failures      = auth_failures      + ?,
                    auth_successes     = auth_successes     + ?,
                    invalid_users      = invalid_users      + ?,
                    connection_count   = connection_count   + ?
                WHERE source_ip = ?
            """, (
                now,
                1 if event.event_type == EventType.AUTH_FAILURE      else 0,
                1 if event.event_type == EventType.AUTH_SUCCESS       else 0,
                1 if event.event_type == EventType.AUTH_INVALID_USER  else 0,
                1 if event.event_type == EventType.CONNECTION_ATTEMPT else 0,
                event.source_ip,
            ))
    conn.close()


def get_profile(source_ip: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM ip_profiles WHERE source_ip = ?", (source_ip,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_profiles(flagged_only: bool = False) -> list[dict]:
    conn = get_connection()
    query = "SELECT * FROM ip_profiles"
    if flagged_only:
        query += " WHERE is_flagged = 1"
    query += " ORDER BY alert_count DESC, total_events DESC"
    rows = [dict(r) for r in conn.execute(query).fetchall()]
    conn.close()
    return rows
