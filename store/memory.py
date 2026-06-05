"""SQLite 기반 상태 저장소 — 수집 데이터, 베이스라인, 알림 이력"""
import sqlite3
import json
from datetime import datetime, timezone
from contextlib import contextmanager
from config import config


def get_conn():
    conn = sqlite3.connect(config.db_path)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS cost_snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            service     TEXT NOT NULL,
            amount_usd  REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS resource_snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            data        TEXT NOT NULL   -- JSON
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            alert_type  TEXT NOT NULL,
            severity    TEXT NOT NULL,  -- critical / warning / info
            title       TEXT NOT NULL,
            detail      TEXT NOT NULL,
            raw_data    TEXT,           -- JSON
            notified    INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS baselines (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL,  -- JSON
            updated_at  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_cost_ts ON cost_snapshots(ts);
        CREATE INDEX IF NOT EXISTS idx_resource_ts ON resource_snapshots(ts);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
        """)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Cost snapshots ────────────────────────────────────────────────────────────

def save_cost_snapshot(service: str, amount_usd: float):
    with db() as conn:
        conn.execute(
            "INSERT INTO cost_snapshots (ts, service, amount_usd) VALUES (?,?,?)",
            (now_iso(), service, amount_usd)
        )


def get_cost_snapshots(hours: int = 168) -> list[dict]:
    with db() as conn:
        rows = conn.execute("""
            SELECT ts, service, amount_usd FROM cost_snapshots
            WHERE ts >= datetime('now', ?)
            ORDER BY ts DESC
        """, (f"-{hours} hours",)).fetchall()
    return [dict(r) for r in rows]


# ── Resource snapshots ────────────────────────────────────────────────────────

def save_resource_snapshot(resource_id: str, resource_type: str, data: dict):
    with db() as conn:
        conn.execute(
            "INSERT INTO resource_snapshots (ts, resource_id, resource_type, data) VALUES (?,?,?,?)",
            (now_iso(), resource_id, resource_type, json.dumps(data))
        )


def get_latest_resource_ids(resource_type: str) -> set[str]:
    with db() as conn:
        rows = conn.execute("""
            SELECT DISTINCT resource_id FROM resource_snapshots
            WHERE resource_type = ?
              AND ts >= datetime('now', '-2 hours')
        """, (resource_type,)).fetchall()
    return {r["resource_id"] for r in rows}


def get_previous_resource_ids(resource_type: str, hours: int = 25) -> set[str]:
    with db() as conn:
        rows = conn.execute("""
            SELECT DISTINCT resource_id FROM resource_snapshots
            WHERE resource_type = ?
              AND ts < datetime('now', '-1 hours')
              AND ts >= datetime('now', ?)
        """, (resource_type, f"-{hours} hours")).fetchall()
    return {r["resource_id"] for r in rows}


# ── Alerts ────────────────────────────────────────────────────────────────────

def save_alert(alert_type: str, severity: str, title: str, detail: str, raw_data: dict = None) -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO alerts (ts, alert_type, severity, title, detail, raw_data) VALUES (?,?,?,?,?,?)",
            (now_iso(), alert_type, severity, title, detail, json.dumps(raw_data) if raw_data else None)
        )
        return cur.lastrowid


def get_recent_alerts(hours: int = 24, limit: int = 50) -> list[dict]:
    with db() as conn:
        rows = conn.execute("""
            SELECT * FROM alerts
            WHERE ts >= datetime('now', ?)
            ORDER BY ts DESC LIMIT ?
        """, (f"-{hours} hours", limit)).fetchall()
    return [dict(r) for r in rows]


def mark_notified(alert_id: int):
    with db() as conn:
        conn.execute("UPDATE alerts SET notified=1 WHERE id=?", (alert_id,))


def get_unnotified_alerts() -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE notified=0 ORDER BY ts ASC"
        ).fetchall()
    return [dict(r) for r in rows]


# ── Baselines ─────────────────────────────────────────────────────────────────

def set_baseline(key: str, value):
    with db() as conn:
        conn.execute("""
            INSERT INTO baselines (key, value, updated_at) VALUES (?,?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
        """, (key, json.dumps(value), now_iso()))


def get_baseline(key: str):
    with db() as conn:
        row = conn.execute("SELECT value FROM baselines WHERE key=?", (key,)).fetchone()
    return json.loads(row["value"]) if row else None
