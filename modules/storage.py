"""
storage.py
----------
Persistencia en SQLite: usuarios, intentos de login, historial de análisis
y registro de auditoría.

· Todas las consultas usan parámetros (?) → sin inyección SQL.
· La ruta de la base de datos se configura con DATA_DIR (por defecto ./data),
  que está excluida del repositorio en .gitignore.
· Los registros de auditoría e intentos de login (contienen IP = dato
  personal) se borran pasados AUDIT_RETENTION_DAYS días.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('admin', 'analyst')),
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL,
    last_login    TEXT
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE,
    ip       TEXT,
    success  INTEGER NOT NULL,
    ts       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analyses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    domain      TEXT NOT NULL,
    ts          TEXT NOT NULL,
    score       INTEGER NOT NULL,
    risk        TEXT NOT NULL,
    result_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    username TEXT,
    event    TEXT NOT NULL,
    detail   TEXT,
    ip       TEXT
);
CREATE INDEX IF NOT EXISTS idx_analyses_domain ON analyses(domain, ts);
CREATE INDEX IF NOT EXISTS idx_attempts_user   ON login_attempts(username, ts);
CREATE INDEX IF NOT EXISTS idx_audit_event     ON audit_log(username, event, ts);
"""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def db_path() -> str:
    data_dir = os.getenv("DATA_DIR", "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "cyberscope.db")


@contextmanager
def connect():
    conn = sqlite3.connect(db_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
    purge_old_records()


def purge_old_records() -> int:
    """Borra auditoría e intentos de login más antiguos que la retención configurada."""
    days = int(os.getenv("AUDIT_RETENTION_DAYS", "90"))
    limit = iso(now_utc() - timedelta(days=days))
    with connect() as conn:
        n = conn.execute("DELETE FROM audit_log WHERE ts < ?", (limit,)).rowcount
        n += conn.execute("DELETE FROM login_attempts WHERE ts < ?", (limit,)).rowcount
    return n


# ── Auditoría ──────────────────────────────────────────────────────────────────

def audit(event: str, username: str | None = None, detail: str | None = None, ip: str | None = None) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO audit_log (ts, username, event, detail, ip) VALUES (?, ?, ?, ?, ?)",
            (iso(now_utc()), username, event, (detail or "")[:500], ip),
        )


def list_audit(limit: int = 200) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT ts, username, event, detail, ip FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]


def count_events(username: str, event: str, since: datetime) -> int:
    with connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE username = ? AND event = ? AND ts >= ?",
            (username, event, iso(since)),
        ).fetchone()
        return row[0]


# ── Historial de análisis ──────────────────────────────────────────────────────

def save_analysis(username: str, analysis: dict) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO analyses (username, domain, ts, score, risk, result_json) VALUES (?, ?, ?, ?, ?, ?)",
            (
                username,
                analysis["domain"],
                analysis["timestamp"],
                analysis["score"]["global_score"],
                analysis["score"]["risk_level"],
                json.dumps(analysis, ensure_ascii=False),
            ),
        )
        return cur.lastrowid


def list_analyses(username: str | None = None, domain: str | None = None, limit: int = 200) -> list[dict]:
    """Historial. username=None devuelve el de todos (solo para administradores)."""
    query = "SELECT id, username, domain, ts, score, risk FROM analyses WHERE 1=1"
    params: list = []
    if username is not None:
        query += " AND username = ?"
        params.append(username)
    if domain:
        query += " AND domain = ?"
        params.append(domain)
    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)
    with connect() as conn:
        return [dict(r) for r in conn.execute(query, params)]


def get_analysis(analysis_id: int, username: str | None = None) -> dict | None:
    """Recupera un análisis. Si se pasa username, solo si pertenece a ese usuario."""
    query = "SELECT result_json FROM analyses WHERE id = ?"
    params: list = [analysis_id]
    if username is not None:
        query += " AND username = ?"
        params.append(username)
    with connect() as conn:
        row = conn.execute(query, params).fetchone()
    return json.loads(row["result_json"]) if row else None
