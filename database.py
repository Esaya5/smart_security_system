"""
Central database (SQLite for prototype simplicity).

Tables
------
known_people     : enrolled people (metadata only; face encodings live encrypted
                   in data/encodings.enc, keyed by the same name)
access_events    : every recognition event (known AND unknown) - audit trail
crime_incidents  : historical crime records (with optional street name)
users            : dashboard logins (student / security / admin)
heatmap_feedback : one-question student awareness feedback
visitors         : security-managed outsider check-in
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS known_people (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    role TEXT DEFAULT 'student',
    enrolled_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL,              -- 'known' or 'unknown'
    person_name TEXT,
    snapshot_path TEXT,                -- file name inside snapshots/
    alert_sent INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS crime_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    crime_type TEXT,
    occurred_at TEXT,
    source TEXT DEFAULT 'historical_dataset',
    street TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'security'
);
CREATE TABLE IF NOT EXISTS heatmap_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    felt_more_aware INTEGER NOT NULL,
    comment TEXT,
    session_id TEXT
);
CREATE TABLE IF NOT EXISTS visitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    purpose TEXT,
    host_name TEXT,
    registered_by TEXT,
    checked_in_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    checked_out_at TEXT,
    active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS visitor_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    purpose TEXT,
    host_name TEXT,
    photo_file TEXT NOT NULL,
    requested_at TEXT NOT NULL
);
"""

_initialised = False


@contextmanager
def get_db():
    config.ensure_directories()
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Creates tables and migrates older databases. Safe to call repeatedly."""
    global _initialised
    if _initialised:
        return
    with get_db() as conn:
        conn.executescript(SCHEMA)
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(crime_incidents)")}
        if "street" not in cols:                      # database from the first prototype
            conn.execute("ALTER TABLE crime_incidents ADD COLUMN street TEXT")
        vcols = {r["name"] for r in conn.execute("PRAGMA table_info(visitors)")}
        # visitors recorded before face capture existed
        if "face_key" not in vcols:
            conn.execute("ALTER TABLE visitors ADD COLUMN face_key TEXT")
    _initialised = True


# --- known_people -------------------------------------------------------------

def upsert_known_person(name: str, role: str = "student") -> None:
    with get_db() as conn:
        conn.execute(
            """INSERT INTO known_people (name, role, enrolled_at) VALUES (?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET role=excluded.role""",
            (name, role, datetime.now().isoformat(timespec="seconds")),
        )


def list_known_people():
    with get_db() as conn:
        return conn.execute("SELECT * FROM known_people ORDER BY name").fetchall()


def delete_known_person(name: str) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM known_people WHERE name = ?", (name,))


# --- access_events ------------------------------------------------------------

def log_access_event(status, person_name, snapshot_name, alert_sent=False) -> int:
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO access_events (timestamp, status, person_name, snapshot_path, alert_sent)
               VALUES (?, ?, ?, ?, ?)""",
            (datetime.now().isoformat(timespec="seconds"), status, person_name,
             snapshot_name, int(alert_sent)),
        )
        return cur.lastrowid


def recent_events(limit: int = 100):
    with get_db() as conn:
        return conn.execute("SELECT * FROM access_events ORDER BY id DESC LIMIT ?", (limit,
            )).fetchall()


def unknown_event_count(since_hours: int = 24) -> int:
    cutoff = (datetime.now() - timedelta(hours=since_hours)).isoformat(timespec="seconds")
    with get_db() as conn:
        return conn.execute(
            "SELECT COUNT(*) AS c FROM access_events WHERE status='unknown' AND timestamp >= ?",
            (cutoff,),
        ).fetchone()["c"]


def purge_old_events(retention_days: int) -> tuple[int, list[str]]:
    """Deletes events older than retention_days. Returns (rows_deleted, snapshot_file_names)
    so the caller can remove the evidence images from disk as well."""
    cutoff = (datetime.now() - timedelta(days=retention_days)).isoformat(timespec="seconds")
    with get_db() as conn:
        files = [r["snapshot_path"] for r in conn.execute(
            "SELECT snapshot_path FROM access_events WHERE timestamp < ? AND snapshot_path IS NOT "
            "NULL",
            (cutoff,))]
        cur = conn.execute("DELETE FROM access_events WHERE timestamp < ?", (cutoff,))
        return cur.rowcount, files


# --- crime_incidents ----------------------------------------------------------

def insert_crime_incident(lat, lng, crime_type, occurred_at, source="historical_dataset",
                          street=None) -> int:
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO crime_incidents (latitude, longitude, crime_type,
                occurred_at, source, street)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (lat, lng, crime_type, occurred_at, source, (street or "").strip() or None),
        )
        return cur.lastrowid


def insert_crime_incidents_bulk(rows: list[tuple]) -> int:
    """rows: (lat, lng, crime_type, occurred_at, source, street)"""
    with get_db() as conn:
        conn.executemany(
            """INSERT INTO crime_incidents (latitude, longitude, crime_type,
                occurred_at, source, street)
               VALUES (?, ?, ?, ?, ?, ?)""", rows)
    return len(rows)


def all_crime_incidents(days: int | None = None, crime_types: list[str] | None = None):
    """Incidents, optionally limited to the last `days` days and/or a set of crime types."""
    sql, args = "SELECT * FROM crime_incidents WHERE 1=1", []
    if days:
        sql += " AND occurred_at >= ?"
        args.append((datetime.now() - timedelta(days=days)).isoformat(timespec="seconds"))
    if crime_types:
        sql += f" AND crime_type IN ({','.join('?' * len(crime_types))})"
        args += crime_types
    with get_db() as conn:
        return conn.execute(sql + " ORDER BY id", args).fetchall()


def delete_crime_incident(incident_id: int) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM crime_incidents WHERE id = ?", (incident_id,))


def incidents_missing_street(limit: int = 500):
    with get_db() as conn:
        return conn.execute(
            "SELECT id, latitude, longitude FROM crime_incidents WHERE street IS NULL LIMIT ?",
            (limit,)
        ).fetchall()


def set_incident_street(incident_id: int, street: str) -> None:
    with get_db() as conn:
        conn.execute("UPDATE crime_incidents SET street = ? WHERE id = ?", (street, incident_id))


def incidents_by_month():
    with get_db() as conn:
        rows = conn.execute(
            """SELECT substr(occurred_at, 1, 7) AS month, COUNT(*) AS count
               FROM crime_incidents WHERE occurred_at IS NOT NULL
               GROUP BY month ORDER BY month""").fetchall()
    return [{"month": r["month"], "count": r["count"]} for r in rows]


def export_crime_rows():
    with get_db() as conn:
        return conn.execute(
            "SELECT latitude, longitude, crime_type, occurred_at, source, street "
            "FROM crime_incidents ORDER BY id").fetchall()


# --- users --------------------------------------------------------------------

def create_user(username: str, password_hash: str, role: str = "security") -> None:
    with get_db() as conn:
        conn.execute("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                     (username, password_hash, role))


def set_password(username: str, password_hash: str) -> bool:
    with get_db() as conn:
        cur = conn.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                           (password_hash, username))
        return cur.rowcount > 0


def get_user(username: str):
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def list_users():
    with get_db() as conn:
        return conn.execute(
            "SELECT id, username, role FROM users ORDER BY role, username").fetchall()


def delete_user(username: str) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))


# --- heatmap_feedback ---------------------------------------------------------

def insert_feedback(felt_more_aware: bool, comment: str | None, session_id: str | None) -> bool:
    """Stores one response. A repeated anonymous session id is ignored (returns False)."""
    with get_db() as conn:
        if session_id and conn.execute(
                "SELECT 1 FROM heatmap_feedback WHERE session_id = ?", (session_id,)).fetchone():
            return False
        conn.execute(
            "INSERT INTO heatmap_feedback (timestamp, felt_more_aware, comment, session_id) VALUES "
            "(?, ?, ?, ?)",
            (datetime.now().isoformat(timespec="seconds"), int(felt_more_aware), comment,
             session_id))
    return True


def feedback_summary() -> dict:
    """Roll-up toward the charter's Objective #3 (80% report increased awareness)."""
    with get_db() as conn:
        rows = conn.execute("SELECT felt_more_aware FROM heatmap_feedback").fetchall()
    total = len(rows)
    aware = sum(r["felt_more_aware"] for r in rows)
    pct = (aware / total * 100) if total else None
    return {
        "total_responses": total,
        "felt_more_aware_count": aware,
        "pct_felt_more_aware": round(pct, 1) if pct is not None else None,
        "meets_80pct_objective": pct is not None and pct >= 80,
    }


# --- visitors -----------------------------------------------------------------

def add_visitor(name, purpose, host_name, registered_by, duration_hours=8) -> int:
    """Checks a visitor in and returns the new visitor id."""
    now = datetime.now()
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO visitors (name, purpose, host_name, registered_by,
                checked_in_at, expires_at, active)
               VALUES (?, ?, ?, ?, ?, ?, 1)""",
            (name, purpose, host_name, registered_by, now.isoformat(timespec="seconds"),
             (now + timedelta(hours=duration_hours)).isoformat(timespec="seconds")))
        return cur.lastrowid


def set_visitor_face_key(visitor_id: int, face_key: str | None) -> None:
    with get_db() as conn:
        conn.execute("UPDATE visitors SET face_key = ? WHERE id = ?", (face_key, visitor_id))


def delete_visitor(visitor_id: int) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM visitors WHERE id = ?", (visitor_id,))


def release_visitor_faces() -> list[str]:
    """Deactivates expired visitors and returns the face keys of every visitor who has left
    (checked out or expired) so the caller can delete their stored face data."""
    now = datetime.now().isoformat(timespec="seconds")
    with get_db() as conn:
        conn.execute("UPDATE visitors SET active = 0 WHERE active = 1 AND expires_at < ?", (now,))
        keys = [r["face_key"] for r in conn.execute(
            "SELECT face_key FROM visitors WHERE active = 0 AND face_key IS NOT NULL")]
        if keys:
            conn.execute("UPDATE visitors SET face_key = NULL WHERE active = 0 AND face_key IS NOT "
                         "NULL")
    return keys


def add_visitor_request(name, purpose, host_name, photo_file) -> int:
    """A visitor recorded their own face; staff must approve before it is enrolled."""
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO visitor_requests (name, purpose, host_name, photo_file, requested_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, purpose, host_name, photo_file, datetime.now().isoformat(timespec="seconds")))
        return cur.lastrowid


def list_visitor_requests():
    with get_db() as conn:
        return conn.execute("SELECT * FROM visitor_requests ORDER BY id").fetchall()


def get_visitor_request(request_id: int):
    with get_db() as conn:
        return conn.execute("SELECT * FROM visitor_requests WHERE id = ?", (request_id,)).fetchone()


def delete_visitor_request(request_id: int) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM visitor_requests WHERE id = ?", (request_id,))


def purge_visitor_requests(hours: int = 24) -> list[str]:
    """Removes requests nobody approved in time; returns their photo file names to delete."""
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat(timespec="seconds")
    with get_db() as conn:
        files = [r["photo_file"] for r in conn.execute(
            "SELECT photo_file FROM visitor_requests WHERE requested_at < ?", (cutoff,))]
        conn.execute("DELETE FROM visitor_requests WHERE requested_at < ?", (cutoff,))
    return files


def list_active_visitors():
    with get_db() as conn:
        conn.execute("UPDATE visitors SET active = 0 WHERE active = 1 AND expires_at < ?",
                     (datetime.now().isoformat(timespec="seconds"),))
        return conn.execute("SELECT * FROM visitors WHERE active = 1 ORDER BY checked_in_at "
                            "DESC").fetchall()


def check_out_visitor(visitor_id: int) -> None:
    with get_db() as conn:
        conn.execute("UPDATE visitors SET active = 0, checked_out_at = ? WHERE id = ?",
                     (datetime.now().isoformat(timespec="seconds"), visitor_id))


# --- analytics / export -------------------------------------------------------

def unknown_alerts_by_hour():
    with get_db() as conn:
        rows = conn.execute(
            """SELECT CAST(substr(timestamp, 12, 2) AS INTEGER) AS hour, COUNT(*) AS count
               FROM access_events WHERE status = 'unknown' GROUP BY hour""").fetchall()
    counts = {r["hour"]: r["count"] for r in rows}
    return [{"hour": h, "count": counts.get(h, 0)} for h in range(24)]


def export_events_rows():
    with get_db() as conn:
        return conn.execute(
            "SELECT timestamp, status, person_name, snapshot_path, alert_sent FROM access_events "
            "ORDER BY id"
        ).fetchall()
