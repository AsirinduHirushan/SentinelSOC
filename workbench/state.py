"""Minimal local audit trail for analyst reviews (SQLite, standard library)."""
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

VALID = {"New", "Investigating", "Closed - Benign", "Escalated"}


def connect(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE IF NOT EXISTS reviews (
       case_id TEXT PRIMARY KEY, status TEXT NOT NULL, notes TEXT NOT NULL,
       updated_at TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit (
       id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
       status TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    conn.commit()
    return conn


def get_review(conn, case_id):
    row = conn.execute("SELECT status, notes, updated_at FROM reviews WHERE case_id=?", (case_id,)).fetchone()
    return {"status": row[0], "notes": row[1], "updated_at": row[2]} if row else {"status": "New", "notes": "", "updated_at": None}


def save_review(conn, case_id, status, notes):
    if status not in VALID:
        raise ValueError("Invalid analyst status")
    if len(notes) > 5000:
        raise ValueError("Notes too long")
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute("INSERT INTO reviews (case_id,status,notes,updated_at) VALUES (?,?,?,?) "
                     "ON CONFLICT(case_id) DO UPDATE SET status=excluded.status, notes=excluded.notes, updated_at=excluded.updated_at",
                     (case_id, status, notes, now))
        conn.execute("INSERT INTO audit (case_id,status,updated_at) VALUES (?,?,?)", (case_id, status, now))


def review_history(conn, case_id):
    return conn.execute("SELECT status,updated_at FROM audit WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
