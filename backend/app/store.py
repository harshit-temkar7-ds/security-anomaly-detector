"""SQLite persistence (standard library only).

Stores scans, the model version/threshold used, per-event results, investigation
status and analyst notes. All SQL is parameterised; ORDER BY clauses are fixed strings.
Scores are stored once, so changing the threshold never needs re-scoring or re-uploading.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Iterator, Optional

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id         TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    filename        TEXT NOT NULL,
    mode            TEXT NOT NULL,
    model_version   TEXT NOT NULL,
    model_threshold REAL NOT NULL,
    threshold       REAL NOT NULL,
    rows_analyzed   INTEGER NOT NULL,
    anomalies_flagged INTEGER NOT NULL,
    rule_flags      INTEGER NOT NULL,
    has_labels      INTEGER NOT NULL,
    uba_min_history INTEGER NOT NULL,
    uba_basis       TEXT NOT NULL,
    evaluation_json TEXT,
    hourly_json     TEXT NOT NULL,
    warning         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    scan_id    TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    row        INTEGER NOT NULL,
    data_json  TEXT NOT NULL,
    score      REAL NOT NULL,
    rule_flag  INTEGER NOT NULL,
    label      INTEGER,
    hour       INTEGER NOT NULL,
    username   TEXT,
    review_reason TEXT NOT NULL,
    uba_json   TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'new',
    status_updated_at TEXT,
    PRIMARY KEY (scan_id, row)
);
CREATE INDEX IF NOT EXISTS idx_events_score ON events(scan_id, score DESC);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(scan_id, username);
CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    TEXT NOT NULL,
    row        INTEGER NOT NULL,
    author     TEXT NOT NULL,
    note       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id, row) REFERENCES events(scan_id, row) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_notes_event ON notes(scan_id, row);
PRAGMA user_version = 1;
"""

_initialised: set[str] = set()
_init_lock = Lock()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    path = settings.db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with _init_lock:
            if str(path) not in _initialised:
                conn.executescript(SCHEMA)
                _initialised.add(str(path))
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _scan(row: sqlite3.Row | None) -> Optional[dict[str, Any]]:
    if row is None:
        return None
    d = dict(row)
    d["has_labels"] = bool(d["has_labels"])
    d["evaluation"] = json.loads(d.pop("evaluation_json")) if d["evaluation_json"] else None
    d["hourly"] = json.loads(d.pop("hourly_json"))
    return d


# ---------------------------------------------------------------- scans
def save_scan(scan: dict[str, Any], events: list[dict[str, Any]]) -> None:
    with connect() as c:
        c.execute(
            "INSERT INTO scans VALUES (:scan_id,:created_at,:filename,:mode,:model_version,"
            ":model_threshold,:threshold,:rows_analyzed,:anomalies_flagged,:rule_flags,:has_labels,"
            ":uba_min_history,:uba_basis,:evaluation_json,:hourly_json,:warning)",
            {
                **scan,
                "has_labels": int(scan["has_labels"]),
                "evaluation_json": json.dumps(scan["evaluation"]) if scan["evaluation"] else None,
                "hourly_json": json.dumps(scan["hourly"]),
            },
        )
        c.executemany(
            "INSERT INTO events (scan_id,row,data_json,score,rule_flag,label,hour,username,"
            "review_reason,uba_json) VALUES (:scan_id,:row,:data_json,:score,:rule_flag,:label,"
            ":hour,:username,:review_reason,:uba_json)",
            events,
        )
        # retention: keep the newest `max_stored_scans`
        c.execute(
            "DELETE FROM scans WHERE scan_id IN (SELECT scan_id FROM scans "
            "ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET ?)",
            (settings.max_stored_scans,),
        )


def get_scan(scan_id: str) -> Optional[dict[str, Any]]:
    with connect() as c:
        return _scan(c.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone())


def list_scans(limit: int = 20, offset: int = 0, q: str | None = None) -> tuple[list[dict[str, Any]], int]:
    where, args = "", []
    if q:
        where, args = "WHERE filename LIKE ? ESCAPE '\\'", [
            "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        ]
    with connect() as c:
        total = c.execute(f"SELECT COUNT(*) FROM scans {where}", args).fetchone()[0]
        rows = c.execute(
            f"SELECT * FROM scans {where} ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
            [*args, limit, offset],
        ).fetchall()
    return [_scan(r) for r in rows], total  # type: ignore[misc]


def delete_scan(scan_id: str) -> bool:
    with connect() as c:
        return c.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,)).rowcount > 0


def update_scan_summary(scan_id: str, threshold: float, flagged: int,
                        evaluation: dict | None, hourly: list[dict]) -> None:
    with connect() as c:
        c.execute(
            "UPDATE scans SET threshold=?, anomalies_flagged=?, evaluation_json=?, hourly_json=? "
            "WHERE scan_id=?",
            (threshold, flagged, json.dumps(evaluation) if evaluation else None,
             json.dumps(hourly), scan_id),
        )


# --------------------------------------------------------------- events
def _event(r: sqlite3.Row) -> dict[str, Any]:
    d = dict(r)
    d["data"] = json.loads(d.pop("data_json"))
    d["uba"] = json.loads(d.pop("uba_json"))
    d["rule_flag"] = bool(d["rule_flag"])
    return d


def load_events(scan_id: str, where: str = "", args: tuple = ()) -> list[dict[str, Any]]:
    """`where` must be a fixed SQL fragment built by this code base, never user text."""
    with connect() as c:
        rows = c.execute(
            f"SELECT * FROM events WHERE scan_id = ? {where} ORDER BY score DESC, row ASC",
            (scan_id, *args),
        ).fetchall()
    return [_event(r) for r in rows]


def get_event(scan_id: str, row: int) -> Optional[dict[str, Any]]:
    with connect() as c:
        r = c.execute("SELECT * FROM events WHERE scan_id=? AND row=?", (scan_id, row)).fetchone()
    return _event(r) if r else None


def score_arrays(scan_id: str) -> dict[str, list]:
    """Light-weight columns for threshold/metric recomputation (no JSON parsing)."""
    with connect() as c:
        rows = c.execute(
            "SELECT row, score, rule_flag, label, hour FROM events WHERE scan_id=? ORDER BY row",
            (scan_id,),
        ).fetchall()
    return {
        "row": [r["row"] for r in rows], "score": [r["score"] for r in rows],
        "rule_flag": [r["rule_flag"] for r in rows], "label": [r["label"] for r in rows],
        "hour": [r["hour"] for r in rows],
    }


def set_status(scan_id: str, row: int, status: str) -> bool:
    with connect() as c:
        return c.execute(
            "UPDATE events SET status=?, status_updated_at=? WHERE scan_id=? AND row=?",
            (status, now(), scan_id, row),
        ).rowcount > 0


def status_counts(scan_id: str, threshold: float) -> dict[str, int]:
    with connect() as c:
        rows = c.execute(
            "SELECT status, COUNT(*) n FROM events WHERE scan_id=? AND score>=? GROUP BY status",
            (scan_id, threshold),
        ).fetchall()
    return {r["status"]: r["n"] for r in rows}


# ---------------------------------------------------------------- notes
def add_note(scan_id: str, row: int, author: str, note: str) -> dict[str, Any]:
    with connect() as c:
        ts = now()
        cur = c.execute(
            "INSERT INTO notes (scan_id,row,author,note,created_at) VALUES (?,?,?,?,?)",
            (scan_id, row, author, note, ts),
        )
        return {"id": cur.lastrowid, "author": author, "note": note, "created_at": ts}


def list_notes(scan_id: str, row: int) -> list[dict[str, Any]]:
    with connect() as c:
        rows = c.execute(
            "SELECT id, author, note, created_at FROM notes WHERE scan_id=? AND row=? ORDER BY id",
            (scan_id, row),
        ).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------- feedback
def feedback_events() -> list[dict[str, Any]]:
    """Analyst decisions usable as feedback: false positives and escalations, across all scans."""
    with connect() as c:
        rows = c.execute(
            "SELECT e.scan_id, e.row, e.data_json, e.score, e.rule_flag, e.status, s.model_version FROM events e "
            "JOIN scans s ON s.scan_id = e.scan_id WHERE e.status IN ('false_positive','escalated') "
            "ORDER BY e.scan_id, e.row"
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["data"] = json.loads(d.pop("data_json"))
        d["rule_flag"] = bool(d["rule_flag"])
        out.append(d)
    return out


def status_totals() -> dict[str, int]:
    with connect() as c:
        rows = c.execute("SELECT status, COUNT(*) n FROM events GROUP BY status").fetchall()
    return {r["status"]: r["n"] for r in rows}
