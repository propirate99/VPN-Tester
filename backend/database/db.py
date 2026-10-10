"""
Database models and SQLite connection handlers for VajraNet AI.
"""

import sqlite3
import json
import os
from typing import Dict, Any, List, Optional

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "vajranet.db"))


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize SQLite database tables for assessments and findings."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                packet_count INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0,
                risk_level TEXT DEFAULT 'UNKNOWN',
                tunnel_info TEXT,
                findings TEXT,
                timeline TEXT,
                anomalies TEXT
            );
        """)
        conn.commit()


def save_assessment(
    filename: str,
    packet_count: int,
    risk_score: float,
    risk_level: str,
    tunnel_info: Dict[str, Any],
    findings: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]]
) -> int:
    """Save an assessment record into SQLite."""
    with get_db_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO assessments (
                filename, packet_count, risk_score, risk_level,
                tunnel_info, findings, timeline, anomalies
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            filename,
            packet_count,
            risk_score,
            risk_level,
            json.dumps(tunnel_info),
            json.dumps(findings),
            json.dumps(timeline),
            json.dumps(anomalies)
        ))
        conn.commit()
        return cursor.lastrowid or 0


def get_assessments() -> List[Dict[str, Any]]:
    """Retrieve all assessment history records."""
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM assessments ORDER BY timestamp DESC").fetchall()
        result = []
        for r in rows:
            result.append({
                "id": r["id"],
                "filename": r["filename"],
                "timestamp": r["timestamp"],
                "packet_count": r["packet_count"],
                "risk_score": r["risk_score"],
                "risk_level": r["risk_level"],
                "tunnel_info": json.loads(r["tunnel_info"] or "{}"),
                "findings": json.loads(r["findings"] or "[]"),
                "timeline": json.loads(r["timeline"] or "[]"),
                "anomalies": json.loads(r["anomalies"] or "[]")
            })
        return result


def get_assessment_by_id(assessment_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve a single assessment record by ID."""
    with get_db_connection() as conn:
        r = conn.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
        if not r:
            return None
        return {
            "id": r["id"],
            "filename": r["filename"],
            "timestamp": r["timestamp"],
            "packet_count": r["packet_count"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
            "tunnel_info": json.loads(r["tunnel_info"] or "{}"),
            "findings": json.loads(r["findings"] or "[]"),
            "timeline": json.loads(r["timeline"] or "[]"),
            "anomalies": json.loads(r["anomalies"] or "[]")
        }
