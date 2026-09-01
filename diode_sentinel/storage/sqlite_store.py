"""
DiodeSentinel - SQLite Persistent Storage Layer
Stores raw flow metadata and security alerts for offline forensic querying.
Adheres to Problem Statement ID 26145 Specification.
"""

import sqlite3
import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from diode_sentinel.config import DATA_DIR


class SQLiteStore:
    """Thread-safe SQLite persistent store for alerts and flow telemetry."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or str(DATA_DIR / "sentinel_events.db")
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Alerts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    flow_id TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    threat_class TEXT NOT NULL,
                    subtype TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    mitre_technique TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    flow_snapshot_json TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Flow Statistics Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flow_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_key TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    packet_count INTEGER NOT NULL,
                    byte_count INTEGER NOT NULL,
                    duration_sec REAL NOT NULL,
                    ja3_hash TEXT,
                    sni TEXT,
                    last_seen_ts REAL NOT NULL
                )
            """)
            conn.commit()

    def insert_alert(self, alert: Dict[str, Any]):
        """Persist a single security alert record."""
        query = """
            INSERT OR IGNORE INTO alerts (
                alert_id, timestamp, flow_id, src_ip, src_port,
                dst_ip, dst_port, protocol, threat_class, subtype,
                severity, confidence_score, mitre_technique, summary,
                evidence_json, flow_snapshot_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (
                    alert.get("alert_id"),
                    alert.get("timestamp"),
                    alert.get("flow_id"),
                    alert.get("src_ip"),
                    alert.get("src_port"),
                    alert.get("dst_ip"),
                    alert.get("dst_port"),
                    alert.get("protocol"),
                    alert.get("threat_class"),
                    alert.get("subtype"),
                    alert.get("severity"),
                    alert.get("confidence_score"),
                    alert.get("mitre_technique"),
                    alert.get("summary"),
                    json.dumps(alert.get("evidence", {})),
                    json.dumps(alert.get("flow_snapshot", {}))
                ))
                conn.commit()
        except Exception:
            pass

    def get_recent_alerts(self, limit: int = 50, threat_class: Optional[str] = None) -> List[Dict[str, Any]]:
        """Query recent alerts with optional threat class filter."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if threat_class:
                cursor.execute(
                    "SELECT * FROM alerts WHERE threat_class = ? ORDER BY id DESC LIMIT ?",
                    (threat_class, limit)
                )
            else:
                cursor.execute(
                    "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
                    (limit,)
                )
            rows = cursor.fetchall()
            
            results = []
            for r in rows:
                item = dict(r)
                item["evidence"] = json.loads(item["evidence_json"])
                item["flow_snapshot"] = json.loads(item["flow_snapshot_json"])
                results.append(item)
            return results

    def get_alert_count_by_threat(self) -> Dict[str, int]:
        """Aggregate total alert counts grouped by threat class."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT threat_class, COUNT(*) as cnt FROM alerts GROUP BY threat_class")
            return {row["threat_class"]: row["cnt"] for row in cursor.fetchall()}
