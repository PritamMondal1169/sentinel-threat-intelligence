"""SQLite/JSON persistent storage for SENTINEL.
Stores investigations, indicators, domains, certificates, scans, campaigns, reports, and monitoring.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_DB_PATH = DATA_DIR / "sentinel.db"


class Storage:
    def __init__(self, db_path: Optional[str | Path] = None):
        if db_path is None:
            env_db = os.getenv("SENTINEL_DB_PATH")
            self.db_path = Path(env_db) if env_db else DEFAULT_DB_PATH
        elif str(db_path) == ":memory:":
            self.db_path = ":memory:"
        else:
            self.db_path = Path(db_path)

        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            isolation_level=None  # autocommit mode
        )
        self._conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        cur = self._conn.cursor()
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            submitter TEXT NOT NULL,
            input TEXT NOT NULL,
            input_hash TEXT,
            status TEXT NOT NULL,
            risk_class TEXT,
            risk_score REAL,
            coverage REAL,
            confidence REAL,
            demo INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            result_json TEXT,
            indicators_json TEXT,
            steps_json TEXT,
            risk_json TEXT
        );

        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            UNIQUE(type, value)
        );

        CREATE TABLE IF NOT EXISTS indicator_sightings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            investigation_id TEXT NOT NULL,
            quality TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id)
        );

        CREATE TABLE IF NOT EXISTS reports (
            report_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            salt_hex TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS report_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            body_json TEXT NOT NULL,
            commitment TEXT NOT NULL,
            chain_json TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(report_id, version)
        );

        CREATE TABLE IF NOT EXISTS website_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            grade TEXT NOT NULL,
            entry_json TEXT NOT NULL,
            owned INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS monitoring_subscriptions (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL UNIQUE,
            email TEXT,
            interval_hours INTEGER DEFAULT 24,
            ownership_declared INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_scan_at TEXT,
            last_grade TEXT,
            active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS message_templates (
            id TEXT PRIMARY KEY,
            template_id TEXT NOT NULL,
            minhash_json TEXT NOT NULL,
            first_seen TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS certificate_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            spki_sha256 TEXT,
            issuer TEXT,
            subject TEXT,
            not_before TEXT,
            not_after TEXT,
            san_json TEXT,
            observed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TEXT NOT NULL,
            active INTEGER DEFAULT 1
        );
        """)

    # --- Investigations ---
    def save_investigation(self, inv: dict):
        cur = self._conn.cursor()
        risk = inv.get("risk", {})
        indicators_list = [
            {"type": t, "value": v, "quality": q}
            for (t, v), q in inv.get("indicators", {}).items()
        ]
        created_at = inv["ts"].isoformat() if isinstance(inv["ts"], datetime) else str(inv["ts"])
        cur.execute("""
            INSERT OR REPLACE INTO investigations (
                id, type, submitter, input, input_hash, status,
                risk_class, risk_score, coverage, confidence, demo,
                created_at, completed_at, result_json, indicators_json, steps_json, risk_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            inv["id"],
            inv["type"],
            inv.get("submitter", "anon"),
            inv.get("input", ""),
            inv.get("input_hash"),
            inv.get("status", "completed"),
            risk.get("class"),
            risk.get("score"),
            risk.get("coverage"),
            risk.get("confidence"),
            1 if inv.get("demo") else 0,
            created_at,
            inv.get("completed_at"),
            json.dumps(inv.get("result", {})),
            json.dumps(indicators_list),
            json.dumps(inv.get("steps", {})),
            json.dumps(risk)
        ))

        # Record indicators
        for (t, v), q in inv.get("indicators", {}).items():
            cur.execute("""
                INSERT OR IGNORE INTO indicators (type, value, first_seen)
                VALUES (?, ?, ?)
            """, (t, v, created_at))
            cur.execute("""
                INSERT INTO indicator_sightings (indicator_type, indicator_value, investigation_id, quality, observed_at)
                VALUES (?, ?, ?, ?, ?)
            """, (t, v, inv["id"], q, created_at))

    def get_investigation(self, iid: str) -> Optional[dict]:
        cur = self._conn.cursor()
        row = cur.execute("SELECT * FROM investigations WHERE id = ?", (iid,)).fetchone()
        if not row:
            return None
        return self._row_to_inv(row)

    def list_investigations(self, limit: int = 100, risk_class: Optional[str] = None) -> list[dict]:
        cur = self._conn.cursor()
        if risk_class:
            rows = cur.execute("""
                SELECT * FROM investigations
                WHERE risk_class = ?
                ORDER BY created_at DESC LIMIT ?
            """, (risk_class, limit)).fetchall()
        else:
            rows = cur.execute("""
                SELECT * FROM investigations
                ORDER BY created_at DESC LIMIT ?
            """, (limit,)).fetchall()
        return [self._row_to_inv(r) for r in rows]

    def all_investigations(self) -> list[dict]:
        cur = self._conn.cursor()
        rows = cur.execute("SELECT * FROM investigations ORDER BY created_at ASC").fetchall()
        return [self._row_to_inv(r) for r in rows]

    def _row_to_inv(self, r: sqlite3.Row) -> dict:
        indicators_raw = json.loads(r["indicators_json"] or "[]")
        indicators_dict = {(item["type"], item["value"]): item["quality"] for item in indicators_raw}
        
        # parse timestamp safely
        try:
            ts = datetime.fromisoformat(r["created_at"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        return {
            "id": r["id"],
            "type": r["type"],
            "submitter": r["submitter"],
            "input": r["input"],
            "input_hash": r["input_hash"],
            "status": r["status"],
            "demo": bool(r["demo"]),
            "ts": ts,
            "created_at": r["created_at"],
            "completed_at": r["completed_at"],
            "result": json.loads(r["result_json"] or "{}"),
            "indicators": indicators_dict,
            "steps": json.loads(r["steps_json"] or "{}"),
            "risk": json.loads(r["risk_json"] or "{}")
        }

    # --- Reports ---
    def save_report(self, report_id: str, inv_id: str, salt_hex: str, versions: list[dict]):
        cur = self._conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cur.execute("""
            INSERT OR REPLACE INTO reports (report_id, investigation_id, salt_hex, created_at)
            VALUES (?, ?, ?, ?)
        """, (report_id, inv_id, salt_hex, now))

        for idx, v in enumerate(versions, 1):
            cur.execute("""
                INSERT OR REPLACE INTO report_versions (report_id, version, body_json, commitment, chain_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                idx,
                json.dumps(v["body"]),
                v["commitment"],
                json.dumps(v.get("chain")),
                v.get("body", {}).get("created_at", now)
            ))

    def get_report(self, report_id: str) -> Optional[dict]:
        cur = self._conn.cursor()
        rep_row = cur.execute("SELECT * FROM reports WHERE report_id = ?", (report_id,)).fetchone()
        if not rep_row:
            return None
        v_rows = cur.execute("""
            SELECT * FROM report_versions WHERE report_id = ? ORDER BY version ASC
        """, (report_id,)).fetchall()
        versions = []
        for vr in v_rows:
            versions.append({
                "body": json.loads(vr["body_json"]),
                "commitment": vr["commitment"],
                "chain": json.loads(vr["chain_json"]) if vr["chain_json"] else None
            })
        return {
            "report_id": rep_row["report_id"],
            "investigation_id": rep_row["investigation_id"],
            "salt": bytes.fromhex(rep_row["salt_hex"]),
            "created_at": rep_row["created_at"],
            "versions": versions
        }

    # --- Website Scans ---
    def save_website_scan(self, domain: str, entry: dict):
        cur = self._conn.cursor()
        cur.execute("""
            INSERT INTO website_scans (domain, scanned_at, grade, entry_json, owned)
            VALUES (?, ?, ?, ?, ?)
        """, (domain, entry["scanned_at"], entry["grade"], json.dumps(entry), 1 if entry.get("owned") else 0))

    def get_website_scans(self, domain: str) -> list[dict]:
        cur = self._conn.cursor()
        rows = cur.execute("""
            SELECT entry_json FROM website_scans WHERE domain = ? ORDER BY scanned_at ASC
        """, (domain,)).fetchall()
        return [json.loads(r["entry_json"]) for r in rows]

    # --- Monitoring Subscriptions ---
    def save_subscription(self, sub: dict):
        cur = self._conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO monitoring_subscriptions (
                id, domain, email, interval_hours, ownership_declared, created_at, last_scan_at, last_grade, active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sub["id"],
            sub["domain"],
            sub.get("email"),
            sub.get("interval_hours", 24),
            1 if sub.get("ownership_declared") else 0,
            sub.get("created_at", datetime.now(timezone.utc).isoformat()),
            sub.get("last_scan_at"),
            sub.get("last_grade"),
            1 if sub.get("active", True) else 0
        ))

    def list_subscriptions(self) -> list[dict]:
        cur = self._conn.cursor()
        rows = cur.execute("SELECT * FROM monitoring_subscriptions ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    # --- Templates ---
    def save_template(self, template_id: str, minhash_list: list[int]):
        cur = self._conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cur.execute("""
            INSERT OR REPLACE INTO message_templates (id, template_id, minhash_json, first_seen)
            VALUES (?, ?, ?, ?)
        """, (template_id, template_id, json.dumps(minhash_list), now))

    def get_templates(self) -> list[tuple[str, list[int]]]:
        cur = self._conn.cursor()
        rows = cur.execute("SELECT template_id, minhash_json FROM message_templates").fetchall()
        return [(r["template_id"], json.loads(r["minhash_json"])) for r in rows]

    # --- Certificate History ---
    def save_cert_observation(self, domain: str, cert_data: dict):
        cur = self._conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cur.execute("""
            INSERT INTO certificate_history (
                domain, sha256, spki_sha256, issuer, subject, not_before, not_after, san_json, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            domain,
            cert_data.get("cert_sha256", ""),
            cert_data.get("spki_sha256"),
            cert_data.get("issuer"),
            cert_data.get("subject"),
            cert_data.get("not_before"),
            cert_data.get("not_after"),
            json.dumps(cert_data.get("san", [])),
            now
        ))

    def get_cert_history(self, domain: str) -> list[dict]:
        cur = self._conn.cursor()
        rows = cur.execute("""
            SELECT * FROM certificate_history WHERE domain = ? ORDER BY observed_at DESC
        """, (domain,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["san"] = json.loads(d["san_json"] or "[]")
            out.append(d)
        return out

    # --- Users & Auth ---
    def save_user(self, user: dict):
        cur = self._conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO users (id, username, password_hash, role, created_at, active)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user["id"],
            user["username"],
            user["password_hash"],
            user.get("role", "viewer"),
            user.get("created_at", datetime.now(timezone.utc).isoformat()),
            1 if user.get("active", True) else 0
        ))

    def get_user_by_username(self, username: str) -> Optional[dict]:
        cur = self._conn.cursor()
        row = cur.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return None
        return dict(row)

    def list_users(self) -> list[dict]:
        cur = self._conn.cursor()
        rows = cur.execute("SELECT id, username, role, created_at, active FROM users ORDER BY created_at ASC").fetchall()
        return [dict(r) for r in rows]


