# app/data/db.py
"""Database connection and schema management."""

import sqlite3
from pathlib import Path

import pandas as pd

# Database file location (project root)
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = BASE_DIR / "main.db"


def preload_csv_if_empty(cursor):
    """Preload CSV data into database if tables are empty (runs once)."""

    data_dir = BASE_DIR / "DATA"

    # ---------- CYBER INCIDENTS ----------
    cursor.execute("SELECT COUNT(*) FROM cyber_incidents")
    if cursor.fetchone()[0] == 0:
        df = pd.read_csv(data_dir / "cyber_incidents.csv")
        for _, r in df.iterrows():
            cursor.execute(
                """
                INSERT INTO cyber_incidents
                (date, title, severity, status, description, reported_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(r["timestamp"]),
                    f"Incident {r['incident_id']}",
                    str(r["severity"]),
                    str(r["status"]),
                    str(r["description"]),
                    "System",
                ),
            )

    # ---------- DATASETS ----------
    cursor.execute("SELECT COUNT(*) FROM datasets_metadata")
    if cursor.fetchone()[0] == 0:
        df = pd.read_csv(data_dir / "datasets_metadata.csv")
        for _, r in df.iterrows():
            cursor.execute(
                """
                INSERT INTO datasets_metadata
                (name, category, size_gb, owner, last_updated)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    str(r["name"]),
                    "General",
                    float(r["rows"]) / 100.0,  # acceptable placeholder size for coursework
                    str(r["uploaded_by"]),
                    str(r["upload_date"]),
                ),
            )

    # ---------- IT TICKETS ----------
    cursor.execute("SELECT COUNT(*) FROM it_tickets")
    if cursor.fetchone()[0] == 0:
        df = pd.read_csv(data_dir / "it_tickets.csv")
        for _, r in df.iterrows():
            cursor.execute(
                """
                INSERT INTO it_tickets
                (title, priority, status, description, assigned_to, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    f"Ticket {r['ticket_id']}",
                    str(r["priority"]),
                    str(r["status"]),
                    str(r["description"]),
                    str(r["assigned_to"]),
                    "System",
                ),
            )


class DatabaseManager:
    """Context manager for SQLite database access."""

    def __init__(self):
        self.conn = None
        self.cursor = None

    def __enter__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self._initialize_schema()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            self.conn.close()

    def execute(self, query, params=()):
        self.cursor.execute(query, params)

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def lastrowid(self):
        return self.cursor.lastrowid

    def commit(self):
        self.conn.commit()

    def _initialize_schema(self):
        """Create all required tables if they do not exist."""

        # USERS TABLE
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # CYBER INCIDENTS TABLE
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS cyber_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT,
                title TEXT,
                severity TEXT,
                status TEXT,
                description TEXT,
                reported_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # DATASETS METADATA TABLE
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS datasets_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                category TEXT,
                size_gb REAL,
                owner TEXT,
                last_updated TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # IT TICKETS TABLE
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS it_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                priority TEXT,
                status TEXT,
                description TEXT,
                assigned_to TEXT,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Ensure tables exist on disk before preload reads them
        self.conn.commit()

        # One-time preload from CSVs (only if tables are empty)
        preload_csv_if_empty(self.cursor)

        # Commit inserted rows
        self.conn.commit()
