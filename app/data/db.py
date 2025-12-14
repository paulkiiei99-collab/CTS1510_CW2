# app/data/db.py
"""Database connection and schema management."""

import sqlite3
from pathlib import Path

# Database file location (project root)
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = BASE_DIR / "main.db"


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
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # CYBER INCIDENTS TABLE
        self.cursor.execute("""
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
        """)

        # DATASETS METADATA TABLE (includes owner + last_updated)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS datasets_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                category TEXT,
                size_gb REAL,
                owner TEXT,
                last_updated TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # IT TICKETS TABLE (includes assigned_to + created_at)
        self.cursor.execute("""
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
        """)
