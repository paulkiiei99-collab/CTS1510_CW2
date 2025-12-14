# app/database.py

import sqlite3
import os

# ------------------------------------
# Database file path (inside /app/data/)
# ------------------------------------
BASE_DIR = os.path.dirname(__file__)          # .../app
DB_FILE = os.path.join(BASE_DIR, "data", "mdx_intel.db")


class DatabaseManager:
    """
    Simple helper class to manage one SQLite database for:
    - users
    - cyber_incidents
    - datasets_metadata
    - it_tickets
    """

    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        # Ensure all tables exist as soon as the manager is created
        self.create_all_tables()

    # -----------------------------
    # Internal connection helper
    # -----------------------------
    def _connect(self):
        return sqlite3.connect(self.db_path)

    # -----------------------------
    # Schema (CREATE TABLE)
    # -----------------------------
    def create_all_tables(self):
        conn = self._connect()
        cur = conn.cursor()

        # --- Users table (Week 7 migration target) ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)

        # --- Cyber Incidents (matches your CYBER_INCIDENTS.db schema) ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cyber_incidents (
                incident_id INTEGER PRIMARY KEY,
                timestamp TEXT,
                severity TEXT,
                category TEXT,
                status TEXT,
                description TEXT
            )
        """)

        # --- Dataset Metadata (matches datasets_metadata.csv) ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS datasets_metadata (
                dataset_id INTEGER PRIMARY KEY,
                name TEXT,
                rows INTEGER,
                columns INTEGER,
                uploaded_by TEXT,
                upload_date TEXT
            )
        """)

        # --- IT Tickets (matches it_tickets.csv columns you use) ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS it_tickets (
                ticket_id INTEGER PRIMARY KEY,
                created_date TEXT,
                status TEXT,
                priority TEXT,
                assigned_to TEXT,
                resolution_time_hours REAL
            )
        """)

        conn.commit()
        conn.close()

    # -----------------------------
    # Generic helper methods
    # -----------------------------
    def execute(self, query, params=None):
        """
        Run INSERT / UPDATE / DELETE.
        """
        if params is None:
            params = ()

        conn = self._connect()
        cur = conn.cursor()
        cur.execute(query, params)
        conn.commit()
        conn.close()

    def fetch_all(self, query, params=None):
        """
        Run a SELECT and return all rows.
        """
        if params is None:
            params = ()

        conn = self._connect()
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()
        return rows

    # -----------------------------
    # Example: simple CRUD wrappers
    # (You can call these from other files if you want)
    # -----------------------------
    def create_user(self, username, password_hash, role):
        self.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )

    def get_user_by_username(self, username):
        rows = self.fetch_all(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        )
        return rows[0] if rows else None
