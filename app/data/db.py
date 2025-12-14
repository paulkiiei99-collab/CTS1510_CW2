import sqlite3

DB_NAME = "main.db"

def connect_database():
    """Connect to SQLite database (creates file if it does not exist)."""
    return sqlite3.connect(DB_NAME)


class DatabaseManager:
    """Context-manager wrapper around sqlite3 for your project."""

    def __init__(self):
        self.conn = connect_database()
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()

    def __enter__(self):
        return self

    def execute(self, query, params=()):
        self.cursor.execute(query, params)

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def commit(self):
        self.conn.commit()

    def lastrowid(self):
        return self.cursor.lastrowid

    def __exit__(self, exc_type, exc, traceback):
        if exc_type is None:
            self.conn.commit()
        self.conn.close()
