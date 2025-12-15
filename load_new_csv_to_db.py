import pandas as pd
import sqlite3
from pathlib import Path
from app.data.db import DatabaseManager

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "DATA"

CYBER_CSV = DATA_DIR / "cyber_incidents.csv"
DATASETS_CSV = DATA_DIR / "datasets_metadata.csv"
TICKETS_CSV = DATA_DIR / "it_tickets.csv"


def load_cyber():
    df = pd.read_csv(CYBER_CSV)
    db = DatabaseManager()
    conn = db.get_connection()
    cursor = conn.cursor()

    for _, r in df.iterrows():
        cursor.execute(
            """
            INSERT INTO cyber_incidents
            (title, category, severity, status, description, created_at, assigned_to)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"Incident {r['incident_id']}",  # title
                str(r["category"]),
                str(r["severity"]),
                str(r["status"]),
                str(r["description"]),
                str(r["timestamp"]),
                "System",
            ),
        )

    conn.commit()
    conn.close()
    print("✓ Loaded cyber incidents")



def load_datasets():
    df = pd.read_csv(DATASETS_CSV)

    with DatabaseManager() as db:
        for _, r in df.iterrows():
            db.execute("""
                INSERT INTO datasets_metadata (name, category, size_gb, owner, last_updated)
                VALUES (?, ?, ?, ?, ?)
            """, (
                str(r["name"]),
                str(r["category"]),
                float(r["size_gb"]),
                str(r.get("owner", "pierre")),
                str(r.get("last_updated", "2025-12-01")),
            ))
        db.commit()


def load_tickets():
    df = pd.read_csv(TICKETS_CSV)

    # Your CSV headers (from your screenshot):
    # ticket_id,priority,description,status,assigned_to,created_at,resolution_time_hours
    df["title"] = df["description"].astype(str).str.slice(0, 40)
    df["created_by"] = "pierre"

    with DatabaseManager() as db:
        for _, r in df.iterrows():
            db.execute("""
                INSERT INTO it_tickets (title, priority, status, description, assigned_to, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                str(r["title"]),
                str(r["priority"]),
                str(r["status"]),
                str(r["description"]),
                str(r["assigned_to"]),
                str(r["created_by"]),
            ))
        db.commit()


def main():
    print("Loading NEW CSV data into main.db ...")
    load_cyber()
    print("✅ cyber incidents loaded")
    load_datasets()
    print("✅ datasets loaded")
    load_tickets()
    print("✅ tickets loaded")
    print("🎉 Done.")


if __name__ == "__main__":
    main()
