"""CRUD operations for datasets_metadata table."""
import pandas as pd
from app.data.db import DatabaseManager


def get_all_datasets():
    """Return all datasets as a pandas DataFrame."""
    with DatabaseManager() as db:
        db.execute("""
            SELECT id, name, category, size_gb, owner, last_updated, created_at
            FROM datasets_metadata
            ORDER BY name
        """)
        rows = db.fetchall()

    if not rows:
        return pd.DataFrame(columns=["id", "name", "category", "size_gb", "owner", "last_updated", "created_at"])

    return pd.DataFrame([dict(row) for row in rows])


def insert_dataset(name, category, size_gb, owner, last_updated):
    """Insert a new dataset."""
    with DatabaseManager() as db:
        db.execute("""
            INSERT INTO datasets_metadata (name, category, size_gb, owner, last_updated)
            VALUES (?, ?, ?, ?, ?)
        """, (name, category, size_gb, owner, last_updated))
        new_id = db.lastrowid()
        db.commit()
    return new_id


def update_dataset(dataset_id, name, category, size_gb, owner, last_updated):
    """Update an existing dataset."""
    with DatabaseManager() as db:
        db.execute("""
            UPDATE datasets_metadata
            SET name = ?, category = ?, size_gb = ?, owner = ?, last_updated = ?
            WHERE id = ?
        """, (name, category, size_gb, owner, last_updated, dataset_id))
        db.commit()


def delete_dataset(dataset_id):
    """Delete a dataset."""
    with DatabaseManager() as db:
        db.execute("DELETE FROM datasets_metadata WHERE id = ?", (dataset_id,))
        db.commit()