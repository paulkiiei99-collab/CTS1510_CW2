"""CRUD operations for it_tickets table."""
import pandas as pd
from app.data.db import DatabaseManager


def get_all_tickets():
    """Return all tickets as a pandas DataFrame."""
    with DatabaseManager() as db:
        db.execute("""
            SELECT id, title, priority, status, description, assigned_to, created_by, created_at
            FROM it_tickets
            ORDER BY created_at DESC
        """)
        rows = db.fetchall()

    if not rows:
        return pd.DataFrame(
            columns=["id", "title", "priority", "status", "description", "assigned_to", "created_by", "created_at"])

    return pd.DataFrame([dict(row) for row in rows])


def insert_ticket(title, priority, status, description, assigned_to, created_by):
    """Insert a new ticket."""
    with DatabaseManager() as db:
        db.execute("""
            INSERT INTO it_tickets (title, priority, status, description, assigned_to, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (title, priority, status, description, assigned_to, created_by))
        new_id = db.lastrowid()
        db.commit()
    return new_id


def update_ticket(ticket_id, title, priority, status, description, assigned_to):
    """Update an existing ticket."""
    with DatabaseManager() as db:
        db.execute("""
            UPDATE it_tickets
            SET title = ?, priority = ?, status = ?, description = ?, assigned_to = ?
            WHERE id = ?
        """, (title, priority, status, description, assigned_to, ticket_id))
        db.commit()


def delete_ticket(ticket_id):
    """Delete a ticket."""
    with DatabaseManager() as db:
        db.execute("DELETE FROM it_tickets WHERE id = ?", (ticket_id,))
        db.commit()


def get_tickets_by_priority(priority):
    """Get tickets by priority."""
    with DatabaseManager() as db:
        db.execute("""
            SELECT id, title, priority, status, description, assigned_to, created_by, created_at
            FROM it_tickets
            WHERE priority = ?
            ORDER BY created_at DESC
        """, (priority,))
        rows = db.fetchall()

    if not rows:
        return pd.DataFrame(
            columns=["id", "title", "priority", "status", "description", "assigned_to", "created_by", "created_at"])

    return pd.DataFrame([dict(row) for row in rows])