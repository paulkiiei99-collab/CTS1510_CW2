# app/data/incidents.py
"""CRUD operations for cyber_incidents table."""

import pandas as pd
from app.data.db import DatabaseManager


def get_all_incidents():
    """Return all incidents as a pandas DataFrame."""
    with DatabaseManager() as db:
        db.execute("""
            SELECT 
                id,
                date,
                title,
                severity,
                status,
                description,
                reported_by,
                created_at
            FROM cyber_incidents
            ORDER BY date DESC, id DESC
        """)
        rows = db.fetchall()

    if not rows:
        return pd.DataFrame(
            columns=[
                "id",
                "date",
                "title",
                "severity",
                "status",
                "description",
                "reported_by",
                "created_at",
            ]
        )

    # Convert sqlite3.Row objects to dicts
    data = [dict(row) for row in rows]
    return pd.DataFrame(data)


def get_incidents_by_severity(severity: str):
    """Return incidents filtered by severity."""
    with DatabaseManager() as db:
        db.execute(
            """
            SELECT 
                id,
                date,
                title,
                severity,
                status,
                description,
                reported_by,
                created_at
            FROM cyber_incidents
            WHERE severity = ?
            ORDER BY date DESC, id DESC
            """,
            (severity,),
        )
        rows = db.fetchall()

    if not rows:
        return pd.DataFrame(
            columns=[
                "id",
                "date",
                "title",
                "severity",
                "status",
                "description",
                "reported_by",
                "created_at",
            ]
        )

    return pd.DataFrame([dict(r) for r in rows])


def get_incidents_by_status(status: str):
    """Return incidents filtered by status."""
    with DatabaseManager() as db:
        db.execute(
            """
            SELECT 
                id,
                date,
                title,
                severity,
                status,
                description,
                reported_by,
                created_at
            FROM cyber_incidents
            WHERE status = ?
            ORDER BY date DESC, id DESC
            """,
            (status,),
        )
        rows = db.fetchall()

    if not rows:
        return pd.DataFrame(
            columns=[
                "id",
                "date",
                "title",
                "severity",
                "status",
                "description",
                "reported_by",
                "created_at",
            ]
        )

    return pd.DataFrame([dict(r) for r in rows])


def insert_incident(date, title, severity, status, description, reported_by):
    """
    Insert a new incident.
    Returns the new incident ID.
    """
    with DatabaseManager() as db:
        db.execute(
            """
            INSERT INTO cyber_incidents 
                (date, title, severity, status, description, reported_by)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (date, title, severity, status, description, reported_by),
        )
        new_id = db.lastrowid()
        db.commit()
    return new_id


def update_incident(incident_id, date, title, severity, status, description):
    """
    Update an existing incident by ID.
    """
    with DatabaseManager() as db:
        db.execute(
            """
            UPDATE cyber_incidents
            SET 
                date = ?,
                title = ?,
                severity = ?,
                status = ?,
                description = ?
            WHERE id = ?
            """,
            (date, title, severity, status, description, incident_id),
        )
        db.commit()


def delete_incident(incident_id):
    """
    Delete an incident by ID.
    """
    with DatabaseManager() as db:
        db.execute(
            "DELETE FROM cyber_incidents WHERE id = ?",
            (incident_id,),
        )
        db.commit()
