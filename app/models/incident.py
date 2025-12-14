# ========================================
# FILE 1: app/models/incident.py
# ========================================
"""Security Incident model class."""
from datetime import datetime
from app.data.db import DatabaseManager
import pandas as pd


class SecurityIncident:
    """Security incident entity class."""

    SEVERITIES = ["Low", "Medium", "High", "Critical"]
    STATUSES = ["Open", "In Progress", "Resolved", "Closed"]

    def __init__(self, incident_id=None, date=None, title=None, severity="Medium",
                 status="Open", description=None, reported_by=None, created_at=None):
        self.id = incident_id
        self.date = date or datetime.now().date()
        self.title = title
        self.severity = severity
        self.status = status
        self.description = description
        self.reported_by = reported_by
        self.created_at = created_at or datetime.now()

    def validate(self):
        """Validate incident data."""
        if not self.title or len(self.title) < 3:
            raise ValueError("Title must be at least 3 characters.")
        if self.severity not in self.SEVERITIES:
            raise ValueError(f"Severity must be one of {self.SEVERITIES}.")
        if self.status not in self.STATUSES:
            raise ValueError(f"Status must be one of {self.STATUSES}.")
        return True

    def save(self):
        """Save incident to database."""
        self.validate()

        with DatabaseManager() as db:
            if self.id is None:
                db.execute("""
                    INSERT INTO cyber_incidents 
                    (date, title, severity, status, description, reported_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (str(self.date), self.title, self.severity,
                      self.status, self.description, self.reported_by))
                self.id = db.lastrowid()
            else:
                db.execute("""
                    UPDATE cyber_incidents 
                    SET date = ?, title = ?, severity = ?, status = ?, 
                        description = ?, reported_by = ?
                    WHERE id = ?
                """, (str(self.date), self.title, self.severity, self.status,
                      self.description, self.reported_by, self.id))
        return self

    def delete(self):
        """Delete incident from database."""
        if self.id:
            with DatabaseManager() as db:
                db.execute("DELETE FROM cyber_incidents WHERE id = ?", (self.id,))
            return True
        return False

    def is_critical(self):
        """Check if incident is critical."""
        return self.severity == "Critical"

    def is_open(self):
        """Check if incident is open."""
        return self.status in ["Open", "In Progress"]

    def resolve(self):
        """Mark incident as resolved."""
        self.status = "Resolved"
        return self.save()

    @classmethod
    def find_by_id(cls, incident_id):
        """Find incident by ID."""
        with DatabaseManager() as db:
            db.execute("SELECT * FROM cyber_incidents WHERE id = ?", (incident_id,))
            row = db.fetchone()

            if row:
                return cls(
                    incident_id=row['id'],
                    date=row['date'],
                    title=row['title'],
                    severity=row['severity'],
                    status=row['status'],
                    description=row['description'],
                    reported_by=row['reported_by'],
                    created_at=row.get('created_at')
                )
        return None

    def to_dict(self):
        """Convert incident to dictionary."""
        return {
            'id': self.id,
            'date': str(self.date),
            'title': self.title,
            'severity': self.severity,
            'status': self.status,
            'description': self.description,
            'reported_by': self.reported_by,
            'created_at': str(self.created_at)
        }

    def __repr__(self):
        return f"<SecurityIncident(id={self.id}, title='{self.title}', severity='{self.severity}')>"
