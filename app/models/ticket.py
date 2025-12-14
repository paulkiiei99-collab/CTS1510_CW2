# ========================================
# FILE 3: app/models/ticket.py
# ========================================
"""IT Ticket model class."""
from datetime import datetime
from app.data.db import DatabaseManager


class ITTicket:
    """IT ticket entity class."""

    PRIORITIES = ["Low", "Medium", "High", "Critical"]
    STATUSES = ["Open", "In Progress", "Closed"]

    def __init__(self, ticket_id=None, title=None, priority="Medium",
                 status="Open", description=None, assigned_to=None,
                 created_by=None, created_at=None):
        self.id = ticket_id
        self.title = title
        self.priority = priority
        self.status = status
        self.description = description
        self.assigned_to = assigned_to
        self.created_by = created_by
        self.created_at = created_at or datetime.now()

    def validate(self):
        """Validate ticket data."""
        if not self.title or len(self.title) < 3:
            raise ValueError("Title must be at least 3 characters.")
        if self.priority not in self.PRIORITIES:
            raise ValueError(f"Priority must be one of {self.PRIORITIES}.")
        if self.status not in self.STATUSES:
            raise ValueError(f"Status must be one of {self.STATUSES}.")
        return True

    def save(self):
        """Save ticket to database."""
        self.validate()

        with DatabaseManager() as db:
            if self.id is None:
                db.execute("""
                    INSERT INTO it_tickets 
                    (title, priority, status, description, assigned_to, created_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (self.title, self.priority, self.status,
                      self.description, self.assigned_to, self.created_by))
                self.id = db.lastrowid()
            else:
                db.execute("""
                    UPDATE it_tickets 
                    SET title = ?, priority = ?, status = ?, 
                        description = ?, assigned_to = ?
                    WHERE id = ?
                """, (self.title, self.priority, self.status,
                      self.description, self.assigned_to, self.id))
        return self

    def delete(self):
        """Delete ticket from database."""
        if self.id:
            with DatabaseManager() as db:
                db.execute("DELETE FROM it_tickets WHERE id = ?", (self.id,))
            return True
        return False

    def is_high_priority(self):
        """Check if ticket is high priority."""
        return self.priority in ["High", "Critical"]

    def close(self):
        """Close the ticket."""
        self.status = "Closed"
        return self.save()

    def to_dict(self):
        """Convert ticket to dictionary."""
        return {
            'id': self.id,
            'title': self.title,
            'priority': self.priority,
            'status': self.status,
            'description': self.description,
            'assigned_to': self.assigned_to,
            'created_by': self.created_by,
            'created_at': str(self.created_at)
        }

    def __repr__(self):
        return f"<ITTicket(id={self.id}, title='{self.title}', priority='{self.priority}')>"
