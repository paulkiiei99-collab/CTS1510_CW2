# ========================================
# FILE 2: app/models/dataset.py
# ========================================
"""Dataset model class."""
from datetime import datetime
from app.data.db import DatabaseManager


class Dataset:
    """Dataset metadata entity class."""

    CATEGORIES = ["Sensitive", "Public", "Internal", "Confidential"]

    def __init__(self, dataset_id=None, name=None, category="Internal",
                 size_gb=0.0, owner=None, last_updated=None, created_at=None):
        self.id = dataset_id
        self.name = name
        self.category = category
        self.size_gb = size_gb
        self.owner = owner
        self.last_updated = last_updated or datetime.now().date()
        self.created_at = created_at or datetime.now()

    def validate(self):
        """Validate dataset data."""
        if not self.name or len(self.name) < 3:
            raise ValueError("Name must be at least 3 characters.")
        if self.category not in self.CATEGORIES:
            raise ValueError(f"Category must be one of {self.CATEGORIES}.")
        if self.size_gb < 0:
            raise ValueError("Size cannot be negative.")
        return True

    def save(self):
        """Save dataset to database."""
        self.validate()

        with DatabaseManager() as db:
            if self.id is None:
                db.execute("""
                    INSERT INTO datasets_metadata 
                    (name, category, size_gb, owner, last_updated)
                    VALUES (?, ?, ?, ?, ?)
                """, (self.name, self.category, self.size_gb,
                      self.owner, str(self.last_updated)))
                self.id = db.lastrowid()
            else:
                db.execute("""
                    UPDATE datasets_metadata 
                    SET name = ?, category = ?, size_gb = ?, 
                        owner = ?, last_updated = ?
                    WHERE id = ?
                """, (self.name, self.category, self.size_gb,
                      self.owner, str(self.last_updated), self.id))
        return self

    def delete(self):
        """Delete dataset from database."""
        if self.id:
            with DatabaseManager() as db:
                db.execute("DELETE FROM datasets_metadata WHERE id = ?", (self.id,))
            return True
        return False

    def is_sensitive(self):
        """Check if dataset is sensitive."""
        return self.category in ["Sensitive", "Confidential"]

    def to_dict(self):
        """Convert dataset to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'size_gb': self.size_gb,
            'owner': self.owner,
            'last_updated': str(self.last_updated),
            'created_at': str(self.created_at)
        }

    def __repr__(self):
        return f"<Dataset(id={self.id}, name='{self.name}', category='{self.category}')>"

