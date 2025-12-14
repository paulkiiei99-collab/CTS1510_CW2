"""User model class."""
import bcrypt
from datetime import datetime
from app.data.db import DatabaseManager


class User:
    """User entity class."""

    def __init__(self, user_id=None, username=None, password_hash=None,
                 role="user", created_at=None):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.created_at = created_at or datetime.now()

    @staticmethod
    def hash_password(plain_password):
        """Hash a plaintext password using bcrypt."""
        password_bytes = plain_password.encode("utf-8")
        salt = bcrypt.gensalt(rounds=12)
        hashed_bytes = bcrypt.hashpw(password_bytes, salt)
        return hashed_bytes.decode("utf-8")

    def verify_password(self, plain_password):
        """Verify password against stored hash."""
        try:
            return bcrypt.checkpw(
                plain_password.encode("utf-8"),
                self.password_hash.encode("utf-8")
            )
        except (ValueError, AttributeError):
            return False

    def save(self):
        """Save user to database."""
        with DatabaseManager() as db:
            if self.id is None:
                # Insert new user
                db.execute("""
                    INSERT INTO users (username, password_hash, role)
                    VALUES (?, ?, ?)
                """, (self.username, self.password_hash, self.role))
                self.id = db.lastrowid()
            else:
                # Update existing user
                db.execute("""
                    UPDATE users 
                    SET username = ?, password_hash = ?, role = ?
                    WHERE id = ?
                """, (self.username, self.password_hash, self.role, self.id))
        return self

    def delete(self):
        """Delete user from database."""
        if self.id:
            with DatabaseManager() as db:
                db.execute("DELETE FROM users WHERE id = ?", (self.id,))
            return True
        return False

    @classmethod
    def find_by_id(cls, user_id):
        """Find user by ID."""
        with DatabaseManager() as db:
            db.execute("""
                SELECT id, username, password_hash, role, created_at
                FROM users WHERE id = ?
            """, (user_id,))
            row = db.fetchone()

            if row:
                return cls(
                    user_id=row['id'],
                    username=row['username'],
                    password_hash=row['password_hash'],
                    role=row['role'],
                    created_at=row['created_at']
                )
        return None

    @classmethod
    def find_by_username(cls, username):
        """Find user by username."""
        with DatabaseManager() as db:
            db.execute("""
                SELECT id, username, password_hash, role, created_at
                FROM users WHERE username = ?
            """, (username,))
            row = db.fetchone()

            if row:
                return cls(
                    user_id=row['id'],
                    username=row['username'],
                    password_hash=row['password_hash'],
                    role=row['role'],
                    created_at=row['created_at']
                )
        return None

    @classmethod
    def authenticate(cls, username, password):
        """Authenticate user and return User object if successful."""
        user = cls.find_by_username(username)
        if user and user.verify_password(password):
            return user
        return None

    @classmethod
    def create(cls, username, password, role="user"):
        """Create a new user."""
        if len(username) < 3 or len(password) < 8:
            raise ValueError("Invalid username or password length.")

        password_hash = cls.hash_password(password)
        user = cls(username=username, password_hash=password_hash, role=role)
        return user.save()

    def to_dict(self):
        """Convert user to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'created_at': str(self.created_at)
        }

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"
