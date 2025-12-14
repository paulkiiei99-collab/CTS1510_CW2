"""User authentication and management service."""
import os
import bcrypt
from pathlib import Path
from app.data.db import DatabaseManager

BCRYPT_ROUNDS = 12
USERS_FILE = Path("users.txt")


def hash_password(plain_password):
    """Hash a plaintext password using bcrypt."""
    password_bytes = plain_password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password, stored_hash):
    """Check a plaintext password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            stored_hash.encode("utf-8")
        )
    except (ValueError, AttributeError):
        return False


def register_user(username, password, role="user"):
    """
    Register a new user into the SQLite DB.
    Returns (success: bool, message: str)
    """
    if not username or "," in username or len(username) > 150:
        return False, "Invalid username."

    if len(password) < 8:
        return False, "Password too short (min 8 characters)."

    with DatabaseManager() as db:
        db.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if db.fetchone():
            return False, "Username already exists."

        hashed = hash_password(password)
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hashed, role)
        )
        db.commit()

    return True, "User registered successfully."


def login_user(username, password):
    """
    Check username and password against the SQLite DB.
    Returns (success: bool, user_dict/message: str)
    """
    with DatabaseManager() as db:
        db.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,)
        )
        row = db.fetchone()

    if not row:
        return False, "User not found."

    # row is a sqlite3.Row object, access by column name
    user_id = row['id']
    stored_hash = row['password_hash']
    role = row['role']

    if verify_password(password, stored_hash):
        # Return user dict on success
        return True, {
            'id': user_id,
            'username': username,
            'role': role
        }
    else:
        return False, "Incorrect password."


def migrate_users_from_file():
    """
    Read users from users.txt (username,hash,role) and insert into SQLite users table.
    Returns number of inserted users.
    """
    if not USERS_FILE.exists():
        return 0

    inserted = 0
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                parts = line.split(",")
                if len(parts) == 3:
                    username, stored_hash, role = parts
                elif len(parts) == 2:
                    username, stored_hash = parts
                    role = "user"
                else:
                    continue
            except ValueError:
                continue

            with DatabaseManager() as db:
                # Skip if exists
                db.execute("SELECT 1 FROM users WHERE username = ?", (username,))
                if db.fetchone():
                    continue

                db.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, stored_hash, role)
                )
                db.commit()
                inserted += 1

    return inserted