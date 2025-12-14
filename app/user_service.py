# app/services/user_service.py
"""User authentication and management service."""
import bcrypt
from pathlib import Path
from app.data.db import DatabaseManager

USERS_FILE = Path("users.txt")


def hash_password(plain_password):
    """Hash a plaintext password using bcrypt."""
    password_bytes = plain_password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    return hashed_bytes.decode("utf-8")


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
    Register a new user in the database.
    Returns (success, message) tuple.
    """
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters."

    if len(password) < 8:
        return False, "Password must be at least 8 characters."

    password_hash = hash_password(password)

    try:
        with DatabaseManager() as db:
            db.execute("""
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
            """, (username, password_hash, role))
            return True, f"User '{username}' registered successfully."
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            return False, "Username already exists."
        return False, f"Registration failed: {str(e)}"


def login_user(username, password):
    """
    Verify user credentials against the database.
    Returns (success, message/user_dict) tuple.
    """
    try:
        with DatabaseManager() as db:
            db.execute("""
                SELECT id, username, password_hash, role 
                FROM users WHERE username = ?
            """, (username,))
            user = db.fetchone()

            if not user:
                return False, "Invalid username or password."

            if verify_password(password, user['password_hash']):
                return True, {
                    'id': user['id'],
                    'username': user['username'],
                    'role': user['role']
                }
            else:
                return False, "Invalid username or password."
    except Exception as e:
        return False, f"Login error: {str(e)}"


def get_user_by_username(username):
    """Get user information by username."""
    with DatabaseManager() as db:
        db.execute("""
            SELECT id, username, role, created_at 
            FROM users WHERE username = ?
        """, (username,))
        return db.fetchone()


def migrate_users_from_file():
    """
    Migrate users from users.txt to the database.
    Returns count of migrated users.
    """
    if not USERS_FILE.exists():
        print(f"[INFO] {USERS_FILE} not found. Skipping migration.")
        return 0

    count = 0
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                parts = line.split(',')
                if len(parts) == 3:
                    username, password_hash, role = parts
                elif len(parts) == 2:
                    username, password_hash = parts
                    role = "user"
                else:
                    continue

                with DatabaseManager() as db:
                    db.execute("""
                        INSERT OR IGNORE INTO users (username, password_hash, role)
                        VALUES (?, ?, ?)
                    """, (username, password_hash, role))
                    count += 1
            except Exception as e:
                print(f"[WARNING] Failed to migrate user: {e}")
                continue

    print(f"[MIGRATION] {count} users migrated from {USERS_FILE}")
    return count


def change_user_password(username, old_password, new_password):
    """
    Change a user's password.
    Returns (success, message) tuple.
    """
    if len(new_password) < 8:
        return False, "New password must be at least 8 characters."

    try:
        with DatabaseManager() as db:
            db.execute("""
                SELECT password_hash FROM users WHERE username = ?
            """, (username,))
            user = db.fetchone()

            if not user:
                return False, "User not found."

            if not verify_password(old_password, user['password_hash']):
                return False, "Current password is incorrect."

            new_hash = hash_password(new_password)
            db.execute("""
                UPDATE users SET password_hash = ? WHERE username = ?
            """, (new_hash, username))

            return True, "Password changed successfully."
    except Exception as e:
        return False, f"Password change failed: {str(e)}"


def get_all_users():
    """Get all users (for admin purposes)."""
    with DatabaseManager() as db:
        db.execute("""
            SELECT id, username, role, created_at 
            FROM users ORDER BY created_at DESC
        """)
        return db.fetchall()