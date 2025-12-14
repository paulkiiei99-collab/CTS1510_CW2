import os
import bcrypt
from app.data.db import connect_database

BCRYPT_ROUNDS = 12
USERS_FILE = "users.txt"   # same file your auth.py uses

def hash_password(plain_password: str) -> str:
    password_bytes = plain_password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            stored_hash.encode("utf-8")
        )
    except ValueError:
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

    conn = connect_database()
    cur = conn.cursor()

    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        return False, "Username already exists."

    hashed = hash_password(password)

    cur.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (username, hashed, role)
    )
    conn.commit()
    conn.close()
    return True, "User registered successfully."


def login_user(username, password):
    """
    Check username and password against the SQLite DB.
    Returns (success: bool, message: str)
    """
    conn = connect_database()
    cur = conn.cursor()

    cur.execute(
        "SELECT password, role FROM users WHERE username = ?",
        (username,)
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return False, "User not found."

    stored_hash, role = row

    if verify_password(password, stored_hash):
        return True, "Login successful."
    else:
        return False, "Incorrect password."

def migrate_users_from_file():
    """
    Read users from users.txt (username,hash) and insert into SQLite users table.
    Returns number of inserted users.
    """
    if not os.path.exists(USERS_FILE):
        return 0

    conn = connect_database()
    cur = conn.cursor()

    inserted = 0
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                username, stored_hash = line.split(",", 1)
            except ValueError:
                continue

            # skip if exists
            cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                continue

            role = "user"
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, stored_hash, role)
            )
            inserted += 1

    conn.commit()
    conn.close()
    return inserted

