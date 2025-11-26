#!/usr/bin/env python2
"""
User Auth Tool

- Uses bcrypt to hash passwords (with salt and cost factor)
- Stores users in a text file: username,hashed_password
- Supports register, login, and change password from the CLI
"""

import os
import argparse
import getpass
import bcrypt

USERS_FILE = "users.txt"
BCRYPT_ROUNDS = 12  # bcrypt cost factor


def ensure_users_file():
    """Create the users file if it does not exist."""
    if not os.path.exists(USERS_FILE):
        # just create an empty file
        with open(USERS_FILE, "a", encoding="utf-8"):
            pass


def hash_password(plain_password):
    """Hash a plaintext password using bcrypt."""
    password_bytes = plain_password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    return hashed_bytes.decode("utf-8")


def verify_password(plain_password, stored_hash):
    """Check a plaintext password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            stored_hash.encode("utf-8")
        )
    except ValueError:
        # if the stored hash is invalid or corrupted
        return False


def load_users():
    """
    Read all users from the file.

    Returns a dictionary: {username: hashed_password}
    """
    ensure_users_file()
    users = {}

    with open(USERS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # split only on the first comma
            try:
                username, hashed = line.split(",", 1)
            except ValueError:
                continue

            users[username] = hashed

    return users


def write_users(users):
    """
    Write the users dictionary back to the file.

    This version just opens the file and overwrites it directly.
    """
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        for username, hashed in users.items():
            f.write(f"{username},{hashed}\n")


def register_user(username, password):
    """
    Register a new user.

    Returns True if registration worked, False otherwise.
    """
    if not username or "," in username or len(username) > 150:
        return False

    # basic password rule
    if len(password) < 8:
        return False

    users = load_users()
    if username in users:
        return False

    users[username] = hash_password(password)
    write_users(users)
    return True


def login_user(username, password):
    """Return True if the username and password are correct."""
    users = load_users()
    stored_hash = users.get(username)
    if not stored_hash:
        return False
    return verify_password(password, stored_hash)


def change_password(username, old_password, new_password):
    """
    Change an existing user's password.

    Returns True on success, False otherwise.
    """
    if len(new_password) < 8:
        return False

    users = load_users()
    stored_hash = users.get(username)
    if not stored_hash:
        return False

    if not verify_password(old_password, stored_hash):
        return False

    users[username] = hash_password(new_password)
    write_users(users)
    return True


def cli_register():
    username = input("username: ").strip()
    password = getpass.getpass("password: ")
    confirm = getpass.getpass("confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    if register_user(username, password):
        print(f"User '{username}' registered.")
    else:
        print("Register failed. Username exists, invalid username, or weak password.")


def cli_login():
    username = input("username: ").strip()
    password = getpass.getpass("password: ")

    if login_user(username, password):
        print("Login successful.")
    else:
        print("Login failed.")


def cli_change_password():
    username = input("username: ").strip()
    old = getpass.getpass("old password: ")
    new = getpass.getpass("new password: ")
    confirm = getpass.getpass("confirm new password: ")

