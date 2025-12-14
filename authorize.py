#!/usr/bin/env python2
"""
User Auth Tool - Complete Implementation

- Uses bcrypt to hash passwords (with salt and cost factor)
- Stores users in a text file: username,hashed_password,role
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
    except (ValueError, AttributeError):
        return False


def load_users():
    """
    Read all users from the file.
    Returns a dictionary: {username: (hashed_password, role)}
    """
    ensure_users_file()
    users = {}

    with open(USERS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                parts = line.split(",")
                if len(parts) == 3:
                    username, hashed, role = parts
                    users[username] = (hashed, role)
                elif len(parts) == 2:
                    username, hashed = parts
                    users[username] = (hashed, "user")  # default role
            except ValueError:
                continue

    return users


def write_users(users):
    """Write the users dictionary back to the file."""
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        for username, (hashed, role) in users.items():
            f.write(f"{username},{hashed},{role}\n")


def register_user(username, password, role="user"):
    """
    Register a new user.
    Returns True if registration worked, False otherwise.
    """
    if not username or "," in username or len(username) > 150:
        return False

    if len(password) < 8:
        return False

    users = load_users()
    if username in users:
        return False

    users[username] = (hash_password(password), role)
    write_users(users)
    return True


def login_user(username, password):
    """Return True if the username and password are correct."""
    users = load_users()
    user_data = users.get(username)
    if not user_data:
        return False
    stored_hash, _ = user_data
    return verify_password(password, stored_hash)


def change_password(username, old_password, new_password):
    """
    Change an existing user's password.
    Returns True on success, False otherwise.
    """
    if len(new_password) < 8:
        return False

    users = load_users()
    user_data = users.get(username)
    if not user_data:
        return False

    stored_hash, role = user_data
    if not verify_password(old_password, stored_hash):
        return False

    users[username] = (hash_password(new_password), role)
    write_users(users)
    return True


def cli_register():
    """CLI interface for user registration."""
    username = input("username: ").strip()
    password = getpass.getpass("password: ")
    confirm = getpass.getpass("confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    role = input("role (user/admin) [default: user]: ").strip() or "user"

    if register_user(username, password, role):
        print(f"User '{username}' registered successfully with role '{role}'.")
    else:
        print("Registration failed. Username exists, invalid username, or weak password.")


def cli_login():
    """CLI interface for user login."""
    username = input("username: ").strip()
    password = getpass.getpass("password: ")

    if login_user(username, password):
        print("Login successful.")
    else:
        print("Login failed. Invalid username or password.")


def cli_change_password():
    """CLI interface for password change."""
    username = input("username: ").strip()
    old = getpass.getpass("old password: ")
    new = getpass.getpass("new password: ")
    confirm = getpass.getpass("confirm new password: ")

    if new != confirm:
        print("New passwords do not match.")
        return

    if change_password(username, old, new):
        print("Password changed successfully.")
    else:
        print("Password change failed. Check your username and old password.")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="User Authentication Tool")
    parser.add_argument(
        "action",
        choices=["register", "login", "change-password"],
        help="Action to perform"
    )

    args = parser.parse_args()

    if args.action == "register":
        cli_register()
    elif args.action == "login":
        cli_login()
    elif args.action == "change-password":
        cli_change_password()


if __name__ == "__main__":
    main()