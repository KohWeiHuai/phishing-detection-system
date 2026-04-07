import hashlib
import os
import re

USERS_FILE = "users.txt"


def validate_username(username: str):
    if not username or not username.strip():
        return False, "Username cannot be blank."
    if "|" in username:
        return False, "Username cannot contain the '|' character."
    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    return True, "OK"


def check_password_policy(password: str):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least 1 uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least 1 lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least 1 number."
    return True, "OK"


def hash_password(password: str, salt: str) -> str:
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120000
    )
    return hashed.hex()


def user_exists(username: str) -> bool:
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("|")
                if len(parts) >= 3 and parts[0] == username:
                    return True
        return False
    except FileNotFoundError:
        return False


def register_user(username: str, password: str, role: str = "user"):
    ok, msg = validate_username(username)
    if not ok:
        return False, msg

    ok, msg = check_password_policy(password)
    if not ok:
        return False, msg

    role = (role or "user").strip().lower()
    if role not in ("user", "admin"):
        role = "user"

    if user_exists(username):
        return False, "Username already exists. Please choose another."

    salt = os.urandom(16).hex()
    pw_hash = hash_password(password, salt)

    with open(USERS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{username}|{salt}|{pw_hash}|{role}\n")

    return True, "User registered successfully."


def authenticate(username: str, password: str):
    """
    Returns ONLY 3 values:
    (ok, msg, role)

    Supports both formats in users.txt:
    old/new: username|salt|hash|role|...
    """
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("|")
                if len(parts) < 3:
                    continue

                u = parts[0]
                salt = parts[1]
                stored_hash = parts[2]
                role = parts[3] if len(parts) >= 4 else "user"

                if u == username:
                    if hash_password(password, salt) == stored_hash:
                        return True, "Password verified.", role
                    return False, "Wrong password.", None

        return False, "User not found.", None
    except FileNotFoundError:
        return False, "No users found. Please register first.", None