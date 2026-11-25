"""Account security policy shared by the app, the seed and the MySQL schema.

The username and password-hash rules here are compiled into CHECK constraints
on `app_user` (see mysql_schema.py), so MySQL itself rejects any row that
breaks them, whichever client writes it. Password *strength* can only be
checked here, before hashing: once a password is a bcrypt hash, the database
cannot see its length or characters. What the database does guarantee is that
nothing other than a bcrypt hash of cost >= BCRYPT_ROUNDS is ever stored.
"""

from __future__ import annotations

import re

import bcrypt

# --------------------------------------------------------------------------- #
# Usernames
# --------------------------------------------------------------------------- #
USERNAME_MIN = 3
USERNAME_MAX = 30
# Lowercase ASCII; starts with a letter; single . _ - separators between
# alphanumeric runs (no leading/trailing/double separators).
USERNAME_PATTERN = r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"
RESERVED_USERNAMES = (
    "admin",
    "administrator",
    "root",
    "system",
    "sysadmin",
    "superuser",
    "mysql",
    "nl_reader",
    "guest",
    "anonymous",
    "null",
    "test",
)
USERNAME_RULES = [
    f"{USERNAME_MIN}–{USERNAME_MAX} characters",
    "Lowercase letters, digits and . _ - only",
    "Must start with a letter",
    "Separators only between letters/digits (no '..', no trailing '.')",
]

_USERNAME_RE = re.compile(USERNAME_PATTERN)


def normalize_username(raw: str) -> str:
    return (raw or "").strip().lower()


def validate_username(username: str) -> list[str]:
    errors: list[str] = []
    if not USERNAME_MIN <= len(username) <= USERNAME_MAX:
        errors.append(f"Username must be {USERNAME_MIN}–{USERNAME_MAX} characters.")
    if not _USERNAME_RE.fullmatch(username):
        errors.append(
            "Username may only use lowercase letters, digits and single . _ - "
            "separators, and must start with a letter."
        )
    if username in RESERVED_USERNAMES:
        errors.append(f"'{username}' is a reserved name.")
    return errors


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
PASSWORD_MIN = 12
PASSWORD_MAX = 64
BCRYPT_MAX_BYTES = 72  # bcrypt silently ignores anything past 72 bytes
BCRYPT_ROUNDS = 12
# Matches only a well-formed bcrypt hash with cost 12..31. `[$]` instead of
# `\$` keeps the pattern free of backslashes, so it is identical in Python
# and inside a MySQL string literal.
BCRYPT_HASH_PATTERN = r"^[$]2[aby][$](1[2-9]|2[0-9]|3[01])[$][./A-Za-z0-9]{53}$"

PASSWORD_RULES = [
    ("length", f"{PASSWORD_MIN}–{PASSWORD_MAX} characters"),
    ("lower", "A lowercase letter"),
    ("upper", "An uppercase letter"),
    ("digit", "A digit"),
    ("symbol", "A symbol (e.g. ! # $ % & *)"),
    ("username", "Does not contain the username"),
]

_COMMON_PASSWORDS = {
    "password1234",
    "password123!",
    "password@123",
    "qwerty123456",
    "123456789012",
    "letmein12345",
    "welcome12345",
    "welcome@1234",
    "admin1234567",
    "changeme1234",
    "iloveyou1234",
}

MAX_FAILED_LOGINS = 5   # mirrored in sp_register_login
LOCKOUT_MINUTES = 15    # mirrored in sp_register_login


def validate_password(password: str, username: str = "") -> list[str]:
    errors: list[str] = []
    if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
        errors.append(f"Password must be {PASSWORD_MIN}–{PASSWORD_MAX} characters.")
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        errors.append(f"Password must be at most {BCRYPT_MAX_BYTES} bytes once encoded.")
    if password != password.strip():
        errors.append("Password must not start or end with whitespace.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in password):
        errors.append("Password must not contain control characters.")
    if not re.search(r"[a-z]", password):
        errors.append("Password needs a lowercase letter.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password needs an uppercase letter.")
    if not re.search(r"\d", password):
        errors.append("Password needs a digit.")
    if not re.search(r"[^A-Za-z0-9\s]", password):
        errors.append("Password needs a symbol.")
    if username and len(username) >= USERNAME_MIN and username.lower() in password.lower():
        errors.append("Password must not contain the username.")
    if re.search(r"(.)\1{3,}", password):
        errors.append("Password must not repeat the same character 4+ times in a row.")
    if password.lower() in _COMMON_PASSWORDS:
        errors.append("That password is too common.")
    return errors


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("ascii")


# Used when the username does not exist, so a failed lookup costs the same
# time as a wrong password and response timing does not reveal valid names.
_DUMMY_HASH = hash_password("dummy-Password-for-timing-1!")


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"), (password_hash or _DUMMY_HASH).encode("ascii")
        ) and password_hash is not None
    except ValueError:
        return False
