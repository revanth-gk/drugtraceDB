"""Environment configuration for the MySQL + MongoDB prototype.

A local `.env` file (git-ignored) can override any of these values. The defaults
point at the user-space MySQL instance on port 3307 and the local MongoDB
service on 27017.
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(ENV_PATH)

MYSQL_HOST = os.environ.get("DRUGTRACE_MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.environ.get("DRUGTRACE_MYSQL_PORT", "3307"))
MYSQL_USER = os.environ.get("DRUGTRACE_MYSQL_USER", "root")
MYSQL_PASSWORD = os.environ.get("DRUGTRACE_MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.environ.get("DRUGTRACE_MYSQL_DB", "drugtrace")

MONGO_URI = os.environ.get("DRUGTRACE_MONGO_URI", "mongodb://127.0.0.1:27017")
MONGO_DATABASE = os.environ.get("DRUGTRACE_MONGO_DB", "drugtrace_logs")

SECRET_KEY = os.environ.get("DRUGTRACE_SECRET", "drugtrace-dev-secret-change-me")

# NL-reader MySQL account (SELECT on views only — see SCHEMA.md §7)
NL_READER_USER = os.environ.get("DRUGTRACE_NL_USER", "nl_reader")
NL_READER_PASSWORD = os.environ.get("DRUGTRACE_NL_PASSWORD", "")

# LLM fallback (Gemini). Leave blank to disable LLM route.
GEMINI_API_KEY = os.environ.get("DRUGTRACE_GEMINI_API_KEY", "")

# Serve the session cookie with the Secure flag (enable behind HTTPS).
SECURE_COOKIES = os.environ.get("DRUGTRACE_SECURE_COOKIES", "0") == "1"
# Flask debug mode (interactive debugger) is off unless explicitly enabled.
DEBUG = os.environ.get("DRUGTRACE_DEBUG", "0") == "1"
