"""Configuration and user registry for MCP Security Simulation v2.

All sensitive values should be set via environment variables in production.
The defaults here are for local demo use only.
"""
import os
import bcrypt
from typing import Dict, Any

# ---------------------------------------------------------------------------
# GitHub API (open-source data backend)
# ---------------------------------------------------------------------------
# Target a public repository.  Override via env vars for your own repo.
GITHUB_REPO: str = os.getenv("GITHUB_REPO", "public-apis/public-apis")
GITHUB_BRANCH: str = os.getenv("GITHUB_BRANCH", "master")
# Optional personal-access token — increases rate limits from 60 to 5 000 req/hr
GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")

# ---------------------------------------------------------------------------
# Cryptography
# ---------------------------------------------------------------------------
# 32-character key used to derive the AES-256 encryption key.
# In production this must come from a secrets manager, NOT source code.
ENCRYPTION_KEY: str = os.getenv(
    "MCP_ENCRYPTION_KEY",
    "mcp-v2-demo-key-change-in-prod!!",  # exactly 32 chars for clarity
)

# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------
SESSION_DURATION: int = int(os.getenv("SESSION_DURATION_SECONDS", "3600"))  # 1 hour

# ---------------------------------------------------------------------------
# User registry
# ---------------------------------------------------------------------------
# Passwords are read from env vars so they never appear in source at runtime.
# bcrypt rounds=10 keeps startup fast while remaining reasonably strong for a demo.
_ROUNDS = 10

def _build_users() -> Dict[str, Dict[str, Any]]:
    raw: Dict[str, str] = {
        "admin":  os.getenv("ADMIN_PASSWORD",  "admin123"),
        "viewer": os.getenv("VIEWER_PASSWORD", "view456"),
    }
    return {
        name: {
            "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=_ROUNDS)),
            "role": "admin" if name == "admin" else "viewer",
        }
        for name, pw in raw.items()
    }


print("[v2] Hashing passwords …")
USERS: Dict[str, Dict[str, Any]] = _build_users()
print("[v2] User registry ready.")
