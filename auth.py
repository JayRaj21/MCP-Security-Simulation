"""Zero-trust authentication module.

Zero-trust means: every request is verified independently, no implicit trust is
ever granted, and every access decision is recorded in the audit log.
"""
import secrets
import time
from typing import Any, Dict, Optional

import bcrypt


class AuthManager:
    """Manages password verification and short-lived session tokens.

    Session tokens are cryptographically random hex strings (256-bit).
    They are stored server-side and expire after ``session_duration`` seconds.
    There is no JWT — the server is the single authority for token validity.
    """

    def __init__(
        self,
        users: Dict[str, Dict[str, Any]],
        session_duration: int = 3600,
    ) -> None:
        self._users = users
        self._session_duration = session_duration
        # token -> {username, role, created_at}
        self._sessions: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Verify credentials.  Returns a session token on success, None on failure."""
        if username not in self._users:
            return None
        user = self._users[username]
        if bcrypt.checkpw(password.encode(), user["password_hash"]):
            return self._create_session(username, user["role"])
        return None

    def verify_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Return session info dict if token is valid and not expired, else None."""
        if not token or token not in self._sessions:
            return None
        session = self._sessions[token]
        if time.time() - session["created_at"] > self._session_duration:
            del self._sessions[token]
            return None
        return session

    def invalidate_session(self, token: str) -> bool:
        """Invalidate (logout) a session.  Returns True if the token existed."""
        if token in self._sessions:
            del self._sessions[token]
            return True
        return False

    def active_usernames(self) -> list:
        """Return usernames that currently hold a valid session."""
        now = time.time()
        return [
            s["username"]
            for s in self._sessions.values()
            if now - s["created_at"] <= self._session_duration
        ]

    def list_active_sessions(self) -> list:
        """Return metadata for all active sessions (token prefix only, never full token)."""
        now = time.time()
        result = []
        for token, s in list(self._sessions.items()):
            age = now - s["created_at"]
            if age <= self._session_duration:
                result.append({
                    "token_prefix": token[:8] + "…",
                    "username": s["username"],
                    "role": s["role"],
                    "age_seconds": int(age),
                    "expires_in_seconds": int(self._session_duration - age),
                })
        return result

    def revoke_all_for_user(self, username: str) -> int:
        """Revoke every session belonging to username. Returns the count revoked."""
        to_delete = [t for t, s in self._sessions.items() if s["username"] == username]
        for t in to_delete:
            del self._sessions[t]
        return len(to_delete)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _create_session(self, username: str, role: str) -> str:
        token = secrets.token_hex(32)  # 256-bit random token
        self._sessions[token] = {
            "username": username,
            "role": role,
            "created_at": time.time(),
        }
        return token
