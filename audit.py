"""Audit logging — records every access attempt with authentication status.

Authenticated users can later query this log to see all unauthorized access
attempts (zero-trust principle: assume breach, detect intruders early).
"""
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class AuditEntry:
    timestamp: str      # ISO-8601 UTC
    username: str       # "anonymous" when unauthenticated
    authenticated: bool
    action: str         # e.g. "read_file", "list_files", "authenticate"
    resource: str       # file path, "session", "audit_log", …
    outcome: str        # "success", "denied", "error: …", "TAMPERED", …


class AuditLogger:
    """In-memory circular audit log.

    Capacity defaults to 1 000 entries; oldest entries are silently dropped
    once the buffer is full (``collections.deque`` with ``maxlen``).
    """

    def __init__(self, capacity: int = 1000) -> None:
        self._log: deque[AuditEntry] = deque(maxlen=capacity)

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(
        self,
        username: Optional[str],
        authenticated: bool,
        action: str,
        resource: str,
        outcome: str,
    ) -> None:
        self._log.append(
            AuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                username=username or "anonymous",
                authenticated=authenticated,
                action=action,
                resource=resource,
                outcome=outcome,
            )
        )

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def get_all(self) -> List[dict]:
        """Return every audit entry as a list of plain dicts."""
        return [asdict(e) for e in self._log]

    def get_unauthorized(self) -> List[dict]:
        """Return only entries where ``authenticated=False``."""
        return [asdict(e) for e in self._log if not e.authenticated]

    def get_failed_auth(self) -> List[dict]:
        """Return only failed authentication attempts (wrong credentials)."""
        return [
            asdict(e) for e in self._log
            if e.action == "authenticate" and not e.authenticated
        ]

    # ------------------------------------------------------------------
    # Formatting
    # ------------------------------------------------------------------

    @staticmethod
    def format_entry(entry: dict) -> str:
        tag = "AUTH  " if entry["authenticated"] else "UNAUTH"
        return (
            f"[{entry['timestamp']}] [{tag}] "
            f"user={entry['username']:<14} "
            f"action={entry['action']:<22} "
            f"resource={entry['resource']:<35} "
            f"outcome={entry['outcome']}"
        )
