"""In-memory test file store with pre-populated sensitive-looking demo files.

These files simulate the kind of data an attacker would want to read or tamper
with — credentials, user records, config, and audit logs.  They are kept in
memory so every server restart returns to a clean state.

The store supports read, write, and delete so users can actively test whether
auth gates are enforced and whether HMAC signatures catch tampering.
"""
import hashlib
import time
from copy import deepcopy
from typing import Optional

# ---------------------------------------------------------------------------
# Pre-populated demo files
# ---------------------------------------------------------------------------
_ORIGINALS: dict[str, str] = {
    "config.json": """\
{
  "server": "mcp-prod-01.internal",
  "version": "2.4.1",
  "database": {
    "host": "db.internal",
    "port": 5432,
    "name": "mcp_production",
    "user": "mcp_app",
    "password": "Xy9#mPqR!2vLzW8n"
  },
  "api_keys": {
    "stripe":    "sk_live_DEMO_FAKE_NOT_REAL_1234567",
    "sendgrid":  "SG.xK2mNpQvR8tLwY3j.aB5cD9eF1gH4iJ7kL0mN",
    "twilio":    "ACb3d5f7h9j1l3n5p7r9t1v3x5z7b9d1"
  },
  "jwt_secret": "ultra-secret-jwt-signing-key-never-expose",
  "debug": false,
  "allowed_origins": ["https://app.example.com", "https://admin.example.com"]
}
""",

    "secrets.env": """\
# Production credentials — DO NOT COMMIT
DATABASE_URL=postgresql://mcp_app:Xy9#mPqR!2vLzW8n@db.internal:5432/mcp_production
REDIS_URL=redis://:r3d!sPa$$w0rd@cache.internal:6379/0
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
S3_BUCKET=mcp-prod-assets-7f3a9b2c
ENCRYPTION_MASTER_KEY=aes256://4e6f726d616c6c79207468697320776f756c642062652072616e646f6d
SMTP_HOST=smtp.sendgrid.net
SMTP_USER=apikey
SMTP_PASSWORD=SG.xK2mNpQvR8tLwY3j.aB5cD9eF1gH4iJ7kL0mN
OAUTH_CLIENT_SECRET=oauth2_prod_XkJ9mNpR8tLwY3j5vB2cD7eF1g
WEBHOOK_SIGNING_SECRET=whsec_8f3a7b2c1d9e4f6g5h0i2j3k4l5m6n7o
""",

    "user_database.csv": """\
id,username,email,role,password_hash,api_token,balance_usd,last_login
1,alice.smith,alice@example.com,admin,$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4oK9Qe9zG6,tok_live_aAbBcCdD1234,84500.00,2026-03-26T14:22:01Z
2,bob.jones,bob@example.com,user,$2b$12$NhfG7kLpR2vQmY8xWz3JtO5s9uVwXa1bCd4eF6gH0iJ2kL4mN6oP8,tok_live_eEfFgGhH5678,3200.50,2026-03-27T09:11:45Z
3,carol.davis,carol@example.com,user,$2b$12$PjhI9mNoQ3wRnZ0yXa4KuP6t1vWxYb2cDe5fG7hI0jK2lM4nO6pQ8,tok_live_iIjJkKlL9012,1250.75,2026-03-25T18:33:12Z
4,dave.wilson,dave@example.com,auditor,$2b$12$RlkJ1nOpS4xTpA1zYb5LvQ7u2wXyZc3dEf6gH8iJ1kL3mN5oP7qR9,tok_live_mMnNoOpP3456,0.00,2026-03-20T07:55:30Z
5,eve.malory,eve@attacker.com,user,$2b$12$TmnL3pQrU5yVqB3aZc6MwR8v3xYzAd4eGf7hI9jK2lM5nO8pQ0rS1,tok_live_qQrRsStT7890,500.00,2026-03-27T23:58:01Z
""",

    "audit_log.txt": """\
2026-03-25 08:01:12 UTC | INFO  | user=alice.smith  | action=LOGIN          | ip=10.0.1.42  | status=SUCCESS
2026-03-25 08:03:45 UTC | INFO  | user=alice.smith  | action=READ_CONFIG    | ip=10.0.1.42  | status=SUCCESS
2026-03-25 11:22:07 UTC | WARN  | user=unknown      | action=LOGIN          | ip=185.220.101.34 | status=FAILED  | attempts=5
2026-03-25 11:22:09 UTC | ALERT | user=unknown      | action=LOGIN          | ip=185.220.101.34 | status=BLOCKED | reason=brute_force
2026-03-26 14:10:33 UTC | INFO  | user=bob.jones    | action=LOGIN          | ip=10.0.2.17  | status=SUCCESS
2026-03-26 14:11:01 UTC | WARN  | user=bob.jones    | action=READ_SECRETS   | ip=10.0.2.17  | status=DENIED  | reason=insufficient_role
2026-03-26 14:15:55 UTC | INFO  | user=alice.smith  | action=WRITE_CONFIG   | ip=10.0.1.42  | status=SUCCESS | change=updated_jwt_secret
2026-03-27 02:44:18 UTC | ALERT | user=eve.malory   | action=READ_USER_DB   | ip=198.51.100.7 | status=DENIED  | reason=suspicious_location
2026-03-27 09:00:00 UTC | INFO  | system            | action=BACKUP         | ip=10.0.0.1   | status=SUCCESS | size_mb=142
2026-03-27 23:58:01 UTC | WARN  | user=eve.malory   | action=LOGIN          | ip=198.51.100.7 | status=SUCCESS | note=off_hours_login
""",

    "encryption_keys.txt": """\
# Master key rotation schedule — HIGHLY CONFIDENTIAL
# Format: key_id | algorithm | key_material | created | expires | status

KEY-001 | AES-256-GCM | 4142434445464748494a4b4c4d4e4f50 | 2025-01-01 | 2026-01-01 | RETIRED
KEY-002 | AES-256-GCM | 5152535455565758595a5b5c5d5e5f60 | 2026-01-01 | 2027-01-01 | ACTIVE
KEY-003 | AES-256-GCM | 6162636465666768696a6b6c6d6e6f70 | 2027-01-01 | 2028-01-01 | PENDING

# Emergency break-glass key (requires 2-person authorisation)
BREAK-GLASS | RSA-4096 | (stored in HSM slot 7) | 2025-06-01 | never | SEALED
""",
}


# ---------------------------------------------------------------------------
# FileStore
# ---------------------------------------------------------------------------
class FileStore:
    """Mutable in-memory file store for demo purposes.

    Every server restart resets to the original content.
    """

    def __init__(self) -> None:
        self._files: dict[str, str] = deepcopy(_ORIGINALS)

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def list_files(self) -> list[dict]:
        return [
            {
                "name": name,
                "path": name,
                "type": "file",
                "size": len(content.encode()),
                "sha": self._sha(content),
            }
            for name, content in self._files.items()
        ]

    def read_file(self, name: str) -> tuple[str, str]:
        """Return (content, sha).  Raises KeyError if file not found."""
        if name not in self._files:
            raise KeyError(f"File not found: '{name}'")
        content = self._files[name]
        return content, self._sha(content)

    def file_exists(self, name: str) -> bool:
        return name in self._files

    def all_names(self) -> list[str]:
        return list(self._files.keys())

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def write_file(self, name: str, content: str) -> str:
        """Write or overwrite a file.  Returns the new SHA."""
        self._files[name] = content
        return self._sha(content)

    def delete_file(self, name: str) -> None:
        if name not in self._files:
            raise KeyError(f"File not found: '{name}'")
        del self._files[name]

    def reset(self) -> list[str]:
        """Restore all files to their original demo content."""
        self._files = deepcopy(_ORIGINALS)
        return list(self._files.keys())

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _sha(content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()[:40]
