"""MCP Security Simulation v2 — FastMCP Server.

Architecture
============
  Data layer   : GitHub REST API  (open-source, read-only, publicly auditable)
  Transport    : FastMCP (MCP protocol over stdio or HTTP)
  Auth         : Zero-trust username/password → short-lived session token
  Confidentiality: AES-256-CBC — unauthenticated callers receive ciphertext only
  Integrity    : HMAC-SHA256 — authenticated callers can detect file tampering
  Audit        : In-memory log, visible only to authenticated users

Zero-trust policy
=================
  * Every tool call is independently authenticated — no implicit trust, ever.
  * Any tool invoked without a valid session token is treated as anonymous.
  * Anonymous callers never receive plaintext content or metadata.
  * All access attempts (authenticated or not) are written to the audit log.
  * Authenticated users can query the audit log to see unauthorized attempts.

Quick-start
===========
  Default credentials (change via env vars):
    admin   / admin123
    viewer  / view456

  1. Call ``authenticate`` to receive a session_token.
  2. Pass that token to any other tool.
  3. Call ``get_audit_log(unauthorized_only=True)`` to see intrusion attempts.

  Set GITHUB_REPO, GITHUB_BRANCH, GITHUB_TOKEN, MCP_ENCRYPTION_KEY,
  ADMIN_PASSWORD, VIEWER_PASSWORD to override defaults.
"""
import sys
import os

# Allow running as ``python v2/server.py`` from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastmcp import FastMCP

from v2.auth import AuthManager
from v2.audit import AuditLogger
from v2.api_client import GitHubAPIClient
from v2.crypto import CryptoManager
from v2.config import (
    USERS,
    GITHUB_REPO,
    GITHUB_BRANCH,
    GITHUB_TOKEN,
    ENCRYPTION_KEY,
    SESSION_DURATION,
)

# ---------------------------------------------------------------------------
# Singletons — one instance per server process
# ---------------------------------------------------------------------------
_auth   = AuthManager(USERS, SESSION_DURATION)
_crypto = CryptoManager(ENCRYPTION_KEY)
_github = GitHubAPIClient(GITHUB_REPO, GITHUB_BRANCH, GITHUB_TOKEN)
_audit  = AuditLogger()

# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    name="Secure File API Server v2",
    instructions="""
Zero-trust MCP server backed by the GitHub REST API.

WORKFLOW
--------
1. Call authenticate(username, password) to get a session_token.
2. Pass session_token to every subsequent tool call.
3. Without a token, all file content and metadata is AES-256 encrypted
   and completely uninterpretable.
4. Call get_audit_log(session_token, unauthorized_only=True) to see
   all intrusion attempts made without valid credentials.

AVAILABLE TOOLS
---------------
  authenticate         — get a session token
  logout               — invalidate your session
  list_files           — browse repository contents
  read_file            — read a file (plaintext when authenticated)
  verify_integrity     — confirm a file hasn't been tampered with
  get_audit_log        — view access log (auth required)
  repository_info      — metadata about the data source
""",
)


# ---------------------------------------------------------------------------
# Tool: authenticate
# ---------------------------------------------------------------------------
@mcp.tool()
def authenticate(username: str, password: str) -> dict:
    """Obtain a session token by providing valid credentials.

    The session token must be passed to every other tool call.
    Sessions expire automatically after 1 hour (configurable via
    SESSION_DURATION_SECONDS environment variable).

    Default credentials:
        admin  / admin123
        viewer / view456
    """
    token = _auth.authenticate(username, password)
    if token:
        _audit.record(username, True, "authenticate", "session", "success")
        return {
            "status": "success",
            "session_token": token,
            "expires_in_seconds": SESSION_DURATION,
            "message": "Authentication successful. Include session_token in every subsequent call.",
        }
    _audit.record(username, False, "authenticate", "session", "invalid credentials")
    return {
        "status": "error",
        "message": "Invalid username or password.",
    }


# ---------------------------------------------------------------------------
# Tool: logout
# ---------------------------------------------------------------------------
@mcp.tool()
def logout(session_token: str) -> dict:
    """Invalidate the current session token immediately.

    After calling this, the token is permanently revoked and a new session
    must be obtained via authenticate.
    """
    session = _auth.verify_session(session_token)
    username = session["username"] if session else None
    revoked = _auth.invalidate_session(session_token)
    if revoked and username:
        _audit.record(username, True, "logout", "session", "success")
        return {"status": "success", "message": "Session invalidated. You are now logged out."}
    return {"status": "error", "message": "Token not found or already expired."}


# ---------------------------------------------------------------------------
# Tool: repository_info
# ---------------------------------------------------------------------------
@mcp.tool()
def repository_info() -> dict:
    """Return metadata about the GitHub repository used as the data source.

    This is the only tool that does not require authentication, as it reveals
    no file content.  Access is still logged.
    """
    _audit.record(None, False, "repository_info", "repo_metadata", "public")
    try:
        info = _github.repo_info()
        return {"status": "success", "repository": info}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Tool: list_files
# ---------------------------------------------------------------------------
@mcp.tool()
def list_files(path: str = "", session_token: str = "") -> dict:
    """List files and directories in the GitHub repository.

    Authenticated callers receive real names, paths, sizes, and Git SHAs.

    Unauthenticated callers receive AES-256-CBC encrypted names and paths.
    The ciphertext is computationally uninterpretable without the server key,
    so directory structure cannot be inferred.

    All calls (authenticated or not) are recorded in the audit log.
    """
    session = _auth.verify_session(session_token) if session_token else None
    username = session["username"] if session else None
    authenticated = session is not None

    try:
        items = _github.list_contents(path)
        _audit.record(username, authenticated, "list_files", path or "/", "success")

        if authenticated:
            return {
                "status": "success",
                "authenticated": True,
                "path": path or "/",
                "item_count": len(items),
                "items": items,
            }

        # Unauthenticated — encrypt all identifying information
        obfuscated = [
            {
                "name": _crypto.encrypt(i["name"]),
                "path": _crypto.encrypt(i["path"]),
                "type": "encrypted",
                "size": "???",
                "sha": "???",
            }
            for i in items
        ]
        return {
            "status": "success",
            "authenticated": False,
            "item_count": len(obfuscated),
            "items": obfuscated,
            "notice": (
                "All metadata is AES-256 encrypted. "
                "Call authenticate() to view real file information."
            ),
        }

    except Exception as exc:
        _audit.record(username, authenticated, "list_files", path or "/", f"error: {exc}")
        return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Tool: read_file
# ---------------------------------------------------------------------------
@mcp.tool()
def read_file(file_path: str, session_token: str = "") -> dict:
    """Read the content of a file from the GitHub repository.

    Authenticated callers receive:
      - plaintext content
      - Git blob SHA (from GitHub)
      - HMAC-SHA256 signature of the content

    Save the hmac_signature value and later call verify_integrity() to detect
    any tampering with the file since it was first read.

    Unauthenticated callers receive:
      - AES-256-CBC encrypted file path (uninterpretable)
      - AES-256-CBC encrypted content (uninterpretable)

    All access attempts are recorded in the audit log.
    """
    session = _auth.verify_session(session_token) if session_token else None
    username = session["username"] if session else None
    authenticated = session is not None

    try:
        content, sha = _github.read_file(file_path)
        signature = _crypto.sign(content)

        _audit.record(username, authenticated, "read_file", file_path, "success")

        if authenticated:
            return {
                "status": "success",
                "authenticated": True,
                "file_path": file_path,
                "content": content,
                "git_sha": sha,
                "hmac_signature": signature,
                "integrity_tip": (
                    "Store hmac_signature and call verify_integrity(file_path, hmac_signature) "
                    "at any later time to confirm the content has not changed."
                ),
            }

        # Unauthenticated — return ciphertext only
        return {
            "status": "success",
            "authenticated": False,
            "file_path": _crypto.encrypt(file_path),
            "content": _crypto.encrypt(content),
            "notice": (
                "Content is AES-256-CBC encrypted and uninterpretable without the server key. "
                "Call authenticate() to read the plaintext."
            ),
        }

    except Exception as exc:
        _audit.record(username, authenticated, "read_file", file_path, f"error: {exc}")
        return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Tool: verify_integrity
# ---------------------------------------------------------------------------
@mcp.tool()
def verify_integrity(file_path: str, expected_hmac: str, session_token: str) -> dict:
    """Verify that a file's current content matches a previously captured HMAC signature.

    Re-fetches the file from GitHub, recomputes the HMAC-SHA256, and compares
    it with expected_hmac using a constant-time comparison to prevent timing attacks.

    Returns whether the file is intact or has been altered.
    Authentication is required — unauthenticated access attempts are logged.
    """
    session = _auth.verify_session(session_token)
    if not session:
        _audit.record(None, False, "verify_integrity", file_path, "denied — not authenticated")
        return {"status": "error", "message": "Authentication required to verify file integrity."}

    try:
        content, sha = _github.read_file(file_path)
        intact = _crypto.verify(content, expected_hmac)
        outcome = "intact" if intact else "TAMPERED"
        _audit.record(session["username"], True, "verify_integrity", file_path, outcome)
        return {
            "status": "success",
            "file_path": file_path,
            "git_sha": sha,
            "intact": intact,
            "verdict": (
                "File is intact — content matches the HMAC signature."
                if intact else
                "WARNING: Content does NOT match the signature. "
                "The file may have been tampered with since the signature was captured."
            ),
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Tool: get_audit_log
# ---------------------------------------------------------------------------
@mcp.tool()
def get_audit_log(session_token: str, unauthorized_only: bool = False) -> dict:
    """Retrieve the server's audit log.

    Only authenticated users can view the audit log (zero-trust: the log
    itself is a protected resource).

    Set unauthorized_only=True to filter for non-authenticated access attempts
    only — this lets you quickly see if anyone tried to access files without
    credentials (potential intrusion detection).

    The audit log captures: timestamp, username, auth status, action,
    resource accessed, and outcome.
    """
    session = _auth.verify_session(session_token)
    if not session:
        _audit.record(
            None, False, "read_audit_log", "audit_log",
            "denied — not authenticated"
        )
        return {"status": "error", "message": "Authentication required to view the audit log."}

    raw_entries = _audit.get_unauthorized() if unauthorized_only else _audit.get_all()
    formatted = [_audit.format_entry(e) for e in raw_entries]

    # Log the audit log access itself
    _audit.record(
        session["username"], True, "read_audit_log", "audit_log",
        f"success ({len(formatted)} entries)"
    )

    return {
        "status": "success",
        "requested_by": session["username"],
        "filter": "unauthorized_only" if unauthorized_only else "all",
        "total_entries": len(formatted),
        "log": formatted,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MCP Security Simulation v2")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="streamable-http",
        help="MCP transport (default: streamable-http for demo)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default: 8000)")
    args = parser.parse_args()

    if args.transport == "streamable-http":
        print(f"[v2] FastMCP server starting on http://{args.host}:{args.port}/mcp")
        print("[v2] Default credentials:  admin / admin123   or   viewer / view456")
        print("[v2] Override via env vars: ADMIN_PASSWORD, VIEWER_PASSWORD, GITHUB_REPO")
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")
