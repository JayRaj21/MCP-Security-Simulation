"""MCP Security Simulation v2 — FastMCP Server.

Architecture
============
  Data layer   : In-memory FileStore with pre-populated sensitive demo files
  Transport    : FastMCP (MCP protocol — streamable-http or stdio)
  Auth         : Zero-trust username/password → short-lived session token
  Confidentiality: AES-256-CBC — unauthenticated callers receive ciphertext
  Integrity    : HMAC-SHA256 — authenticated callers can detect file tampering
  Audit        : In-memory log, visible only to authenticated users

Demo files
==========
  config.json          Server config with DB credentials and API keys
  secrets.env          Production environment secrets and cloud keys
  user_database.csv    User records with hashed passwords and API tokens
  audit_log.txt        Access and security event log
  encryption_keys.txt  Key rotation schedule (highest sensitivity)

Zero-trust policy
=================
  * Every tool call is independently authenticated — no implicit trust, ever.
  * Any call without a valid session token is treated as anonymous.
  * Anonymous callers receive only AES-256 ciphertext — never plaintext.
  * All access attempts (authenticated or not) are written to the audit log.
  * Authenticated users can query the audit log to see unauthorized attempts.

Quick-start
===========
  Default credentials (override via env vars ADMIN_PASSWORD / VIEWER_PASSWORD):
    admin   / admin123
    viewer  / view456

  1. Call authenticate to receive a session_token.
  2. Pass that token to any other tool.
  3. Call get_audit_log(unauthorized_only=True) to see intrusion attempts.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastmcp import FastMCP

from auth import AuthManager
from audit import AuditLogger
from crypto import CryptoManager
from filestore import FileStore
from config import (
    USERS,
    ENCRYPTION_KEY,
    SESSION_DURATION,
)

# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------
_auth    = AuthManager(USERS, SESSION_DURATION)
_crypto  = CryptoManager(ENCRYPTION_KEY)
_store   = FileStore()
_audit   = AuditLogger()

# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    name="Secure File Server v2",
    instructions="""
Zero-trust MCP server with pre-populated sensitive demo files.

Demo files available:
  config.json          — server config with DB credentials and API keys
  secrets.env          — production environment secrets
  user_database.csv    — user records with password hashes and tokens
  audit_log.txt        — access and security event log
  encryption_keys.txt  — encryption key rotation schedule

WORKFLOW
--------
1. Call list_files() without a token  →  see AES-256 encrypted filenames
2. Call read_file("secrets.env")      →  see AES-256 encrypted content
3. Call authenticate("admin","admin123") to get a session_token
4. Call list_files(session_token=...) →  see real filenames
5. Call read_file("secrets.env", session_token=...) →  see plaintext
6. Call sign("secrets.env", session_token=...) to capture HMAC signature
7. Call write_file to modify a file, then verify_integrity to detect the change
8. Call get_audit_log(session_token, unauthorized_only=True) to see intrusions

AVAILABLE TOOLS
---------------
  authenticate         — get a session token
  logout               — invalidate your session
  list_files           — list demo files
  read_file            — read a file (plaintext when authenticated)
  write_file           — overwrite a file (requires authentication)
  delete_file          — delete a file (requires authentication)
  reset_files          — restore all files to original content (requires auth)
  verify_integrity     — confirm a file hasn't been tampered with
  get_audit_log        — view access log (auth required)
""",
)


# ---------------------------------------------------------------------------
# Tool: authenticate
# ---------------------------------------------------------------------------
@mcp.tool()
def authenticate(username: str, password: str) -> dict:
    """Authenticate with username and password to receive a session token.

    The session token must be passed to every other tool call.
    Sessions expire automatically after 1 hour.

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
            "message": "Authentication successful. Pass session_token to every subsequent call.",
        }
    _audit.record(username, False, "authenticate", "session", "invalid credentials")
    return {"status": "error", "message": "Invalid username or password."}


# ---------------------------------------------------------------------------
# Tool: logout
# ---------------------------------------------------------------------------
@mcp.tool()
def logout(session_token: str) -> dict:
    """Invalidate the current session token immediately.

    After calling this the token is permanently revoked and a new session
    must be obtained via authenticate.
    """
    session = _auth.verify_session(session_token)
    username = session["username"] if session else None
    if _auth.invalidate_session(session_token) and username:
        _audit.record(username, True, "logout", "session", "success")
        return {"status": "success", "message": "Session invalidated. You are now logged out."}
    return {"status": "error", "message": "Token not found or already expired."}


# ---------------------------------------------------------------------------
# Tool: list_files
# ---------------------------------------------------------------------------
@mcp.tool()
def list_files(session_token: str = "") -> dict:
    """List the demo files on the server.

    Authenticated — real filenames, sizes, and SHA-256 hashes.
    Unauthenticated — AES-256-CBC encrypted names (computationally uninterpretable).

    All calls are recorded in the audit log.
    """
    session = _auth.verify_session(session_token) if session_token else None
    username = session["username"] if session else None
    authenticated = session is not None

    files = _store.list_files()
    _audit.record(username, authenticated, "list_files", "/", "success")

    if authenticated:
        return {
            "status": "success",
            "authenticated": True,
            "file_count": len(files),
            "files": files,
        }

    obfuscated = [
        {
            "name": _crypto.encrypt(f["name"]),
            "path": _crypto.encrypt(f["path"]),
            "type": "encrypted",
            "size": "???",
            "sha": "???",
        }
        for f in files
    ]
    return {
        "status": "success",
        "authenticated": False,
        "file_count": len(obfuscated),
        "files": obfuscated,
        "notice": (
            "All metadata is AES-256 encrypted. "
            "Call authenticate() to view real file names."
        ),
    }


# ---------------------------------------------------------------------------
# Tool: read_file
# ---------------------------------------------------------------------------
@mcp.tool()
def read_file(filename: str, session_token: str = "") -> dict:
    """Read the content of a demo file.

    Authenticated — plaintext content + HMAC-SHA256 signature.
      Save the hmac_signature and call verify_integrity later to check
      whether the file has been modified since you read it.

    Unauthenticated — AES-256-CBC encrypted content (uninterpretable).

    All access attempts are recorded in the audit log.

    Available files:
      config.json, secrets.env, user_database.csv,
      audit_log.txt, encryption_keys.txt
    """
    session = _auth.verify_session(session_token) if session_token else None
    username = session["username"] if session else None
    authenticated = session is not None

    try:
        content, sha = _store.read_file(filename)
    except KeyError:
        _audit.record(username, authenticated, "read_file", filename, "not found")
        available = ", ".join(_store.all_names())
        return {"status": "error", "message": f"File not found: '{filename}'. Available: {available}"}

    signature = _crypto.sign(content)
    _audit.record(username, authenticated, "read_file", filename, "success")

    if authenticated:
        return {
            "status": "success",
            "authenticated": True,
            "filename": filename,
            "content": content,
            "sha256": sha,
            "hmac_signature": signature,
            "tip": f"Run verify_integrity('{filename}', '{signature[:16]}…') later to detect changes.",
        }

    return {
        "status": "success",
        "authenticated": False,
        "filename": _crypto.encrypt(filename),
        "content": _crypto.encrypt(content),
        "notice": (
            "Content is AES-256-CBC encrypted and uninterpretable without the server key. "
            "Call authenticate() to read the plaintext."
        ),
    }


# ---------------------------------------------------------------------------
# Tool: write_file
# ---------------------------------------------------------------------------
@mcp.tool()
def write_file(filename: str, content: str, session_token: str) -> dict:
    """Overwrite a file's content. Requires authentication.

    After writing, any previously captured HMAC signature for this file will
    no longer match — call verify_integrity to observe the change.

    Unauthenticated write attempts are blocked and logged.
    """
    session = _auth.verify_session(session_token)
    if not session:
        _audit.record(None, False, "write_file", filename, "denied — not authenticated")
        return {"status": "error", "message": "Authentication required to write files."}

    new_sha = _store.write_file(filename, content)
    new_sig = _crypto.sign(content)
    _audit.record(session["username"], True, "write_file", filename, "success")
    return {
        "status": "success",
        "filename": filename,
        "sha256": new_sha,
        "hmac_signature": new_sig,
        "message": f"File '{filename}' written. Any old HMAC signature is now invalid.",
    }


# ---------------------------------------------------------------------------
# Tool: delete_file
# ---------------------------------------------------------------------------
@mcp.tool()
def delete_file(filename: str, session_token: str) -> dict:
    """Delete a demo file. Requires authentication.

    Use reset_files to restore all files to their original content.
    Unauthenticated delete attempts are blocked and logged.
    """
    session = _auth.verify_session(session_token)
    if not session:
        _audit.record(None, False, "delete_file", filename, "denied — not authenticated")
        return {"status": "error", "message": "Authentication required to delete files."}

    try:
        _store.delete_file(filename)
    except KeyError:
        return {"status": "error", "message": f"File not found: '{filename}'"}

    _audit.record(session["username"], True, "delete_file", filename, "success")
    return {"status": "success", "message": f"File '{filename}' deleted. Run reset_files to restore it."}


# ---------------------------------------------------------------------------
# Tool: reset_files
# ---------------------------------------------------------------------------
@mcp.tool()
def reset_files(session_token: str) -> dict:
    """Restore all demo files to their original content. Requires authentication.

    Use this after modifying or deleting files to get back to a clean state.
    """
    session = _auth.verify_session(session_token)
    if not session:
        _audit.record(None, False, "reset_files", "/", "denied — not authenticated")
        return {"status": "error", "message": "Authentication required to reset files."}

    restored = _store.reset()
    _audit.record(session["username"], True, "reset_files", "/", f"restored {len(restored)} files")
    return {
        "status": "success",
        "message": "All files restored to original demo content.",
        "files_restored": restored,
    }


# ---------------------------------------------------------------------------
# Tool: verify_integrity
# ---------------------------------------------------------------------------
@mcp.tool()
def verify_integrity(filename: str, expected_hmac: str, session_token: str) -> dict:
    """Verify that a file's current content matches a previously captured HMAC signature.

    Re-reads the file, recomputes the HMAC-SHA256, and compares using a
    constant-time comparison to prevent timing attacks.

    Useful for detecting whether write_file (or any other change) has modified
    a file since the signature was captured with read_file.

    Requires authentication — attempts without a token are blocked and logged.
    """
    session = _auth.verify_session(session_token)
    if not session:
        _audit.record(None, False, "verify_integrity", filename, "denied — not authenticated")
        return {"status": "error", "message": "Authentication required to verify file integrity."}

    try:
        content, sha = _store.read_file(filename)
    except KeyError:
        return {"status": "error", "message": f"File not found: '{filename}'"}

    intact = _crypto.verify(content, expected_hmac)
    outcome = "intact" if intact else "TAMPERED"
    _audit.record(session["username"], True, "verify_integrity", filename, outcome)
    return {
        "status": "success",
        "filename": filename,
        "sha256": sha,
        "intact": intact,
        "verdict": (
            "File is intact — content matches the HMAC signature."
            if intact else
            "WARNING: Content does NOT match the signature. "
            "The file has been modified since the signature was captured."
        ),
    }


# ---------------------------------------------------------------------------
# Tool: get_audit_log
# ---------------------------------------------------------------------------
@mcp.tool()
def get_audit_log(session_token: str, unauthorized_only: bool = False) -> dict:
    """Retrieve the server's audit log.

    Only authenticated users can view the audit log (zero-trust: the log
    itself is a protected resource).

    Set unauthorized_only=True to filter for non-authenticated access attempts,
    so you can see exactly who tried to read files without credentials.

    The log captures: timestamp, username, auth status, action, resource, outcome.
    """
    session = _auth.verify_session(session_token)
    if not session:
        _audit.record(None, False, "read_audit_log", "audit_log", "denied — not authenticated")
        return {"status": "error", "message": "Authentication required to view the audit log."}

    raw = _audit.get_unauthorized() if unauthorized_only else _audit.get_all()
    formatted = [_audit.format_entry(e) for e in raw]

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
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    if args.transport == "streamable-http":
        print(f"[v2] FastMCP server on http://{args.host}:{args.port}/mcp")
        print("[v2] Demo files: config.json  secrets.env  user_database.csv  audit_log.txt  encryption_keys.txt")
        print("[v2] Credentials: admin/admin123  or  viewer/view456")
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")
