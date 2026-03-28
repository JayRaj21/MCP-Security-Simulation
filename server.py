"""MCP Security Gateway — FastMCP server proxying the JSONPlaceholder API.

Architecture
============
  Backend      : JSONPlaceholder REST API (jsonplaceholder.typicode.com)
  Transport    : FastMCP (MCP protocol — streamable-http or stdio)
  Auth         : Zero-trust username/password → short-lived session token
  Confidentiality: AES-256-CBC — unauthenticated callers receive ciphertext
  Integrity    : HMAC-SHA256 — authenticated callers can verify response integrity
  Audit        : In-memory circular buffer, visible only to authenticated users

Gateway Pattern
===============
  Every resource tool call:
    1. Independently verifies the session token (zero-trust, no implicit trust)
    2. Fetches live data from the JSONPlaceholder backend API
    3. Authenticated   → returns plaintext JSON + HMAC-SHA256 signature
       Unauthenticated → returns AES-256-CBC encrypted blob
    4. Records the access attempt in the audit log

Available Resources (proxied from JSONPlaceholder)
===================================================
  users   — 10 users with contact details, addresses, and company info
  posts   — 100 blog posts (10 per user)
  todos   — 200 tasks (20 per user)

Quick-start
===========
  Default credentials (override via env vars ADMIN_PASSWORD / VIEWER_PASSWORD):
    admin   / admin123
    viewer  / view456

  1. Call authenticate to receive a session_token.
  2. Pass that token to any resource tool.
  3. Call get_audit_log(session_token, unauthorized_only=True) to see intrusions.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastmcp import FastMCP

from auth import AuthManager
from audit import AuditLogger
from crypto import CryptoManager
from backend import BackendAPI
from config import USERS, ENCRYPTION_KEY, SESSION_DURATION

# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------
_auth    = AuthManager(USERS, SESSION_DURATION)
_crypto  = CryptoManager(ENCRYPTION_KEY)
_backend = BackendAPI()
_audit   = AuditLogger()


# ---------------------------------------------------------------------------
# Gateway envelope helper
# ---------------------------------------------------------------------------
def _respond(resource: str, data, session, username) -> dict:
    """Wrap backend data in the auth-appropriate response envelope.

    Authenticated   → plaintext data + HMAC-SHA256 signature.
    Unauthenticated → AES-256-CBC encrypted JSON blob, uninterpretable.
    """
    json_str = json.dumps(data, ensure_ascii=False)
    signature = _crypto.sign(json_str)

    if session:
        return {
            "status": "success",
            "authenticated": True,
            "resource": resource,
            "data": data,
            "hmac_signature": signature,
        }

    return {
        "status": "success",
        "authenticated": False,
        "resource": resource,
        "data": _crypto.encrypt(json_str),
        "notice": (
            "Response is AES-256-CBC encrypted. "
            "Call authenticate() to receive plaintext data."
        ),
    }


# ---------------------------------------------------------------------------
# FastMCP gateway
# ---------------------------------------------------------------------------
mcp = FastMCP(
    name="MCP Security Gateway",
    instructions="""
Zero-trust MCP gateway that proxies the JSONPlaceholder REST API.

Every request is independently authenticated. Unauthenticated callers receive
AES-256-CBC ciphertext. Authenticated callers receive plaintext + HMAC signatures.
All access attempts are recorded in the audit log.

WORKFLOW
--------
1. Call list_users() without a token        → see encrypted user list
2. Call get_user(1) without a token         → see encrypted user data
3. Call authenticate("admin", "admin123")   → get session_token
4. Call list_users(session_token=...)       → see real user data
5. Call get_user(3, session_token=...)      → see full user profile
6. Call list_posts(user_id=3, ...)          → see that user's posts
7. Call verify_integrity to confirm a response hasn't changed
8. Call get_audit_log(session_token, unauthorized_only=True) → see intrusions

AVAILABLE TOOLS
---------------
  authenticate      — get a session token
  logout            — invalidate your session
  list_users        — list all users from the backend API
  get_user          — fetch a single user by ID (1-10)
  list_posts        — list posts, optionally filtered by user ID
  get_post          — fetch a single post by ID (1-100)
  list_todos        — list todos, optionally filtered by user ID
  get_todo          — fetch a single todo by ID (1-200)
  verify_integrity  — re-fetch a resource and verify its HMAC signature
  get_audit_log     — view the access log (authentication required)
""",
)


# ---------------------------------------------------------------------------
# Tool: authenticate
# ---------------------------------------------------------------------------
@mcp.tool()
def authenticate(username: str, password: str) -> dict:
    """Authenticate with username and password to receive a session token.

    The session token must be passed to every subsequent tool call.
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
            "message": "Authentication successful.",
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
        return {"status": "success", "message": "Session invalidated."}
    return {"status": "error", "message": "Token not found or already expired."}


# ---------------------------------------------------------------------------
# Tool: list_users
# ---------------------------------------------------------------------------
@mcp.tool()
def list_users(session_token: str = "") -> dict:
    """List all users from the backend API.

    Authenticated   — full plaintext user records (name, email, address, company)
                      plus HMAC-SHA256 signature of the response.
    Unauthenticated — AES-256-CBC encrypted user list (uninterpretable).

    All calls are recorded in the audit log.
    """
    session = _auth.verify_session(session_token) if session_token else None
    username = session["username"] if session else None

    try:
        data = _backend.list_users()
    except Exception as e:
        _audit.record(username, session is not None, "list_users", "/users", f"backend error: {e}")
        return {"status": "error", "message": f"Backend API error: {e}"}

    _audit.record(username, session is not None, "list_users", "/users", "success")
    return _respond("/users", data, session, username)


# ---------------------------------------------------------------------------
# Tool: get_user
# ---------------------------------------------------------------------------
@mcp.tool()
def get_user(user_id: int, session_token: str = "") -> dict:
    """Fetch a single user by ID (1-10) from the backend API.

    Authenticated   — full user profile (name, email, phone, address, company)
                      plus HMAC-SHA256 signature.
    Unauthenticated — AES-256-CBC encrypted user data.
    """
    session = _auth.verify_session(session_token) if session_token else None
    username = session["username"] if session else None
    resource = f"/users/{user_id}"

    try:
        data = _backend.get_user(user_id)
    except Exception as e:
        _audit.record(username, session is not None, "get_user", resource, f"error: {e}")
        return {"status": "error", "message": f"Backend API error: {e}"}

    _audit.record(username, session is not None, "get_user", resource, "success")
    return _respond(resource, data, session, username)


# ---------------------------------------------------------------------------
# Tool: list_posts
# ---------------------------------------------------------------------------
@mcp.tool()
def list_posts(user_id: int = 0, session_token: str = "") -> dict:
    """List posts from the backend API, optionally filtered by user.

    user_id=0 (default) returns all 100 posts.
    user_id=1..10 returns the 10 posts belonging to that user.

    Authenticated   — full plaintext post list + HMAC signature.
    Unauthenticated — AES-256-CBC encrypted response.
    """
    session = _auth.verify_session(session_token) if session_token else None
    username = session["username"] if session else None
    resource = f"/posts?userId={user_id}" if user_id else "/posts"

    try:
        data = _backend.list_posts(user_id or None)
    except Exception as e:
        _audit.record(username, session is not None, "list_posts", resource, f"error: {e}")
        return {"status": "error", "message": f"Backend API error: {e}"}

    _audit.record(username, session is not None, "list_posts", resource, "success")
    return _respond(resource, data, session, username)


# ---------------------------------------------------------------------------
# Tool: get_post
# ---------------------------------------------------------------------------
@mcp.tool()
def get_post(post_id: int, session_token: str = "") -> dict:
    """Fetch a single post by ID (1-100) from the backend API.

    Authenticated   — full post content (title, body) + HMAC signature.
    Unauthenticated — AES-256-CBC encrypted post data.
    """
    session = _auth.verify_session(session_token) if session_token else None
    username = session["username"] if session else None
    resource = f"/posts/{post_id}"

    try:
        data = _backend.get_post(post_id)
    except Exception as e:
        _audit.record(username, session is not None, "get_post", resource, f"error: {e}")
        return {"status": "error", "message": f"Backend API error: {e}"}

    _audit.record(username, session is not None, "get_post", resource, "success")
    return _respond(resource, data, session, username)


# ---------------------------------------------------------------------------
# Tool: list_todos
# ---------------------------------------------------------------------------
@mcp.tool()
def list_todos(user_id: int = 0, session_token: str = "") -> dict:
    """List todos from the backend API, optionally filtered by user.

    user_id=0 (default) returns all 200 todos.
    user_id=1..10 returns the 20 todos belonging to that user.

    Authenticated   — full plaintext todo list + HMAC signature.
    Unauthenticated — AES-256-CBC encrypted response.
    """
    session = _auth.verify_session(session_token) if session_token else None
    username = session["username"] if session else None
    resource = f"/todos?userId={user_id}" if user_id else "/todos"

    try:
        data = _backend.list_todos(user_id or None)
    except Exception as e:
        _audit.record(username, session is not None, "list_todos", resource, f"error: {e}")
        return {"status": "error", "message": f"Backend API error: {e}"}

    _audit.record(username, session is not None, "list_todos", resource, "success")
    return _respond(resource, data, session, username)


# ---------------------------------------------------------------------------
# Tool: get_todo
# ---------------------------------------------------------------------------
@mcp.tool()
def get_todo(todo_id: int, session_token: str = "") -> dict:
    """Fetch a single todo by ID (1-200) from the backend API.

    Authenticated   — todo content + completion status + HMAC signature.
    Unauthenticated — AES-256-CBC encrypted todo data.
    """
    session = _auth.verify_session(session_token) if session_token else None
    username = session["username"] if session else None
    resource = f"/todos/{todo_id}"

    try:
        data = _backend.get_todo(todo_id)
    except Exception as e:
        _audit.record(username, session is not None, "get_todo", resource, f"error: {e}")
        return {"status": "error", "message": f"Backend API error: {e}"}

    _audit.record(username, session is not None, "get_todo", resource, "success")
    return _respond(resource, data, session, username)


# ---------------------------------------------------------------------------
# Tool: verify_integrity
# ---------------------------------------------------------------------------
@mcp.tool()
def verify_integrity(resource_type: str, resource_id: int, expected_hmac: str, session_token: str) -> dict:
    """Re-fetch a resource from the backend and verify it matches a saved HMAC.

    The gateway re-fetches the resource live from the backend API, recomputes
    its HMAC-SHA256, and compares against expected_hmac using constant-time
    comparison (prevents timing attacks).

    Use this to detect:
      - Upstream API returning inconsistent/changed data
      - Man-in-the-middle modification of API responses
      - Local signature corruption (tamper simulation)

    resource_type: "user", "post", or "todo"
    resource_id:   numeric ID of the resource to re-fetch and verify

    Requires authentication.
    """
    session = _auth.verify_session(session_token)
    if not session:
        resource = f"/{resource_type}s/{resource_id}"
        _audit.record(None, False, "verify_integrity", resource, "denied — not authenticated")
        return {"status": "error", "message": "Authentication required to verify integrity."}

    resource = f"/{resource_type}s/{resource_id}"
    try:
        if resource_type == "user":
            data = _backend.get_user(resource_id)
        elif resource_type == "post":
            data = _backend.get_post(resource_id)
        elif resource_type == "todo":
            data = _backend.get_todo(resource_id)
        else:
            return {
                "status": "error",
                "message": f"Unknown resource_type '{resource_type}'. Use 'user', 'post', or 'todo'.",
            }
    except Exception as e:
        return {"status": "error", "message": f"Backend API error: {e}"}

    json_str = json.dumps(data, ensure_ascii=False)
    intact = _crypto.verify(json_str, expected_hmac)
    outcome = "intact" if intact else "TAMPERED"
    _audit.record(session["username"], True, "verify_integrity", resource, outcome)

    return {
        "status": "success",
        "resource": resource,
        "intact": intact,
        "verdict": (
            f"{resource} is intact — response matches the saved HMAC signature."
            if intact else
            f"WARNING: {resource} does NOT match the saved signature. "
            "The backend response has changed or the signature was corrupted."
        ),
    }


# ---------------------------------------------------------------------------
# Tool: get_audit_log
# ---------------------------------------------------------------------------
@mcp.tool()
def get_audit_log(session_token: str, unauthorized_only: bool = False) -> dict:
    """Retrieve the gateway's audit log.

    Only authenticated users can view the audit log (zero-trust: the log
    itself is a protected resource).

    Set unauthorized_only=True to filter for unauthenticated access attempts
    — see exactly who tried to read data without credentials.
    """
    session = _auth.verify_session(session_token)
    if not session:
        _audit.record(None, False, "read_audit_log", "audit_log", "denied — not authenticated")
        return {"status": "error", "message": "Authentication required to view the audit log."}

    raw = _audit.get_unauthorized() if unauthorized_only else _audit.get_all()
    formatted = [_audit.format_entry(e) for e in raw]

    _audit.record(
        session["username"], True, "read_audit_log", "audit_log",
        f"success ({len(formatted)} entries)",
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

    parser = argparse.ArgumentParser(description="MCP Security Gateway")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="streamable-http")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    if args.transport == "streamable-http":
        print(f"[gateway] FastMCP server  →  http://{args.host}:{args.port}/mcp")
        print("[gateway] Backend API     →  https://jsonplaceholder.typicode.com")
        print("[gateway] Credentials     →  admin/admin123   viewer/view456")
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")
