"""MCP Security Gateway — Web Application.

FastAPI server providing a browser-based zero-trust file management UI.
Uses the same security model as the MCP gateway:
  - AES-256-CBC encryption for unauthenticated callers
  - HMAC-SHA256 integrity checking on file content
  - Circular audit log of every access attempt
  - Short-lived session tokens, server-side only (no JWT)

Quick-start
===========
    make webapp            # http://127.0.0.1:8080
    Credentials:  admin / admin123   |   viewer / view456
"""
from __future__ import annotations

import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

sys.path.insert(0, str(Path(__file__).parent))

from auth import AuthManager
from audit import AuditLogger
from crypto import CryptoManager
from filestore import FileStore
from config import USERS, ENCRYPTION_KEY, SESSION_DURATION

# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------
_auth      = AuthManager(USERS, SESSION_DURATION)
_crypto    = CryptoManager(ENCRYPTION_KEY)
_filestore = FileStore()
_audit     = AuditLogger()

# ---------------------------------------------------------------------------
# App / static files
# ---------------------------------------------------------------------------
app   = FastAPI(title="MCP Security Gateway")
_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


def _session(request: Request):
    """Verify the X-Session-Token header; return session dict or None."""
    token = request.headers.get("x-session-token", "")
    return _auth.verify_session(token) if token else None


def _token(request: Request) -> str:
    return request.headers.get("x-session-token", "")


# ---------------------------------------------------------------------------
# SPA
# ---------------------------------------------------------------------------
@app.get("/")
async def index():
    return FileResponse(str(_STATIC / "index.html"))


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
class LoginBody(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
async def api_login(body: LoginBody):
    token = _auth.authenticate(body.username, body.password)
    if token:
        sess = _auth.verify_session(token)
        _audit.record(body.username, True, "authenticate", "session", "success")
        return {
            "status": "success",
            "session_token": token,
            "username": body.username,
            "role": sess["role"],
            "expires_in": SESSION_DURATION,
        }
    _audit.record(body.username, False, "authenticate", "session", "invalid credentials")
    return JSONResponse(
        {"status": "error", "message": "Invalid username or password."},
        status_code=401,
    )


@app.post("/api/auth/logout")
async def api_logout(request: Request):
    token = _token(request)
    sess = _session(request)
    username = sess["username"] if sess else None
    if _auth.invalidate_session(token) and username:
        _audit.record(username, True, "logout", "session", "success")
        return {"status": "success"}
    return JSONResponse({"status": "error", "message": "Session not found."}, status_code=400)


# ---------------------------------------------------------------------------
# Files — NOTE: more-specific routes (/{name}/integrity, /{name}/repair)
#         must be declared BEFORE the generic /{name} routes so FastAPI's
#         router resolves them correctly.
# ---------------------------------------------------------------------------
@app.get("/api/files")
async def api_list_files(request: Request):
    sess = _session(request)
    username = sess["username"] if sess else None
    files = _filestore.list_files()
    _audit.record(username, sess is not None, "list_files", "filestore",
                  f"success ({len(files)} files)")
    if not sess:
        return {
            "authenticated": False,
            "count": len(files),
            "files": [
                {"name": f"file-{i + 1}", "masked": True, "size_bytes": f["size_bytes"]}
                for i, f in enumerate(files)
            ],
        }
    return {"authenticated": True, "count": len(files), "files": files}


@app.get("/api/files/{name}/integrity")
async def api_check_integrity(name: str, request: Request):
    sess = _session(request)
    if not sess:
        _audit.record(None, False, "check_integrity", f"filestore/{name}",
                      "denied — not authenticated")
        return JSONResponse({"status": "error", "message": "Authentication required."}, status_code=401)
    try:
        result = _filestore.check_integrity(name)
    except KeyError as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=404)
    verdict = ("intact" if result["intact"] is True
               else "TAMPERED" if result["intact"] is False
               else "new file")
    _audit.record(sess["username"], True, "check_integrity", f"filestore/{name}", verdict)
    return {"status": "success", "filename": name, "verdict": verdict, **result}


@app.post("/api/files/{name}/repair")
async def api_repair_file(name: str, request: Request):
    sess = _session(request)
    if not sess:
        _audit.record(None, False, "repair_file", f"filestore/{name}",
                      "denied — not authenticated")
        return JSONResponse({"status": "error", "message": "Authentication required."}, status_code=401)
    if sess["role"] != "admin":
        _audit.record(sess["username"], True, "repair_file", f"filestore/{name}",
                      "denied — admin only")
        return JSONResponse({"status": "error", "message": "Admin role required."}, status_code=403)
    if not _filestore.repair_file(name):
        return JSONResponse(
            {"status": "error", "message": f"No original exists for '{name}'."},
            status_code=404,
        )
    _audit.record(sess["username"], True, "repair_file", f"filestore/{name}", "restored")
    return {"status": "success", "message": f"'{name}' restored to original content."}


@app.get("/api/files/{name}")
async def api_read_file(name: str, request: Request):
    sess = _session(request)
    username = sess["username"] if sess else None
    try:
        content, sha = _filestore.read_file(name)
        integrity = _filestore.check_integrity(name)
    except KeyError as e:
        _audit.record(username, sess is not None, "read_file", f"filestore/{name}", f"error: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=404)
    _audit.record(username, sess is not None, "read_file", f"filestore/{name}", "success")
    if not sess:
        return {
            "authenticated": False,
            "filename": "████████",
            "content": _crypto.encrypt(content),
            "notice": "Content is AES-256-CBC encrypted. Authenticate to view.",
        }
    return {
        "authenticated": True,
        "filename": name,
        "content": content,
        "sha256": sha,
        "intact": integrity["intact"],
    }


class WriteBody(BaseModel):
    content: str


@app.put("/api/files/{name}")
async def api_write_file(name: str, body: WriteBody, request: Request):
    sess = _session(request)
    if not sess:
        _audit.record(None, False, "write_file", f"filestore/{name}",
                      "denied — not authenticated")
        return JSONResponse({"status": "error", "message": "Authentication required."}, status_code=401)
    new_sha = _filestore.write_file(name, body.content)
    _audit.record(sess["username"], True, "write_file", f"filestore/{name}",
                  f"written — sha={new_sha[:16]}…")
    return {"status": "success", "filename": name, "sha256": new_sha}


@app.delete("/api/files/{name}")
async def api_delete_file(name: str, request: Request):
    sess = _session(request)
    if not sess:
        _audit.record(None, False, "delete_file", f"filestore/{name}",
                      "denied — not authenticated")
        return JSONResponse({"status": "error", "message": "Authentication required."}, status_code=401)
    try:
        _filestore.delete_file(name)
    except KeyError as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=404)
    _audit.record(sess["username"], True, "delete_file", f"filestore/{name}", "deleted")
    return {"status": "success", "message": f"'{name}' deleted."}


# ---------------------------------------------------------------------------
# Scan / Reset
# ---------------------------------------------------------------------------
@app.get("/api/scan")
async def api_scan(request: Request):
    sess = _session(request)
    if not sess:
        _audit.record(None, False, "scan_files", "filestore",
                      "denied — not authenticated")
        return JSONResponse({"status": "error", "message": "Authentication required."}, status_code=401)
    tampered = _filestore.detect_tampered()
    _audit.record(sess["username"], True, "scan_files", "filestore",
                  f"{len(tampered)} tampered file(s)")
    return {"status": "success", "tampered_files": tampered, "count": len(tampered)}


@app.post("/api/reset")
async def api_reset(request: Request):
    sess = _session(request)
    if not sess:
        _audit.record(None, False, "reset_files", "filestore",
                      "denied — not authenticated")
        return JSONResponse({"status": "error", "message": "Authentication required."}, status_code=401)
    if sess["role"] != "admin":
        _audit.record(sess["username"], True, "reset_files", "filestore",
                      "denied — admin only")
        return JSONResponse({"status": "error", "message": "Admin role required."}, status_code=403)
    restored = _filestore.reset_all()
    _audit.record(sess["username"], True, "reset_files", "filestore",
                  f"restored {len(restored)} files")
    return {"status": "success", "files": restored, "count": len(restored)}


# ---------------------------------------------------------------------------
# Activity log
# ---------------------------------------------------------------------------
@app.get("/api/activity")
async def api_activity(request: Request):
    sess = _session(request)
    if not sess:
        _audit.record(None, False, "read_activity", "audit_log",
                      "denied — not authenticated")
        return JSONResponse({"status": "error", "message": "Authentication required."}, status_code=401)
    entries = list(reversed(_audit.get_all()))
    _audit.record(sess["username"], True, "read_activity", "audit_log",
                  f"success ({len(entries)} entries)")
    return {"status": "success", "entries": entries}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MCP Security Gateway — Web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    print(f"[gateway] Web UI      →  http://{args.host}:{args.port}")
    print("[gateway] FileStore   →  5 demo files (auto-restored on start)")
    print("[gateway] Credentials →  admin/admin123  |  viewer/view456")
    uvicorn.run(app, host=args.host, port=args.port)
