"""Automated demo walkthrough for the MCP Security Gateway.

Walks through every security feature non-interactively:

  1.  Unauthenticated list_users     → encrypted blob
  2.  Unauthenticated get_user(3)    → encrypted blob
  3.  Authenticate as admin          → get session token
  4.  list_users with token          → plaintext user list
  5.  get_user(3) with token         → full profile
  6.  list_posts(user_id=3)          → that user's 10 posts
  7.  get_post(1)                    → single post in full
  8.  list_todos(user_id=1)          → that user's todos with completion status
  9.  sign user 3  +  verify intact  → HMAC integrity check (should pass)
  10. tampertest user 3              → corrupted signature → tamper detected
  11. get_audit_log(unauthorized_only=True) → see steps 1-2 recorded
  12. logout

Usage
-----
    python demo_client.py               # connect to http://127.0.0.1:8000/mcp
    python demo_client.py --url http:// # custom server URL
"""
import argparse
import asyncio
import json
import sys
import textwrap
from typing import Any

from fastmcp import Client

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[31m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_CYAN   = "\033[36m"
_DIM    = "\033[2m"


def _c(text, colour): return f"{colour}{text}{_RESET}"
def _header(title):
    bar = "─" * 70
    print(f"\n{_c(bar, _CYAN)}\n{_c('  ' + title, _BOLD + _CYAN)}\n{_c(bar, _CYAN)}")
def _step(n, desc): print(f"\n{_c(f'[Step {n}]', _BOLD + _YELLOW)} {desc}")
def _ok(msg):   print(f"  {_c('✓', _GREEN)} {msg}")
def _warn(msg): print(f"  {_c('!', _RED + _BOLD)} {msg}")
def _info(msg): print(f"  {_c('·', _DIM)} {msg}")


def _r(result) -> dict:
    return result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)


def _pause(auto: bool) -> None:
    if not auto:
        input(f"  {_c('Press Enter to continue…', _DIM)}")


async def run_demo(server_url: str, auto: bool) -> None:
    _header("MCP Security Gateway — Automated Demo")
    print(f"\n  Gateway : {_c(server_url, _CYAN)}")
    print(f"  Backend : {_c('https://jsonplaceholder.typicode.com', _CYAN)}\n")
    _pause(auto)

    async with Client(server_url) as client:
        token = None

        # ── Step 1: unauthenticated list_users ────────────────────────────────
        _step(1, "list_users() without authentication → expect AES-256 ciphertext")
        d = _r(await client.call_tool("list_users", {"session_token": ""}))
        assert d["authenticated"] is False, "Expected unauthenticated response"
        blob = d["data"]
        _warn(f"Response is encrypted (uninterpretable):  {blob[:60]}…")
        _info(d.get("notice", ""))
        _pause(auto)

        # ── Step 2: unauthenticated get_user ─────────────────────────────────
        _step(2, "get_user(3) without authentication → expect AES-256 ciphertext")
        d = _r(await client.call_tool("get_user", {"user_id": 3, "session_token": ""}))
        assert d["authenticated"] is False
        _warn(f"Encrypted user profile:  {d['data'][:60]}…")
        _pause(auto)

        # ── Step 3: authenticate ──────────────────────────────────────────────
        _step(3, "authenticate('admin', 'admin123') → get session token")
        d = _r(await client.call_tool("authenticate", {"username": "admin", "password": "admin123"}))
        assert d["status"] == "success", f"Auth failed: {d}"
        token = d["session_token"]
        _ok(f"Authenticated  |  token: {token[:16]}…  (expires in {d['expires_in_seconds']}s)")
        _pause(auto)

        # ── Step 4: list_users authenticated ─────────────────────────────────
        _step(4, "list_users(session_token=…) → plaintext user list")
        d = _r(await client.call_tool("list_users", {"session_token": token}))
        assert d["authenticated"] is True
        users = d["data"]
        _ok(f"Received {len(users)} users in plaintext")
        for u in users[:3]:
            _info(f"  {u['id']:<3} {u['name']:<25} {u['email']}")
        _info(f"  … and {len(users) - 3} more")
        _pause(auto)

        # ── Step 5: get_user authenticated ───────────────────────────────────
        _step(5, "get_user(3, session_token=…) → full profile")
        d = _r(await client.call_tool("get_user", {"user_id": 3, "session_token": token}))
        u = d["data"]
        _ok(f"User 3: {u['name']} ({u['email']})")
        _info(f"  company  : {u.get('company', {}).get('name')}")
        _info(f"  address  : {u.get('address', {}).get('city')}")
        _info(f"  hmac     : {d.get('hmac_signature','')[:32]}…")
        _pause(auto)

        # ── Step 6: list_posts for user 3 ────────────────────────────────────
        _step(6, "list_posts(user_id=3, session_token=…) → that user's posts")
        d = _r(await client.call_tool("list_posts", {"user_id": 3, "session_token": token}))
        posts = d["data"]
        _ok(f"Received {len(posts)} posts for user 3")
        for p in posts[:3]:
            _info(f"  post {p['id']:<4} {p['title'][:52]}")
        _pause(auto)

        # ── Step 7: get_post ─────────────────────────────────────────────────
        _step(7, "get_post(1, session_token=…) → single post in full")
        d = _r(await client.call_tool("get_post", {"post_id": 1, "session_token": token}))
        p = d["data"]
        _ok(f"Post 1: '{p['title']}'")
        for line in p.get("body", "").splitlines()[:3]:
            _info(f"  {line}")
        _pause(auto)

        # ── Step 8: list_todos for user 1 ────────────────────────────────────
        _step(8, "list_todos(user_id=1, session_token=…) → todos with completion status")
        d = _r(await client.call_tool("list_todos", {"user_id": 1, "session_token": token}))
        todos = d["data"]
        done  = sum(1 for t in todos if t.get("completed"))
        _ok(f"Received {len(todos)} todos for user 1  ({done} completed, {len(todos)-done} pending)")
        for t in todos[:4]:
            flag = "✓" if t.get("completed") else "✗"
            _info(f"  [{flag}] {t['title'][:55]}")
        _pause(auto)

        # ── Step 9: sign + verify integrity ──────────────────────────────────
        _step(9, "Sign user 3's response, then verify it hasn't changed")
        d = _r(await client.call_tool("get_user", {"user_id": 3, "session_token": token}))
        saved_hmac = d["hmac_signature"]
        _ok(f"Saved HMAC:  {saved_hmac[:32]}…")

        d = _r(await client.call_tool("verify_integrity", {
            "resource_type": "user", "resource_id": 3,
            "expected_hmac": saved_hmac, "session_token": token,
        }))
        assert d["intact"] is True, f"Unexpected tamper: {d}"
        _ok(d["verdict"])
        _pause(auto)

        # ── Step 10: tampertest ───────────────────────────────────────────────
        _step(10, "Corrupt the saved signature → tamper detection should fire")
        bad_hmac = saved_hmac[:8] + "DEADBEEF" + saved_hmac[16:]
        _warn(f"Corrupted HMAC:  {bad_hmac[:32]}…")
        d = _r(await client.call_tool("verify_integrity", {
            "resource_type": "user", "resource_id": 3,
            "expected_hmac": bad_hmac, "session_token": token,
        }))
        assert d["intact"] is False, "Expected tamper detection to trigger"
        _warn(d["verdict"])
        _ok("Tamper detection is working correctly.")
        _pause(auto)

        # ── Step 11: audit log ────────────────────────────────────────────────
        _step(11, "get_audit_log(unauthorized_only=True) → see steps 1 and 2")
        d = _r(await client.call_tool("get_audit_log", {
            "session_token": token, "unauthorized_only": True
        }))
        entries = d.get("log", [])
        _ok(f"Audit log has {len(entries)} unauthorized access attempt(s):")
        for entry in entries:
            _info(f"  {entry}")
        _pause(auto)

        # ── Step 12: logout ───────────────────────────────────────────────────
        _step(12, "logout → invalidate the session token")
        d = _r(await client.call_tool("logout", {"session_token": token}))
        assert d["status"] == "success"
        _ok(d["message"])

        _header("Demo complete")
        print(textwrap.dedent(f"""
  {_c('What was demonstrated:', _BOLD)}

  1.  Zero-trust auth   — every request verified independently
  2.  Encryption        — unauthenticated callers see only AES-256 ciphertext
  3.  Real backend API  — data live from jsonplaceholder.typicode.com
  4.  HMAC integrity    — gateway signs every response for tamper detection
  5.  Audit log         — all access attempts recorded, visible to auth users
        """))


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Security Gateway demo")
    parser.add_argument("--url", default="http://127.0.0.1:8000/mcp")
    parser.add_argument("--auto", action="store_true", help="Run without pausing between steps")
    args = parser.parse_args()
    asyncio.run(run_demo(args.url, args.auto))


if __name__ == "__main__":
    main()
