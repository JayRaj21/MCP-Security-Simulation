"""Interactive demo client for MCP Security Simulation v2.

Connects to the running FastMCP server and walks through the security features:

  1. Show that unauthenticated access returns encrypted, uninterpretable data
  2. Authenticate and read files in plaintext
  3. Capture an HMAC signature and verify file integrity
  4. View the audit log to see all unauthorized access attempts

Usage
-----
    python v2/demo_client.py                     # connect to default http://127.0.0.1:8000/mcp
    python v2/demo_client.py --url http://...    # custom server URL
    python v2/demo_client.py --auto              # run all steps non-interactively
"""
import argparse
import asyncio
import json
import sys
import textwrap
from typing import Any

from fastmcp import Client

# ANSI colours — fall back gracefully on terminals that don't support them
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[31m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_CYAN   = "\033[36m"
_DIM    = "\033[2m"


def _c(text: str, colour: str) -> str:
    return f"{colour}{text}{_RESET}"


def _header(title: str) -> None:
    bar = "─" * 70
    print(f"\n{_c(bar, _CYAN)}")
    print(f"{_c('  ' + title, _BOLD + _CYAN)}")
    print(f"{_c(bar, _CYAN)}")


def _step(n: int, description: str) -> None:
    print(f"\n{_c(f'[Step {n}]', _BOLD + _YELLOW)} {description}")


def _ok(msg: str) -> None:
    print(f"  {_c('✓', _GREEN)} {msg}")


def _warn(msg: str) -> None:
    print(f"  {_c('!', _RED + _BOLD)} {msg}")


def _info(msg: str) -> None:
    print(f"  {_c('·', _DIM)} {msg}")


def _dump(label: str, data: Any, max_len: int = 120) -> None:
    raw = json.dumps(data, indent=2)
    if len(raw) > max_len * 3:
        lines = raw.splitlines()[:12]
        raw = "\n".join(lines) + f"\n  … ({len(raw)} chars total, truncated)"
    print(f"\n  {_c(label + ':', _BOLD)}")
    for line in raw.splitlines():
        print(f"    {_DIM}{line}{_RESET}")


def _pause(auto: bool) -> None:
    if not auto:
        try:
            input(f"\n  {_c('Press Enter to continue …', _DIM)}")
        except EOFError:
            pass


async def run_demo(server_url: str, auto: bool) -> None:
    _header("MCP Security Simulation v2 — Live Demo")
    print(f"\n  Server : {_c(server_url, _CYAN)}")
    print(  "  Target : GitHub repository (public-apis/public-apis)\n")

    async with Client(server_url) as client:

        # ------------------------------------------------------------------ #
        # 0 — list available tools
        # ------------------------------------------------------------------ #
        _step(0, "Discover available MCP tools")
        tools = await client.list_tools()
        for t in tools:
            _ok(f"{t.name:<22}  {t.description.splitlines()[0] if t.description else ''}")
        _pause(auto)

        # ------------------------------------------------------------------ #
        # 1 — unauthenticated list_files
        # ------------------------------------------------------------------ #
        _step(1, "List files WITHOUT authentication  →  encrypted metadata")
        result = await client.call_tool("list_files", {"path": ""})
        parsed = result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)
        _info(f"authenticated = {parsed.get('authenticated')}")
        _info(f"item_count    = {parsed.get('item_count')}")
        items = parsed.get("items", [])[:3]
        for item in items:
            _warn(f"name (encrypted): {item['name'][:60]}…")
        _info(parsed.get("notice", ""))
        _pause(auto)

        # ------------------------------------------------------------------ #
        # 2 — unauthenticated read_file
        # ------------------------------------------------------------------ #
        _step(2, "Read a file WITHOUT authentication  →  encrypted content")
        result = await client.call_tool("read_file", {"file_path": "README.md"})
        parsed = result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)
        _info(f"authenticated  = {parsed.get('authenticated')}")
        ct = parsed.get("content", "")
        _warn(f"content (AES-256 ciphertext, first 80 chars): {ct[:80]}…")
        _info(parsed.get("notice", ""))
        _pause(auto)

        # ------------------------------------------------------------------ #
        # 3 — authenticate
        # ------------------------------------------------------------------ #
        _step(3, "Authenticate as admin")
        result = await client.call_tool(
            "authenticate", {"username": "admin", "password": "admin123"}
        )
        parsed = result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)
        if parsed.get("status") != "success":
            _warn(f"Authentication failed: {parsed}")
            return
        token = parsed["session_token"]
        _ok(f"status         = {parsed['status']}")
        _ok(f"session_token  = {token[:24]}… (truncated for display)")
        _ok(f"expires_in     = {parsed.get('expires_in_seconds')}s")
        _pause(auto)

        # ------------------------------------------------------------------ #
        # 4 — authenticated list_files
        # ------------------------------------------------------------------ #
        _step(4, "List files WITH authentication  →  real metadata")
        result = await client.call_tool(
            "list_files", {"path": "", "session_token": token}
        )
        parsed = result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)
        _ok(f"authenticated = {parsed.get('authenticated')}")
        _ok(f"item_count    = {parsed.get('item_count')}")
        for item in parsed.get("items", [])[:5]:
            _ok(f"  {item['type']:<6}  {item['name']:<40}  {item.get('size', '')} bytes")
        _pause(auto)

        # ------------------------------------------------------------------ #
        # 5 — authenticated read_file + capture HMAC
        # ------------------------------------------------------------------ #
        _step(5, "Read README.md WITH authentication  →  plaintext + HMAC signature")
        result = await client.call_tool(
            "read_file", {"file_path": "README.md", "session_token": token}
        )
        parsed = result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)
        content_preview = parsed.get("content", "")[:200].replace("\n", " ")
        hmac_sig = parsed.get("hmac_signature", "")
        _ok(f"authenticated  = {parsed.get('authenticated')}")
        _ok(f"git_sha        = {parsed.get('git_sha', '')[:12]}…")
        _ok(f"content (first 200 chars): {content_preview}…")
        _ok(f"hmac_signature = {hmac_sig[:32]}…")
        _pause(auto)

        # ------------------------------------------------------------------ #
        # 6 — verify_integrity (intact)
        # ------------------------------------------------------------------ #
        _step(6, "Verify file integrity  →  content unchanged since step 5")
        result = await client.call_tool(
            "verify_integrity",
            {"file_path": "README.md", "expected_hmac": hmac_sig, "session_token": token},
        )
        parsed = result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)
        _ok(f"intact  = {parsed.get('intact')}")
        _ok(f"verdict = {parsed.get('verdict')}")
        _pause(auto)

        # ------------------------------------------------------------------ #
        # 7 — verify_integrity with tampered HMAC
        # ------------------------------------------------------------------ #
        _step(7, "Simulate tampered signature  →  integrity check fails")
        bad_sig = hmac_sig[:10] + "0000000000" + hmac_sig[20:]
        result = await client.call_tool(
            "verify_integrity",
            {"file_path": "README.md", "expected_hmac": bad_sig, "session_token": token},
        )
        parsed = result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)
        _warn(f"intact  = {parsed.get('intact')}")
        _warn(f"verdict = {parsed.get('verdict')}")
        _pause(auto)

        # ------------------------------------------------------------------ #
        # 8 — attempt verify_integrity without auth
        # ------------------------------------------------------------------ #
        _step(8, "Attempt verify_integrity WITHOUT session token  →  denied + logged")
        result = await client.call_tool(
            "verify_integrity",
            {"file_path": "README.md", "expected_hmac": hmac_sig, "session_token": ""},
        )
        parsed = result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)
        _warn(f"status  = {parsed.get('status')}")
        _warn(f"message = {parsed.get('message')}")
        _pause(auto)

        # ------------------------------------------------------------------ #
        # 9 — audit log (unauthorized only)
        # ------------------------------------------------------------------ #
        _step(9, "Read audit log  →  all unauthorized attempts (requires auth)")
        result = await client.call_tool(
            "get_audit_log",
            {"session_token": token, "unauthorized_only": True},
        )
        parsed = result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)
        _ok(f"requested_by   = {parsed.get('requested_by')}")
        _ok(f"filter         = {parsed.get('filter')}")
        _ok(f"total_entries  = {parsed.get('total_entries')}")
        print()
        for line in parsed.get("log", []):
            print(f"  {_c(line, _RED if 'UNAUTH' in line else _GREEN)}")
        _pause(auto)

        # ------------------------------------------------------------------ #
        # 10 — logout
        # ------------------------------------------------------------------ #
        _step(10, "Logout  →  session token invalidated")
        result = await client.call_tool("logout", {"session_token": token})
        parsed = result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)
        _ok(f"status  = {parsed.get('status')}")
        _ok(f"message = {parsed.get('message')}")

        # Confirm token is now invalid
        result = await client.call_tool(
            "list_files", {"session_token": token}
        )
        post_logout = result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)
        _warn(f"Using old token after logout → authenticated={post_logout.get('authenticated')} (token rejected, content encrypted)")

    _header("Demo complete")
    print(textwrap.dedent(f"""
  Summary of security properties demonstrated:
    {_c('✓', _GREEN)} Unauthenticated callers receive AES-256-CBC ciphertext — uninterpretable
    {_c('✓', _GREEN)} Authenticated callers receive plaintext + HMAC-SHA256 integrity signature
    {_c('✓', _GREEN)} Tampered signatures are detected via constant-time HMAC comparison
    {_c('✓', _GREEN)} verify_integrity requires authentication (zero-trust)
    {_c('✓', _GREEN)} All access attempts (auth and unauth) recorded in audit log
    {_c('✓', _GREEN)} Audit log is itself a protected resource — auth required to read it
    {_c('✓', _GREEN)} GitHub API backend is read-only — files cannot be altered through server
    {_c('✓', _GREEN)} Session tokens expire and are revoked immediately on logout
    """))


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Security Simulation v2 demo client")
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8000/mcp",
        help="FastMCP server URL (default: http://127.0.0.1:8000/mcp)",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Run all steps without pausing for Enter",
    )
    args = parser.parse_args()
    asyncio.run(run_demo(args.url, args.auto))


if __name__ == "__main__":
    main()
