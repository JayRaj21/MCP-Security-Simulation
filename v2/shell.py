"""Interactive security shell for MCP Security Simulation v2.

Lets users actively test every security feature against the live FastMCP server:
  - Login / logout
  - List files (see encrypted vs plaintext metadata)
  - Read files (see AES-256 ciphertext vs plaintext)
  - Sign a file (capture its HMAC-SHA256 signature)
  - Verify a file (check it hasn't been tampered with)
  - View the audit log (see all unauthorized access attempts)

Usage
-----
    python v2/shell.py                    # connect to http://127.0.0.1:8000/mcp
    python v2/shell.py --url http://...   # custom server URL
"""
import argparse
import asyncio
import json
import shlex
import sys
import textwrap
from typing import Optional

from fastmcp import Client

# ── ANSI colours ─────────────────────────────────────────────────────────────
R = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
WHITE = "\033[97m"

def c(text, *codes): return "".join(codes) + str(text) + R
def ok(msg):   print(f"  {c('✓', GREEN, BOLD)} {msg}")
def err(msg):  print(f"  {c('✗', RED,   BOLD)} {msg}")
def info(msg): print(f"  {c('·', DIM  )} {msg}")
def warn(msg): print(f"  {c('!', YELLOW, BOLD)} {msg}")
def sep():     print(c("  " + "─" * 66, DIM))


# ── Shell state ───────────────────────────────────────────────────────────────
class ShellState:
    def __init__(self):
        self.token:    Optional[str] = None
        self.username: Optional[str] = None
        # file_path -> hmac_signature (stored by 'sign' command)
        self.signatures: dict[str, str] = {}

    @property
    def authenticated(self) -> bool:
        return self.token is not None

    def prompt(self) -> str:
        if self.authenticated:
            return f"\n{c('[', DIM)}{c(self.username, GREEN, BOLD)}{c(']', DIM)} {c('>', BOLD)} "
        return f"\n{c('[', DIM)}{c('unauth', YELLOW)}{c(']', DIM)} {c('>', BOLD)} "


# ── Helpers ───────────────────────────────────────────────────────────────────
def _result(r) -> dict:
    """Extract the dict from a CallToolResult."""
    if isinstance(r.data, dict):
        return r.data
    return json.loads(r.content[0].text)


def _truncate(text: str, width: int = 120) -> str:
    if len(text) <= width:
        return text
    return text[:width] + c(f"  … ({len(text)} chars)", DIM)


def _print_file_content(content: str, authenticated: bool) -> None:
    if not authenticated:
        warn("Content is AES-256-CBC encrypted (uninterpretable without the key):")
        print(f"  {c(_truncate(content, 100), RED)}")
        return
    lines = content.splitlines()
    preview = lines[:20]
    for line in preview:
        print(f"  {line}")
    if len(lines) > 20:
        info(f"… {len(lines) - 20} more lines (showing first 20)")


# ── Command handlers ──────────────────────────────────────────────────────────
async def cmd_login(client: Client, state: ShellState, args: list[str]) -> None:
    if len(args) < 2:
        err("Usage: login <username> <password>")
        return
    username, password = args[0], args[1]
    r = _result(await client.call_tool("authenticate", {"username": username, "password": password}))
    if r.get("status") == "success":
        state.token = r["session_token"]
        state.username = username
        ok(f"Authenticated as {c(username, GREEN, BOLD)}  (session expires in {r.get('expires_in_seconds')}s)")
    else:
        err(r.get("message", "Authentication failed"))


async def cmd_logout(client: Client, state: ShellState, _args: list[str]) -> None:
    if not state.authenticated:
        warn("You are not logged in.")
        return
    r = _result(await client.call_tool("logout", {"session_token": state.token}))
    if r.get("status") == "success":
        ok(r.get("message", "Logged out."))
        state.token = None
        state.username = None
    else:
        err(r.get("message", "Logout failed"))


async def cmd_list(client: Client, state: ShellState, args: list[str]) -> None:
    path = args[0] if args else ""
    r = _result(await client.call_tool(
        "list_files",
        {"path": path, "session_token": state.token or ""},
    ))
    if r.get("status") == "error":
        err(r["message"]); return

    auth = r.get("authenticated", False)
    items = r.get("items", [])
    info(f"Path: {c(path or '/', CYAN)}  |  authenticated: {c(auth, GREEN if auth else YELLOW)}  |  items: {len(items)}")
    sep()

    if not auth:
        warn(r.get("notice", ""))
        print()
        for item in items:
            print(f"  {c('file', DIM):<18} {c(item['name'][:60], RED)}  {c('(encrypted)', DIM)}")
        return

    for item in items:
        type_colour = CYAN if item["type"] == "dir" else WHITE
        size = f"{item['size']} B" if item.get("size") else ""
        print(
            f"  {c(item['type'][:3], type_colour):<18}"
            f"  {c(item['name'], BOLD):<42}"
            f"  {c(size, DIM)}"
        )


async def cmd_read(client: Client, state: ShellState, args: list[str]) -> None:
    if not args:
        err("Usage: read <file_path>"); return
    path = args[0]
    r = _result(await client.call_tool(
        "read_file",
        {"file_path": path, "session_token": state.token or ""},
    ))
    if r.get("status") == "error":
        err(r["message"]); return

    auth = r.get("authenticated", False)
    info(f"File: {c(path, CYAN)}  |  authenticated: {c(auth, GREEN if auth else YELLOW)}")
    if auth:
        info(f"git_sha: {c(r.get('git_sha','')[:16], DIM)}…")
        info(f"hmac_signature: {c(r.get('hmac_signature','')[:24], DIM)}…  (use 'sign {path}' to save it)")
    sep()
    _print_file_content(r.get("content", ""), auth)


async def cmd_sign(client: Client, state: ShellState, args: list[str]) -> None:
    """Read a file and save its HMAC signature for later verification."""
    if not args:
        err("Usage: sign <file_path>"); return
    if not state.authenticated:
        err("You must be logged in to sign a file."); return
    path = args[0]
    r = _result(await client.call_tool(
        "read_file",
        {"file_path": path, "session_token": state.token},
    ))
    if r.get("status") == "error":
        err(r["message"]); return
    sig = r.get("hmac_signature", "")
    state.signatures[path] = sig
    ok(f"Signature saved for {c(path, CYAN)}")
    info(f"HMAC-SHA256: {c(sig, BOLD)}")
    info(f"Run {c('verify ' + path, YELLOW)} later to check if the file has changed.")


async def cmd_verify(client: Client, state: ShellState, args: list[str]) -> None:
    if not args:
        err("Usage: verify <file_path>"); return
    if not state.authenticated:
        err("You must be logged in to verify integrity."); return
    path = args[0]
    if path not in state.signatures:
        err(f"No saved signature for '{path}'.  Run {c('sign ' + path, YELLOW)} first.")
        return
    sig = state.signatures[path]
    r = _result(await client.call_tool(
        "verify_integrity",
        {"file_path": path, "expected_hmac": sig, "session_token": state.token},
    ))
    if r.get("status") == "error":
        err(r["message"]); return
    intact = r.get("intact", False)
    if intact:
        ok(r.get("verdict", "Intact"))
    else:
        err(r.get("verdict", "TAMPERED"))


async def cmd_tamper_test(client: Client, state: ShellState, args: list[str]) -> None:
    """Deliberately corrupt a saved signature to demonstrate tamper detection."""
    if not args:
        err("Usage: tampertest <file_path>"); return
    if not state.authenticated:
        err("You must be logged in."); return
    path = args[0]
    if path not in state.signatures:
        err(f"No saved signature for '{path}'.  Run {c('sign ' + path, YELLOW)} first.")
        return
    original = state.signatures[path]
    bad_sig = original[:8] + "DEADBEEF" + original[16:]
    warn(f"Corrupting saved signature for {c(path, CYAN)}:")
    info(f"  original : {original[:24]}…")
    info(f"  corrupted: {bad_sig[:24]}…")
    r = _result(await client.call_tool(
        "verify_integrity",
        {"file_path": path, "expected_hmac": bad_sig, "session_token": state.token},
    ))
    if r.get("intact"):
        warn("Unexpected: integrity check passed (should have failed)")
    else:
        err(f"Tamper detected! {r.get('verdict', '')}")
    info(f"Signature restored to original.")
    # Keep the original sig intact
    state.signatures[path] = original


async def cmd_audit(client: Client, state: ShellState, args: list[str]) -> None:
    if not state.authenticated:
        err("You must be logged in to view the audit log.")
        info("Tip: your current unauthenticated access attempts are being recorded right now.")
        return
    unauth_only = "--all" not in args
    r = _result(await client.call_tool(
        "get_audit_log",
        {"session_token": state.token, "unauthorized_only": unauth_only},
    ))
    if r.get("status") == "error":
        err(r["message"]); return
    entries = r.get("log", [])
    info(
        f"Filter: {c('unauthorized only', YELLOW) if unauth_only else c('all entries', CYAN)}"
        f"  |  total: {c(len(entries), BOLD)}"
    )
    sep()
    if not entries:
        ok("No entries match the current filter.")
        return
    for line in entries:
        colour = RED if "UNAUTH" in line else GREEN
        print(f"  {c(line, colour)}")


async def cmd_repo(client: Client, _state: ShellState, _args: list[str]) -> None:
    r = _result(await client.call_tool("repository_info", {}))
    if r.get("status") == "error":
        err(r["message"]); return
    repo = r.get("repository", {})
    ok(f"{c(repo.get('full_name',''), CYAN, BOLD)}")
    info(repo.get("description", ""))
    info(f"Default branch : {repo.get('default_branch','')}")
    info(f"Stars          : {repo.get('stargazers_count','')}")
    info(f"URL            : {repo.get('html_url','')}")


async def cmd_status(_client: Client, state: ShellState, _args: list[str]) -> None:
    if state.authenticated:
        ok(f"Logged in as {c(state.username, GREEN, BOLD)}")
        if state.signatures:
            info(f"Saved signatures ({len(state.signatures)}):")
            for path, sig in state.signatures.items():
                info(f"  {c(path, CYAN):<40} {c(sig[:16], DIM)}…")
    else:
        warn("Not authenticated  —  all file content is AES-256 encrypted")
    info("Server: http://127.0.0.1:8000/mcp  |  Data: GitHub REST API")


def cmd_help(_client, _state, _args) -> None:
    print(textwrap.dedent(f"""
  {c('COMMANDS', BOLD, CYAN)}

  {c('Authentication', BOLD)}
    {c('login <user> <pass>', YELLOW)}      Authenticate and open a session
    {c('logout', YELLOW)}                  End your session

  {c('Files  (encrypted when logged out, plaintext when logged in)', BOLD)}
    {c('list [path]', YELLOW)}              List files in the repository
    {c('read <file>', YELLOW)}              Read a file\'s content
    {c('sign <file>', YELLOW)}              Read a file and save its HMAC-SHA256 signature
    {c('verify <file>', YELLOW)}            Verify a signed file hasn\'t changed
    {c('tampertest <file>', YELLOW)}        Corrupt a signature to show tamper detection

  {c('Security audit', BOLD)}
    {c('audit', YELLOW)}                   Show unauthorized access attempts (login required)
    {c('audit --all', YELLOW)}             Show all access attempts

  {c('Info', BOLD)}
    {c('repo', YELLOW)}                    Show repository metadata
    {c('status', YELLOW)}                  Show your current session and saved signatures
    {c('help', YELLOW)}                    Show this message
    {c('exit', YELLOW)}                    Quit

  {c('TIPS', BOLD)}
    • Try {c('list', YELLOW)} without logging in — metadata is AES-256 encrypted
    • {c('login admin admin123', YELLOW)} → {c('list', YELLOW)} to see the difference
    • {c('sign README.md', YELLOW)} → {c('tampertest README.md', YELLOW)} to see tamper detection
    • {c('logout', YELLOW)} → {c('audit', YELLOW)} (denied) then re-login → {c('audit', YELLOW)} (visible)
    """))


# ── Main REPL ─────────────────────────────────────────────────────────────────
COMMANDS = {
    "login":      cmd_login,
    "logout":     cmd_logout,
    "list":       cmd_list,
    "read":       cmd_read,
    "sign":       cmd_sign,
    "verify":     cmd_verify,
    "tampertest": cmd_tamper_test,
    "audit":      cmd_audit,
    "repo":       cmd_repo,
    "status":     cmd_status,
    "help":       cmd_help,
}


async def repl(server_url: str) -> None:
    print(f"""
{c('═' * 70, CYAN)}
{c('  MCP Security Simulation v2  —  Interactive Shell', BOLD + CYAN)}
{c('═' * 70, CYAN)}

  Server  : {c(server_url, CYAN)}
  Data    : GitHub REST API  (public-apis/public-apis)

  {c('Type  help  to see all commands.', DIM)}
  {c('Try   list  without logging in to see encrypted metadata.', DIM)}
""")

    async with Client(server_url) as client:
        state = ShellState()
        while True:
            try:
                raw = input(state.prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                print(f"\n{c('Bye!', DIM)}")
                break

            if not raw:
                continue

            try:
                parts = shlex.split(raw)
            except ValueError as e:
                err(f"Parse error: {e}"); continue

            verb, *args = parts

            if verb in ("exit", "quit", "q"):
                print(c("Bye!", DIM)); break

            handler = COMMANDS.get(verb)
            if handler is None:
                err(f"Unknown command: {c(verb, YELLOW)}  (type {c('help', YELLOW)} to see commands)")
                continue

            try:
                result = handler(client, state, args)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                err(f"Error: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Security Simulation v2 interactive shell")
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8000/mcp",
        help="FastMCP server URL (default: http://127.0.0.1:8000/mcp)",
    )
    args = parser.parse_args()
    asyncio.run(repl(args.url))


if __name__ == "__main__":
    main()
