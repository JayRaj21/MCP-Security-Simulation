"""Interactive security shell for MCP Security Simulation v2.

Lets users actively test every security feature against the live FastMCP server.

Demo files pre-loaded on the server:
  config.json          Server config with DB credentials and API keys
  secrets.env          Production environment secrets and cloud keys
  user_database.csv    User records with hashed passwords and API tokens
  audit_log.txt        Access and security event log
  encryption_keys.txt  Encryption key rotation schedule

Commands
--------
  login / logout                    — manage your session
  list                              — see files (encrypted vs plaintext)
  read <file>                       — read a file
  write <file> <content>            — overwrite a file
  delete <file>                     — delete a file
  reset                             — restore all files to original content
  sign <file>                       — save a file's HMAC signature
  verify <file>                     — check the file hasn't changed
  tampertest <file>                 — corrupt the saved signature to trigger detection
  audit / audit --all               — view access log
  status / help / exit

Usage
-----
    python v2/shell.py                 # connect to http://127.0.0.1:8000/mcp
    python v2/shell.py --url http://.. # custom server URL
"""
import argparse
import asyncio
import json
import shlex
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
def err(msg):  print(f"  {c('✗', RED, BOLD)} {msg}")
def info(msg): print(f"  {c('·', DIM)} {msg}")
def warn(msg): print(f"  {c('!', YELLOW, BOLD)} {msg}")
def sep():     print(c("  " + "─" * 66, DIM))


# ── Shell state ───────────────────────────────────────────────────────────────
class ShellState:
    def __init__(self):
        self.token:    Optional[str] = None
        self.username: Optional[str] = None
        self.signatures: dict[str, str] = {}  # filename -> saved HMAC

    @property
    def authenticated(self) -> bool:
        return self.token is not None

    def prompt(self) -> str:
        if self.authenticated:
            return f"\n{c('[', DIM)}{c(self.username, GREEN, BOLD)}{c(']', DIM)} {c('>', BOLD)} "
        return f"\n{c('[', DIM)}{c('unauth', YELLOW)}{c(']', DIM)} {c('>', BOLD)} "


# ── Helpers ───────────────────────────────────────────────────────────────────
def _r(result) -> dict:
    return result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)


def _truncate(text: str, width: int = 100) -> str:
    return text if len(text) <= width else text[:width] + c(f" … ({len(text)} chars)", DIM)


def _print_content(content: str, authenticated: bool) -> None:
    sep()
    if not authenticated:
        warn("AES-256-CBC encrypted — uninterpretable without the key:")
        print(f"  {c(_truncate(content, 80), RED)}")
        return
    lines = content.splitlines()
    for line in lines[:30]:
        print(f"  {line}")
    if len(lines) > 30:
        info(f"… {len(lines) - 30} more lines (showing first 30)")


# ── Command handlers ──────────────────────────────────────────────────────────
async def cmd_login(client, state, args):
    if len(args) < 2:
        err("Usage: login <username> <password>"); return
    d = _r(await client.call_tool("authenticate", {"username": args[0], "password": args[1]}))
    if d.get("status") == "success":
        state.token = d["session_token"]
        state.username = args[0]
        ok(f"Authenticated as {c(args[0], GREEN, BOLD)}  (expires in {d.get('expires_in_seconds')}s)")
    else:
        err(d.get("message", "Authentication failed"))


async def cmd_logout(client, state, _args):
    if not state.authenticated:
        warn("You are not logged in."); return
    d = _r(await client.call_tool("logout", {"session_token": state.token}))
    if d.get("status") == "success":
        ok(d["message"])
        state.token = None
        state.username = None
    else:
        err(d.get("message", "Logout failed"))


async def cmd_list(client, state, _args):
    d = _r(await client.call_tool("list_files", {"session_token": state.token or ""}))
    if d.get("status") == "error":
        err(d["message"]); return
    auth = d.get("authenticated", False)
    files = d.get("files", [])
    info(f"authenticated: {c(auth, GREEN if auth else YELLOW)}  |  files: {len(files)}")
    sep()
    if not auth:
        warn(d.get("notice", ""))
        print()
        for f in files:
            print(f"  {c('file', DIM):<18}  {c(_truncate(f['name'], 55), RED)}  {c('(encrypted)', DIM)}")
        return
    for f in files:
        sha = f.get("sha", "")[:10]
        print(
            f"  {c(f['type'][:3], CYAN):<18}"
            f"  {c(f['name'], BOLD):<40}"
            f"  {c(str(f.get('size','')), DIM):<10} B"
            f"  {c(sha + '…', DIM)}"
        )


async def cmd_read(client, state, args):
    if not args:
        err("Usage: read <filename>"); return
    d = _r(await client.call_tool("read_file", {"filename": args[0], "session_token": state.token or ""}))
    if d.get("status") == "error":
        err(d["message"]); return
    auth = d.get("authenticated", False)
    info(f"file: {c(args[0], CYAN)}  |  authenticated: {c(auth, GREEN if auth else YELLOW)}")
    if auth:
        info(f"sha256: {c(d.get('sha256','')[:16], DIM)}…")
        info(f"hmac:   {c(d.get('hmac_signature','')[:24], DIM)}…  (run 'sign {args[0]}' to save it)")
    _print_content(d.get("content", ""), auth)


async def cmd_write(client, state, args):
    if len(args) < 2:
        err("Usage: write <filename> <new content>"); return
    filename = args[0]
    content = " ".join(args[1:])
    if not state.authenticated:
        err("Authentication required to write files.")
        info("Tip: your blocked attempt has been recorded in the audit log."); return
    d = _r(await client.call_tool("write_file", {
        "filename": filename, "content": content, "session_token": state.token
    }))
    if d.get("status") == "success":
        ok(d["message"])
        info(f"new sha256: {c(d.get('sha256','')[:16], DIM)}…")
        if filename in state.signatures:
            warn(f"You have a saved signature for '{filename}' — run 'verify {filename}' to see it fail.")
    else:
        err(d.get("message", "Write failed"))


async def cmd_delete(client, state, args):
    if not args:
        err("Usage: delete <filename>"); return
    if not state.authenticated:
        err("Authentication required to delete files.")
        info("Tip: your blocked attempt has been recorded in the audit log."); return
    filename = args[0]
    d = _r(await client.call_tool("delete_file", {"filename": filename, "session_token": state.token}))
    if d.get("status") == "success":
        ok(d["message"])
        state.signatures.pop(filename, None)
    else:
        err(d.get("message", "Delete failed"))


async def cmd_reset(client, state, _args):
    if not state.authenticated:
        err("Authentication required to reset files."); return
    d = _r(await client.call_tool("reset_files", {"session_token": state.token}))
    if d.get("status") == "success":
        ok(d["message"])
        for name in d.get("files_restored", []):
            info(f"  restored: {c(name, CYAN)}")
        state.signatures.clear()
    else:
        err(d.get("message", "Reset failed"))


async def cmd_sign(client, state, args):
    if not args:
        err("Usage: sign <filename>"); return
    if not state.authenticated:
        err("You must be logged in to sign a file."); return
    d = _r(await client.call_tool("read_file", {"filename": args[0], "session_token": state.token}))
    if d.get("status") == "error":
        err(d["message"]); return
    sig = d.get("hmac_signature", "")
    state.signatures[args[0]] = sig
    ok(f"Signature saved for {c(args[0], CYAN)}")
    info(f"HMAC-SHA256: {c(sig, BOLD)}")
    info(f"Now try:  write {args[0]} tampered content  →  verify {args[0]}")


async def cmd_verify(client, state, args):
    if not args:
        err("Usage: verify <filename>"); return
    if not state.authenticated:
        err("Authentication required to verify integrity.")
        info("Tip: your blocked attempt has been recorded in the audit log."); return
    filename = args[0]
    if filename not in state.signatures:
        err(f"No saved signature for '{filename}'.  Run: {c('sign ' + filename, YELLOW)}")
        return
    d = _r(await client.call_tool("verify_integrity", {
        "filename": filename,
        "expected_hmac": state.signatures[filename],
        "session_token": state.token,
    }))
    if d.get("status") == "error":
        err(d["message"]); return
    if d.get("intact"):
        ok(d["verdict"])
    else:
        err(d["verdict"])


async def cmd_tampertest(client, state, args):
    """Corrupt the saved signature locally to trigger tamper detection."""
    if not args:
        err("Usage: tampertest <filename>"); return
    if not state.authenticated:
        err("You must be logged in."); return
    filename = args[0]
    if filename not in state.signatures:
        err(f"No saved signature for '{filename}'.  Run: {c('sign ' + filename, YELLOW)}")
        return
    original = state.signatures[filename]
    bad = original[:8] + "DEADBEEF" + original[16:]
    warn(f"Corrupting local signature for {c(filename, CYAN)}:")
    info(f"  original : {original[:24]}…")
    info(f"  corrupted: {bad[:24]}…")
    d = _r(await client.call_tool("verify_integrity", {
        "filename": filename, "expected_hmac": bad, "session_token": state.token
    }))
    if d.get("intact"):
        warn("Unexpected: check passed with corrupted signature")
    else:
        err(f"Tamper detected!  {d.get('verdict', '')}")
    state.signatures[filename] = original
    info("Original signature restored.")


async def cmd_audit(client, state, args):
    if not state.authenticated:
        err("Authentication required to view the audit log.")
        warn("Your unauthenticated attempts are being recorded right now.")
        info(f"Log in, then run {c('audit', YELLOW)} to see them."); return
    unauth_only = "--all" not in args
    d = _r(await client.call_tool("get_audit_log", {
        "session_token": state.token, "unauthorized_only": unauth_only
    }))
    if d.get("status") == "error":
        err(d["message"]); return
    entries = d.get("log", [])
    info(
        f"Filter: {c('unauthorized only', YELLOW) if unauth_only else c('all entries', CYAN)}"
        f"  |  total: {c(len(entries), BOLD)}"
    )
    sep()
    if not entries:
        ok("No entries match the current filter."); return
    for line in entries:
        colour = RED if "UNAUTH" in line else GREEN
        print(f"  {c(line, colour)}")


async def cmd_status(_client, state, _args):
    if state.authenticated:
        ok(f"Logged in as {c(state.username, GREEN, BOLD)}")
        if state.signatures:
            info(f"Saved signatures ({len(state.signatures)}):")
            for filename, sig in state.signatures.items():
                info(f"  {c(filename, CYAN):<36} {c(sig[:16], DIM)}…")
    else:
        warn("Not authenticated — all content is AES-256 encrypted")


def cmd_help(_c, _s, _a):
    print(textwrap.dedent(f"""
  {c('COMMANDS', BOLD + CYAN)}

  {c('Authentication', BOLD)}
    {c('login <user> <pass>', YELLOW)}         Authenticate and open a session
    {c('logout', YELLOW)}                     End your session

  {c('Files', BOLD)}
    {c('list', YELLOW)}                        List files (encrypted when logged out)
    {c('read <file>', YELLOW)}                 Read a file's content
    {c('write <file> <content>', YELLOW)}      Overwrite a file (auth required)
    {c('delete <file>', YELLOW)}               Delete a file (auth required)
    {c('reset', YELLOW)}                       Restore all files to original content

  {c('Integrity', BOLD)}
    {c('sign <file>', YELLOW)}                 Save a file's HMAC-SHA256 signature
    {c('verify <file>', YELLOW)}               Check the file hasn't changed
    {c('tampertest <file>', YELLOW)}           Corrupt the signature to trigger detection

  {c('Audit', BOLD)}
    {c('audit', YELLOW)}                       Show unauthorized access attempts (auth required)
    {c('audit --all', YELLOW)}                 Show all access attempts

  {c('Other', BOLD)}
    {c('status', YELLOW)}                      Show your session and saved signatures
    {c('help', YELLOW)}                        Show this message
    {c('exit', YELLOW)}                        Quit

  {c('SUGGESTED FLOWS', BOLD)}

  See encryption in action:
    {c('list', YELLOW)}                       → encrypted filenames
    {c('read secrets.env', YELLOW)}           → encrypted content
    {c('login admin admin123', YELLOW)}       → get session
    {c('list', YELLOW)}  {c('read secrets.env', YELLOW)}  → plaintext

  Test integrity protection:
    {c('sign config.json', YELLOW)}           → save HMAC
    {c('verify config.json', YELLOW)}         → intact ✓
    {c('write config.json HACKED', YELLOW)}   → overwrite it
    {c('verify config.json', YELLOW)}         → tamper detected ✗
    {c('reset', YELLOW)}                      → restore original

  Test access control:
    {c('logout', YELLOW)}
    {c('write secrets.env evil', YELLOW)}     → blocked + logged
    {c('login admin admin123', YELLOW)}
    {c('audit', YELLOW)}                      → see the blocked attempt
    """))


# ── Command registry ──────────────────────────────────────────────────────────
COMMANDS = {
    "login":      cmd_login,
    "logout":     cmd_logout,
    "list":       cmd_list,
    "read":       cmd_read,
    "write":      cmd_write,
    "delete":     cmd_delete,
    "reset":      cmd_reset,
    "sign":       cmd_sign,
    "verify":     cmd_verify,
    "tampertest": cmd_tampertest,
    "audit":      cmd_audit,
    "status":     cmd_status,
    "help":       cmd_help,
}

# ── REPL ──────────────────────────────────────────────────────────────────────
async def repl(server_url: str) -> None:
    print(f"""
{c('═' * 70, CYAN)}
{c('  MCP Security Simulation v2  —  Interactive Shell', BOLD + CYAN)}
{c('═' * 70, CYAN)}

  Server : {c(server_url, CYAN)}

  {c('Demo files on the server:', BOLD)}
    config.json           server config + DB credentials + API keys
    secrets.env           production environment secrets
    user_database.csv     user records with password hashes
    audit_log.txt         security event log
    encryption_keys.txt   key rotation schedule

  {c('Type  help  to see all commands.', DIM)}
  {c('Quick start:  list  →  read secrets.env  →  login admin admin123  →  repeat', DIM)}
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
                err(f"Unknown command: {c(verb, YELLOW)}  (type {c('help', YELLOW)})")
                continue
            try:
                result = handler(client, state, args)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                err(f"Error: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Security Simulation v2 interactive shell")
    parser.add_argument("--url", default="http://127.0.0.1:8000/mcp")
    args = parser.parse_args()
    asyncio.run(repl(args.url))


if __name__ == "__main__":
    main()
