"""Interactive security shell for the MCP Security Gateway.

Connects to the running FastMCP gateway and lets you test every security
feature against the live JSONPlaceholder backend.

Commands
--------
  login / logout / status           — manage your session
  users                             — list all users (encrypted vs plaintext)
  user <id>                         — get a single user (1-10)
  posts [<user_id>]                 — list posts, optionally by user
  post <id>                         — get a single post (1-100)
  todos [<user_id>]                 — list todos, optionally by user
  todo <id>                         — get a single todo (1-200)
  sign <type> <id>                  — save HMAC signature (e.g. sign user 3)
  verify <type> <id>                — verify resource hasn't changed
  tampertest <type> <id>            — corrupt the saved signature to trigger detection
  audit / audit --all               — view access log (auth required)
  help / exit

Usage
-----
    python shell.py                  # connect to http://127.0.0.1:8000/mcp
    python shell.py --url http://..  # custom server URL
"""
import argparse
import asyncio
import json
import shlex
import textwrap
from typing import Optional

from fastmcp import Client

# ── ANSI colours ─────────────────────────────────────────────────────────────
R      = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"

def c(text, *codes): return "".join(codes) + str(text) + R
def ok(msg):   print(f"  {c('✓', GREEN, BOLD)} {msg}")
def err(msg):  print(f"  {c('✗', RED, BOLD)} {msg}")
def info(msg): print(f"  {c('·', DIM)} {msg}")
def warn(msg): print(f"  {c('!', YELLOW, BOLD)} {msg}")
def sep():     print(c("  " + "─" * 66, DIM))


# ── Shell state ───────────────────────────────────────────────────────────────
class ShellState:
    def __init__(self):
        self.token:      Optional[str]  = None
        self.username:   Optional[str]  = None
        self.signatures: dict[str, str] = {}   # "user:3" → hmac

    @property
    def authenticated(self) -> bool:
        return self.token is not None

    def prompt(self) -> str:
        if self.authenticated:
            return f"\n{c('[', DIM)}{c(self.username, GREEN, BOLD)}{c(']', DIM)} {c('>', BOLD)} "
        return f"\n{c('[', DIM)}{c('unauth', YELLOW)}{c(']', DIM)} {c('>', BOLD)} "


# ── Response helpers ──────────────────────────────────────────────────────────
def _r(result) -> dict:
    return result.data if isinstance(result.data, dict) else json.loads(result.content[0].text)

def _trunc(text: str, width: int = 70) -> str:
    return text if len(text) <= width else text[:width] + c(f"… ({len(text)})", DIM)


# ── Display helpers ───────────────────────────────────────────────────────────
def _print_encrypted(blob: str) -> None:
    warn("AES-256-CBC encrypted — uninterpretable without the key:")
    print(f"  {c(_trunc(blob, 80), RED)}")


def _print_users(users: list) -> None:
    fmt = "  {:<4} {:<24} {:<30} {}"
    print(c(fmt.format("ID", "NAME", "EMAIL", "COMPANY"), DIM))
    sep()
    for u in users:
        print(fmt.format(
            c(u["id"], CYAN),
            u.get("name", "")[:23],
            u.get("email", "")[:29],
            u.get("company", {}).get("name", "")[:24],
        ))


def _print_user(u: dict) -> None:
    addr = u.get("address", {})
    co   = u.get("company", {})
    sep()
    for k, v in [
        ("id",         u.get("id")),
        ("name",       u.get("name")),
        ("username",   u.get("username")),
        ("email",      u.get("email")),
        ("phone",      u.get("phone")),
        ("website",    u.get("website")),
        ("address",    f"{addr.get('street')}, {addr.get('city')} {addr.get('zipcode')}"),
        ("company",    co.get("name")),
        ("catchPhrase",co.get("catchPhrase")),
    ]:
        print(f"  {c(k + ':', DIM):<28} {v}")


def _print_posts(posts: list) -> None:
    fmt = "  {:<5} {:<5} {}"
    print(c(fmt.format("ID", "USER", "TITLE"), DIM))
    sep()
    for p in posts[:20]:
        print(fmt.format(c(p["id"], CYAN), p.get("userId", ""), p.get("title", "")[:55]))
    if len(posts) > 20:
        info(f"… {len(posts) - 20} more posts (showing first 20)")


def _print_post(p: dict) -> None:
    sep()
    print(f"  {c('id:', DIM):<18} {p.get('id')}")
    print(f"  {c('userId:', DIM):<18} {p.get('userId')}")
    print(f"  {c('title:', DIM):<18} {p.get('title')}")
    print(f"  {c('body:', DIM)}")
    for line in p.get("body", "").splitlines():
        print(f"    {line}")


def _print_todos(todos: list) -> None:
    fmt = "  {:<5} {:<5} {:<6} {}"
    print(c(fmt.format("ID", "USER", "DONE", "TITLE"), DIM))
    sep()
    for t in todos[:20]:
        done = c("✓", GREEN) if t.get("completed") else c("✗", RED)
        print(fmt.format(c(t["id"], CYAN), t.get("userId", ""), done, t.get("title", "")[:52]))
    if len(todos) > 20:
        info(f"… {len(todos) - 20} more todos (showing first 20)")


def _print_todo(t: dict) -> None:
    sep()
    done = c("✓  completed", GREEN) if t.get("completed") else c("✗  not completed", YELLOW)
    print(f"  {c('id:', DIM):<18} {t.get('id')}")
    print(f"  {c('userId:', DIM):<18} {t.get('userId')}")
    print(f"  {c('status:', DIM):<18} {done}")
    print(f"  {c('title:', DIM):<18} {t.get('title')}")


# ── Command handlers ──────────────────────────────────────────────────────────
async def cmd_login(client, state, args):
    if len(args) < 2:
        err("Usage: login <username> <password>"); return
    d = _r(await client.call_tool("authenticate", {"username": args[0], "password": args[1]}))
    if d.get("status") == "success":
        state.token    = d["session_token"]
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
        state.token = state.username = None
        state.signatures.clear()
    else:
        err(d.get("message", "Logout failed"))


async def cmd_users(client, state, _args):
    d = _r(await client.call_tool("list_users", {"session_token": state.token or ""}))
    if d.get("status") == "error":
        err(d["message"]); return
    auth = d.get("authenticated", False)
    info(f"resource: {c('/users', CYAN)}  |  authenticated: {c(auth, GREEN if auth else YELLOW)}")
    sep()
    if not auth:
        _print_encrypted(d.get("data", "")); return
    _print_users(d.get("data", []))
    info(f"hmac: {c(d.get('hmac_signature','')[:20], DIM)}…  (run 'sign user <id>' to save a signature)")


async def cmd_user(client, state, args):
    if not args:
        err("Usage: user <id>  (1-10)"); return
    try:
        uid = int(args[0])
    except ValueError:
        err("user_id must be an integer"); return
    d = _r(await client.call_tool("get_user", {"user_id": uid, "session_token": state.token or ""}))
    if d.get("status") == "error":
        err(d["message"]); return
    auth = d.get("authenticated", False)
    info(f"resource: {c(f'/users/{uid}', CYAN)}  |  authenticated: {c(auth, GREEN if auth else YELLOW)}")
    if not auth:
        sep(); _print_encrypted(d.get("data", "")); return
    _print_user(d.get("data", {}))
    info(f"hmac: {c(d.get('hmac_signature','')[:20], DIM)}…  (run 'sign user {uid}' to save)")


async def cmd_posts(client, state, args):
    uid = int(args[0]) if args and args[0].isdigit() else 0
    d = _r(await client.call_tool("list_posts", {"user_id": uid, "session_token": state.token or ""}))
    if d.get("status") == "error":
        err(d["message"]); return
    auth = d.get("authenticated", False)
    resource = f"/posts?userId={uid}" if uid else "/posts"
    info(f"resource: {c(resource, CYAN)}  |  authenticated: {c(auth, GREEN if auth else YELLOW)}")
    sep()
    if not auth:
        _print_encrypted(d.get("data", "")); return
    _print_posts(d.get("data", []))


async def cmd_post(client, state, args):
    if not args:
        err("Usage: post <id>  (1-100)"); return
    try:
        pid = int(args[0])
    except ValueError:
        err("post_id must be an integer"); return
    d = _r(await client.call_tool("get_post", {"post_id": pid, "session_token": state.token or ""}))
    if d.get("status") == "error":
        err(d["message"]); return
    auth = d.get("authenticated", False)
    info(f"resource: {c(f'/posts/{pid}', CYAN)}  |  authenticated: {c(auth, GREEN if auth else YELLOW)}")
    if not auth:
        sep(); _print_encrypted(d.get("data", "")); return
    _print_post(d.get("data", {}))
    info(f"hmac: {c(d.get('hmac_signature','')[:20], DIM)}…  (run 'sign post {pid}' to save)")


async def cmd_todos(client, state, args):
    uid = int(args[0]) if args and args[0].isdigit() else 0
    d = _r(await client.call_tool("list_todos", {"user_id": uid, "session_token": state.token or ""}))
    if d.get("status") == "error":
        err(d["message"]); return
    auth = d.get("authenticated", False)
    resource = f"/todos?userId={uid}" if uid else "/todos"
    info(f"resource: {c(resource, CYAN)}  |  authenticated: {c(auth, GREEN if auth else YELLOW)}")
    sep()
    if not auth:
        _print_encrypted(d.get("data", "")); return
    _print_todos(d.get("data", []))


async def cmd_todo(client, state, args):
    if not args:
        err("Usage: todo <id>  (1-200)"); return
    try:
        tid = int(args[0])
    except ValueError:
        err("todo_id must be an integer"); return
    d = _r(await client.call_tool("get_todo", {"todo_id": tid, "session_token": state.token or ""}))
    if d.get("status") == "error":
        err(d["message"]); return
    auth = d.get("authenticated", False)
    info(f"resource: {c(f'/todos/{tid}', CYAN)}  |  authenticated: {c(auth, GREEN if auth else YELLOW)}")
    if not auth:
        sep(); _print_encrypted(d.get("data", "")); return
    _print_todo(d.get("data", {}))
    info(f"hmac: {c(d.get('hmac_signature','')[:20], DIM)}…  (run 'sign todo {tid}' to save)")


async def cmd_sign(client, state, args):
    if len(args) < 2:
        err("Usage: sign <type> <id>   (type: user | post | todo)"); return
    if not state.authenticated:
        err("You must be logged in to sign a resource."); return
    rtype, rid_str = args[0], args[1]
    try:
        rid = int(rid_str)
    except ValueError:
        err("id must be an integer"); return

    tool_map = {"user": "get_user", "post": "get_post", "todo": "get_todo"}
    id_param  = {"user": "user_id",  "post": "post_id",  "todo": "todo_id"}
    if rtype not in tool_map:
        err(f"Unknown type '{rtype}'. Use: user, post, todo"); return

    d = _r(await client.call_tool(tool_map[rtype], {id_param[rtype]: rid, "session_token": state.token}))
    if d.get("status") == "error":
        err(d["message"]); return

    sig = d.get("hmac_signature", "")
    key = f"{rtype}:{rid}"
    state.signatures[key] = sig
    ok(f"Signature saved for {c(key, CYAN)}")
    info(f"HMAC-SHA256: {c(sig, BOLD)}")
    info(f"Now try:  tampertest {rtype} {rid}  →  verify {rtype} {rid}")


async def cmd_verify(client, state, args):
    if len(args) < 2:
        err("Usage: verify <type> <id>   (type: user | post | todo)"); return
    if not state.authenticated:
        err("Authentication required to verify integrity.")
        info("Tip: your blocked attempt has been recorded in the audit log."); return
    rtype, rid_str = args[0], args[1]
    try:
        rid = int(rid_str)
    except ValueError:
        err("id must be an integer"); return

    key = f"{rtype}:{rid}"
    if key not in state.signatures:
        err(f"No saved signature for '{key}'.  Run: {c('sign ' + rtype + ' ' + rid_str, YELLOW)}")
        return

    d = _r(await client.call_tool("verify_integrity", {
        "resource_type": rtype,
        "resource_id":   rid,
        "expected_hmac": state.signatures[key],
        "session_token": state.token,
    }))
    if d.get("status") == "error":
        err(d["message"]); return
    if d.get("intact"):
        ok(d["verdict"])
    else:
        err(d["verdict"])


async def cmd_tampertest(client, state, args):
    if len(args) < 2:
        err("Usage: tampertest <type> <id>   (type: user | post | todo)"); return
    if not state.authenticated:
        err("You must be logged in."); return
    rtype, rid_str = args[0], args[1]
    try:
        rid = int(rid_str)
    except ValueError:
        err("id must be an integer"); return

    key = f"{rtype}:{rid}"
    if key not in state.signatures:
        err(f"No saved signature for '{key}'.  Run: {c('sign ' + rtype + ' ' + rid_str, YELLOW)}")
        return

    original = state.signatures[key]
    bad = original[:8] + "DEADBEEF" + original[16:]
    warn(f"Corrupting local signature for {c(key, CYAN)}:")
    info(f"  original:  {original[:24]}…")
    info(f"  corrupted: {bad[:24]}…")

    d = _r(await client.call_tool("verify_integrity", {
        "resource_type": rtype,
        "resource_id":   rid,
        "expected_hmac": bad,
        "session_token": state.token,
    }))
    if d.get("intact"):
        warn("Unexpected: check passed with corrupted signature")
    else:
        err(f"Tamper detected!  {d.get('verdict', '')}")

    state.signatures[key] = original
    info("Original signature restored.")


async def cmd_sessions(client, state, _args):
    if not state.authenticated:
        err("Authentication required."); return
    d = _r(await client.call_tool("list_active_sessions", {"session_token": state.token}))
    if d.get("status") == "error":
        err(d["message"]); return
    sessions = d.get("sessions", [])
    fmt = "  {:<12} {:<16} {:<10} {:<12} {}"
    print(c(fmt.format("TOKEN", "USERNAME", "ROLE", "AGE (s)", "EXPIRES IN (s)"), DIM))
    sep()
    for s in sessions:
        print(fmt.format(
            c(s["token_prefix"], CYAN),
            s["username"],
            s["role"],
            s["age_seconds"],
            s["expires_in_seconds"],
        ))
    info(f"Total active sessions: {c(len(sessions), BOLD)}")


async def cmd_kick(client, state, args):
    if not args:
        err("Usage: kick <username>"); return
    if not state.authenticated:
        err("Authentication required."); return
    target = args[0]
    d = _r(await client.call_tool("force_logout_user", {
        "target_username": target, "session_token": state.token
    }))
    if d.get("status") == "error":
        err(d["message"]); return
    ok(d["message"])


async def cmd_failed_auth(client, state, _args):
    if not state.authenticated:
        err("Authentication required."); return
    d = _r(await client.call_tool("get_failed_auth_attempts", {"session_token": state.token}))
    if d.get("status") == "error":
        err(d["message"]); return
    entries = d.get("log", [])
    info(f"Failed auth attempts: {c(len(entries), BOLD)}")
    sep()
    if not entries:
        ok("No failed authentication attempts recorded."); return
    for line in entries:
        print(f"  {c(line, RED)}")


async def cmd_delete(client, state, args):
    if len(args) < 2:
        err("Usage: delete <type> <id>   (type: user | post | todo)"); return
    if not state.authenticated:
        err("Authentication required."); return
    rtype, rid_str = args[0], args[1]
    try:
        rid = int(rid_str)
    except ValueError:
        err("id must be an integer"); return

    tool_map = {"user": "delete_user", "post": "delete_post", "todo": "delete_todo"}
    id_param  = {"user": "user_id",    "post": "post_id",     "todo": "todo_id"}
    if rtype not in tool_map:
        err(f"Unknown type '{rtype}'. Use: user, post, todo"); return

    d = _r(await client.call_tool(tool_map[rtype], {id_param[rtype]: rid, "session_token": state.token}))
    if d.get("status") == "error":
        err(d["message"]); return
    warn(d["message"])


async def cmd_restore(client, state, _args):
    if not state.authenticated:
        err("Authentication required."); return
    d = _r(await client.call_tool("restore_all", {"session_token": state.token}))
    if d.get("status") == "error":
        err(d["message"]); return
    ok(d["message"])
    restored = d.get("restored", {})
    for resource, count in restored.items():
        info(f"  {resource}: {count} item(s) undeleted")


async def cmd_files(client, state, _args):
    if not state.authenticated:
        err("Authentication required."); return
    d = _r(await client.call_tool("list_files", {"session_token": state.token}))
    if d.get("status") == "error":
        err(d["message"]); return
    files = d.get("files", [])
    fmt = "  {:<28} {:<10} {:<20} {}"
    print(c(fmt.format("NAME", "SIZE", "SHA256", "INTEGRITY"), DIM))
    sep()
    for f in files:
        intact = f.get("intact")
        if intact is True:
            tag = c("intact", GREEN)
        elif intact is False:
            tag = c("TAMPERED", RED + BOLD)
        else:
            tag = c("new file", YELLOW)
        print(fmt.format(
            c(f["name"], CYAN),
            str(f["size_bytes"]) + "B",
            f.get("sha256", ""),
            tag,
        ))


async def cmd_file(client, state, args):
    if not args:
        err("Usage: file <name>"); return
    if not state.authenticated:
        err("Authentication required."); return
    filename = args[0]
    d = _r(await client.call_tool("read_file", {"filename": filename, "session_token": state.token}))
    if d.get("status") == "error":
        err(d["message"]); return
    intact = d.get("intact")
    intact_tag = (c("intact", GREEN) if intact is True
                  else c("TAMPERED", RED + BOLD) if intact is False
                  else c("new file", YELLOW))
    info(f"file: {c(filename, CYAN)}  |  integrity: {intact_tag}")
    sep()
    for line in d.get("content", "").splitlines():
        print(f"  {line}")
    info(f"sha256: {c(d.get('sha256', '')[:20], DIM)}…")


async def cmd_writefile(client, state, args):
    if len(args) < 2:
        err("Usage: writefile <name> <content>"); return
    if not state.authenticated:
        err("Authentication required."); return
    filename, content = args[0], " ".join(args[1:])
    d = _r(await client.call_tool("write_file", {
        "filename": filename, "content": content, "session_token": state.token
    }))
    if d.get("status") == "error":
        err(d["message"]); return
    warn(d["message"])
    info(f"sha256: {c(d.get('sha256', '')[:20], DIM)}…")
    info(f"Run: checkfile {filename}  to confirm tamper detection")


async def cmd_deletefile(client, state, args):
    if not args:
        err("Usage: deletefile <name>"); return
    if not state.authenticated:
        err("Authentication required."); return
    filename = args[0]
    d = _r(await client.call_tool("delete_file", {"filename": filename, "session_token": state.token}))
    if d.get("status") == "error":
        err(d["message"]); return
    warn(d["message"])


async def cmd_checkfile(client, state, args):
    if not args:
        err("Usage: checkfile <name>"); return
    if not state.authenticated:
        err("Authentication required."); return
    filename = args[0]
    d = _r(await client.call_tool("check_file_integrity", {
        "filename": filename, "session_token": state.token
    }))
    if d.get("status") == "error":
        err(d["message"]); return
    intact = d.get("intact")
    if intact is True:
        ok(f"{c(filename, CYAN)} is intact — SHA-256 matches original.")
    elif intact is False:
        err(f"TAMPERED: {c(filename, CYAN)} does not match original!")
        info(f"  current:  {d.get('current_sha256', '')[:32]}…")
        info(f"  original: {d.get('original_sha256', '')[:32]}…")
        info(f"  Run: repairfile {filename}  to restore")
    else:
        warn(f"{c(filename, CYAN)} is a new file — no original to compare against.")


async def cmd_scanfiles(client, state, _args):
    if not state.authenticated:
        err("Authentication required."); return
    d = _r(await client.call_tool("detect_tampered_files", {"session_token": state.token}))
    if d.get("status") == "error":
        err(d["message"]); return
    tampered = d.get("tampered_files", [])
    if not tampered:
        ok(d["verdict"])
    else:
        err(d["verdict"])
        for name in tampered:
            print(f"    {c('→', RED)} {c(name, CYAN)}")
        info("Run: resetfiles  to restore all  |  repairfile <name>  for one file")


async def cmd_repairfile(client, state, args):
    if not args:
        err("Usage: repairfile <name>"); return
    if not state.authenticated:
        err("Authentication required."); return
    filename = args[0]
    d = _r(await client.call_tool("repair_file", {"filename": filename, "session_token": state.token}))
    if d.get("status") == "error":
        err(d["message"]); return
    ok(d["message"])


async def cmd_resetfiles(client, state, _args):
    if not state.authenticated:
        err("Authentication required."); return
    d = _r(await client.call_tool("reset_files", {"session_token": state.token}))
    if d.get("status") == "error":
        err(d["message"]); return
    ok(d["message"])
    for name in d.get("files", []):
        info(f"  restored: {c(name, CYAN)}")


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
            for key, sig in state.signatures.items():
                info(f"  {c(key, CYAN):<36} {c(sig[:16], DIM)}…")
    else:
        warn("Not authenticated — all responses are AES-256 encrypted")


def cmd_help(_c, _s, _a):
    print(textwrap.dedent(f"""
  {c('COMMANDS', BOLD + CYAN)}

  {c('Authentication', BOLD)}
    {c('login <user> <pass>', YELLOW)}          Authenticate and open a session
    {c('logout', YELLOW)}                      End your session

  {c('Resources  (encrypted when logged out)', BOLD)}
    {c('users', YELLOW)}                        List all users
    {c('user <id>', YELLOW)}                    Get a single user  (id: 1-10)
    {c('posts [<user_id>]', YELLOW)}            List posts, optionally filtered by user
    {c('post <id>', YELLOW)}                    Get a single post  (id: 1-100)
    {c('todos [<user_id>]', YELLOW)}            List todos, optionally filtered by user
    {c('todo <id>', YELLOW)}                    Get a single todo  (id: 1-200)

  {c('Delete / Restore  (auth required)', BOLD)}
    {c('delete user <id>', YELLOW)}             Soft-delete a user
    {c('delete post <id>', YELLOW)}             Soft-delete a post
    {c('delete todo <id>', YELLOW)}             Soft-delete a todo
    {c('restore', YELLOW)}                      Restore all soft-deleted resources  [admin]

  {c('File integrity  (auth required)', BOLD)}
    {c('list / files', YELLOW)}                 List demo files with integrity status
    {c('file <name>', YELLOW)}                  Read a file with integrity check
    {c('writefile <name> <content>', YELLOW)}   Write/overwrite a file (simulates tampering)
    {c('deletefile <name>', YELLOW)}            Delete a file
    {c('checkfile <name>', YELLOW)}             Check one file's SHA-256 against original
    {c('scanfiles', YELLOW)}                    Scan all files and report tampered ones
    {c('repairfile <name>', YELLOW)}            Restore one file to original  [admin]
    {c('resetfiles', YELLOW)}                   Restore all files to original  [admin]

  {c('API Integrity  (HMAC)', BOLD)}
    {c('sign <type> <id>', YELLOW)}             Save a resource HMAC-SHA256 signature
    {c('verify <type> <id>', YELLOW)}           Re-fetch and verify the HMAC
    {c('tampertest <type> <id>', YELLOW)}       Corrupt the signature to trigger detection

  {c('Audit  (auth required)', BOLD)}
    {c('audit', YELLOW)}                        Show unauthorized access attempts
    {c('audit --all', YELLOW)}                  Show all access attempts
    {c('failed-auth', YELLOW)}                  Show failed login attempts  [admin]

  {c('Session management  (admin only)', BOLD)}
    {c('sessions', YELLOW)}                     List all active sessions
    {c('kick <username>', YELLOW)}              Force-logout all sessions for a user

  {c('Other', BOLD)}
    {c('status', YELLOW)}                       Show your session and saved signatures
    {c('help', YELLOW)}                         Show this message
    {c('exit', YELLOW)}                         Quit

  {c('SUGGESTED FLOWS', BOLD)}

  See encryption in action:
    {c('users', YELLOW)}                        → encrypted list
    {c('user 3', YELLOW)}                       → encrypted profile
    {c('login admin admin123', YELLOW)}         → get session
    {c('users', YELLOW)}  {c('user 3', YELLOW)}               → plaintext

  Test soft-delete and restore:
    {c('login admin admin123', YELLOW)}
    {c('delete user 5', YELLOW)}               → user 5 removed from list
    {c('users', YELLOW)}                        → 9 users visible
    {c('restore', YELLOW)}                      → all 10 users back

  Test integrity protection:
    {c('sign user 3', YELLOW)}                  → save HMAC
    {c('verify user 3', YELLOW)}                → intact ✓
    {c('tampertest user 3', YELLOW)}            → tamper detected ✗

  Test file integrity monitoring:
    {c('login admin admin123', YELLOW)}
    {c('files', YELLOW)}                        → all 5 files intact
    {c('writefile secrets.env HACKED', YELLOW)} → tamper a file
    {c('scanfiles', YELLOW)}                    → secrets.env reported TAMPERED
    {c('checkfile secrets.env', YELLOW)}        → SHA mismatch shown
    {c('repairfile secrets.env', YELLOW)}       → restored to original
    {c('scanfiles', YELLOW)}                    → all files intact again

  Test access control:
    {c('logout', YELLOW)}
    {c('todos 1', YELLOW)}                      → encrypted + logged
    {c('login admin admin123', YELLOW)}
    {c('audit', YELLOW)}                        → see the unauthorized attempts
    {c('failed-auth', YELLOW)}                  → see failed logins
    """))


# ── Command registry ──────────────────────────────────────────────────────────
COMMANDS = {
    "login":       cmd_login,
    "logout":      cmd_logout,
    "users":       cmd_users,
    "user":        cmd_user,
    "posts":       cmd_posts,
    "post":        cmd_post,
    "todos":       cmd_todos,
    "todo":        cmd_todo,
    "sign":        cmd_sign,
    "verify":      cmd_verify,
    "tampertest":  cmd_tampertest,
    "audit":       cmd_audit,
    "sessions":    cmd_sessions,
    "kick":        cmd_kick,
    "failed-auth": cmd_failed_auth,
    "delete":      cmd_delete,
    "restore":     cmd_restore,
    "list":        cmd_files,
    "files":       cmd_files,
    "file":        cmd_file,
    "writefile":   cmd_writefile,
    "deletefile":  cmd_deletefile,
    "checkfile":   cmd_checkfile,
    "scanfiles":   cmd_scanfiles,
    "repairfile":  cmd_repairfile,
    "resetfiles":  cmd_resetfiles,
    "status":      cmd_status,
    "help":        cmd_help,
}


# ── REPL ──────────────────────────────────────────────────────────────────────
async def repl(server_url: str) -> None:
    print(f"""
{c('═' * 70, CYAN)}
{c('  MCP Security Gateway  —  Interactive Shell', BOLD + CYAN)}
{c('═' * 70, CYAN)}

  Gateway : {c(server_url, CYAN)}
  Backend : {c('https://jsonplaceholder.typicode.com', CYAN)}

  {c('Resources proxied through the gateway:', BOLD)}
    users   — 10 users with contact details, addresses, and companies
    posts   — 100 blog posts across all users
    todos   — 200 tasks across all users

  {c('Type  help  to see all commands.', DIM)}
  {c('Quick start:  users  →  user 1  →  login admin admin123  →  repeat', DIM)}
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
    parser = argparse.ArgumentParser(description="MCP Security Gateway interactive shell")
    parser.add_argument("--url", default="http://127.0.0.1:8000/mcp")
    args = parser.parse_args()
    asyncio.run(repl(args.url))


if __name__ == "__main__":
    main()
