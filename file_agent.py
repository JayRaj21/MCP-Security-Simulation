"""
Interactive File Agent — you are the malicious agent.

Simulates an attacker with local access trying to read, modify, and destroy
MCP-related configuration and data files in the test_files/ directory.

Security OFF — all operations succeed freely.
Security ON  — write and delete operations are blocked by HMAC-SHA256
               integrity seals. Use 'toggle' to switch at any time.

On every program startup, deleted or modified test files are restored to
their original state automatically.
"""

import hmac as _hmac
import json
from pathlib import Path

from security import SHARED_SECRET

# ─── ANSI colours ────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

TEST_DIR = Path(__file__).parent / "test_files"

# ─── Reference file content ───────────────────────────────────────────────────
# Ground-truth versions. Any deleted or modified files are restored to this
# content on every startup.

ORIGINAL_FILES: dict[str, str] = {
    "config.json": json.dumps(
        {
            "server":       "mcp-prod-01.internal",
            "port":         8081,
            "api_key":      "sk-prod-a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5",
            "database_url": "postgres://admin:s3cr3t@db.internal:5432/mcpdb",
            "debug":        False,
        },
        indent=2,
    ),
    "user_database.csv": (
        "user_id,name,email,role,api_token\n"
        "user-42,Alice Smith,alice@example.com,admin,tok_a1b2c3d4\n"
        "user-17,Bob Jones,bob@example.com,user,tok_b2c3d4e5\n"
        "user-99,Carol Davis,carol@example.com,superadmin,tok_c3d4e5f6\n"
    ),
    "secrets.env": (
        "# Production credentials — DO NOT SHARE\n"
        "JWT_SECRET=8f14e45fceea167a5a36dedd4bea2543\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "STRIPE_SECRET_KEY=sk_live_DEMO_FAKE_KEY_NOT_REAL\n"
        "ENCRYPTION_KEY=AES256:b94f8c2e3a1d7f6b9e2c5a8d3f1b4e7a\n"
    ),
    "audit_log.txt": (
        "[2024-01-15 09:23:11] LOGIN    user-42  (alice@example.com)   SUCCESS\n"
        "[2024-01-15 09:24:55] ACCESS   user-42  /admin/users          READ\n"
        "[2024-01-15 10:01:33] TRANSFER user-17  $500 → acct-222       CONFIRMED\n"
        "[2024-01-15 10:45:22] LOGIN    user-99  (carol@example.com)   SUCCESS\n"
        "[2024-01-15 11:12:08] CONFIG   user-99  server_config         MODIFIED\n"
    ),
}

NAMES = list(ORIGINAL_FILES.keys())


# ─── HMAC integrity helpers ──────────────────────────────────────────────────

def _file_hmac(content: str) -> str:
    return _hmac.new(SHARED_SECRET, content.encode("utf-8"), "sha256").hexdigest()

def _sig_path(name: str) -> Path:
    return TEST_DIR / f".{name}.sig"

def _seal(name: str, content: str) -> None:
    _sig_path(name).write_text(_file_hmac(content))

def _unseal(name: str) -> None:
    sp = _sig_path(name)
    if sp.exists():
        sp.unlink()

def _is_sealed(name: str) -> bool:
    path = TEST_DIR / name
    sp   = _sig_path(name)
    if not path.exists() or not sp.exists():
        return False
    return _hmac.compare_digest(
        _file_hmac(path.read_text()),
        sp.read_text().strip(),
    )


# ─── Startup restoration ─────────────────────────────────────────────────────

def restore_test_files(security_enabled: bool) -> None:
    """Restore any missing or modified test files. Seal them if security is on."""
    TEST_DIR.mkdir(exist_ok=True)
    created  = []
    restored = []

    for name, content in ORIGINAL_FILES.items():
        path    = TEST_DIR / name
        current = path.read_text() if path.exists() else None

        if current is None:
            path.write_text(content)
            created.append(name)
        elif current != content:
            path.write_text(content)
            restored.append(name)

        if security_enabled:
            _seal(name, content)
        else:
            _unseal(name)

    tag = f"{CYAN}[FILE AGENT]{RESET}"
    if created:
        print(f"{tag} Created  : {', '.join(created)}")
    if restored:
        print(f"{tag} Restored : {', '.join(restored)}")
    if not created and not restored:
        print(f"{tag} All test files intact.")
    if security_enabled:
        print(f"{tag} Files sealed with HMAC-SHA256.")
    print()


# ─── Toggle ──────────────────────────────────────────────────────────────────

def _cmd_toggle(state: dict) -> None:
    """Flip the security flag and (un)seal all files accordingly."""
    state["security"] = not state["security"]
    security = state["security"]

    if security:
        sealed = []
        for name in NAMES:
            path = TEST_DIR / name
            if path.exists():
                _seal(name, path.read_text())
                sealed.append(name)
        print(f"\n{GREEN}{BOLD}  Security ON — HMAC-SHA256 seals applied.{RESET}")
        print(f"  Write and delete operations are now blocked.")
        for name in sealed:
            print(f"{GREEN}    ✓ {name}{RESET}")
    else:
        for name in NAMES:
            _unseal(name)
        print(f"\n{RED}{BOLD}  Security OFF — integrity seals removed.{RESET}")
        print(f"  Files are unprotected. You can freely modify or delete them.")

    print()


# ─── Individual commands ─────────────────────────────────────────────────────

def _cmd_list(security_enabled: bool) -> None:
    print(f"\n  {'FILE':<26} {'SIZE':>7}  STATUS")
    print(f"  {'─'*26} {'─'*7}  {'─'*30}")

    for name in NAMES:
        path = TEST_DIR / name
        if not path.exists():
            print(f"  {name:<26} {'':>7}  {RED}DELETED{RESET}")
            continue

        content = path.read_text()
        size    = len(content.encode())
        intact  = content == ORIGINAL_FILES[name]
        state   = f"{GREEN}intact{RESET}" if intact else f"{YELLOW}modified{RESET}"

        if security_enabled:
            sealed = _is_sealed(name)
            seal_s = f"{GREEN}sealed ✓{RESET}" if sealed else f"{RED}seal broken ✗{RESET}"
            print(f"  {name:<26} {size:>6}B  {state}  |  {seal_s}")
        else:
            print(f"  {name:<26} {size:>6}B  {state}")

    print()


def _cmd_read(args: list[str]) -> None:
    if not args:
        print(f"{RED}  Usage: read <filename>{RESET}\n")
        return
    name = args[0]
    if name not in ORIGINAL_FILES:
        print(f"{RED}  '{name}' is not a test file. Use 'list' to see available files.{RESET}\n")
        return
    path = TEST_DIR / name
    if not path.exists():
        print(f"{RED}  '{name}' has been deleted.{RESET}\n")
        return
    print(f"\n{DIM}  ── {name} {'─' * max(0, 52 - len(name))}{RESET}")
    for line in path.read_text().splitlines():
        print(f"  {line}")
    print(f"{DIM}  {'─'*56}{RESET}\n")


def _cmd_modify(args: list[str], security_enabled: bool) -> None:
    if len(args) < 2:
        print(f"{RED}  Usage: modify <filename> <new content>{RESET}\n")
        return
    name, content = args[0], args[1]
    if name not in ORIGINAL_FILES:
        print(f"{RED}  '{name}' is not a test file. Use 'list' to see available files.{RESET}\n")
        return

    if security_enabled:
        print(f"{RED}{BOLD}  [BLOCKED]{RESET} Cannot modify '{name}'.")
        print(f"  The file is sealed with HMAC-SHA256.")
        print(f"  Modification requires the shared secret key — which you don't have.\n")
        return

    (TEST_DIR / name).write_text(content)
    print(f"{YELLOW}  [MODIFIED]{RESET} '{name}' overwritten ({len(content.encode())} bytes).\n")


def _cmd_append(args: list[str], security_enabled: bool) -> None:
    if len(args) < 2:
        print(f"{RED}  Usage: append <filename> <content>{RESET}\n")
        return
    name, content = args[0], args[1]
    if name not in ORIGINAL_FILES:
        print(f"{RED}  '{name}' is not a test file.{RESET}\n")
        return

    if security_enabled:
        print(f"{RED}{BOLD}  [BLOCKED]{RESET} Cannot append to '{name}'.")
        print(f"  The file is sealed with HMAC-SHA256.")
        print(f"  Modification requires the shared secret key — which you don't have.\n")
        return

    path = TEST_DIR / name
    if not path.exists():
        print(f"{RED}  '{name}' does not exist (was it deleted?).{RESET}\n")
        return
    line = content if content.endswith("\n") else content + "\n"
    with path.open("a") as f:
        f.write(line)
    print(f"{YELLOW}  [APPENDED]{RESET} Line appended to '{name}'.\n")


def _cmd_delete(args: list[str], security_enabled: bool) -> None:
    if not args:
        print(f"{RED}  Usage: delete <filename>{RESET}\n")
        return
    name = args[0]
    if name not in ORIGINAL_FILES:
        print(f"{RED}  '{name}' is not a test file.{RESET}\n")
        return

    if security_enabled:
        print(f"{RED}{BOLD}  [BLOCKED]{RESET} Cannot delete '{name}'.")
        print(f"  The file is sealed with HMAC-SHA256.")
        print(f"  Deletion requires the shared secret key — which you don't have.\n")
        return

    path = TEST_DIR / name
    if not path.exists():
        print(f"{YELLOW}  '{name}' is already deleted.{RESET}\n")
        return
    path.unlink()
    print(f"{RED}  [DELETED]{RESET} '{name}' removed from disk.\n")


def _cmd_status(security_enabled: bool) -> None:
    mode = (
        f"{GREEN}SECURE — files are HMAC-sealed{RESET}"
        if security_enabled
        else f"{RED}INSECURE — no integrity protection{RESET}"
    )
    print(f"\n  Security: {mode}\n")

    if security_enabled:
        print(f"  {'FILE':<26} INTEGRITY")
        print(f"  {'─'*26} {'─'*30}")
        for name in NAMES:
            path = TEST_DIR / name
            if not path.exists():
                verdict = f"{RED}FILE DELETED — seal invalidated{RESET}"
            elif _is_sealed(name):
                verdict = f"{GREEN}✓ signature valid{RESET}"
            else:
                verdict = f"{RED}✗ signature mismatch — tampered outside CLI{RESET}"
            print(f"  {name:<26} {verdict}")
    else:
        print("  No signatures in use. Any file can be freely modified or deleted.")

    print()


# ─── Main REPL ───────────────────────────────────────────────────────────────

def _help(security_enabled: bool) -> None:
    toggle_hint = (
        f"    {BOLD}toggle{RESET}                        turn security {RED}OFF{RESET} — remove HMAC seals"
        if security_enabled
        else f"    {BOLD}toggle{RESET}                        turn security {GREEN}ON{RESET}  — apply HMAC seals"
    )
    print(f"""
  {BOLD}Commands:{RESET}
    list                          list test files and their status
    read   <file>                 print file contents to screen
    modify <file> <new content>   overwrite the entire file
    append <file> <content>       add a line to the end of a file
    delete <file>                 delete a file from disk
    status                        show security mode and file integrity
{toggle_hint}
    help                          show this message
    exit                          quit

  {BOLD}Test files:{RESET}
    {BOLD}config.json{RESET}       server config with API keys and DB credentials
    {BOLD}user_database.csv{RESET} user records, roles, and API tokens
    {BOLD}secrets.env{RESET}       production credentials and encryption keys
    {BOLD}audit_log.txt{RESET}     access and transaction log

  {BOLD}Attack ideas (try with security OFF):{RESET}
    append audit_log.txt [2024-01-15 13:00:00] TRANSFER user-42 $99999 CONFIRMED
    modify secrets.env JWT_SECRET=attacker_controlled_secret
    delete user_database.csv
    modify config.json {{"server":"attacker.evil","api_key":"stolen"}}
""")


def _prompt(security_enabled: bool) -> str:
    seal = f"{GREEN}SECURE{RESET}" if security_enabled else f"{RED}INSECURE{RESET}"
    return f"{RED}[ATTACKER | {seal}{RED}]{RESET} > "


def run_interactive(security_enabled: bool) -> None:
    """Start the interactive file agent REPL."""
    state = {"security": security_enabled}

    mode_str = (
        f"{GREEN}SECURE (HMAC-SHA256 active){RESET}"
        if security_enabled
        else f"{RED}INSECURE (no protection){RESET}"
    )

    print(f"\n{BOLD}{'═'*65}")
    print(f"  MCP SECURITY SIMULATION  —  {mode_str}")
    print(f"{'═'*65}{RESET}")
    print()
    print(f"  You are the malicious agent. The test_files/ directory contains")
    print(f"  sensitive MCP server files. Try to read, modify, and delete them.")
    print(f"  Use {BOLD}toggle{RESET} to switch security on or off at any time.")
    print()

    if security_enabled:
        print(f"  {GREEN}{BOLD}Security is ON.{RESET} Files are HMAC-sealed.")
        print(f"  You can READ files — but writes and deletes are blocked.")
    else:
        print(f"  {RED}{BOLD}Security is OFF.{RESET} Files are unprotected.")
        print(f"  You can freely modify or delete anything.")

    print()
    print(f"  Type {BOLD}help{RESET} to see all commands and attack ideas.")
    print()

    restore_test_files(state["security"])

    while True:
        try:
            raw = input(_prompt(state["security"])).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not raw:
            continue

        parts = raw.split(None, 2)
        cmd   = parts[0].lower()
        args  = parts[1:]

        if cmd in ("exit", "quit"):
            print(f"\n  Goodbye.\n")
            break
        elif cmd == "help":
            _help(state["security"])
        elif cmd == "toggle":
            _cmd_toggle(state)
        elif cmd == "list":
            _cmd_list(state["security"])
        elif cmd == "status":
            _cmd_status(state["security"])
        elif cmd == "read":
            _cmd_read(args)
        elif cmd == "modify":
            _cmd_modify(args, state["security"])
        elif cmd == "append":
            _cmd_append(args, state["security"])
        elif cmd == "delete":
            _cmd_delete(args, state["security"])
        else:
            print(f"  Unknown command '{cmd}'. Type 'help' for available commands.\n")
