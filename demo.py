"""
MCP Security Simulation — Main Demo Script

Demonstrates how a MITM agent intercepts and manipulates MCP traffic,
and how HMAC-SHA256 message signing prevents these attacks.

Usage:
    python demo.py              # Insecure mode — all attacks succeed
    python demo.py --security   # Secure mode  — attacks are blocked

Architecture:
    Client (this script)
        ↓  connects to port 8080 (thinking it's the real server)
    MITM Proxy (mitm_proxy.py) — intercepts, reads, modifies messages
        ↓  proxies to port 8081 (the real server)
    MCP Server (mcp_server.py) — processes legitimate tool calls
"""
import argparse
import sys
import threading
import time

from werkzeug.serving import make_server

import mcp_client
import mcp_server
import mitm_proxy
from mcp_client import MCPClient, SecurityError

# ─── ANSI colours ────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def banner(text: str, color: str = BOLD, width: int = 65) -> None:
    print(f"\n{color}{'═' * width}")
    print(f"  {text}")
    print(f"{'═' * width}{RESET}")


def section(title: str) -> None:
    print(f"\n{CYAN}{'─' * 65}")
    print(f"  {title}")
    print(f"{'─' * 65}{RESET}")


def ok(msg: str)      -> None: print(f"{GREEN}  ✓  {msg}{RESET}")
def fail(msg: str)    -> None: print(f"{RED}  ✗  {msg}{RESET}")
def warn(msg: str)    -> None: print(f"{YELLOW}  ⚠  {msg}{RESET}")
def blocked(msg: str) -> None: print(f"{GREEN}{BOLD}  [BLOCKED] {msg}{RESET}")
def pwned(msg: str)   -> None: print(f"{RED}{BOLD}  [ATTACK SUCCEEDED] {msg}{RESET}")


# ─── Demo scenarios ───────────────────────────────────────────────────────────

def scenario_tool_injection(client: MCPClient) -> None:
    section("SCENARIO 1 — Tool Injection")
    print(f"  Client requests the list of available tools.")
    print(f"  {DIM}MITM will inject a malicious 'system_shell' tool into the response.{RESET}\n")

    try:
        tools = client.list_tools()
        names = [t["name"] for t in tools]

        if "system_shell" in names:
            pwned(f"Client received {len(tools)} tools — 'system_shell' was INJECTED!")
            for t in tools:
                marker = f"  {RED}← INJECTED by MITM{RESET}" if t["name"] == "system_shell" else ""
                print(f"    • {t['name']}{marker}")
        else:
            ok(f"Client received {len(names)} legitimate tools: {', '.join(names)}")
            blocked("Injected tool rejected — server signature didn't match the tampered list")

    except SecurityError as exc:
        blocked(str(exc))


def scenario_response_tamper_calculator(client: MCPClient) -> None:
    section("SCENARIO 2 — Response Tampering (Calculator)")
    expression = "1000 * 1.15"
    expected   = 1150.0
    print(f"  Client calls: calculator({expression!r})")
    print(f"  Expected result: {expected}")
    print(f"  {DIM}MITM will skim 5% off the result before returning it.{RESET}\n")

    try:
        res = client.call_tool("calculator", {"expression": expression})

        if res.get("code") == 401:
            blocked("Tampered request rejected by server (HTTP 401)")
            return

        got = res.get("result")
        if got is None:
            fail(f"Tool returned an error: {res.get('error')}")
            return

        if abs(float(got) - expected) > 0.01:
            pwned(f"Result was TAMPERED — expected {expected}, got {got}")
        else:
            ok(f"Result is correct: {got}")
            blocked("Response tampering detected and rejected by client")

    except SecurityError as exc:
        blocked(str(exc))


def scenario_request_and_response_tamper_transfer(client: MCPClient) -> None:
    section("SCENARIO 3 — Request + Response Tampering (Bank Transfer)")
    amount   = 500
    from_acc = "acct-111"
    to_acc   = "acct-222"
    print(f"  Client sends: transfer ${amount} from {from_acc} to {to_acc}")
    print(
        f"  {DIM}MITM will inflate amount to ${amount * 1.5:.0f} "
        f"and redirect funds to its own account.{RESET}\n"
    )

    try:
        res = client.call_tool("bank_transfer", {
            "amount":       amount,
            "from_account": from_acc,
            "to_account":   to_acc,
        })

        if res.get("code") == 401:
            blocked("Tampered request rejected by server (HTTP 401) — funds protected")
            return

        txn = res.get("result", {})
        got_amount  = txn.get("amount", 0)
        got_to      = txn.get("to_account", "")
        got_txn_id  = txn.get("transaction_id", "")

        tampered = (got_amount != amount or got_to != to_acc)
        if tampered:
            pwned(f"Transfer was TAMPERED: ${got_amount} sent to '{got_to}'")
            if got_to == mitm_proxy.ATTACKER_ACCOUNT:
                fail("Funds redirected to attacker's account!")
            if got_amount != amount:
                fail(f"Amount inflated: ${amount} → ${got_amount}")
        else:
            ok(f"Transfer confirmed: ${got_amount} to {got_to} [{got_txn_id}]")
            blocked("Transfer details were integrity-protected — request rejected by server")

    except SecurityError as exc:
        blocked(str(exc))


def scenario_exfiltration_user_lookup(client: MCPClient, security: bool) -> None:
    section("SCENARIO 4 — Data Exfiltration + Response Tampering (User Lookup)")
    user_id = "user-42"
    print(f"  Client looks up profile for user '{user_id}'")
    print(
        f"  {DIM}MITM will log all sensitive data in transit "
        f"AND tamper with the returned balance.{RESET}\n"
    )

    try:
        res = client.call_tool("user_lookup", {"user_id": user_id})

        if res.get("code") == 401:
            blocked("Tampered request rejected by server (HTTP 401)")
        elif "result" in res:
            user = res["result"]
            balance = user.get("balance", "?")
            real_balance = 12450.00  # known ground truth from mcp_server.USERS

            if balance != real_balance:
                pwned(f"Balance was TAMPERED — got ${balance}, real balance is ${real_balance}")
                fail(f"Full profile received: {user}")
            else:
                ok(f"Received correct profile: name={user.get('name')}, balance=${balance}")
                blocked("Response tampering detected and rejected")
        else:
            fail(f"Lookup failed: {res.get('error')}")

    except SecurityError as exc:
        blocked(str(exc))

    # Exfiltration succeeds regardless of signing — highlight this key limitation
    print()
    warn("IMPORTANT LIMITATION:")
    if security:
        warn("Even with HMAC signing ENABLED, the MITM could still READ all data in transit.")
    else:
        warn("The MITM read all data in transit (expected — no security active).")
    warn("HMAC signing prevents TAMPERING, not EAVESDROPPING.")
    warn("TLS encryption is required to achieve confidentiality.")


# ─── Orchestration ────────────────────────────────────────────────────────────

def run_demo(security: bool) -> None:
    mode_str  = f"{GREEN}SECURE (HMAC-SHA256 active){RESET}" if security else f"{RED}INSECURE (no signing){RESET}"
    banner(f"MCP SECURITY SIMULATION  —  {mode_str}", BOLD)

    print(f"  {'─'*61}")
    print(f"  Architecture:")
    print(f"    Client → MITM Proxy (port 8080) → MCP Server (port 8081)")
    print(f"    The client connects to the MITM, not the real server.")
    print(f"  {'─'*61}\n")

    # ── Propagate security flag ──────────────────────────────────────────────
    mcp_server.SECURITY_ENABLED = security
    mcp_client.SECURITY_ENABLED = security
    # mitm_proxy deliberately never receives this flag — it has no secret key

    # ── Start servers ────────────────────────────────────────────────────────
    server_8081 = make_server("127.0.0.1", 8081, mcp_server.app)
    server_8080 = make_server("127.0.0.1", 8080, mitm_proxy.app)

    threading.Thread(target=server_8081.serve_forever, daemon=True).start()
    threading.Thread(target=server_8080.serve_forever, daemon=True).start()
    time.sleep(0.5)  # Allow both servers to bind before sending requests

    print(f"  MCP Server started on port 8081")
    print(f"  MITM Proxy started on port 8080")
    print(f"  Client connecting through MITM…\n")

    # ── Run scenarios ────────────────────────────────────────────────────────
    client = MCPClient(base_url="http://127.0.0.1:8080")

    scenario_tool_injection(client)
    scenario_response_tamper_calculator(client)
    scenario_request_and_response_tamper_transfer(client)
    scenario_exfiltration_user_lookup(client, security)

    # ── Print MITM exfiltration log ──────────────────────────────────────────
    mitm_proxy.print_exfil_summary()

    # ── Summary ──────────────────────────────────────────────────────────────
    if security:
        banner(
            f"RESULT: Integrity attacks BLOCKED by HMAC-SHA256 signing\n"
            f"  Note: data confidentiality still requires TLS",
            GREEN,
        )
    else:
        banner(
            "RESULT: All attacks SUCCEEDED — client accepted tampered data",
            RED,
        )

    # ── Cleanup ──────────────────────────────────────────────────────────────
    server_8081.shutdown()
    server_8080.shutdown()
    mitm_proxy.EXFIL_LOG.clear()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MCP Security Simulation — demonstrates MITM attacks on MCP servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python demo.py              # Show attacks succeeding (no security)\n"
            "  python demo.py --security   # Show attacks being blocked (HMAC signing)\n"
        ),
    )
    parser.add_argument(
        "--security",
        action="store_true",
        help="Enable HMAC-SHA256 message signing to demonstrate attack prevention",
    )
    args = parser.parse_args()
    run_demo(security=args.security)


if __name__ == "__main__":
    main()
