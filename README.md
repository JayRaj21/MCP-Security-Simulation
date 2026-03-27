# MCP Security Simulation

A demonstration of man-in-the-middle (MITM) vulnerabilities in standard MCP (Model Context Protocol) servers, and how HMAC-SHA256 message signing addresses them.

## Quick Start

**Prerequisites:** Python 3.8 or newer. No other tools needed.

```bash
# Clone the repo
git clone https://github.com/JayRaj21/MCP-Security-Simulation.git
cd MCP-Security-Simulation

# Run the insecure demo (attacks succeed)
python3 run.py

# Run the secure demo (attacks blocked)
python3 run.py --security
```

> **Windows users:** replace `python3` with `python` in all commands.

`run.py` handles everything automatically — it creates a virtual environment and installs dependencies on first run, then launches the demo. No manual setup required.

---

## What this demonstrates

MCP servers communicate over HTTP without built-in message integrity guarantees. A MITM attacker positioned between the client and server can:

| Attack | Effect |
|--------|--------|
| **Tool Injection** | Add malicious tools to the server's tool catalogue |
| **Response Tampering** | Modify results returned by tools (e.g. skim financial calculations) |
| **Request Tampering** | Alter requests before they reach the server (e.g. redirect bank transfers) |
| **Data Exfiltration** | Read all sensitive data passing through (user profiles, balances, etc.) |

The security layer adds **HMAC-SHA256 message signing** to every request and response. Any modification by the MITM invalidates the signature, and the client or server detects and rejects the tampered message.

## Architecture

```
┌─────────────┐     ┌──────────────────────┐     ┌──────────────┐
│  MCP Client │────▶│  MITM Proxy :8080    │────▶│  MCP Server  │
│  (demo.py)  │◀────│  (mitm_proxy.py)     │◀────│  :8081       │
└─────────────┘     │  reads, modifies,    │     │  (mcp_server │
                    │  injects, exfiltrates│     │  .py)        │
                    └──────────────────────┘     └──────────────┘

The client connects to the MITM on port 8080, thinking it is the real server.
```

## How to toggle security

The `--security` flag is the only switch needed:

```bash
python3 run.py              # No signing — all attacks succeed
python3 run.py --security   # HMAC-SHA256 signing — attacks blocked
```

| Flag | What changes |
|------|-------------|
| *(absent)* | No signing anywhere — MITM can freely tamper with everything |
| `--security` | Client signs requests, server verifies them; server signs responses, client verifies them |

The MITM proxy **always attempts all attacks** in both modes. The difference is whether the client and server detect and reject them.

## Security mechanism

Every message is signed with **HMAC-SHA256** using a shared secret:

```
signature = HMAC-SHA256(shared_secret, canonical_json(payload))
```

- **Client** signs all requests before sending
- **Server** verifies request signatures and rejects invalid ones (HTTP 401)
- **Server** signs all responses before returning
- **Client** verifies response signatures and raises `SecurityError` on failure

The MITM has no access to the shared secret, so it cannot forge a valid signature for any message it tampers with.

### Key limitation: confidentiality

HMAC signing guarantees **integrity** (tampering is detected) but not **confidentiality** (the MITM can still *read* all data). The exfiltration attack succeeds even with signing enabled. TLS encryption is required to prevent eavesdropping — this is shown explicitly in Scenario 4.

## Project structure

```
MCP-Security-Simulation/
├── run.py           # One-command launcher (handles venv + deps automatically)
├── demo.py          # Main demo script — orchestrates all servers and scenarios
├── mcp_server.py    # Simulated MCP server (port 8081)
├── mitm_proxy.py    # Malicious MITM proxy (port 8080)
├── mcp_client.py    # MCP client library used by the demo
├── security.py      # HMAC-SHA256 signing and verification
└── requirements.txt
```

## Example output

### Insecure mode

```
  SCENARIO 1 — Tool Injection
  [MITM] Intercepted GET /mcp/tools/list
  [ATTACK] ⚠  TOOL INJECTION: Appended 'system_shell' to tool list
  [ATTACK SUCCEEDED] Client received 5 tools — 'system_shell' was INJECTED!
    • calculator
    • weather
    • bank_transfer
    • user_lookup
    • system_shell  ← INJECTED by MITM
```

### Secure mode

```
  SCENARIO 1 — Tool Injection
  [MITM] Intercepted GET /mcp/tools/list
  [ATTACK] ⚠  TOOL INJECTION: Appended 'system_shell' to tool list
  [CLIENT] Verifying tools/list response signature…
  [BLOCKED] Tool list signature verification FAILED — response was tampered with
```

## Limitations and next steps

- **No TLS** — the demo uses plain HTTP. Adding TLS would prevent eavesdropping (Scenario 4).
- **No replay protection** — a captured valid message could be replayed. Adding a nonce + timestamp to the signed payload and tracking seen nonces server-side would address this.
- **Symmetric key** — both sides share the same secret. Asymmetric signing (RSA/ECDSA) would allow the server to publish a public key, removing the need to pre-share a secret.
- **Simplified MCP** — real MCP uses JSON-RPC over stdio or SSE. The HTTP API here is representative but not spec-compliant.
