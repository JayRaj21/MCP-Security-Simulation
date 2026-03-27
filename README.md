# MCP Security Simulation

A demonstration of man-in-the-middle (MITM) vulnerabilities in standard MCP (Model Context Protocol) servers, and how HMAC-SHA256 message signing addresses them.

## Quick Start

**Prerequisites:** Python 3.8 or newer. No other tools needed.

```bash
# Clone the repo
git clone https://github.com/JayRaj21/MCP-Security-Simulation.git
cd MCP-Security-Simulation

# Run the MITM demo — insecure (attacks succeed)
python3 run.py

# Run the MITM demo — secure (attacks blocked)
python3 run.py --security

# Become the malicious agent — manipulate files interactively (no security)
python3 run.py --interactive

# Become the malicious agent — with security active (operations blocked)
python3 run.py --interactive --security
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

## Modes

### MITM network demo (default)

Watch automated attack scenarios play out between client, MITM proxy, and server.

```bash
python3 run.py              # attacks succeed
python3 run.py --security   # attacks blocked
```

### Interactive file agent

You become the attacker. The `test_files/` directory contains fake MCP server credentials, user records, and logs. Try to steal, modify, or destroy them.

```bash
python3 run.py --interactive            # no protection — do whatever you want
python3 run.py --interactive --security # files are HMAC-sealed — writes blocked
```

**Available commands in interactive mode:**

| Command | Description |
|---------|-------------|
| `list` | Show all test files and their integrity status |
| `read <file>` | Print a file's contents |
| `modify <file> <content>` | Overwrite a file with new content |
| `append <file> <content>` | Add a line to a file |
| `delete <file>` | Delete a file from disk |
| `status` | Show security mode and HMAC seal status for each file |
| `help` | Show all commands and attack ideas |
| `exit` | Leave interactive mode |

**Test files:**

| File | Contents |
|------|----------|
| `config.json` | Server config with API keys and database credentials |
| `user_database.csv` | User records, roles, and API tokens |
| `secrets.env` | Production credentials and encryption keys |
| `audit_log.txt` | Access and transaction audit log |

Every time the program starts, any deleted or modified files are automatically restored to their original state.

## How to toggle security

The `--security` flag works the same way in both modes:

| Flag | MITM demo | Interactive file agent |
|------|-----------|----------------------|
| *(absent)* | MITM tampers freely, client accepts everything | Files unprotected — modify and delete anything |
| `--security` | Tampered messages rejected by client/server | Files sealed with HMAC-SHA256 — writes and deletes blocked |

The attacks are always *attempted* — security determines whether they succeed.

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
├── demo.py          # Entry point — MITM demo and interactive file agent
├── mcp_server.py    # Simulated MCP server (port 8081)
├── mitm_proxy.py    # Malicious MITM proxy (port 8080)
├── mcp_client.py    # MCP client library
├── file_agent.py    # Interactive file manipulation agent
├── security.py      # HMAC-SHA256 signing and verification (shared by all)
├── test_files/      # Auto-created — the files you try to attack
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
