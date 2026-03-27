# MCP Security Simulation

An interactive demonstration of file integrity vulnerabilities and HMAC-SHA256 protection. You play the role of a malicious agent trying to read, modify, and destroy sensitive MCP server files — and can toggle the security layer on and off at any time to see the difference.

## Quick Start

**Prerequisites:** Python 3.8 or newer. No other tools needed.

```bash
# Clone the repo
git clone https://github.com/JayRaj21/MCP-Security-Simulation.git
cd MCP-Security-Simulation

# Start with security OFF (files unprotected)
python3 run.py

# Start with security ON (files HMAC-sealed)
python3 run.py --security
```

> **Windows users:** replace `python3` with `python` in all commands.

`run.py` handles everything automatically — it creates a virtual environment and installs dependencies on first run. No manual setup required.

**Toggle security at any time** using the `toggle` command inside the session — no need to restart.

---

## What this demonstrates

MCP server files (configs, credentials, logs) have no built-in integrity protection. A local attacker can freely read, modify, or delete them. The security layer uses **HMAC-SHA256** to seal each file with a cryptographic signature. Any attempt to write or delete a sealed file is rejected — the same mechanism used to protect network messages in MCP.

### Key limitation

HMAC signing guarantees **integrity** (tampering is blocked) but not **confidentiality** (files can still be read). This is visible in the demo — `read` always works regardless of security state. Encryption would be needed for confidentiality.

## Commands

| Command | Description |
|---------|-------------|
| `list` | Show all test files and their integrity status |
| `read <file>` | Print a file's contents to screen |
| `modify <file> <content>` | Overwrite a file entirely |
| `append <file> <content>` | Add a line to the end of a file |
| `delete <file>` | Delete a file from disk |
| `toggle` | Switch security on or off |
| `status` | Show security mode and HMAC seal status per file |
| `help` | Show all commands and attack ideas |
| `exit` | Quit |

## Test files

Created automatically in `test_files/` and restored on every startup:

| File | Contents |
|------|----------|
| `config.json` | Server config with API keys and database credentials |
| `user_database.csv` | User records, roles, and API tokens |
| `secrets.env` | Production credentials and encryption keys |
| `audit_log.txt` | Access and transaction audit log |

Any files deleted or modified in a previous session are automatically restored when the program starts again.

## How security works

When security is **ON**, each file gets a `.sig` file containing an HMAC-SHA256 hash of its content, computed with a shared secret key:

```
signature = HMAC-SHA256(shared_secret, file_content)
```

Any `modify`, `append`, or `delete` command is blocked before touching the filesystem. The attacker cannot forge a valid signature without the secret key.

When security is **OFF**, the `.sig` files are removed and all operations proceed freely.

## Example session

```
[ATTACKER | INSECURE] > delete user_database.csv
  [DELETED] 'user_database.csv' removed from disk.

[ATTACKER | INSECURE] > toggle
  Security ON — HMAC-SHA256 seals applied.
    ✓ config.json
    ✓ secrets.env
    ✓ audit_log.txt

[ATTACKER | SECURE] > delete user_database.csv
  [BLOCKED] Cannot delete 'user_database.csv'.
  The file is sealed with HMAC-SHA256.
  Deletion requires the shared secret key — which you don't have.

[ATTACKER | SECURE] > read secrets.env
  # Production credentials — DO NOT SHARE
  JWT_SECRET=8f14e45fceea167a5a36dedd4bea2543
  ...
  (read succeeds — signing prevents tampering, not eavesdropping)
```

## Project structure

```
MCP-Security-Simulation/
├── run.py           # One-command launcher (handles venv + deps automatically)
├── demo.py          # Entry point — argument parsing
├── file_agent.py    # Interactive REPL and file integrity logic
├── security.py      # HMAC-SHA256 signing and verification
├── test_files/      # Auto-created — the files you try to attack
├── mcp_server.py    # Reference: simulated MCP server (educational)
├── mitm_proxy.py    # Reference: malicious MITM proxy (educational)
├── mcp_client.py    # Reference: MCP client library (educational)
└── requirements.txt
```
