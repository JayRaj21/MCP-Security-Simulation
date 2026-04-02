# MCP Security Gateway

A zero-trust MCP gateway that sits between MCP clients and a live backend REST API. Every request is independently authenticated. Unauthenticated callers receive AES-256-CBC ciphertext. Authenticated callers receive plaintext JSON with HMAC-SHA256 integrity signatures. All access attempts are recorded in an audit log.

```
MCP Client  ──►  MCP Gateway (this project)  ──►  JSONPlaceholder REST API
                 • auth / zero-trust                (live external data)
                 • AES-256 encryption
                 • HMAC-SHA256 signing
                 • audit logging
```

---

## Quick Start

**Prerequisites:** Python 3.8+

```bash
# Terminal 1 — start the gateway server
make server

# Terminal 2 — open the interactive shell
make shell

# Terminal 2 (alternative) — run the automated 12-step demo instead
make demo
```

The server listens at `http://127.0.0.1:8000/mcp`. The backend is the public [JSONPlaceholder](https://jsonplaceholder.typicode.com) API (no API key required).

---

## Security features demonstrated

| Feature | What it does |
|---------|--------------|
| Zero-trust auth | Every tool call verifies the session token independently — no implicit trust |
| AES-256-CBC encryption | Unauthenticated callers receive an encrypted blob, not readable data |
| HMAC-SHA256 signing | Authenticated responses include a signature for tamper detection |
| Integrity verification | Re-fetch a resource live and compare its HMAC against a saved value |
| Audit log | All access attempts (including unauthenticated ones) recorded and queryable |
| Session management | Short-lived tokens (1 hour), revocable via logout |

---

## Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin`  | `admin123` | admin |
| `viewer` | `view456`  | viewer |

Override at runtime via environment variables: `ADMIN_PASSWORD`, `VIEWER_PASSWORD`.

---

## Interactive shell commands

Start the shell with `make shell`, then use any of these commands:

### Resource commands

| Command | Description |
|---------|-------------|
| `users` | List all 10 users from the backend API |
| `user <id>` | Fetch a single user profile (ID 1–10) |
| `posts [user_id]` | List posts, optionally filtered by user (100 total, 10 per user) |
| `post <id>` | Fetch a single post (ID 1–100) |
| `todos [user_id]` | List todos with completion status (200 total, 20 per user) |
| `todo <id>` | Fetch a single todo (ID 1–200) |

When unauthenticated, resource commands return an AES-256 encrypted blob. After logging in, they return plaintext data.

### Auth commands

| Command | Description |
|---------|-------------|
| `login` | Authenticate and receive a session token |
| `logout` | Invalidate the current session token |
| `status` | Show current auth state (token, username) |

### Integrity commands

| Command | Description |
|---------|-------------|
| `sign <type> <id>` | Fetch a resource and save its HMAC signature |
| `verify <type> <id>` | Re-fetch a resource and check it matches the saved HMAC |
| `tampertest <type> <id>` | Corrupt a saved HMAC and verify tamper detection fires |

`<type>` is one of: `user`, `post`, `todo`

### Audit commands

| Command | Description |
|---------|-------------|
| `audit` | View the full audit log (requires login) |
| `audit unauth` | View only unauthenticated access attempts |

### Other

| Command | Description |
|---------|-------------|
| `help` | Show all commands |
| `exit` | Quit |

---

## Automated demo (`make demo`)

Runs 12 steps non-interactively:

1. `list_users()` unauthenticated → encrypted blob
2. `get_user(3)` unauthenticated → encrypted blob
3. Authenticate as `admin` → receive session token
4. `list_users(token)` → plaintext user list
5. `get_user(3, token)` → full user profile
6. `list_posts(user_id=3, token)` → that user's 10 posts
7. `get_post(1, token)` → single post in full
8. `list_todos(user_id=1, token)` → todos with completion status
9. Sign user 3's response, verify it → HMAC intact
10. Corrupt the HMAC → tamper detection fires
11. `get_audit_log(unauthorized_only=True)` → shows steps 1 and 2
12. Logout → token invalidated

Run with `--auto` to skip the Enter-to-continue prompts:

```bash
.venv/bin/python demo_client.py --auto
```

---

## MCP tools (server API)

These are the tools exposed over the MCP protocol, callable by any MCP client:

| Tool | Parameters | Description |
|------|------------|-------------|
| `authenticate` | `username`, `password` | Returns a session token (1 hour expiry) |
| `logout` | `session_token` | Revokes the token immediately |
| `list_users` | `session_token=""` | All 10 users |
| `get_user` | `user_id`, `session_token=""` | Single user by ID (1–10) |
| `list_posts` | `user_id=0`, `session_token=""` | Posts; `user_id=0` returns all 100 |
| `get_post` | `post_id`, `session_token=""` | Single post by ID (1–100) |
| `list_todos` | `user_id=0`, `session_token=""` | Todos; `user_id=0` returns all 200 |
| `get_todo` | `todo_id`, `session_token=""` | Single todo by ID (1–200) |
| `verify_integrity` | `resource_type`, `resource_id`, `expected_hmac`, `session_token` | Re-fetches resource and compares HMAC |
| `get_audit_log` | `session_token`, `unauthorized_only=False` | Audit log (auth required) |

---

## Project structure

```
MCP-Security-Simulation/
├── server.py          # FastMCP gateway — all tools, auth enforcement, response wrapping
├── shell.py           # Interactive REPL client for testing the gateway
├── demo_client.py     # Automated 12-step demo walkthrough
├── backend.py         # HTTP wrapper around the JSONPlaceholder REST API
├── auth.py            # AuthManager — bcrypt password hashing, session tokens
├── crypto.py          # CryptoManager — AES-256-CBC encryption, HMAC-SHA256 signing
├── audit.py           # AuditLogger — circular in-memory buffer of access events
├── config.py          # User registry, encryption key, session duration
├── requirements.txt   # Python dependencies
└── Makefile           # make server / make shell / make demo
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_PASSWORD` | `admin123` | Password for the admin account |
| `VIEWER_PASSWORD` | `view456` | Password for the viewer account |
| `MCP_ENCRYPTION_KEY` | `mcp-v2-demo-key-change-in-prod!!` | 32-char AES-256 key |
| `SESSION_DURATION_SECONDS` | `3600` | Token lifetime in seconds |
