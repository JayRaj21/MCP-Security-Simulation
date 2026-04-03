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
| File integrity monitoring | SHA-256 tracks whether demo files have been tampered with |
| File regeneration | Tampered or deleted files can be restored to original content; all files reset on server start |
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
| `users` | List all users from the backend API |
| `user <id>` | Fetch a single user profile (ID 1–10) |
| `posts [user_id]` | List posts, optionally filtered by user (100 total, 10 per user) |
| `post <id>` | Fetch a single post (ID 1–100) |
| `todos [user_id]` | List todos with completion status (200 total, 20 per user) |
| `todo <id>` | Fetch a single todo (ID 1–200) |

When unauthenticated, resource commands return an AES-256 encrypted blob. After logging in, they return plaintext data.

### Auth commands

| Command | Description |
|---------|-------------|
| `login <user> <pass>` | Authenticate and receive a session token |
| `logout` | Invalidate the current session token |
| `status` | Show current auth state (token, username) |

### Delete / restore commands (auth required)

Deletions are soft-delete only — held in memory, not sent to the backend. All deletions are automatically cleared when the server restarts.

| Command | Description |
|---------|-------------|
| `delete user <id>` | Soft-delete a user — hidden from all subsequent calls |
| `delete post <id>` | Soft-delete a post |
| `delete todo <id>` | Soft-delete a todo |
| `restore` | Restore all soft-deleted resources to original state _(admin only)_ |

### File integrity commands (auth required)

Five pre-loaded demo files simulate sensitive server data (`config.json`, `secrets.env`, `user_database.csv`, `audit_log.txt`, `encryption_keys.txt`). All files are automatically restored to their original content on every server start.

| Command | Description |
|---------|-------------|
| `files` | List all demo files with size and integrity status (intact / TAMPERED) |
| `file <name>` | Read a file's content with its current SHA-256 and integrity check |
| `writefile <name> <content>` | Write/overwrite a file — simulates an attacker tampering with it |
| `deletefile <name>` | Delete a file from the store |
| `checkfile <name>` | Compare a file's SHA-256 against its original — reports intact or TAMPERED |
| `scanfiles` | Scan all files and list every one that has been tampered with |
| `repairfile <name>` | Restore a single file to its original content _(admin only)_ |
| `resetfiles` | Restore all files to original content _(admin only)_ |

### API integrity commands

| Command | Description |
|---------|-------------|
| `sign <type> <id>` | Fetch a resource and save its HMAC signature |
| `verify <type> <id>` | Re-fetch a resource and check it matches the saved HMAC |
| `tampertest <type> <id>` | Corrupt a saved HMAC and verify tamper detection fires |

`<type>` is one of: `user`, `post`, `todo`

### Audit commands (auth required)

| Command | Description |
|---------|-------------|
| `audit` | View unauthorized access attempts |
| `audit --all` | View all access attempts |
| `failed-auth` | View only failed login attempts _(admin only)_ |

### Session management (admin only)

| Command | Description |
|---------|-------------|
| `sessions` | List all active sessions (token prefix, username, role, expiry) |
| `kick <username>` | Immediately revoke all sessions for a given user |

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
| `list_users` | `session_token=""` | All users (excluding soft-deleted) |
| `get_user` | `user_id`, `session_token=""` | Single user by ID (1–10) |
| `list_posts` | `user_id=0`, `session_token=""` | Posts; `user_id=0` returns all |
| `get_post` | `post_id`, `session_token=""` | Single post by ID (1–100) |
| `list_todos` | `user_id=0`, `session_token=""` | Todos; `user_id=0` returns all |
| `get_todo` | `todo_id`, `session_token=""` | Single todo by ID (1–200) |
| `delete_user` | `user_id`, `session_token` | Soft-delete a user (auth required) |
| `delete_post` | `post_id`, `session_token` | Soft-delete a post (auth required) |
| `delete_todo` | `todo_id`, `session_token` | Soft-delete a todo (auth required) |
| `restore_all` | `session_token` | Clear all soft-deletes (admin only) |
| `verify_integrity` | `resource_type`, `resource_id`, `expected_hmac`, `session_token` | Re-fetches resource and compares HMAC |
| `get_audit_log` | `session_token`, `unauthorized_only=False` | Audit log (auth required) |
| `get_failed_auth_attempts` | `session_token` | Failed login attempts only (admin only) |
| `list_active_sessions` | `session_token` | All live sessions with metadata (admin only) |
| `force_logout_user` | `target_username`, `session_token` | Revoke all sessions for a user (admin only) |
| `list_files` | `session_token` | List demo files with integrity status (auth required) |
| `read_file` | `filename`, `session_token` | Read a file's content and integrity check (auth required) |
| `write_file` | `filename`, `content`, `session_token` | Write/overwrite a file — simulates tampering (auth required) |
| `delete_file` | `filename`, `session_token` | Delete a demo file (auth required) |
| `check_file_integrity` | `filename`, `session_token` | Compare file SHA-256 to original (auth required) |
| `detect_tampered_files` | `session_token` | Scan all files and return tampered ones (auth required) |
| `repair_file` | `filename`, `session_token` | Restore one file to original (admin only) |
| `reset_files` | `session_token` | Restore all files to original (admin only) |

---

## Project structure

```
MCP-Security-Simulation/
├── server.py          # FastMCP gateway — all tools, auth enforcement, response wrapping
├── shell.py           # Interactive REPL client for testing the gateway
├── demo_client.py     # Automated 12-step demo walkthrough
├── backend.py         # HTTP wrapper around the JSONPlaceholder REST API
├── filestore.py       # In-memory file store with integrity monitoring and repair
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
