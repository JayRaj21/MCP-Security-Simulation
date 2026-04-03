# MCP Security Gateway

A zero-trust security gateway with two interfaces:

- **Web UI (v3)** — browser-based file management dashboard with live activity log
- **MCP gateway (v2)** — FastMCP server proxying the JSONPlaceholder REST API via the MCP protocol

Both interfaces share the same security model: every request is independently authenticated, unauthenticated callers receive AES-256-CBC ciphertext, authenticated callers receive plaintext with HMAC-SHA256 integrity signatures, and all access attempts are recorded in an audit log.

---

## Quick Start

**Prerequisites:** Python 3.8+

```bash
# Web UI — open http://127.0.0.1:8080 in your browser  ← START HERE
make web

# MCP gateway (separate terminal pair)
make server   # Terminal 1
make shell    # Terminal 2
make demo     # Terminal 2 (automated demo instead of shell)
```

---

## Security features

| Feature | What it does |
|---------|--------------|
| Zero-trust auth | Every request verifies the session token independently — no implicit trust |
| AES-256-CBC encryption | Unauthenticated callers receive an encrypted blob, not readable data |
| HMAC-SHA256 signing | Authenticated responses include a signature for tamper detection |
| Integrity verification | SHA-256 hash comparison detects modified or tampered files |
| File regeneration | Tampered or deleted files are restored on server start; manual repair also available |
| Activity log | Every access attempt (authenticated or not) is recorded and queryable |
| Session management | Short-lived tokens (1 hour), revocable at any time |

---

## Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin`  | `admin123` | admin |
| `viewer` | `view456`  | viewer |

Override at runtime: `ADMIN_PASSWORD`, `VIEWER_PASSWORD`.

---

## Web UI (`make webapp`)

Open `http://127.0.0.1:8080` in a browser.

### Layout

```
┌─────────────────────────────────────────────────────────────┐
│  🔒 MCP Security Gateway            [● admin (admin)] [Logout] │
├─────────────────┬───────────────────────────────────────────┤
│  FILE STORE  5  │  secrets.env         [⚠ TAMPERED]         │
│  ─────────────  │  ─────────────────────────────────────     │
│  ● config.json  │  DATABASE_URL=postgresql://...             │
│  ⚠ secrets.env  │  ...                                       │
│  ● user_db.csv  │                [🔍 Check][↺ Repair][🗑 Del] │
│  ● audit.txt    │                                            │
│  ● enc_keys.txt │                                            │
│  ─────────────  │                                            │
│  [＋ Add File]  │                                            │
│  [⚡ Scan][↺ Reset]                                          │
├─────────────────┴───────────────────────────────────────────┤
│  ACTIVITY LOG                                    [↻]         │
│  14:05:22  admin  write_file  filestore/secrets  written…    │
│  14:05:10  admin  list_files  filestore          success…    │
└─────────────────────────────────────────────────────────────┘
```

### Zero-trust behaviour

| State | File list | File content | Activity log |
|-------|-----------|--------------|--------------|
| Not logged in | File count shown; names masked as `████████████` | AES-256 encrypted blob | Hidden |
| Logged in (viewer) | Real names + integrity dots | Plaintext + integrity badge | Visible |
| Logged in (admin) | Same + Repair / Reset All buttons | Same + Repair button on tampered files | Visible |

### File actions

| Button / action | Who | What it does |
|-----------------|-----|-------------|
| Select file | any auth | View content; integrity badge shown |
| ✏️ Edit → 💾 Save | any auth | Modify file content in-browser |
| 🗑 Delete | any auth | Remove file from store |
| 🔍 Check | any auth | Re-hash and compare against original SHA-256 |
| ↺ Repair | admin | Restore one file to its original content |
| ＋ Add File | any auth | Create a new file with custom content |
| ⚡ Scan | any auth | Scan all files for hash mismatches |
| ↺ Reset All | admin | Restore every file to original content |

### Demo walkthrough

**See encryption in action:**
1. Open the page without logging in — file names are masked, count is visible
2. Click a masked file — content shown as AES-256 encrypted blob
3. Click **Login** → `admin` / `admin123`
4. File names and content are now readable

**Test file integrity monitoring:**
1. Log in as admin
2. Select `secrets.env` → Edit → change a line → Save
3. The sidebar dot turns red; the file header shows `⚠ TAMPERED`
4. Click **↺ Repair** → file restored, dot turns green
5. Or click **⚡ Scan** to find all tampered files at once

**Test access control:**
1. Log out
2. Try clicking any file — encrypted content is returned and logged
3. Log in → **Activity Log** shows the unauthenticated attempts

---

## Demo files

Five pre-populated files simulate sensitive server data.  
All files are **automatically restored to original content on every server start**.

| File | Contents |
|------|---------|
| `config.json` | Server config with database credentials and API keys |
| `secrets.env` | Environment variables including AWS keys and OAuth secrets |
| `user_database.csv` | User records with password hashes and API tokens |
| `audit_log.txt` | Historical access log with brute-force attempt example |
| `encryption_keys.txt` | Key rotation schedule (AES-256-GCM, break-glass key) |

---

## Interactive shell (`make shell`)

Start the server first (`make server`), then open the shell.

### File integrity commands (auth required)

| Command | Description |
|---------|-------------|
| `list` / `files` | List all demo files with integrity status |
| `file <name>` | Read a file with SHA-256 and integrity check |
| `writefile <name> <content>` | Write/overwrite a file |
| `deletefile <name>` | Delete a file |
| `checkfile <name>` | Compare SHA-256 against original |
| `scanfiles` | Scan all files and report tampered ones |
| `repairfile <name>` | Restore one file to original _(admin only)_ |
| `resetfiles` | Restore all files to original _(admin only)_ |

### Resource commands (JSONPlaceholder proxy)

| Command | Description |
|---------|-------------|
| `users` | List all users (encrypted when logged out) |
| `user <id>` | Fetch a single user profile (ID 1–10) |
| `posts [user_id]` | List posts, optionally filtered by user |
| `post <id>` | Fetch a single post (ID 1–100) |
| `todos [user_id]` | List todos with completion status |
| `todo <id>` | Fetch a single todo (ID 1–200) |

### Auth commands

| Command | Description |
|---------|-------------|
| `login <user> <pass>` | Authenticate and receive a session token |
| `logout` | Invalidate the current session token |
| `status` | Show auth state and saved signatures |

### Delete / restore commands (auth required)

| Command | Description |
|---------|-------------|
| `delete user/post/todo <id>` | Soft-delete a resource |
| `restore` | Restore all soft-deleted resources _(admin only)_ |

### API integrity commands

| Command | Description |
|---------|-------------|
| `sign <type> <id>` | Save a resource HMAC-SHA256 signature |
| `verify <type> <id>` | Re-fetch and verify the HMAC |
| `tampertest <type> <id>` | Corrupt the signature to trigger detection |

`<type>` is one of: `user`, `post`, `todo`

### Audit commands (auth required)

| Command | Description |
|---------|-------------|
| `audit` | View unauthorized access attempts |
| `audit --all` | View all access attempts |
| `failed-auth` | View failed login attempts _(admin only)_ |

### Session management (admin only)

| Command | Description |
|---------|-------------|
| `sessions` | List all active sessions |
| `kick <username>` | Force-logout all sessions for a user |

---

## Web API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/auth/login` | — | Authenticate; returns session token |
| `POST` | `/api/auth/logout` | required | Invalidate session |
| `GET` | `/api/files` | optional | List files (names masked if unauthenticated) |
| `GET` | `/api/files/{name}` | optional | Read file (encrypted if unauthenticated) |
| `PUT` | `/api/files/{name}` | required | Write / create a file |
| `DELETE` | `/api/files/{name}` | required | Delete a file |
| `GET` | `/api/files/{name}/integrity` | required | Check SHA-256 against original |
| `POST` | `/api/files/{name}/repair` | admin | Restore one file to original |
| `GET` | `/api/scan` | required | Scan all files for tampering |
| `POST` | `/api/reset` | admin | Restore all files to original |
| `GET` | `/api/activity` | required | Full activity log (most recent first) |

---

## MCP tools (FastMCP server API)

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
| `delete_user` | `user_id`, `session_token` | Soft-delete a user |
| `delete_post` | `post_id`, `session_token` | Soft-delete a post |
| `delete_todo` | `todo_id`, `session_token` | Soft-delete a todo |
| `restore_all` | `session_token` | Clear all soft-deletes (admin only) |
| `verify_integrity` | `resource_type`, `resource_id`, `expected_hmac`, `session_token` | Re-fetches resource and compares HMAC |
| `get_audit_log` | `session_token`, `unauthorized_only=False` | Audit log |
| `get_failed_auth_attempts` | `session_token` | Failed logins only (admin only) |
| `list_active_sessions` | `session_token` | All live sessions (admin only) |
| `force_logout_user` | `target_username`, `session_token` | Revoke all sessions for a user (admin only) |
| `list_files` | `session_token` | List demo files with integrity status |
| `read_file` | `filename`, `session_token` | Read file content and integrity |
| `write_file` | `filename`, `content`, `session_token` | Write / overwrite a file |
| `delete_file` | `filename`, `session_token` | Delete a demo file |
| `check_file_integrity` | `filename`, `session_token` | Compare SHA-256 to original |
| `detect_tampered_files` | `session_token` | Scan all files for tampering |
| `repair_file` | `filename`, `session_token` | Restore one file to original (admin only) |
| `reset_files` | `session_token` | Restore all files to original (admin only) |

---

## Project structure

```
MCP-Security-Simulation/
├── webapp.py          # FastAPI web server — REST API + serves the SPA
├── static/
│   └── index.html     # Single-page web UI (zero-trust file manager + activity log)
├── server.py          # FastMCP gateway — MCP protocol tools
├── shell.py           # Interactive CLI client for the MCP gateway
├── demo_client.py     # Automated 12-step MCP demo walkthrough
├── filestore.py       # In-memory file store with SHA-256 integrity monitoring
├── backend.py         # HTTP wrapper around the JSONPlaceholder REST API
├── auth.py            # AuthManager — bcrypt password hashing, session tokens
├── crypto.py          # CryptoManager — AES-256-CBC encryption, HMAC-SHA256 signing
├── audit.py           # AuditLogger — circular in-memory buffer of access events
├── config.py          # User registry, encryption key, session duration
├── requirements.txt   # Python dependencies
└── Makefile           # make web / make server / make shell / make demo
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_PASSWORD` | `admin123` | Password for the admin account |
| `VIEWER_PASSWORD` | `view456` | Password for the viewer account |
| `MCP_ENCRYPTION_KEY` | `mcp-v2-demo-key-change-in-prod!!` | 32-char AES-256 key |
| `SESSION_DURATION_SECONDS` | `3600` | Token lifetime in seconds |
