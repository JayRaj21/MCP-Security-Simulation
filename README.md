# MCP Security Gateway — Web UI

A browser-based zero-trust file management dashboard. Every request is independently authenticated. Unauthenticated users see the file list but not file names or content — all data is AES-256-CBC encrypted until you log in. Every access attempt is recorded in a live activity log.

---

## Quick Start

**Prerequisites:** Python 3.8+

```bash
make web
```

Opens at `http://127.0.0.1:8080`. On first run (or whenever `requirements.txt` changes) the Makefile installs all dependencies automatically — no manual `pip install` needed.

---

## Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin`  | `admin123` | Full access — can repair and reset files |
| `viewer` | `view456`  | Read + write access, no repair/reset |

Override at runtime: `ADMIN_PASSWORD`, `VIEWER_PASSWORD`.

---

## Security features

| Feature | Behaviour |
|---------|-----------|
| Zero-trust auth | Every API request independently verifies the session token |
| AES-256-CBC encryption | Unauthenticated requests receive a ciphertext blob, not readable data |
| File integrity monitoring | SHA-256 hash of each file is compared against the original on every read |
| File regeneration | All files auto-restore on server start; individual repair and full reset available |
| Activity log | Every access attempt — authenticated or not — is recorded and displayed |
| Session tokens | 256-bit random tokens, server-side only, 1-hour expiry |

---

## UI overview

```
┌────────────────────────────────────────────────────────────────┐
│  MCP Security Gateway              [● admin (admin)] [Logout]  │
├──────────────────┬─────────────────────────────────────────────┤
│  FILE STORE  5   │  secrets.env              [⚠ TAMPERED]      │
│  ─────────────   │  ─────────────────────────────────────────  │
│  ● config.json   │  DATABASE_URL=postgresql://...              │
│  ⚠ secrets.env   │  AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE     │
│  ● user_db.csv   │  ...                                        │
│  ● audit.txt     │           [🔍 Check] [↺ Repair] [🗑 Delete]  │
│  ● enc_keys.txt  │                                             │
│  ─────────────   │                                             │
│  [＋ Add File]   │                                             │
│  [⚡ Scan] [↺ Reset All]                                        │
├──────────────────┴─────────────────────────────────────────────┤
│  ACTIVITY LOG                                         [↻]      │
│  14:05:22  admin  write_file  filestore/secrets  written…      │
│  14:05:10  admin  list_files  filestore          success…      │
└────────────────────────────────────────────────────────────────┘
```

### What unauthenticated users see

- File count is visible in the sidebar header
- File names are masked (`████████████`) — count reveals files exist, nothing more
- Clicking any file shows the AES-256 encrypted blob, not the content
- Activity log is hidden entirely

### File actions

| Button | Who | What it does |
|--------|-----|-------------|
| Select file | any | View content; integrity badge shown (✓ intact / ⚠ TAMPERED) |
| ✏️ Edit → 💾 Save | any auth | Edit content in-browser and save |
| 🗑 Delete | any auth | Remove file from the store |
| 🔍 Check | any auth | Re-hash and compare against original SHA-256 |
| ↺ Repair | admin | Restore one file to its original content |
| ＋ Add File | any auth | Create a new file with custom name and content |
| ⚡ Scan | any auth | Scan all files and report any with hash mismatches |
| ↺ Reset All | admin | Restore every file to original content at once |

---

## Demo files

Five pre-populated files simulate sensitive server data. All are **automatically restored on every server start**.

| File | Contents |
|------|---------|
| `config.json` | Server config with database credentials and API keys |
| `secrets.env` | Environment variables including AWS keys and OAuth secrets |
| `user_database.csv` | User records with password hashes and API tokens |
| `audit_log.txt` | Historical access log with a brute-force attempt example |
| `encryption_keys.txt` | Key rotation schedule with AES-256-GCM and break-glass key |

---

## Testing

### Running the server

```bash
make web
# Server starts at http://127.0.0.1:8080
```

All state is in memory. Restarting the server resets every file to its original content and clears the session and activity log.

### Manual test cases

**1. Encryption — verify unauthenticated access is blocked**

1. Open `http://127.0.0.1:8080` without logging in
2. Sidebar shows 5 files with masked names (`████████████`)
3. Click any masked entry — the main panel shows the AES-256 ciphertext blob
4. Log in as `viewer` / `view456`
5. File names and content are now visible in plaintext

Expected: unauthenticated users cannot read any file content.

---

**2. File integrity — detect and repair tampering**

1. Log in as `admin` / `admin123`
2. Select `secrets.env` — integrity badge shows **✓ intact**
3. Click **✏️ Edit**, change a line (e.g. append ` # TAMPERED`), click **💾 Save**
4. Integrity badge immediately changes to **⚠ TAMPERED**; sidebar dot turns red
5. Click **🔍 Check** — confirms hash mismatch with original SHA-256
6. Click **↺ Repair** — file content restored; badge returns to **✓ intact**

Expected: any modification is detected by SHA-256 comparison; admin can repair individual files.

---

**3. Bulk scan and reset**

1. Log in as `admin`
2. Edit `config.json` and `audit_log.txt` (change any content, save each)
3. Click **⚡ Scan** — toast reports "2 tampered: config.json, audit_log.txt"
4. Click **↺ Reset All** and confirm — toast reports all 5 files restored

Expected: scan identifies all modified files; reset restores everything in one action.

---

**4. Access control — viewer cannot repair**

1. Log in as `viewer` / `view456`
2. Edit any file so it shows **⚠ TAMPERED**
3. The **↺ Repair** button is not visible; **↺ Reset All** button is not shown in the sidebar

Expected: repair and reset are restricted to the admin role.

---

**5. Activity log — audit trail**

1. Open the page without logging in and click a few masked file entries
2. Log in as `admin`
3. The activity log shows the earlier unauthenticated attempts, tagged `[UNAUTH]`

Expected: all access attempts are logged regardless of authentication state.

---

**6. Attack simulation — automated attacker scenario**

1. Click **⚡ Simulate Attack** in the header (no login required)
2. The panel runs 7 steps automatically:
   - Unauthenticated file list → **Blocked** (masked names only)
   - Unauthenticated file read → **Blocked** (AES-256 ciphertext)
   - Brute-force login with wrong passwords → **Blocked**
   - Viewer login with correct credentials → **Visible** (token obtained)
   - File tamper as viewer → **Visible** (viewer can write)
   - Audit log read as viewer → **Visible** (viewer can see log)
   - Viewer logout → token invalidated
3. After the run, click **View Activity Log** to see every step recorded in the audit trail

Expected: each step is tagged Blocked, Visible, or Exposed with a one-line explanation; the full scenario is captured in the activity log.

---

## Web API

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

## Project structure

```
MCP-Security-Simulation/
├── webapp.py          # FastAPI server — REST API, config, audit log, serves the SPA
├── static/
│   └── index.html     # Single-page web UI (self-contained HTML/CSS/JS)
├── filestore.py       # In-memory file store with SHA-256 integrity monitoring
├── auth.py            # AuthManager — bcrypt password hashing, session tokens
├── crypto.py          # CryptoManager — AES-256-CBC encryption, HMAC-SHA256 signing
├── requirements.txt   # Python dependencies
└── Makefile           # make web
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_PASSWORD` | `admin123` | Password for the admin account |
| `VIEWER_PASSWORD` | `view456` | Password for the viewer account |
| `MCP_ENCRYPTION_KEY` | `mcp-v2-demo-key-change-in-prod!!` | 32-char AES-256 key |
| `SESSION_DURATION_SECONDS` | `3600` | Token lifetime in seconds |
