# JOCKY V5 Production Deployment Guide

## Overview
This document covers Linux server deployment, Windows agent setup,
environment variables, authentication, TLS, database backup/restore,
firewall configuration, Docker, and troubleshooting.

---

## 1. Prerequisites

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Python    | 3.11    | 3.13        |
| SQLite    | 3.39    | 3.45+       |
| LLVM/Clang| 14      | 17+         |
| nginx     | 1.18    | 1.25+       |
| Docker    | 20.10   | 24+         |

---

## 2. Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JOCKY_API_KEY` | **Yes** | — | API key for agent/dashboard auth |
| `JOCKY_DB` | No | `jocky_forensics.db` | SQLite database path |
| `JOCKY_EVIDENCE_DIR` | No | `evidence/` | Evidence archive storage |
| `JOCKY_BACKUP_DIR` | No | `backups/` | Database backup directory |
| `JOCKY_HOST` | No | `127.0.0.1` | Flask bind host (keep 127.0.0.1 in prod) |
| `JOCKY_PORT` | No | `5000` | Flask bind port |
| `JOCKY_BACKUP_INTERVAL_HOURS` | No | `6` | Automated backup interval |
| `JOCKY_JOB_TIMEOUT_MINUTES` | No | `60` | Job expiry timeout |
| `JOCKY_STALE_DEVICE_DAYS` | No | `30` | Days before a device is marked stale |

**Never commit `JOCKY_API_KEY` to source control.** Use a `.env` file
(excluded by `.gitignore`) or a secrets manager.

---

## 3. Linux Server Setup

```bash
# 1. Clone and install
git clone https://github.com/your-org/jocky.git /opt/jocky
cd /opt/jocky
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Create .env file (not committed)
cat > .env << 'ENVEOF'
JOCKY_API_KEY=your-strong-random-key-here
JOCKY_DB=/opt/jocky/data/jocky_forensics.db
JOCKY_EVIDENCE_DIR=/opt/jocky/data/evidence
JOCKY_BACKUP_DIR=/opt/jocky/data/backups
ENVEOF

# 3. Initialise database
python -c "from server.database import init_db; init_db()"

# 4. Run server (behind nginx)
export $(cat .env | xargs)
python -m server.server
```

---

## 4. TLS / Reverse Proxy (nginx)

```bash
# Install nginx and certbot
sudo apt install nginx python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d your.domain.example

# Copy JOCKY nginx config
sudo cp deploy/nginx.conf /etc/nginx/sites-available/jocky
# Edit: replace 'your.domain.example' with your actual domain
sudo nano /etc/nginx/sites-available/jocky
sudo ln -s /etc/nginx/sites-available/jocky /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

The server must bind to `127.0.0.1:5000` only (set `JOCKY_HOST=127.0.0.1`).
nginx handles TLS termination and rate limiting.

---

## 5. Authentication & Key Rotation

```python
from server.database import create_api_key, revoke_api_key, list_api_keys

# Create a new key (only the hash is stored — never the raw key)
create_api_key("my-new-key-abc123", label="analyst-workstation", expires_in_days=90)

# Rotate: create new key, then revoke old
create_api_key("new-key-xyz789", label="analyst-workstation-rotated",
               rotate_from_hash="<hash-of-old-key>", expires_in_days=90)
revoke_api_key("my-new-key-abc123")

# List all keys with status
print(list_api_keys())
```

**Key management rules:**
- Keys are stored as SHA-256 hashes only — the raw key is never persisted.
- Set `expires_in_days` for all production keys (recommended: 90 days).
- Rotate keys before expiry using `rotate_from_hash` for continuity tracking.
- Revoke compromised keys immediately with `revoke_api_key()`.
- Never log the raw API key; mask it in any audit output.

---

## 6. Docker Deployment

```bash
# 1. Create .env with all required variables
echo "JOCKY_API_KEY=$(openssl rand -hex 32)" > .env

# 2. Build and start
cd /opt/jocky
docker compose --env-file .env -f deploy/docker-compose.yml up -d

# 3. Verify health
curl http://127.0.0.1:5000/api/health

# 4. View logs
docker logs jocky_central_server
```

---

## 7. Database Backup & Restore

```python
from server.database import backup_db, restore_db, list_backups

# Manual backup (returns path + SHA-256)
meta = backup_db()
print("Backup:", meta["backup"], "SHA-256:", meta["sha256"])

# List backups
for b in list_backups():
    print(b["filename"], b["size_bytes"], "bytes")

# Restore (verifies SHA-256 before overwrite, creates safety backup first)
result = restore_db(
    backup_path="/opt/jocky/data/backups/jocky_forensics.20260911T060000Z.db",
    expected_sha256="<sha256-from-meta>"
)
print(result)
```

Automated backups run every 6 hours via the `jocky-backup` Docker sidecar.
The last 14 backups are retained; older ones are pruned automatically.

---

## 8. Firewall Configuration

```bash
# Allow HTTPS inbound, block direct Flask port from external
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp      # for redirect only
sudo ufw deny 5000/tcp     # block direct Flask access
sudo ufw enable
```

Only nginx (on 443) should be reachable externally.
Flask (5000) listens on localhost only.

---

## 9. Windows Agent Setup

```powershell
# 1. Install Python 3.11+
# 2. Clone / copy jocky to C:\jocky
cd C:\jocky
pip install -r requirements.txt

# 3. Register and start agent
$env:JOCKY_SERVER = "https://your.domain.example"
$env:JOCKY_API_KEY = "your-api-key"
python agent\jocky_agent.py --server $env:JOCKY_SERVER --api-key $env:JOCKY_API_KEY
```

Supported collection on Windows: processes, network, users, system info,
event logs, browser artifacts, driver inventory, memory telemetry.

---

## 10. Monitoring & Health

The `/api/health` endpoint returns:
```json
{
  "status": "healthy",
  "db_accessible": true,
  "evidence_dir_accessible": true,
  "active_devices": 3,
  "pending_jobs": 1,
  "backup_dir": "/app/data/backups",
  "timestamp": "2026-09-11T08:00:00+00:00"
}
```

Configure your monitoring system (Prometheus, Uptime Robot, etc.) to
poll `/api/health` every 30 seconds.

---

## 11. Troubleshooting

| Symptom | Check |
|---------|-------|
| 401 Unauthorized | `JOCKY_API_KEY` mismatch or expired/revoked key |
| 429 Too Many Requests | nginx rate limit — increase `burst` or reduce poll frequency |
| Agent can't connect | Firewall blocking 443, or wrong `--server` URL |
| Database locked | WAL mode is enabled; a long-running query may hold a lock |
| Backup fails | Check `JOCKY_BACKUP_DIR` exists and is writable |
| Evidence hash mismatch | Archive was modified after upload; check `evidence.verify_all()` |

---

## 12. Security Notes

- This platform does **not** implement AV/EDR bypass, guaranteed non-detection,
  or covert communication.
- All collection is **read-only** on the endpoint; no security controls are
  disabled, patched, or modified.
- Experimental runtime components (`runtime/jocky_inject_linux.c`,
  `runtime/jocky_unhook_linux.c`, `runtime/jocky_byovd_linux.c`) are
  **not compiled or included** in production releases. They are marked as
  research-only in the codebase.
- The production build path (`tools/build_jocky.py`) does not invoke
  any experimental runtime.
