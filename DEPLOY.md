# HQG Platform — Deployment Guide

Deploy the full stack (frontend + backend + worker + Redis) on any Ubuntu VPS with a single command.

---

## Requirements

| Tool | Minimum version |
|------|----------------|
| Docker | 24+ |
| Docker Compose plugin | 2.20+ |
| RAM | 2 GB (4 GB recommended) |
| Disk | 10 GB free |

Install on a fresh Ubuntu VPS:

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker (official script)
curl -fsSL https://get.docker.com | sudo sh

# Add your user to the docker group (re-login after)
sudo usermod -aG docker $USER
```

---

## 1. Clone the repository

```bash
git clone <your-repo-url> hqg
cd hqg
```

---

## 2. Configure environment

```bash
cp .env.example .env
nano .env
```

**Required change — set your VPS public IP or domain in `ALLOWED_ORIGINS`:**

```env
# Replace with your actual IP or domain:
ALLOWED_ORIGINS=http://203.0.113.10:3000,http://203.0.113.10:8000
```

Optional — add your NVD API key for faster CVE lookups:

```env
NVD_API_KEY=your-nvd-key-here
```

---

## 3. Deploy

```bash
docker compose up -d
```

This will:
1. Build the backend image (Python 3.11 + all dependencies)
2. Build the frontend image (Node 18 → nginx)
3. Start Redis with persistent storage
4. Start the FastAPI backend on port 8000
5. Start the Celery worker (connected to Redis)
6. Start the nginx frontend on port 3000

**First build takes 5–10 minutes.** Subsequent starts are instant.

---

## 4. Access the platform

| Service | URL |
|---------|-----|
| Frontend | `http://YOUR_VPS_IP:3000` |
| Backend API | `http://YOUR_VPS_IP:8000/docs` |
| Health check | `http://YOUR_VPS_IP:8000/health` |

Default login credentials are seeded automatically on first start (see `backend/core/user_store.py`).

---

## 5. Common operations

### View live logs (all services)

```bash
docker compose logs -f
```

### View logs for a specific service

```bash
docker compose logs -f backend
docker compose logs -f worker
docker compose logs -f frontend
```

### Check service status

```bash
docker compose ps
```

### Restart a single service

```bash
docker compose restart backend
docker compose restart worker
```

### Stop everything

```bash
docker compose down
```

### Stop and wipe all data (Redis volume)

```bash
docker compose down -v
```

---

## 6. Rebuild after code changes

```bash
# Rebuild and restart all services
docker compose up -d --build

# Rebuild only the backend (faster when only Python code changed)
docker compose up -d --build backend worker
```

---

## 7. Firewall

Open the required ports on your VPS:

```bash
sudo ufw allow 3000/tcp   # frontend
sudo ufw allow 8000/tcp   # backend API (optional — only needed for direct API access)
sudo ufw enable
```

Redis (6379) is **not** exposed to the host — it's only reachable between containers on the internal Docker network.

---

## 8. Architecture

```
Internet
   │
   ├── :3000 ──► frontend (nginx)
   │                  │
   │            /api/* proxy
   │                  │
   └── :8000 ──► backend (FastAPI)
                      │
              ┌───────┴───────┐
              │               │
            redis           worker
           (broker)        (Celery)
```

All containers communicate over the internal `hqg_net` bridge network using service names as hostnames (`redis`, `backend`, `worker`, `frontend`).

---

## 9. Persistent data

| Volume | Contents |
|--------|----------|
| `redis_data` | All Redis data (scan results, findings, CVE cache) |
| `reports_data` | Generated HTML/PDF/JSON/CSV reports |

Volumes survive `docker compose down`. Only `docker compose down -v` removes them.

---

## 10. Production hardening (optional)

For a public-facing deployment, consider:

- **HTTPS**: Put nginx or Caddy in front as a reverse proxy with TLS termination
- **Auth**: Change default admin credentials immediately after first login
- **Firewall**: Close port 8000 if accessing the API only through the frontend proxy
- **`APP_DEBUG=false`**: Already set in the `.env` template

Example Caddy config for automatic HTTPS:

```
hqg.yourdomain.com {
    reverse_proxy localhost:3000
}

api.hqg.yourdomain.com {
    reverse_proxy localhost:8000
}
```
