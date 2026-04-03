#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# HQG Platform — One-command auto-install & deploy
# Usage: bash setup.sh
# Tested on: Ubuntu 22.04 / 24.04
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── 0. Root check ─────────────────────────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
  warn "Running as root. Docker group setup will be skipped."
fi

# ── 1. Install Docker if missing ──────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  info "Docker not found — installing via official script..."
  if ! command -v curl &>/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y curl
  fi
  curl -fsSL https://get.docker.com | sudo sh
  if [[ $EUID -ne 0 ]]; then
    sudo usermod -aG docker "$USER"
    warn "Added $USER to docker group. You may need to re-login for group changes to take effect."
    warn "If 'docker' commands fail below, run: newgrp docker"
  fi
  success "Docker installed: $(docker --version)"
else
  success "Docker already installed: $(docker --version)"
fi

# Ensure docker compose v2 plugin is available
if ! docker compose version &>/dev/null 2>&1; then
  info "Docker Compose plugin not found — installing..."
  COMPOSE_VERSION="v2.27.0"
  COMPOSE_DIR="${HOME}/.docker/cli-plugins"
  mkdir -p "$COMPOSE_DIR"
  curl -fsSL \
    "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" \
    -o "$COMPOSE_DIR/docker-compose"
  chmod +x "$COMPOSE_DIR/docker-compose"
  success "Docker Compose installed: $(docker compose version)"
else
  success "Docker Compose already installed: $(docker compose version)"
fi

# ── 2. Create .env from template if not present ───────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f .env ]]; then
  if [[ -f .env.example ]]; then
    cp .env.example .env
    info "Created .env from .env.example"
  else
    error ".env.example not found. Make sure you are running this script from the repo root."
  fi
else
  info ".env already exists — skipping copy"
fi

# ── 3. Generate SECRET_KEY ────────────────────────────────────────────────────
CURRENT_KEY=$(grep -E '^SECRET_KEY=' .env | cut -d= -f2-)
if [[ -z "$CURRENT_KEY" || "$CURRENT_KEY" == "CHANGE_ME"* ]]; then
  NEW_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null \
            || openssl rand -hex 32)
  # Replace (handles both empty and placeholder values)
  sed -i "s|^SECRET_KEY=.*|SECRET_KEY=${NEW_KEY}|" .env
  success "SECRET_KEY generated and saved to .env"
else
  info "SECRET_KEY already set — skipping"
fi

# ── 4. Prompt for admin password ──────────────────────────────────────────────
CURRENT_PASS=$(grep -E '^HQG_ADMIN_PASSWORD=' .env | cut -d= -f2-)
if [[ -z "$CURRENT_PASS" || "$CURRENT_PASS" == "CHANGE_ME"* ]]; then
  echo ""
  echo -e "${YELLOW}Set the admin password for the HQG platform:${NC}"
  while true; do
    read -rsp "  Enter admin password (min 8 chars): " ADMIN_PASS; echo
    if [[ ${#ADMIN_PASS} -lt 8 ]]; then
      warn "Password too short. Please use at least 8 characters."
    else
      read -rsp "  Confirm password: " ADMIN_PASS2; echo
      if [[ "$ADMIN_PASS" == "$ADMIN_PASS2" ]]; then
        break
      else
        warn "Passwords do not match. Try again."
      fi
    fi
  done
  # Escape special characters for sed
  ESCAPED=$(printf '%s\n' "$ADMIN_PASS" | sed 's/[[\.*^$()+?{|]/\\&/g')
  sed -i "s|^HQG_ADMIN_PASSWORD=.*|HQG_ADMIN_PASSWORD=${ESCAPED}|" .env
  success "Admin password saved to .env"
else
  info "HQG_ADMIN_PASSWORD already set — skipping"
fi

# ── 5. Prompt for ALLOWED_ORIGINS ─────────────────────────────────────────────
CURRENT_ORIGINS=$(grep -E '^ALLOWED_ORIGINS=' .env | cut -d= -f2-)
DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "YOUR_SERVER_IP")
echo ""
echo -e "${YELLOW}Set ALLOWED_ORIGINS (CORS whitelist for the frontend):${NC}"
echo -e "  Current value: ${CYAN}${CURRENT_ORIGINS}${NC}"
echo -e "  Detected server IP: ${CYAN}${DEFAULT_IP}${NC}"
read -rp "  Enter value [leave blank to auto-use detected IP, or enter IP/domain]: " ORIGINS_INPUT
if [[ -n "$ORIGINS_INPUT" ]]; then
  # If user entered just an IP or domain (no scheme), prefix http://
  if [[ ! "$ORIGINS_INPUT" =~ ^https?:// ]]; then
    ORIGINS_INPUT="http://${ORIGINS_INPUT}:3000"
  fi
  sed -i "s|^ALLOWED_ORIGINS=.*|ALLOWED_ORIGINS=${ORIGINS_INPUT}|" .env
  success "ALLOWED_ORIGINS updated to: ${ORIGINS_INPUT}"
else
  # Auto-set to detected IP (most common case for VPS deployments)
  if [[ "$DEFAULT_IP" != "YOUR_SERVER_IP" && "$DEFAULT_IP" != "127.0.0.1" ]]; then
    AUTO_ORIGIN="http://${DEFAULT_IP}:3000"
    sed -i "s|^ALLOWED_ORIGINS=.*|ALLOWED_ORIGINS=${AUTO_ORIGIN}|" .env
    success "ALLOWED_ORIGINS auto-set to: ${AUTO_ORIGIN}"
  else
    info "ALLOWED_ORIGINS unchanged: ${CURRENT_ORIGINS}"
  fi
fi

# ── 6. Configure firewall (ufw) ───────────────────────────────────────────────
if command -v ufw &>/dev/null; then
  echo ""
  read -rp "Open firewall ports 3000 (frontend) and 8000 (API) via ufw? [Y/n]: " UFW_CHOICE
  UFW_CHOICE="${UFW_CHOICE:-Y}"
  if [[ "$UFW_CHOICE" =~ ^[Yy]$ ]]; then
    sudo ufw allow 3000/tcp >/dev/null 2>&1 && success "ufw: port 3000 open"
    sudo ufw allow 8000/tcp >/dev/null 2>&1 && success "ufw: port 8000 open"
    sudo ufw --force enable >/dev/null 2>&1 && success "ufw: enabled"
  else
    info "Skipping firewall configuration"
  fi
fi

# ── 7. Build and start all services ──────────────────────────────────────────
echo ""
info "Building and starting all services (this may take 5–10 minutes on first run)..."
docker compose up -d --build

echo ""
success "All services started!"

# ── 8. Wait for backend health check ─────────────────────────────────────────
echo ""
info "Waiting for backend to become healthy..."
ATTEMPTS=0
MAX_ATTEMPTS=30
until curl -sf http://localhost:8000/health >/dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if [[ $ATTEMPTS -ge $MAX_ATTEMPTS ]]; then
    warn "Backend health check timed out after ${MAX_ATTEMPTS} attempts."
    warn "Run 'docker compose logs backend' to investigate."
    break
  fi
  echo -n "."
  sleep 3
done
[[ $ATTEMPTS -lt $MAX_ATTEMPTS ]] && echo "" && success "Backend is healthy!"

# ── 9. Print access URLs ──────────────────────────────────────────────────────
FINAL_IP=$(grep -E '^ALLOWED_ORIGINS=' .env | cut -d= -f2- | sed 's|https\?://||' | sed 's|:.*||')
[[ -z "$FINAL_IP" || "$FINAL_IP" == "localhost" ]] && FINAL_IP="${DEFAULT_IP}"

echo ""
echo -e "─────────────────────────────────────────────────────"
echo -e "${GREEN}  HQG Platform is running!${NC}"
echo -e "─────────────────────────────────────────────────────"
echo -e "  Frontend   : ${CYAN}http://${FINAL_IP}:3000${NC}"
echo -e "  API docs   : ${CYAN}http://${FINAL_IP}:8000/docs${NC}  (dev only)"
echo -e "  Health     : ${CYAN}http://${FINAL_IP}:8000/health${NC}"
echo -e "─────────────────────────────────────────────────────"
echo -e "  Admin user : ${YELLOW}$(grep -E '^HQG_ADMIN_USERNAME=' .env | cut -d= -f2-)${NC}"
echo -e "  Password   : set in .env (HQG_ADMIN_PASSWORD)"
echo -e "─────────────────────────────────────────────────────"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo -e "  docker compose logs -f          # live logs (all services)"
echo -e "  docker compose logs -f backend  # backend only"
echo -e "  docker compose ps               # service status"
echo -e "  docker compose restart backend  # restart backend"
echo -e "  docker compose down             # stop all services"
echo -e "  docker compose down -v          # stop + wipe data"
echo ""
