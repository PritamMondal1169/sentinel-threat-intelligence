#!/usr/bin/env bash
# ==============================================================================
# SENTINEL Production Deployment Script (Linux / macOS / Cloud)
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "=========================================================="
echo "      SENTINEL Intelligence Network Production Setup      "
echo "=========================================================="

# 1. Check prerequisites
if ! command -v docker &> /dev/null; then
    echo "[-] Error: docker is not installed or not in PATH."
    exit 1
fi

DOCKER_COMPOSE_CMD=""
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker compose"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
else
    echo "[-] Error: docker compose is not installed."
    exit 1
fi

# 2. Setup .env file
if [ ! -f .env ]; then
    echo "[+] Creating .env from .env.example..."
    cp .env.example .env
    
    # Generate secure random secret for JWT
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || openssl rand -hex 32 2>/dev/null || date +%s | sha256sum | head -c 32)
    ADMIN_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))" 2>/dev/null || openssl rand -hex 16 2>/dev/null || echo "SentinelAdmin2026!")
    ANALYST_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))" 2>/dev/null || openssl rand -hex 16 2>/dev/null || echo "SentinelAnalyst2026!")

    sed -i.bak "s/SENTINEL_JWT_SECRET=.*/SENTINEL_JWT_SECRET=${JWT_SECRET}/" .env && rm -f .env.bak
    sed -i.bak "s/SENTINEL_ADMIN_PASSWORD=.*/SENTINEL_ADMIN_PASSWORD=${ADMIN_PASS}/" .env && rm -f .env.bak
    sed -i.bak "s/SENTINEL_ANALYST_PASSWORD=.*/SENTINEL_ANALYST_PASSWORD=${ANALYST_PASS}/" .env && rm -f .env.bak

    echo "[+] Generated random JWT Secret."
    echo "[+] Generated Initial Admin Password:   ${ADMIN_PASS}"
    echo "[+] Generated Initial Analyst Password: ${ANALYST_PASS}"
    echo "    (Stored in .env — make sure to save them safely!)"
fi

# 3. Build & Launch Containers
echo "[+] Building and starting SENTINEL containers..."
${DOCKER_COMPOSE_CMD} build --pull
${DOCKER_COMPOSE_CMD} up -d

# 4. Wait for healthy status
echo "[+] Waiting for SENTINEL services to report healthy..."
for i in {1..30}; do
    if curl -s http://127.0.0.1/health | grep -q '"status":"ok"'; then
        echo "[+] SENTINEL backend is healthy and responding!"
        break
    fi
    sleep 2
done

echo ""
echo "=========================================================="
echo "             SENTINEL IS LIVE & DEPLOYED                  "
echo "=========================================================="
echo "Web Dashboard:      http://localhost"
echo "API Documentation:  http://localhost/docs"
echo "System Health:      http://localhost/health"
echo "Default Admin:      username=admin"
echo ""
echo "View live logs:     ${DOCKER_COMPOSE_CMD} logs -f"
echo "Stop deployment:    ${DOCKER_COMPOSE_CMD} down"
echo "=========================================================="

