# ==============================================================================
# SENTINEL Root Production Container Dockerfile
# Automatically detected by Render, Railway, Fly.io, Koyeb, and Cloud Providers
# ==============================================================================

# ---------- Stage 1: Dependency Builder ----------
FROM python:3.11-slim AS builder

WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------- Stage 2: Production Runtime ----------
FROM python:3.11-slim AS production

LABEL org.opencontainers.image.title="SENTINEL" \
      org.opencontainers.image.description="AI-Powered Web Threat Detection & Digital Trust Intelligence Network" \
      org.opencontainers.image.version="1.0.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app" \
    PORT=8000

# Create unprivileged system group & user
RUN groupadd -r -g 10001 sentinel && \
    useradd -r -u 10001 -g sentinel -m -d /home/sentinel -s /sbin/nologin sentinel && \
    mkdir -p /app /app/data && \
    chown -R sentinel:sentinel /app /home/sentinel

WORKDIR /app

# Copy installed Python packages into /usr/local so all UIDs resolve dependencies
COPY --from=builder /install /usr/local

# Copy backend code
COPY --chown=sentinel:sentinel backend/ /app/

USER sentinel

EXPOSE 8000

# Docker Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, sys, urllib.request; port = os.environ.get('PORT', '8000'); sys.exit(0 if urllib.request.urlopen(f'http://localhost:{port}/health', timeout=3).getcode() == 200 else 1)"

# shortcut: single uvicorn worker shares in-memory S.invs/jobs/rate-limit state; switch to Redis+Postgres before multi-worker scaling
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --proxy-headers --forwarded-allow-ips '127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'"]
