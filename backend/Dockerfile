# ==============================================================================
# SENTINEL Production Container Dockerfile
# Multi-stage, unprivileged non-root user, minimal attack surface
# ==============================================================================

# ---------- Stage 1: Dependency Builder ----------
FROM python:3.11-slim AS builder

WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ---------- Stage 2: Production Runtime ----------
FROM python:3.11-slim AS production

LABEL org.opencontainers.image.title="SENTINEL" \
      org.opencontainers.image.description="AI-Powered Web Threat Detection & Digital Trust Intelligence Network" \
      org.opencontainers.image.version="1.0.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/sentinel/.local/bin:${PATH}" \
    PYTHONPATH="/app"

# Create unprivileged system group & user
RUN groupadd -r -g 10001 sentinel && \
    useradd -r -u 10001 -g sentinel -m -d /home/sentinel -s /sbin/nologin sentinel && \
    mkdir -p /app /app/data && \
    chown -R sentinel:sentinel /app /home/sentinel

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder --chown=sentinel:sentinel /root/.local /home/sentinel/.local

# Copy application source code
COPY --chown=sentinel:sentinel . /app

USER sentinel

EXPOSE 8000

# Docker Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=3).getcode() == 200 else 1)"

# shortcut: single uvicorn worker shares in-memory S.invs/jobs/rate-limit state; switch to Redis+Postgres before multi-worker scaling
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*"]
