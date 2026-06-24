# SentinelSSH backend — Flask REST API + SocketIO + static SOC dashboard.
# Build context is the repository root (so the shared `core` package and the
# `frontend/` assets can be copied alongside the backend).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app:/app/backend \
    PORT=8008

WORKDIR /app

# curl is used by the container HEALTHCHECK.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first for better layer caching.
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Application code + shared packages + static frontend.
COPY core /app/core
COPY backend /app/backend
COPY frontend /app/frontend
COPY scripts /app/scripts
COPY deploy /app/deploy

RUN chmod +x /app/backend/entrypoint.sh && mkdir -p /app/data

EXPOSE 8008

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
    CMD curl -fsS http://localhost:8008/health || exit 1

ENTRYPOINT ["/app/backend/entrypoint.sh"]
