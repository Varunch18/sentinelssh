# SentinelSSH honeypot — paramiko SSH listener + ingest pipeline.
# Build context is the repository root (the pipeline sink imports `core`).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    HONEYPOT_PORT=2222

WORKDIR /app

COPY honeypot/requirements.txt /app/honeypot/requirements.txt
RUN pip install --no-cache-dir -r /app/honeypot/requirements.txt

COPY core /app/core
COPY honeypot /app/honeypot

# Persistent host key + capture log live on mounted volumes.
RUN mkdir -p /app/keys /app/data

EXPOSE 2222

# Lightweight TCP liveness probe on the listener port.
HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=5 \
    CMD python -c "import socket,sys; s=socket.create_connection(('127.0.0.1',int(__import__('os').environ.get('HONEYPOT_PORT','2222'))),2); s.close()" || exit 1

CMD ["python", "-m", "honeypot.server"]
