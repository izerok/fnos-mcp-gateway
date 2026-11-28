# fnos-mcp — one container, one HTTP MCP service + admin-managed panel.
# Machine profiles are seeded read-only, then edited in the panel and
# persisted to /data/profiles.json (0600).
# Build-time only: downloads the official fnos-cli Linux binary and
# verifies it (.gz SHA-256 pin + `fnos-cli --version` self-check).
# Runtime never downloads the CLI.
# NOTE: the asset name is fnos-cli-<version>-linux-<arch>.gz (verified
# against the live v0.6.2 release). The tag carries neither release.json
# nor SHA256SUMS; the pins below were computed by downloading both
# assets and hashing them directly (x64 f3233408..., arm64 db7d7a1e...).
# If the Release layout changes, the build fails loudly here instead of
# shipping a wrong binary.
FROM python:3.12-slim

ARG FNOS_CLI_VERSION=0.6.2
ARG FNOS_CLI_X64_SHA256=f3233408662bf667355135771ce0d6db856ef334f16c5a552a53970976ffdc79
ARG FNOS_CLI_ARM64_SHA256=db7d7a1ecac51bf1213b1b3a7eee77e14b5d16604ace00f83ba6587dad649ebc

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FNOS_CLI_CONFIG_DIR=/data/fnos-cli \
    FNOS_CLI_SESSION_STORAGE=file \
    TRIM_CLI_DISTRIBUTION=fnos \
    HOME=/data/home \
    MCP_PORT=8000

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- official fnos-cli (pinned, hash-verified) -------------------------
# The download logic lives in docker/ as plain shell + Python so the
# Dockerfile itself stays single-line instructions (no multi-line quoted
# strings, no heredocs — both break some builders).
COPY docker/ /tmp/docker-build/
RUN sh /tmp/docker-build/install-fnos-cli.sh && rm -rf /tmp/docker-build

# --- app ------------------------------------------------------------------
WORKDIR /app
COPY pyproject.toml ./
COPY src/ ./src/
COPY web/ ./web/
RUN pip install --no-cache-dir -e . \
    && useradd -u 10001 -m -s /usr/sbin/nologin fnos \
    && mkdir -p /data/fnos-cli /data/home /data/locks \
    && chown -R 10001:10001 /data /app

USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"]
CMD ["python", "-m", "fnos_mcp"]
