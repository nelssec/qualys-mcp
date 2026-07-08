# Build stage: same image family as runtime so the Python version matches.
FROM cgr.dev/chainguard/python:latest-dev AS builder
# The dev image defaults to nonroot (uid 65532), which cannot create /app or
# /data at the filesystem root. Switch to root for the build steps only; the
# runtime stage copies artifacts out with an explicit --chown=65532:65532, so
# this has no effect on the final (nonroot) runtime image.
USER root
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY qualys_mcp.py ./
COPY qualys/ ./qualys/
RUN python -m venv /app/venv \
    && /app/venv/bin/pip install --no-cache-dir . \
    && mkdir -p /data/cache

# Runtime: distroless-style Wolfi image — no shell, no pip, nonroot (uid 65532).
FROM cgr.dev/chainguard/python:latest
ENV MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    QUALYS_MCP_CACHE_DIR=/data/cache
COPY --from=builder --chown=65532:65532 /app/venv /app/venv
COPY --from=builder --chown=65532:65532 /data /data
VOLUME /data/cache
EXPOSE 8000
# Healthy = server accepts connections. Any HTTP status (incl. 401/406) proves
# liveness without needing the customer's auth token; only a connection-level
# failure marks unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import os,sys,urllib.request,urllib.error\ntry:\n    urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('MCP_PORT','8000')+'/mcp/', timeout=4)\nexcept urllib.error.HTTPError:\n    pass\nexcept Exception:\n    sys.exit(1)\nsys.exit(0)"]
ENTRYPOINT ["/app/venv/bin/qualys-mcp"]
