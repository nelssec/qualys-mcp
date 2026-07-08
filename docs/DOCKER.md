# Running qualys-mcp with Docker

This guide covers building and running the Qualys MCP server as a Docker container that speaks MCP over Streamable HTTP, so it can serve multiple clients (Claude Code, Claude Desktop, or any other MCP-compatible client) from one long-running process.

If you just want the quickest single-user setup, the [README](../README.md) covers running via `uvx` with stdio transport — no Docker required. Use this guide when you want a persistent, network-reachable server.

## 1. Requirements

- Docker 24 or later, with Compose v2 (`docker compose`, not the old standalone `docker-compose`)
- A Qualys API user — a **read-only** user is strongly recommended, since the server only ever performs read operations
- Outbound HTTPS access from wherever the container runs to your Qualys platform (e.g. `qualysapi.qg2.apps.qualys.com` and `gateway.qg2.apps.qualys.com` for US2)

## 2. Build the image

From the repository root:

```bash
docker build -t qualys-mcp:latest .
```

This produces a small, hardened image:

- Multi-stage build on Chainguard/Wolfi base images
- Final runtime image has **no shell and no package manager** (distroless-style)
- Runs as a **non-root user** (uid 65532), not root
- Contains no credentials — those are supplied at container run time, never baked into the image

## 3. Configure

Copy the example environment file and fill in your Qualys credentials:

```bash
cp .env.example .env
```

Edit `.env` and set at minimum `QUALYS_USERNAME`, `QUALYS_PASSWORD`, and `QUALYS_POD`. `.env` is already excluded from both git and the Docker build context, so your credentials never leave your machine.

### Environment variables

| Variable | Required? | Default | Purpose |
|---|---|---|---|
| `QUALYS_USERNAME` | Yes | — | Qualys API username |
| `QUALYS_PASSWORD` | Yes | — | Qualys API password |
| `QUALYS_POD` | Yes (unless using the URL pair below) | — | Your Qualys platform POD code (`US1`, `US2`, `US3`, `US4`, `EU1`, `EU2`, `EU3`, `IN1`, `CA1`, `AE1`, `UK1`, `AU1`, `KSA1`). The server derives the correct API and gateway URLs from this. |
| `QUALYS_BASE_URL` | Yes, only if not using `QUALYS_POD` | — | Explicit Qualys API base URL (e.g. `https://qualysapi.qg2.apps.qualys.com`). Use this together with `QUALYS_GATEWAY_URL` instead of `QUALYS_POD` if your platform URL isn't covered by a POD code. |
| `QUALYS_GATEWAY_URL` | Yes, only if not using `QUALYS_POD` | — | Explicit Qualys gateway URL (e.g. `https://gateway.qg2.apps.qualys.com`). Pairs with `QUALYS_BASE_URL`. |
| `MCP_AUTH_TOKEN` | No | unset (no auth) | Bearer token clients must send as `Authorization: Bearer <token>`. Strongly recommended if the server is reachable from anywhere beyond localhost. Generate one with `openssl rand -hex 32`. |
| `MCP_PORT` | No | `8000` | Port the server listens on inside the container. `compose.yaml` reads this same value to set the published port, so change it here only. |
| `MCP_TRANSPORT` | No | `http` (baked into the image) | Transport the server speaks. The Docker image is built to always run in `http` mode; you don't need to set this yourself when using Docker. |
| `MCP_HOST` | No | `0.0.0.0` (baked into the image) | Interface the server binds to inside the container. Leave this alone — the container's own network namespace is already isolated, and `compose.yaml` controls host exposure via `ports:`. |
| `QUALYS_MCP_CACHE_DIR` | No | `/data/cache` (baked into the image) | Where response caches are stored inside the container. Matches the `qualys-cache` volume mount — no need to change it. |

You only need to touch the first five rows in normal use. The last three are baked into the image already and listed here for completeness.

## 4. Run

```bash
docker compose up -d
```

Check that the container is healthy:

```bash
docker compose ps
```

You should see `STATUS` reported as `Up ... (healthy)`.

Check the startup log for the transport banner:

```bash
docker compose logs
```

Look for a line like:

```
[qualys-mcp] transport=streamable-http  http://0.0.0.0:8000/mcp/  auth=none
```

(`auth=bearer` instead of `auth=none` if you set `MCP_AUTH_TOKEN`.)

By default, `compose.yaml` publishes the server only on `127.0.0.1` (loopback) — it is not reachable from other machines. You can confirm the server is answering with:

```bash
curl http://127.0.0.1:8000/mcp
```

A `406 Not Acceptable` response (or `401 Unauthorized` if you set `MCP_AUTH_TOKEN`) means the server is up and reachable — either proves the server is answering. MCP clients speak a specific content-negotiation protocol (and, when configured, a bearer-token auth check) that a plain `curl` request doesn't satisfy, so 406/401 here is expected and healthy, not an error.

## 5. Connect clients

### Claude Code

```bash
claude mcp add --transport http qualys http://127.0.0.1:8000/mcp/
```

If you set `MCP_AUTH_TOKEN`, include it as a header:

```bash
claude mcp add --transport http qualys http://127.0.0.1:8000/mcp/ --header "Authorization: Bearer <token>"
```

### Any other MCP client (generic JSON config)

```json
{
  "mcpServers": {
    "qualys": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp/"
    }
  }
}
```

With a token configured, add a `headers` block:

```json
{
  "mcpServers": {
    "qualys": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp/",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

## 6. Security notes

- **The image itself contains no credentials.** `QUALYS_USERNAME` / `QUALYS_PASSWORD` are supplied only at container run time via `.env`, and `.env` is excluded from both version control and the Docker build context.
- **This server proxies your Qualys credentials.** Anyone who can reach the MCP endpoint and doesn't need a bearer token can make read-only Qualys API calls on your behalf. Treat network exposure accordingly.
- **Default exposure is loopback-only.** `compose.yaml` publishes the port as `127.0.0.1:<port>:<port>`, so only processes on the same machine can reach it out of the box.
- **Widening exposure requires a token.** If you remove the `127.0.0.1:` prefix in `compose.yaml` (or otherwise expose the port beyond localhost), set `MCP_AUTH_TOKEN` in `.env` first. Without it, anyone who can reach the port can use your Qualys credentials through the server.
- **Use a TLS-terminating reverse proxy for any non-local exposure.** The server itself speaks plain HTTP; if you expose it beyond your own machine (e.g. to other hosts on a private network), put a reverse proxy (nginx, Caddy, Traefik, your cloud load balancer, etc.) in front of it to terminate TLS.
- **The runtime image runs as a non-root user with no shell.** A Trivy vulnerability scan of the built image found **0 HIGH and 0 CRITICAL vulnerabilities** across the Wolfi OS layer and all 65 scanned Python packages.

## 7. Persistence

The server caches Qualys API responses to disk to keep repeated queries fast. `compose.yaml` mounts a named Docker volume, `qualys-cache`, at `/data/cache` inside the container, so the cache survives container restarts.

It's always safe to clear the cache — it rebuilds automatically from live Qualys data on the next request:

```bash
docker compose down -v
```

The `-v` flag removes the named volume along with the containers. Plain `docker compose down` (without `-v`) stops the container but keeps the cache volume intact for next time.

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Container exits immediately; `docker compose logs` shows `OSError: Qualys platform not configured...` | `QUALYS_POD` (or the `QUALYS_BASE_URL` / `QUALYS_GATEWAY_URL` pair) is missing from `.env` | Edit `.env` and set `QUALYS_POD` (or both URL variables), then `docker compose up -d` again |
| Requests to the MCP endpoint return `401 Unauthorized` | `MCP_AUTH_TOKEN` is set on the server but the client isn't sending a matching `Authorization: Bearer <token>` header | Add the header on the client side (see [Connect clients](#5-connect-clients)), or confirm the token in `.env` matches what the client sends |
| Tool calls succeed but return Qualys-side `401`/`403` errors in the response | `QUALYS_USERNAME` / `QUALYS_PASSWORD` are wrong, or the API user lacks permission for the requested module | Verify the credentials work by logging into the Qualys UI directly, and confirm the API user's role has access to the relevant module (VMDR, CSAM, etc.) |
| Qualys-side `401` errors even though the same credentials work outside Docker | Your password contains a `$`. Docker Compose expands `$NAME` inside `.env` values, silently mangling the password before it reaches the container | In `.env`, escape each `$` as `$$` (e.g. write `pa$$word` for `pa$word`). Alternatively, run without compose — `docker run --env-file .env ...` passes values through literally, no escaping needed |
| `docker compose ps` never shows `healthy` | Server process crashed on startup, or is still starting | Check `docker compose logs` for the actual error; the health check allows a 15-second startup grace period before the first check |
