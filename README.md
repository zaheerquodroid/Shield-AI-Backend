# ShieldAI Security Proxy

A generic reverse proxy that wraps any web application with security middleware — WAF, session validation, error sanitization, audit logging, and more — without modifying the upstream app.

## Architecture

```
Client → ALB → ShieldAI Proxy → Upstream App
                  │
          ┌───────┴────────┐
          │  Middleware     │
          │  Pipeline       │
          │                 │
          │  1. Router      │
          │  2. Context     │
          │  3. Session     │
          │  4. Sanitizer   │
          │  5. Audit       │
          └─────────────────┘
```

## Features

- **Reverse Proxy** — Transparent forwarding of all HTTP methods, headers, and streaming responses
- **Multi-Tenant** — Route by `Host` header to per-customer configuration
- **Context Injection** — Add `X-Request-ID`, `X-Tenant-ID`, `X-User-ID` headers; strip spoofed headers
- **Middleware Pipeline** — Ordered, configurable chain of request/response processors
- **Config API** — CRUD endpoints for managing customers and apps
- **Health Checks** — `/health` and `/ready` endpoints with dependency status

## Quick Start

### Local Development

```bash
# Start all services (proxy, Redis, PostgreSQL, mock upstream)
docker compose -f docker/docker-compose.dev.yml up

# Proxy is available at http://localhost:8080
curl http://localhost:8080/health
curl http://localhost:8080/anything
```

### Run Tests

```bash
pip install -e ".[dev]"
pytest tests/
```

## Project Structure

```
proxy/                  # Application code
  main.py               # FastAPI app + reverse proxy
  config/               # YAML + env config, multi-tenant config service
  middleware/            # Ordered middleware pipeline
  models/               # Pydantic models + SQL schema
  api/                  # Config CRUD + auth
  store/                # Redis + PostgreSQL connections
  health.py             # Health/readiness endpoints
  logging_config.py     # structlog JSON logging

terraform/              # AWS ECS Fargate infrastructure
docker/                 # Dockerfile + docker-compose
tests/                  # pytest test suite
```

## Configuration

Configuration is loaded from YAML defaults, overridden by environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_UPSTREAM_URL` | `http://localhost:3000` | Default upstream app URL |
| `PROXY_LISTEN_PORT` | `8080` | Proxy listen port |
| `PROXY_REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `PROXY_POSTGRES_URL` | `postgresql://...` | PostgreSQL connection URL |
| `PROXY_LOG_LEVEL` | `info` | Log level |
| `PROXY_CONFIG_FILE` | `proxy/config/defaults.yaml` | Config file path |
| `PROXY_API_KEY` | (required) | API key for config endpoints |

## License

MIT
