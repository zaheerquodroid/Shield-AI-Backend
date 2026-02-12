# Shield AI — Product Stories & Tasks

**Product:** ShieldAI Security Wrapper
**Jira Project:** [SHIELD](https://quodroid.atlassian.net/jira/software/projects/SHIELD/boards)
**Date:** February 2026
**Source:** Derived from Coco TestAI Security Audit, genericized for multi-app use
**Total Estimated Effort:** ~327 hours (full product)
**Epics:** 14 | **Stories:** 28 | **Priority Split:** P0 ~118h, P1 ~139h, P2 ~70h

---

## How to Read This Document

- **Epics** group related work by product component.
- **Stories** describe a product capability from a customer perspective.
- **Tasks** are specific developer actions to build the feature.
- **Priority** follows product roadmap: P0 (MVP), P1 (Core), P2 (Growth).
- **Effort** is in developer-hours and includes implementation + testing.
- **Dependencies** are noted where a story requires another to be completed first.

---

## Product Architecture

```
Internet → Edge Platform (CloudFront SaaS / Cloudflare) → WAF + Headers → Security Proxy → Customer App → Database Proxy → PostgreSQL
```

| Component | Epics | Purpose |
|-----------|-------|---------|
| Security Proxy Platform | SHIELD-34 | Core reverse proxy application, config system, deployment |
| Multi-Tenant Edge Platform | SHIELD-39 | CloudFront SaaS Manager, Cloudflare alternative, customer onboarding |
| Edge Security | SHIELD-1, SHIELD-2 | WAF rules, security headers, rate limiting, bot protection |
| Security Proxy Features | SHIELD-3, SHIELD-4, SHIELD-5, SHIELD-6 | Sanitize traffic, manage sessions, log everything |
| Database Proxy | SHIELD-7 | Enforce tenant isolation at database level |
| Infrastructure | SHIELD-8, SHIELD-9 | Secure deployment, secrets management |
| Developer Tools | SHIELD-10, SHIELD-11, SHIELD-12 | CI/CD templates, SBOM, policy templates |

---

## Table of Contents

- [SHIELD-34: Security Proxy Platform Foundation](#shield-34-security-proxy-platform-foundation)
- [SHIELD-39: Multi-Tenant Edge Platform](#shield-39-multi-tenant-edge-platform)
- [SHIELD-1: WAF & Threat Protection](#shield-1-waf--threat-protection)
- [SHIELD-2: Security Headers](#shield-2-security-headers)
- [SHIELD-3: Response Sanitization](#shield-3-response-sanitization)
- [SHIELD-4: Request Sanitization & LLM Protection](#shield-4-request-sanitization--llm-protection)
- [SHIELD-5: Session Management](#shield-5-session-management)
- [SHIELD-6: Audit Logging & Compliance](#shield-6-audit-logging--compliance)
- [SHIELD-7: Row-Level Security & Tenant Isolation](#shield-7-row-level-security--tenant-isolation)
- [SHIELD-8: Secrets Management](#shield-8-secrets-management)
- [SHIELD-9: Container & Kubernetes Hardening](#shield-9-container--kubernetes-hardening)
- [SHIELD-10: CI/CD Security Scanning Templates](#shield-10-cicd-security-scanning-templates)
- [SHIELD-11: SBOM & Supply Chain Security](#shield-11-sbom--supply-chain-security)
- [SHIELD-12: Security Policy Templates](#shield-12-security-policy-templates)
- [Effort Summary](#effort-summary)

---

## SHIELD-34: Security Proxy Platform Foundation

**Priority:** P0 — MVP
**Component:** Security Proxy Platform
**Source:** SECURITY_WRAPPER.md — Component 2 (Security Proxy Application)
**Blocks:** SHIELD-3, SHIELD-4, SHIELD-5, SHIELD-6 (all proxy feature epics depend on this)

> This epic builds the core reverse proxy application that all security middleware plugs into.
> Without this, none of the proxy feature stories (error sanitization, LLM protection, session management, audit logging) can be implemented.

---

### Story 34.1: Build security proxy reverse proxy application (SHIELD-35)

**As a** ShieldAI operator, **I want** a high-performance reverse proxy application with an ordered middleware pipeline, **so that** security middleware can inspect, modify, and log all HTTP traffic between the edge and customer applications without modifying customer code.

**Acceptance Criteria:**
- Proxy accepts HTTP/HTTPS connections and forwards to a configurable upstream origin URL.
- Request/response middleware pipeline supports an ordered chain: session validator → request sanitizer → context injector → upstream → response sanitizer → audit logger → session updater.
- Middleware can be individually enabled/disabled per customer configuration.
- Proxy preserves all request headers, body, query parameters, and streaming responses.
- Proxy supports HTTP/1.1 and HTTP/2.
- Health check endpoint (`GET /health`) returns 200 with proxy status, upstream reachability, and Redis connectivity.
- Readiness probe (`GET /ready`) returns 200 only when proxy is fully initialized.
- Graceful shutdown drains in-flight requests (30s timeout) on SIGTERM.
- Configuration loaded from YAML file with environment variable overrides.
- Proxy adds <10ms p99 latency overhead.
- All application logs emitted as structured JSON.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 35.1 | Scaffold proxy application using FastAPI/Starlette (Python) or net/http (Go). Implement reverse proxy handler that reads upstream URL from config and forwards all requests with full header/body preservation. Support configurable listen port (default 8080). | `proxy/main.py` or `proxy/main.go` | 4h |
| 35.2 | Build middleware pipeline framework: ordered list of middleware functions, each receiving request context and returning modified request/response. Support async middleware for non-blocking I/O. Middleware registration via config. | `proxy/middleware/pipeline.py` | 3h |
| 35.3 | Implement configuration loader: read YAML config file path from `CONFIG_FILE` env var, merge with environment variables. Config schema includes: upstream_url, listen_port, redis_url, log_level, enabled_features map, middleware_chain order. Support hot-reload on SIGHUP signal. | `proxy/config/loader.py` | 2h |
| 35.4 | Add health check endpoint (`GET /health`) returning JSON with proxy status, upstream ping result, Redis ping result. Add readiness probe (`GET /ready`) that returns 503 until all connections are established. | `proxy/health.py` | 1h |
| 35.5 | Implement graceful shutdown: on SIGTERM, stop accepting new connections, wait for in-flight requests to complete (30s max), then exit 0. Log shutdown progress. | `proxy/main.py` | 1h |
| 35.6 | Add structured JSON logging using `structlog` or equivalent. Every log line includes: timestamp, level, module, message, request_id (from context). Log format configurable (JSON for prod, human-readable for dev). | `proxy/logging.py` | 1h |
| 35.7 | Create Dockerfile: multi-stage build (builder + runtime), non-root user, HEALTHCHECK instruction, minimal base image (python:3.12-slim or alpine). | `proxy/Dockerfile` | 1h |
| 35.8 | Add Redis connection pool for session storage and rate limiting. Configurable pool size (default 10). Connection retry with exponential backoff (max 5 retries). Graceful degradation if Redis unavailable (skip session checks, log warning). | `proxy/store/redis.py` | 2h |
| 35.9 | Test: proxy forwards GET/POST/PUT/DELETE correctly, middleware chain executes in order, health check reports accurate status, graceful shutdown completes in-flight requests, config reload works, Redis connection pool handles disconnects. | Testing | 3h |

**Total Effort:** 18 hours

---

### Story 34.2: Build context injector middleware (SHIELD-36)

**As a** ShieldAI customer, **I want** every request to my app enriched with security context headers (request ID, tenant ID, user ID), **so that** my application and downstream components (database proxy, logging) can correlate requests, identify tenants, and trace issues.

**Acceptance Criteria:**
- Every proxied request gets a unique `X-Request-ID` header (UUID v4, first 8 characters).
- `X-Tenant-ID` header injected from session context (if authenticated session exists).
- `X-User-ID` header injected from session context (if authenticated session exists).
- `X-Forwarded-For` header correctly set with client IP (appended if already present).
- Client-supplied `X-Tenant-ID` and `X-User-ID` headers are stripped before injection to prevent spoofing.
- Original client `X-Request-ID` preserved as `X-Original-Request-ID` if present.
- Context values available to all downstream middleware via request context object.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 36.1 | Build `ContextInjector` middleware. Generate UUID for X-Request-ID (8-char prefix), strip client-supplied X-Tenant-ID and X-User-ID, inject from session context if available, set X-Forwarded-For from client IP. Store all context values in request state for downstream middleware. | `proxy/middleware/context_injector.py` | 2h |
| 36.2 | Implement header security: strip all `X-ShieldAI-*` internal headers from incoming requests. Preserve original X-Request-ID as X-Original-Request-ID. Add X-Forwarded-Proto header. | `proxy/middleware/context_injector.py` | 1h |
| 36.3 | Test: verify headers injected correctly, verify spoofed X-Tenant-ID stripped, verify X-Request-ID unique per request, verify context available to downstream middleware. | Testing | 1h |

**Total Effort:** 4 hours

---

### Story 34.3: Build multi-tenant customer configuration system (SHIELD-37)

**As a** ShieldAI operator, **I want** a configuration system that stores per-customer security settings and routes requests to the correct customer configuration, **so that** each customer's proxy behavior (enabled features, endpoint patterns, thresholds) is independently configurable without redeploying the proxy.

**Acceptance Criteria:**
- Customer configuration stored in PostgreSQL with JSON settings.
- Configuration schema includes: customer_id, app name, origin URL, custom domain, enabled features (booleans), LLM endpoint patterns, auth endpoint patterns, webhook endpoint patterns, rate limit overrides, session timeout, header preset mode.
- Proxy loads all customer configs on startup and caches in memory.
- Configuration hot-reloads on change (polling every 60s or PostgreSQL LISTEN/NOTIFY).
- Multi-tenant request routing: proxy identifies customer by `Host` header (custom domain lookup), loads correct config, attaches to request context.
- Config CRUD API endpoints protected by API key authentication.
- Fallback to default configuration if customer-specific config not found.
- Default config: all features enabled, standard timeouts, standard rate limits.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 37.1 | Design and create PostgreSQL schema: `customers` table (id UUID, name, plan, api_key_hash, created_at, settings JSONB), `apps` table (id UUID, customer_id FK, name, origin_url, domain UNIQUE, enabled_features JSONB, settings JSONB, created_at). Create migration SQL. | `proxy/models/schema.sql` | 3h |
| 37.2 | Build configuration service: load all customer configs on startup into memory dict keyed by domain. Provide `get_config(domain)` method. Cache with 60s TTL. Fallback to default config for unknown domains. | `proxy/config/customer_config.py` | 3h |
| 37.3 | Build request router middleware: on each request, extract `Host` header, lookup domain in config service, attach customer config to request context. If domain not found, use default config. Log unknown domains at WARN level. | `proxy/middleware/router.py` | 2h |
| 37.4 | Build config CRUD API: `POST /api/config/customers/` (create), `GET /api/config/customers/{id}` (read), `PUT /api/config/customers/{id}` (update), `DELETE /api/config/customers/{id}` (delete). Same for apps. Protected by API key in `Authorization` header. | `proxy/api/config.py` | 3h |
| 37.5 | Implement config hot-reload: use PostgreSQL LISTEN/NOTIFY on config changes, or poll every 60s for updated_at changes. Invalidate in-memory cache on change. Log reloads. | `proxy/config/customer_config.py` | 1h |
| 37.6 | Test: multi-tenant routing correctly resolves different domains to different configs, config changes propagate within 60s, fallback to defaults works, API CRUD operations work, API key auth rejects unauthorized requests. | Testing | 2h |

**Total Effort:** 14 hours

---

### Story 34.4: Build security proxy and database proxy deployment infrastructure (SHIELD-38)

**As a** ShieldAI operator, **I want** the security proxy and database proxy containerized and deployable to AWS ECS Fargate with auto-scaling, health checks, and multi-environment support, **so that** the proxy infrastructure can be deployed, operated, and scaled in production.

**Acceptance Criteria:**
- Security proxy Docker image builds, passes health checks, and runs as non-root.
- Database proxy Docker image builds, passes health checks, and runs as non-root.
- ECS Fargate task definitions created via Terraform for both proxies.
- ALB configured to route all external traffic to security proxy.
- Security proxy connects to Redis (sessions) and PostgreSQL (config).
- Database proxy accepts PostgreSQL wire protocol connections from customer app.
- Auto-scaling policies: target CPU 70%, target request count 1000/instance. Min 1, max 10.
- Environment-specific configurations (test/demo/prod) via Terraform tfvars.
- CloudWatch log groups created for both proxy containers.
- Security groups: ALB → security proxy (8080), security proxy → customer app (configurable), db-proxy → RDS (5432). No direct internet access to proxies.
- docker-compose.yml for local development simulating full topology.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 38.1 | Create Terraform module `proxy-ecs/` for security proxy: ECS Fargate task definition (CPU 256, memory 512 for test; 512/1024 for prod), container definition referencing proxy Docker image, environment variables from Secrets Manager, ALB target group with health check on `/health`. | `terraform/modules/proxy-ecs/` | 3h |
| 38.2 | Create Terraform module `db-proxy-ecs/` for database proxy: ECS Fargate task definition, security group allowing port 5432 inbound only from security proxy SG, environment variables for upstream PostgreSQL connection. | `terraform/modules/db-proxy-ecs/` | 2h |
| 38.3 | Configure ALB: HTTPS listener (443) with ACM certificate, forward to security proxy target group. HTTP listener (80) redirects to HTTPS. Health check path `/health`, interval 15s, threshold 2. | `terraform/modules/proxy-ecs/alb.tf` | 1h |
| 38.4 | Add auto-scaling: ECS service auto-scaling with target tracking on CPU utilization (70%) and ALB request count per target (1000). Min capacity 1 (test) / 2 (prod), max capacity 10. Scale-in cooldown 300s. | `terraform/modules/proxy-ecs/scaling.tf` | 1h |
| 38.5 | Add environment-specific tfvars: test (1 instance, passthrough mode, relaxed timeouts), demo (2 instances, enforce mode), prod (2+ instances, enforce mode, strict timeouts). | `terraform/environments/{test,demo,prod}.tfvars` | 1h |
| 38.6 | Create `docker-compose.dev.yml` for local development: security proxy, database proxy, Redis, PostgreSQL, and a mock upstream app. Network topology mirrors production. Includes volume mounts for live code reload. | `infrastructure/docker/docker-compose.dev.yml` | 1h |
| 38.7 | Test: deploy to test environment via Terraform, verify traffic flows through ALB → proxy → upstream, verify health checks pass, verify auto-scaling triggers on load, verify CloudWatch logs appear. | Testing | 2h |

**Total Effort:** 11 hours

---

## SHIELD-39: Multi-Tenant Edge Platform

**Priority:** P0 — MVP (SHIELD-40), P1 — Core (SHIELD-41, SHIELD-42)
**Component:** Edge Security Layer
**Source:** SECURITY_WRAPPER.md — Components 1B and 1C

> This epic builds the multi-tenant edge infrastructure that provides WAF, DDoS, and security headers for all customer domains.
> CloudFront SaaS Manager is the primary platform (10-20x cheaper than Cloudflare Enterprise for multi-tenant).
> Cloudflare module provides an alternative for single-domain or non-AWS deployments.

---

### Story 39.1: Deploy AWS CloudFront SaaS Manager multi-tenant distribution (SHIELD-40)

**As a** ShieldAI operator, **I want** a CloudFront multi-tenant distribution with inherited WAF and security headers, **so that** every customer domain automatically gets edge-level WAF protection, DDoS mitigation, and security headers without per-customer WAF configuration.

**Acceptance Criteria:**
- Multi-tenant CloudFront distribution created via Terraform.
- WAF WebACL (from SHIELD-13) attached to distribution — all distribution tenants inherit WAF rules automatically.
- Response Headers Policy attached — all tenants inherit security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- Distribution tenant Terraform resource template available for per-customer provisioning.
- Each tenant maps a customer domain to a customer-specific origin URL (via security proxy).
- SSL certificates managed via ACM (free, auto-renewing).
- TLS 1.2+ enforced for all tenants.
- Viewer protocol policy set to redirect-to-https.
- All HTTP methods allowed (GET, POST, PUT, DELETE, PATCH, OPTIONS).
- Headers and cookies forwarded to origin (proxy handles caching).
- Cost: <$0.10/tenant after first 200 (free).

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 40.1 | Create Terraform module `cloudfront-saas/` with `aws_cloudfront_distribution` resource configured as multi-tenant. Default origin pointing to security proxy ALB. Viewer protocol policy: redirect-to-https. Forward all headers, query strings, and cookies to origin. Price class: PriceClass_100. | `terraform/modules/cloudfront-saas/main.tf` | 3h |
| 40.2 | Attach WAF WebACL (created by SHIELD-13 waf/ module) to multi-tenant distribution via `web_acl_id`. Verify all distribution tenants inherit WAF rules. | `terraform/modules/cloudfront-saas/main.tf` | 1h |
| 40.3 | Create `aws_cloudfront_response_headers_policy` resource with security headers: HSTS (max-age=31536000, includeSubDomains, preload), CSP (configurable default), X-Frame-Options (DENY), X-Content-Type-Options (nosniff), Referrer-Policy (strict-origin-when-cross-origin), XSS-Protection (1; mode=block), Permissions-Policy (camera=(), microphone=(), geolocation=()) via custom headers. Attach to distribution. | `terraform/modules/cloudfront-saas/headers.tf` | 2h |
| 40.4 | Create Terraform resource template for `aws_cloudfront_distribution_tenant`. Variables: customer_domain, customer_origin, acm_certificate_arn, customer_id tag. Template creates tenant with custom origin config (HTTPS-only, TLS 1.2). | `terraform/modules/cloudfront-saas/tenant.tf` | 2h |
| 40.5 | Add variables.tf with all configurable values: environment, security_proxy_domain, wildcard_cert_arn, enable_bot_control, waf_web_acl_arn. Add outputs.tf exposing distribution_id, distribution_domain_name for DNS setup. | `terraform/modules/cloudfront-saas/variables.tf` | 1h |
| 40.6 | Test: create multi-tenant distribution, add test tenant domain, verify WAF blocks SQLi (`?id=1' OR '1'='1`), verify security headers present in response, verify TLS enforcement, verify traffic routes through proxy to origin. | Testing | 3h |

**Total Effort:** 12 hours

---

### Story 39.2: Build customer domain onboarding automation (SHIELD-41)

**As a** ShieldAI operator, **I want** customer domain onboarding automated via API, **so that** new customers can be fully provisioned (SSL certificate, edge protection, proxy routing) by providing their domain and origin URL, without manual infrastructure work.

**Acceptance Criteria:**
- Onboarding API accepts: customer domain and origin URL.
- ACM certificate requested automatically for customer domain (DNS validation method).
- DNS validation CNAME record returned to customer for them to add to their DNS.
- Certificate validation status polled automatically; tenant created when certificate is validated.
- Distribution tenant created under the multi-tenant CloudFront distribution.
- Customer receives final CNAME record to point their domain to CloudFront.
- Onboarding status trackable: `certificate_pending` → `certificate_validated` → `tenant_created` → `dns_verified` → `active`.
- Offboarding removes distribution tenant, deletes certificate, and marks customer inactive.
- Customer record created in configuration database during onboarding.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 41.1 | Build onboarding API endpoint (`POST /api/onboard/`): accept `customer_domain` and `origin_url`. Validate domain format. Request ACM certificate via boto3 (DNS validation). Store onboarding record in PostgreSQL with status `certificate_pending`. Return DNS validation CNAME records to caller. | `proxy/api/onboarding.py` | 3h |
| 41.2 | Build certificate validation poller: background job checks ACM certificate status every 60s for pending onboardings. When status changes to `ISSUED`, update record to `certificate_validated` and trigger tenant creation. Timeout after 72 hours (mark as `failed`). | `proxy/jobs/cert_poller.py` | 2h |
| 41.3 | Build distribution tenant creator: called when certificate validates. Use boto3 `create_distribution_tenant()` to create tenant under multi-tenant distribution. Set customer origin and ACM certificate. Update status to `tenant_created`. Create customer record in config database. | `proxy/jobs/tenant_creator.py` | 2h |
| 41.4 | Build onboarding status API: `GET /api/onboard/{customer_id}/status` returns current step, required actions (DNS records to add), and next steps. `GET /api/onboard/` lists all onboardings for operator. | `proxy/api/onboarding.py` | 1h |
| 41.5 | Build offboarding API: `DELETE /api/onboard/{customer_id}` removes CloudFront distribution tenant, requests ACM certificate deletion, marks customer as inactive in config database. Idempotent. | `proxy/api/onboarding.py` | 1h |
| 41.6 | Test: full onboarding flow end-to-end with test domain. Verify SSL certificate provisioned, distribution tenant created, WAF inherited, traffic routes correctly. Test offboarding cleanup. | Testing | 2h |

**Total Effort:** 11 hours

---

### Story 39.3: Build Cloudflare edge security Terraform module (SHIELD-42)

**As a** ShieldAI customer hosting on non-AWS infrastructure (Vercel, Railway, Render, self-hosted), **I want** equivalent edge security (WAF, rate limiting, security headers) provisioned via Cloudflare, **so that** I get the same edge protections regardless of my hosting provider.

**Acceptance Criteria:**
- Terraform module deploys complete Cloudflare edge security: WAF managed rulesets, custom rate limiting rules, security header Transform Rules, and zone settings.
- WAF managed rulesets enabled: Cloudflare Managed Ruleset (SQLi, XSS, RCE), OWASP Core Ruleset, Exposed Credentials Check.
- Rate limiting rules: auth endpoints (20 req/min per IP), API endpoints (100 req/min per IP), global (500 req/min per IP). Thresholds configurable via variables.
- Security headers injected via Response Header Modification Transform Rules: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection.
- Zone settings configured: SSL Full (Strict), minimum TLS version 1.2, HSTS enabled, Bot Fight Mode enabled.
- DNS record created pointing customer domain to security proxy (or directly to app origin).
- Environment-based mode: `log` for test (WAF in simulate mode), `block` for production.
- Module usable standalone (Cloudflare-only) or alongside security proxy.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 42.1 | Create Terraform module `cloudflare-edge/` with Cloudflare provider. Deploy managed WAF rulesets via `cloudflare_ruleset`: Cloudflare Managed Ruleset, OWASP Core Ruleset. Configure action mode based on environment variable (log for test, block for prod). | `terraform/modules/cloudflare-edge/waf.tf` | 2h |
| 42.2 | Add custom rate limiting rulesets via `cloudflare_ruleset` (kind=zone, phase=http_ratelimit): auth endpoint rate limit (URI path contains `/auth/` or `/login`), API rate limit (URI path contains `/api/`), global rate limit (all requests). Thresholds configurable via Terraform variables. Action: block with 429 response. | `terraform/modules/cloudflare-edge/rate_limiting.tf` | 2h |
| 42.3 | Add Response Header Modification Transform Rules via `cloudflare_ruleset` (phase=http_response_headers_transform): set all security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection). Remove `Server` and `X-Powered-By` headers. | `terraform/modules/cloudflare-edge/headers.tf` | 1h |
| 42.4 | Configure zone settings via `cloudflare_zone_settings_override`: SSL mode (full_strict), minimum TLS version (1.2), always_use_https (on), security_level (medium). Enable Bot Fight Mode via `cloudflare_bot_management` or zone setting. | `terraform/modules/cloudflare-edge/zone.tf` | 1h |
| 42.5 | Add `cloudflare_record` resource for DNS: CNAME pointing customer domain to security proxy (or app origin). Proxied through Cloudflare (orange cloud). Variables: zone_id, domain, origin. | `terraform/modules/cloudflare-edge/dns.tf` | 0.5h |
| 42.6 | Test: verify WAF blocks SQLi (`?id=1' OR '1'='1`) and XSS (`<script>alert(1)</script>`), verify rate limiting returns 429 after threshold, verify security headers present in all responses, verify SSL/TLS enforcement. | Testing | 1.5h |

**Total Effort:** 8 hours

---

## SHIELD-1: WAF & Threat Protection

**Priority:** P0 — MVP
**Component:** Edge Security Layer
**Source Audit Ref:** Epics 4 (Rate Limiting)
**Depends On:** SHIELD-40 (CloudFront SaaS Manager distribution to attach WAF to)

---

### Story 1.1: Deploy edge WAF with managed rulesets (SHIELD-13)

**As a** ShieldAI customer, **I want** my app automatically protected against common web attacks (SQLi, XSS, RCE), **so that** known exploit patterns are blocked before reaching my application.

**Acceptance Criteria:**
- WAF blocks SQL injection, XSS, and known bad input patterns.
- Managed rulesets (AWS CRS, SQLi, Known Bad Inputs) are enabled for all customers.
- WAF operates in count mode for test environments and block mode for production.
- Blocked requests return a clean 403 response.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 1.1.1 | Create Terraform module `waf/` that deploys AWS WAF WebACL with managed rule groups: `AWSManagedRulesCommonRuleSet`, `AWSManagedRulesSQLiRuleSet`, `AWSManagedRulesKnownBadInputsRuleSet`. | `terraform/modules/waf/` | 4h |
| 1.1.2 | Add environment-based mode toggle: `count` for test, `block` for prod. Variable: `waf_block_mode`. | `terraform/modules/waf/variables.tf` | 1h |
| 1.1.3 | Attach WAF WebACL to CloudFront multi-tenant distribution (or ALB for single-tenant). | `terraform/modules/waf/` | 1h |
| 1.1.4 | Enable CloudWatch metrics for all rule groups. Create dashboard showing blocked requests by rule. | `terraform/modules/waf/`, dashboard config | 2h |
| 1.1.5 | Test WAF rules: verify SQLi blocked (`?id=1' OR '1'='1`), verify XSS blocked (`<script>alert(1)</script>`), verify legitimate requests pass. | Testing | 2h |

**Total Effort:** 10 hours

---

### Story 1.2: Add rate limiting rules (SHIELD-14)

**As a** ShieldAI customer, **I want** automatic rate limiting on auth endpoints and global traffic, **so that** brute force, credential stuffing, and DDoS attacks are mitigated.

**Acceptance Criteria:**
- Auth endpoints (`/api/auth/*`, `/auth/*`, `/login*`) limited to 500 req/5min per IP.
- Global rate limit of 2000 req/5min per IP.
- Rate-limited requests return 429 Too Many Requests.
- Rate limit thresholds are configurable per customer in the dashboard.
- Rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`) included in responses.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 1.2.1 | Add rate-based WAF rules: auth endpoint rate limit (scoped by URI path pattern), global rate limit. Configurable thresholds via Terraform variables. | `terraform/modules/waf/` | 3h |
| 1.2.2 | Build auto-detection logic in proxy that identifies auth endpoints by URL pattern (`/login`, `/signup`, `/api/auth/*`, `/auth/*`) and applies stricter limits. | `proxy/middleware/rate_limiter.py` | 4h |
| 1.2.3 | Add rate limit response headers to proxy responses. | `proxy/middleware/rate_limiter.py` | 1h |
| 1.2.4 | Build customer configuration API/model for custom rate limit overrides per endpoint pattern. | `proxy/config/`, database schema | 3h |
| 1.2.5 | Test: verify 429 after exceeding limit, verify rate limit resets after window, verify per-IP isolation. | Testing | 2h |

**Total Effort:** 13 hours

---

### Story 1.3: Add bot protection and credential stuffing detection (SHIELD-15)

**As a** ShieldAI customer, **I want** automated bot traffic detected and challenged, **so that** credential stuffing and scraping attacks are blocked.

**Acceptance Criteria:**
- AWS Bot Control or equivalent enabled for Pro+ customers.
- Suspicious login attempts trigger CAPTCHA challenge.
- Account Takeover Prevention (ATP) checks credentials against breach databases.
- Dashboard shows bot traffic vs human traffic breakdown.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 1.3.1 | Add optional Bot Control managed rule group to WAF (enabled via feature flag per customer plan). | `terraform/modules/waf/` | 2h |
| 1.3.2 | Add ATP rule for login endpoints (configurable login path pattern). | `terraform/modules/waf/` | 2h |
| 1.3.3 | Add CAPTCHA challenge action for suspicious login patterns. | `terraform/modules/waf/` | 1h |
| 1.3.4 | Test: verify bot traffic is challenged, verify ATP blocks known-breached credentials. | Testing | 2h |

**Total Effort:** 7 hours

---

## SHIELD-2: Security Headers

**Priority:** P0 — MVP
**Component:** Edge Security Layer
**Source Audit Ref:** Epic 5 (Security Headers)

---

### Story 2.1: Inject security headers into all responses (SHIELD-16)

**As a** ShieldAI customer, **I want** all recommended security headers automatically added to my app's responses, **so that** browser-based attacks (clickjacking, XSS, MIME sniffing, protocol downgrade) are mitigated.

**Acceptance Criteria:**
- All responses include: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- Headers injected at the edge (CloudFront Response Headers Policy or Cloudflare Transform Rules).
- Customer can choose preset modes: Strict, Balanced, Permissive.
- Customer can customize individual headers via dashboard.
- Security score reflects header configuration.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 2.1.1 | Create Terraform module `security-headers/` with CloudFront Response Headers Policy: HSTS (31536000, includeSubDomains, preload), CSP (configurable), X-Frame-Options (DENY), X-Content-Type-Options (nosniff), Referrer-Policy (strict-origin-when-cross-origin), Permissions-Policy (camera=(), microphone=(), geolocation=()). | `terraform/modules/security-headers/` | 3h |
| 2.1.2 | Create equivalent Cloudflare Transform Rules configuration for non-AWS deployments. | `terraform/modules/cloudflare-headers/` | 2h |
| 2.1.3 | Build preset system: define Strict, Balanced, Permissive header profiles. Store as configuration. | `proxy/config/header_presets.yaml` | 2h |
| 2.1.4 | Build customer configuration API for custom header overrides. | `proxy/config/`, API endpoint | 2h |
| 2.1.5 | Add CSP builder in proxy that merges customer's app-specific CSP needs (e.g., Google Fonts, analytics scripts) with security defaults. | `proxy/middleware/csp_builder.py` | 3h |
| 2.1.6 | Verify with SecurityHeaders.com and Mozilla Observatory: score should be A or A+. | Testing | 2h |

**Total Effort:** 14 hours

---

## SHIELD-3: Response Sanitization

**Priority:** P0 — MVP
**Component:** Security Proxy
**Source Audit Ref:** Epic 2 (Error Handling & Exception Security)
**Depends On:** SHIELD-35 (Security Proxy application must exist)

---

### Story 3.1: Sanitize error responses to prevent information leakage (SHIELD-17)

**As a** ShieldAI customer, **I want** all error responses from my app automatically sanitized, **so that** stack traces, database errors, file paths, and internal details are never exposed to end users.

**Acceptance Criteria:**
- All 4xx/5xx responses are intercepted by the proxy.
- Response body is scanned for sensitive patterns (stack traces, file paths, DB errors, debug info).
- If sensitive content detected, body is replaced with a generic error message + unique error reference ID.
- Original error is logged to the audit store with the reference ID.
- Customer can search error reference IDs in the dashboard.
- Works with any backend (Django, Express, Rails, FastAPI, etc.).

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 3.1.1 | Build `ResponseSanitizer` middleware in the security proxy. On 4xx/5xx responses: parse body, scan for sensitive patterns. Pattern library should detect: Python tracebacks (`Traceback`, `File "..."`), Node.js errors (`at Object.<anonymous>`), Java stack traces, generic patterns (`Exception:`, `Error:`, `psycopg2`, `mysql`, `SQLSTATE`), file paths (`/home/`, `/var/`, `/app/`, `/usr/`), IP addresses, connection strings. | `proxy/middleware/response_sanitizer.py` | 6h |
| 3.1.2 | Build generic error response formatter. For each status code, return a clean JSON response: `{"error": true, "message": "...", "error_id": "a1b2c3d4", "status": 500}`. Status-specific messages: 400 (invalid request), 401 (auth required), 403 (forbidden), 404 (not found), 500 (internal error). | `proxy/middleware/response_sanitizer.py` | 2h |
| 3.1.3 | Log original error body to audit store with the error reference ID, request ID, path, method, timestamp. Enable dashboard search by error_id. | `proxy/middleware/response_sanitizer.py`, audit store | 2h |
| 3.1.4 | Add configurable mode: `passthrough` (no sanitization, for dev), `log_only` (detect but don't replace), `sanitize` (replace). Default: `sanitize`. | `proxy/config/` | 1h |
| 3.1.5 | Strip sensitive response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Debug-*`). | `proxy/middleware/response_sanitizer.py` | 1h |
| 3.1.6 | Test with multiple backend frameworks: Django (Python traceback), Express (Node.js stack), Rails (Ruby error), FastAPI (Pydantic validation). Verify all are sanitized. | Testing | 3h |

**Total Effort:** 15 hours

---

## SHIELD-4: Request Sanitization & LLM Protection

**Priority:** P1 — Core
**Component:** Security Proxy
**Source Audit Ref:** Epic 9 (AI/LLM Security)
**Depends On:** SHIELD-35 (Security Proxy application must exist)

---

### Story 4.1: Sanitize user input before LLM prompt interpolation (SHIELD-18)

**As a** ShieldAI customer, **I want** user input automatically sanitized on my LLM-facing endpoints, **so that** prompt injection attacks are detected and neutralized before reaching my AI/LLM backend.

**Acceptance Criteria:**
- Customer configures which endpoints send user input to LLMs (e.g., `/api/chat`, `/api/generate`).
- Request bodies on those endpoints are scanned for injection patterns.
- Detected patterns are escaped or wrapped in delimiters (`<user_data>...</user_data>`).
- Detection is logged; blocking is configurable (detect-only vs. sanitize vs. block).
- Works with any LLM-backed endpoint (OpenAI, Anthropic, local models).

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 4.1.1 | Build `LLMSanitizer` middleware. For configured LLM endpoint patterns, intercept request body. For each string field, apply sanitization: wrap in `<user_data>` delimiters, escape existing XML-like tags, truncate to configurable max length (default 10,000 chars). | `proxy/middleware/llm_sanitizer.py` | 4h |
| 4.1.2 | Build injection pattern detector: check for common patterns ("ignore previous instructions", "you are now", "reveal your prompt", "system prompt", template injection `{{`, `{%`). Log detection events with request context. Return text unchanged in detect-only mode. | `proxy/middleware/llm_sanitizer.py` | 3h |
| 4.1.3 | Build customer configuration for LLM endpoint patterns. Support wildcard paths (e.g., `/api/ai/*`, `/api/chat/*`). | `proxy/config/`, API | 2h |
| 4.1.4 | Add configurable mode: `detect_only` (log but don't modify), `sanitize` (wrap/escape), `block` (reject requests with injection patterns). Default: `sanitize`. | `proxy/config/` | 1h |
| 4.1.5 | Test with realistic prompt injection payloads. Verify sanitized output is safe for interpolation. Verify legitimate user input passes through correctly. | Testing | 2h |

**Total Effort:** 12 hours

---

### Story 4.2: Validate URLs to prevent SSRF attacks (SHIELD-19)

**As a** ShieldAI customer, **I want** URL fields in requests validated against SSRF attacks, **so that** attackers cannot trick my app into making requests to internal networks.

**Acceptance Criteria:**
- Customer configures which endpoints contain URL fields (webhooks, integrations, callbacks).
- URL fields are parsed and resolved; private IPs, loopback, link-local, and metadata IPs are rejected.
- Configurable allowlist for known-good internal URLs.
- Blocked SSRF attempts are logged.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 4.2.1 | Build `SSRFValidator` middleware. For configured endpoint patterns, parse JSON body and find URL-like fields. For each URL: resolve hostname to IP, reject if private (10.x, 172.16-31.x, 192.168.x), loopback (127.x, ::1), link-local (169.254.x), or cloud metadata (169.254.169.254). | `proxy/middleware/ssrf_validator.py` | 4h |
| 4.2.2 | Build customer configuration for SSRF-protected endpoints and URL field allowlists. | `proxy/config/`, API | 1h |
| 4.2.3 | Test: verify private IPs blocked, metadata endpoint blocked, legitimate external URLs pass. | Testing | 1h |

**Total Effort:** 6 hours

---

### Story 4.3: Verify callback/webhook signatures (SHIELD-20)

**As a** ShieldAI customer, **I want** incoming webhook callbacks verified with HMAC signatures, **so that** only authorized sources can submit data to my callback endpoints.

**Acceptance Criteria:**
- Customer configures callback endpoints and their HMAC secrets.
- Proxy validates signature header before forwarding to app.
- Expired or invalid signatures are rejected with 401.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 4.3.1 | Build `CallbackVerifier` middleware. Extract signature from configurable header (default: `X-Signature`), extract timestamp from `X-Timestamp`, verify timestamp within 5 minutes, compute HMAC-SHA256 and compare using constant-time comparison. | `proxy/middleware/callback_verifier.py` | 3h |
| 4.3.2 | Build customer configuration for callback endpoints and their signing secrets. | `proxy/config/`, API | 1h |
| 4.3.3 | Test: valid HMAC accepted, invalid rejected, expired timestamp rejected. | Testing | 1h |

**Total Effort:** 5 hours

---

## SHIELD-5: Session Management

**Priority:** P1 — Core
**Component:** Security Proxy
**Source Audit Ref:** Epic 11 (Session Management Hardening)
**Depends On:** SHIELD-35 (Security Proxy application), SHIELD-35 task 35.8 (Redis connection)

---

### Story 5.1: Add idle session timeout (SHIELD-21)

**As a** ShieldAI customer, **I want** user sessions to expire after a configurable period of inactivity, **so that** unattended workstations don't remain authenticated.

**Acceptance Criteria:**
- Proxy manages sessions in Redis (separate from app sessions).
- Session `last_activity` updated on each request.
- If idle time exceeds threshold (default 30 minutes), return 401.
- Configurable timeout per customer.
- Works with any backend auth system.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 5.1.1 | Build `SessionValidator` middleware. On each request: extract session token from cookie or Authorization header, load session from Redis, check `last_activity` against idle timeout threshold, reject with 401 if exceeded, update `last_activity` if valid. | `proxy/middleware/session_validator.py` | 4h |
| 5.1.2 | Build session data model in Redis: `session:{token}` → `{user_id, tenant_id, fingerprint, last_activity, created_at, ip, user_agent}`. | `proxy/session/store.py` | 2h |
| 5.1.3 | Build session lifecycle manager: create session on login response detection, delete on logout response detection, update on every request. Detect login/logout by configurable path patterns and response status codes. | `proxy/middleware/session_updater.py` | 3h |
| 5.1.4 | Add configurable idle timeout (default 30 min) and absolute timeout (default 24 hours) per customer. | `proxy/config/`, API | 1h |
| 5.1.5 | Test: session expires after idle, active sessions extended, login creates session, logout deletes session. | Testing | 2h |

**Total Effort:** 12 hours

---

### Story 5.2: Add session binding (anti-hijacking) (SHIELD-22)

**As a** ShieldAI customer, **I want** sessions bound to the client's IP and user-agent, **so that** stolen session cookies are harder to use from a different device.

**Acceptance Criteria:**
- On session creation, store fingerprint (hash of IP + User-Agent).
- On each request, compare current fingerprint with stored.
- On mismatch: configurable action (warn, block, or require re-auth).
- Dashboard shows session binding violations.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 5.2.1 | On session creation, compute fingerprint from IP + User-Agent and store in Redis session. On each request, recompute and compare. | `proxy/middleware/session_validator.py` | 2h |
| 5.2.2 | Add configurable binding mode: `off` (no binding), `warn` (log mismatch, allow), `strict` (reject on mismatch). Default: `warn`. | `proxy/config/` | 1h |
| 5.2.3 | Log session binding violations to audit store with details (old IP vs new IP, old UA vs new UA). | `proxy/middleware/session_validator.py`, audit store | 1h |
| 5.2.4 | Test: matching fingerprint passes, changed IP triggers configured action. | Testing | 1h |

**Total Effort:** 5 hours

---

## SHIELD-6: Audit Logging & Compliance

**Priority:** P1 — Core
**Component:** Security Proxy
**Source Audit Ref:** Epic 6 (Structured Audit Logging)
**Depends On:** SHIELD-35 (Security Proxy application)

---

### Story 6.1: Log all requests with structured audit metadata (SHIELD-23)

**As a** ShieldAI customer, **I want** all requests to my app logged in a structured, queryable format, **so that** I have a complete audit trail for incident investigation and compliance.

**Acceptance Criteria:**
- Every request/response logged with: timestamp, request_id, method, path, status, duration_ms, client_ip, user_agent, country (GeoIP), user_id, action type, blocked status, block reason.
- Logs stored in queryable store (ClickHouse or PostgreSQL) with configurable retention (7/30/90/365 days by plan).
- Logs searchable and filterable in dashboard.
- Export to CSV, JSON, and via API.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 6.1.1 | Build `AuditLogger` middleware. On every request/response, construct structured audit record with all required fields. Write asynchronously to log pipeline (Kafka or direct to store). | `proxy/middleware/audit_logger.py` | 4h |
| 6.1.2 | Build action detection: map path + method + status patterns to named actions (e.g., `POST /api/auth/login/ 200` → `user.login`, `DELETE /api/*/` → `resource.delete`). Customer-configurable action mappings. | `proxy/middleware/audit_logger.py`, config | 3h |
| 6.1.3 | Build audit storage: ClickHouse schema for high-volume log ingestion. Partitioned by customer_id and timestamp. Retention policy per customer plan. | `infrastructure/clickhouse/schema.sql` | 4h |
| 6.1.4 | Build audit query API: `GET /api/audit-logs/` with filtering by action, user, path, date range, status. Pagination. CSV and JSON export. | API endpoint | 4h |
| 6.1.5 | Build log pipeline: proxy → Kafka → ClickHouse (analytics) + S3 (long-term archive). | `infrastructure/kafka/` | 3h |
| 6.1.6 | Build cleanup job: delete audit records older than retention period per customer plan. | Scheduled job | 1h |
| 6.1.7 | Test: verify audit records created for all request types, verify filtering works, verify export works, verify retention cleanup. | Testing | 3h |

**Total Effort:** 22 hours

---

### Story 6.2: Emit structured JSON logs for observability (SHIELD-24)

**As a** ShieldAI operator, **I want** all proxy application logs emitted in structured JSON format with consistent fields, **so that** they can be ingested by CloudWatch, Datadog, or ELK for centralized monitoring and alerting.

**Acceptance Criteria:**
- All proxy application logs (not audit logs — those are separate) emitted as JSON with fields: timestamp, level, module, message, request_id, exc_info.
- Log level configurable per environment (DEBUG for dev, INFO for prod).
- Logs written to stdout for container log collection.
- Webhook integration for real-time log streaming to customer-configured endpoints (Slack, PagerDuty, custom URL).
- Webhook payloads include: event type, severity, message, timestamp, and relevant context.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 6.2.1 | Configure proxy logging framework to emit structured JSON: timestamp, level, module, message, request_id, exc_info. | Proxy application | 1.5h |
| 6.2.2 | Add webhook integration for real-time log streaming to customer-configured endpoints (Slack, PagerDuty, custom). | API, webhook module | 3h |

**Total Effort:** 4.5 hours

---

## SHIELD-7: Row-Level Security & Tenant Isolation

**Priority:** P1 — Core
**Component:** Database Proxy
**Source Audit Ref:** Epic 7 (Database Row-Level Security)
**Depends On:** SHIELD-38 (database proxy deployment infrastructure)

---

### Story 7.1: Enforce PostgreSQL RLS via database proxy (SHIELD-25)

**As a** ShieldAI customer with a multi-tenant PostgreSQL database, **I want** database-level row-level security enforced automatically, **so that** a bug in my application code cannot leak data across tenants.

**Acceptance Criteria:**
- Database proxy sits between customer app and PostgreSQL.
- On each connection/transaction, proxy executes `SET app.current_tenant_id = '{tenant_id}'`.
- Tenant ID extracted from proxy session context (X-Tenant-ID header).
- RLS policies on all tenant-scoped tables automatically filter rows.
- Superuser/migration connections bypass RLS.
- Works with any framework that uses PostgreSQL (Django, Rails, Express+pg, etc.).

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 7.1.1 | Build database proxy application (Go or Python) that accepts PostgreSQL wire protocol connections, reads tenant context from connection metadata or application_name, and forwards to real PostgreSQL. | `db-proxy/` | 6h |
| 7.1.2 | On each transaction, execute `SET LOCAL app.current_tenant_id = '{tenant_id}'` before forwarding queries. | `db-proxy/` | 2h |
| 7.1.3 | Create SQL migration template that enables RLS on tenant-scoped tables: `ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; CREATE POLICY tenant_isolation ON {table} USING (tenant_id = current_setting('app.current_tenant_id')::uuid);` | `db-proxy/migrations/rls_template.sql` | 3h |
| 7.1.4 | Build auto-discovery: scan customer's database schema to identify tables with `tenant_id` column, generate RLS migration. | `db-proxy/tools/discover_tenant_tables.py` | 3h |
| 7.1.5 | Configure migration/superuser bypass: connections from admin role bypass RLS. | `db-proxy/`, PostgreSQL role config | 1h |
| 7.1.6 | Test: create two tenants with data, verify Tenant A cannot query Tenant B's data even with raw SQL, verify CRUD works for both tenants. | Testing | 4h |

**Total Effort:** 19 hours

---

## SHIELD-8: Secrets Management

**Priority:** P1 — Core
**Component:** Infrastructure
**Source Audit Ref:** Epic 8 (Secrets Management)

---

### Story 8.1: Integrate secrets management for customer apps (SHIELD-26)

**As a** ShieldAI customer, **I want** my application secrets managed securely, **so that** secrets are not stored in environment variables or source code.

**Acceptance Criteria:**
- ShieldAI provides integration with AWS Secrets Manager, GCP Secret Manager, or HashiCorp Vault.
- Terraform modules deploy secrets infrastructure.
- Secrets injected into customer's container at startup.
- Secret rotation supported with zero-downtime.
- Fallback to environment variables for local development.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 8.1.1 | Create Terraform module `secrets/` for AWS Secrets Manager: create secrets, configure auto-rotation, output ARNs for ECS task definitions. | `terraform/modules/secrets/` | 4h |
| 8.1.2 | Create equivalent module for GCP Secret Manager. | `terraform/modules/gcp-secrets/` | 3h |
| 8.1.3 | Build helper library/sidecar that fetches secrets at startup and exposes them as environment variables. Includes caching (5-min TTL) and fallback to `os.getenv()`. | `tools/secret-injector/` | 3h |
| 8.1.4 | Create KMS encryption Terraform module: enable encryption at rest for RDS, S3, ElastiCache with automatic key rotation. | `terraform/modules/encryption/` | 2h |
| 8.1.5 | Document secret rotation procedure. | Documentation | 1h |
| 8.1.6 | Test: verify secrets fetched correctly, verify fallback works, verify rotation doesn't cause downtime. | Testing | 2h |

**Total Effort:** 15 hours

---

## SHIELD-9: Container & Kubernetes Hardening

**Priority:** P1 — Core
**Component:** Infrastructure
**Source Audit Ref:** Epic 10 (Kubernetes & Container Hardening)

---

### Story 9.1: Enforce network isolation for customer workloads (SHIELD-27)

**As a** ShieldAI customer running workloads in Kubernetes, **I want** my pods isolated from other customers' pods via NetworkPolicy, **so that** one customer's workload cannot communicate with another's.

**Acceptance Criteria:**
- Helm chart `shieldai-security-policies` created with NetworkPolicy resources.
- Default deny all ingress to customer workload namespaces.
- Egress allowed only to: DNS (kube-dns, port 53), HTTPS (port 443) to external URLs, and results callback API endpoint.
- Egress blocked to: internal cluster IPs (10.x), cloud metadata (169.254.169.254), other customer namespaces.
- NetworkPolicy applied per customer namespace via Helm values.
- Compromised test code cannot make lateral movements within the cluster.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 9.1.1 | Create Helm chart `shieldai-security-policies` with NetworkPolicy: deny all ingress by default, allow egress only to DNS (port 53), HTTPS (port 443), and callback API. Block egress to internal cluster IPs, cloud metadata (169.254.169.254). | `helm/shieldai-security-policies/` | 3h |
| 9.1.2 | Test: verify pods cannot communicate with each other, can still reach external URLs and callback API. | Testing | 2h |

**Total Effort:** 5 hours

---

### Story 9.2: Enforce pod security standards (SHIELD-28)

**As a** ShieldAI operator, **I want** all customer workload pods running with restricted security contexts, **so that** container escape attacks are mitigated.

**Acceptance Criteria:**
- All customer workload pods run as non-root user.
- Root filesystem is read-only (writable `/tmp` via emptyDir volume).
- Privilege escalation is disabled.
- All Linux capabilities are dropped.
- Seccomp profile set to RuntimeDefault.
- PodSecurity admission label `restricted` enforced on customer namespaces.
- Existing workloads verified to function correctly under restricted context.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 9.2.1 | Add security context to Helm chart: `runAsNonRoot: true`, `readOnlyRootFilesystem: true` (with writable `/tmp` via emptyDir), `allowPrivilegeEscalation: false`, `capabilities: drop: ["ALL"]`, `seccompProfile: RuntimeDefault`. | `helm/shieldai-security-policies/` | 2h |
| 9.2.2 | Apply PodSecurity label on customer namespaces: `pod-security.kubernetes.io/enforce: restricted`. | Helm chart | 1h |
| 9.2.3 | Test workloads still function with restricted context. Fix permission issues. | Testing | 2h |

**Total Effort:** 5 hours

---

### Story 9.3: Add code validation for AI-generated scripts (SHIELD-29)

**As a** ShieldAI customer running AI-generated code, **I want** generated scripts analyzed for dangerous patterns before execution, **so that** malicious or unsafe code is caught before it can harm my infrastructure.

**Acceptance Criteria:**
- Code validator service exposes an HTTP API accepting code snippets (Python, JavaScript, etc.).
- Service parses code into AST and walks the tree checking for dangerous patterns.
- Dangerous imports detected: `os`, `subprocess`, `socket`, `shutil`, `ctypes`, `importlib`.
- Dangerous builtins detected: `exec`, `eval`, `compile`, `__import__`.
- Shell execution patterns detected in string literals.
- Configurable allowlist (e.g., `selenium`, `playwright`, `pytest` always allowed) and blocklist per customer.
- API returns pass/fail verdict with detailed findings (line number, pattern matched, severity).
- Integrates with K8s executor: job only created if validation passes.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 9.3.1 | Build code validator service: accept code (Python, JavaScript, etc.) via API, parse into AST, walk AST checking for dangerous imports (`os`, `subprocess`, `socket`, `shutil`, `ctypes`), dangerous builtins (`exec`, `eval`, `compile`, `__import__`), shell execution patterns. Return pass/fail with findings. | `services/code-validator/` | 6h |
| 9.3.2 | Build configurable allowlist/blocklist: certain imports always allowed (e.g., `selenium`, `playwright`, `pytest`), certain always blocked. Customer-configurable. | `services/code-validator/config.yaml` | 1h |
| 9.3.3 | Test: script with `import os` flagged, `subprocess.run` flagged, `from selenium import webdriver` passes, `eval()` flagged. | Testing | 2h |

**Total Effort:** 9 hours

---

## SHIELD-10: CI/CD Security Scanning Templates

**Priority:** P2 — Growth
**Component:** Developer Tools
**Source Audit Ref:** Epic 14 (CI/CD Security Pipeline)

---

### Story 10.1: Provide reusable GitHub Actions security scanning workflows (SHIELD-30)

**As a** ShieldAI customer, **I want** pre-built security scanning workflows I can add to my CI/CD pipeline, **so that** vulnerabilities are caught on every PR without me configuring tools from scratch.

**Acceptance Criteria:**
- Published GitHub Action: `shieldai/security-scan` that runs SAST, SCA, and secret scanning.
- Supports Python (bandit, pip-audit), JavaScript/TypeScript (eslint-plugin-security, npm audit), and Go.
- Secret scanning via gitleaks.
- Results posted as PR annotations.
- Build fails on high-severity findings (configurable threshold).

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 10.1.1 | Create composite GitHub Action `shieldai/security-scan` with jobs for: SAST (bandit for Python, eslint-security for JS), SCA (pip-audit, npm audit), secret detection (gitleaks). | `github-actions/security-scan/` | 6h |
| 10.1.2 | Build result aggregator that posts findings as PR check annotations. | `github-actions/security-scan/` | 3h |
| 10.1.3 | Add configurable severity threshold: fail on `high`, `critical`, or `any`. | `github-actions/security-scan/` | 1h |
| 10.1.4 | Create Dependabot configuration template (`.github/dependabot.yml`) for common ecosystems. | `templates/dependabot.yml` | 1h |
| 10.1.5 | Add container image scanning job using Trivy. | `github-actions/security-scan/` | 2h |
| 10.1.6 | Create pre-commit hook config template with gitleaks and detect-secrets. | `templates/.pre-commit-config.yaml` | 1h |
| 10.1.7 | Test by opening PRs with known vulnerabilities. Verify build fails and annotations appear. | Testing | 2h |

**Total Effort:** 16 hours

---

## SHIELD-11: SBOM & Supply Chain Security

**Priority:** P2 — Growth
**Component:** Developer Tools
**Source Audit Ref:** Epic 15 (Supply Chain & SBOM)

---

### Story 11.1: Generate SBOM for customer applications (SHIELD-31)

**As a** ShieldAI customer, **I want** a Software Bill of Materials automatically generated for my application, **so that** I can track all dependencies for vulnerability management and compliance.

**Acceptance Criteria:**
- SBOM generated in CycloneDX JSON format.
- Supports Python (pip/poetry), JavaScript (npm/yarn), Go, and Docker images.
- SBOM stored as build artifact and accessible in dashboard.
- Automated on release tags.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 11.1.1 | Add SBOM generation jobs to `shieldai/security-scan` action: `cyclonedx-py` for Python, `@cyclonedx/cyclonedx-npm` for JS, `cyclonedx-gomod` for Go. | `github-actions/security-scan/` | 3h |
| 11.1.2 | Upload SBOMs as GitHub release artifacts. | `github-actions/security-scan/` | 1h |
| 11.1.3 | Build SBOM viewer in ShieldAI dashboard: list dependencies, highlight known CVEs. | Dashboard feature | 3h |
| 11.1.4 | Test: generate SBOMs for sample Python, JS, and Go projects. Verify completeness. | Testing | 1.5h |

**Total Effort:** 8.5 hours

---

## SHIELD-12: Security Policy Templates

**Priority:** P2 — Growth
**Component:** Developer Tools
**Source Audit Ref:** Epic 17 (Security Documentation & Policies)

---

### Story 12.1: Provide customizable security policy templates (SHIELD-32)

**As a** ShieldAI customer preparing for SOC 2 or ISO 27001, **I want** pre-written security policy templates that I can customize with my company details, **so that** I can establish a documented security program without starting from scratch.

**Acceptance Criteria:**
- Template library includes all policies required for SOC 2 Type II.
- Templates are markdown files with placeholder variables (`{{COMPANY_NAME}}`, `{{SECURITY_CONTACT}}`, etc.).
- Customer can download, customize, and host policies.
- Dashboard integration: policies linked to security score.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 12.1.1 | Write Information Security Policy template — overall security framework, responsibilities, scope. | `templates/policies/information-security-policy.md` | 6h |
| 12.1.2 | Write Access Control Policy template — access granting, MFA requirements, role definitions. | `templates/policies/access-control-policy.md` | 4h |
| 12.1.3 | Write Incident Response Plan template — detection, triage, containment, communication, recovery. Include 72-hour GDPR notification requirement. | `templates/policies/incident-response-plan.md` | 8h |
| 12.1.4 | Write Data Classification Policy template — categories, handling rules per category. | `templates/policies/data-classification-policy.md` | 3h |
| 12.1.5 | Write Acceptable Use Policy template. | `templates/policies/acceptable-use-policy.md` | 3h |
| 12.1.6 | Write Change Management Policy template — code review, deployment, rollback procedures. | `templates/policies/change-management-policy.md` | 3h |
| 12.1.7 | Write Vendor Management Policy template — third-party security assessment process. | `templates/policies/vendor-management-policy.md` | 3h |
| 12.1.8 | Write Business Continuity & Disaster Recovery Plan template. | `templates/policies/bcdr-plan.md` | 6h |
| 12.1.9 | Write Data Retention & Deletion Schedule template. | `templates/policies/data-retention-schedule.md` | 3h |
| 12.1.10 | Build template customization tool: replace placeholders with customer details, generate PDF output. | Dashboard feature, tool | 3h |

**Total Effort:** 42 hours

---

### Story 12.2: Provide security.txt and vulnerability disclosure templates (SHIELD-33)

**As a** ShieldAI customer, **I want** an RFC 9116 compliant `security.txt` file and a vulnerability disclosure policy automatically available for my domain, **so that** security researchers can responsibly report vulnerabilities and my app meets industry best practices.

**Acceptance Criteria:**
- `/.well-known/security.txt` template created following RFC 9116 with placeholder fields (contact, encryption, preferred-languages, expires, policy URL).
- Template auto-served via security proxy for customers who enable it.
- Vulnerability disclosure policy template covers: scope, safe harbor, reporting process, response timeline, rewards (optional).
- Customer can customize all fields via configuration.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 12.2.1 | Create `/.well-known/security.txt` template following RFC 9116 with placeholder fields. Add proxy route that serves the file for customers who enable it, populated from customer config. | `templates/security.txt`, `proxy/routes/well_known.py` | 1.5h |
| 12.2.2 | Create vulnerability disclosure policy template covering: scope, safe harbor, reporting process, response SLAs, recognition/rewards section. | `templates/policies/vulnerability-disclosure.md` | 2h |

**Total Effort:** 3.5 hours

---

## Effort Summary

### By Epic

| Epic | Priority | Hours | Component | Stories |
|------|----------|-------|-----------|---------|
| SHIELD-34: Proxy Platform Foundation | P0 | 47 | Proxy Platform | 4 |
| SHIELD-39: Multi-Tenant Edge Platform | P0/P1 | 31 | Edge Platform | 3 |
| SHIELD-1: WAF & Threat Protection | P0 | 30 | Edge Security | 3 |
| SHIELD-2: Security Headers | P0 | 14 | Edge Security | 1 |
| SHIELD-3: Response Sanitization | P0 | 15 | Proxy Features | 1 |
| SHIELD-4: Request Sanitization & LLM | P1 | 23 | Proxy Features | 3 |
| SHIELD-5: Session Management | P1 | 17 | Proxy Features | 2 |
| SHIELD-6: Audit Logging | P1 | 26.5 | Proxy Features | 2 |
| SHIELD-7: Database RLS | P1 | 19 | DB Proxy | 1 |
| SHIELD-8: Secrets Management | P1 | 15 | Infrastructure | 1 |
| SHIELD-9: Container Hardening | P1 | 19 | Infrastructure | 3 |
| SHIELD-10: CI/CD Templates | P2 | 16 | Dev Tools | 1 |
| SHIELD-11: SBOM | P2 | 8.5 | Dev Tools | 1 |
| SHIELD-12: Policy Templates | P2 | 45.5 | Dev Tools | 2 |
| **TOTAL** | | **~327 hours** | | **28 stories** |

### By Priority

| Priority | Hours | Description |
|----------|-------|-------------|
| **P0 — MVP** | ~118 | Proxy platform, multi-tenant edge (CloudFront SaaS), WAF, headers, response sanitization |
| **P1 — Core** | ~139 | LLM protection, sessions, audit logging, RLS, secrets, K8s, Cloudflare, customer onboarding |
| **P2 — Growth** | ~70 | Developer tools: CI/CD, SBOM, policy templates |

### By Component

| Component | Hours | Epics |
|-----------|-------|-------|
| Security Proxy Platform | 47 | SHIELD-34 |
| Multi-Tenant Edge Platform | 31 | SHIELD-39 |
| Edge Security | 44 | SHIELD-1, SHIELD-2 |
| Security Proxy Features | 81.5 | SHIELD-3, SHIELD-4, SHIELD-5, SHIELD-6 |
| Database Proxy | 19 | SHIELD-7 |
| Infrastructure | 34 | SHIELD-8, SHIELD-9 |
| Developer Tools | 70 | SHIELD-10, SHIELD-11, SHIELD-12 |

### Suggested Sprint Plan (2-week sprints, 2 developers)

| Sprint | Epics | Hours | Milestone |
|--------|-------|-------|-----------|
| Sprint 1 | SHIELD-34 (Proxy Foundation) | ~47 | Core proxy platform running — middleware pipeline, config system, deployment |
| Sprint 2 | SHIELD-1, SHIELD-2 | ~44 | Edge security live — WAF + headers protect all apps |
| Sprint 3 | SHIELD-40 (CloudFront SaaS Manager) | ~12 | Multi-tenant edge platform — customer domains get WAF + headers automatically |
| Sprint 4 | SHIELD-3 | ~15 | Response sanitization live — error leaks eliminated |
| Sprint 5 | SHIELD-5, SHIELD-4 (Story 4.1) | ~29 | Session management + LLM protection live |
| Sprint 6 | SHIELD-6 | ~26.5 | Audit logging live — compliance ready |
| Sprint 7 | SHIELD-4 (4.2, 4.3), SHIELD-8 | ~26 | SSRF/callback protection + secrets management |
| Sprint 8 | SHIELD-7 | ~19 | Database RLS live — tenant isolation enforced |
| Sprint 9 | SHIELD-41, SHIELD-42, SHIELD-9 | ~38 | Customer onboarding automation + Cloudflare module + K8s hardening |
| Sprint 10 | SHIELD-10, SHIELD-11 | ~24.5 | CI/CD templates + SBOM launched |
| Sprint 11 | SHIELD-12 | ~45.5 | Policy templates — enterprise feature complete |

### Dependency Graph

```
SHIELD-34 (Proxy Platform) ──┬──→ SHIELD-3 (Response Sanitization)
                              ├──→ SHIELD-4 (Request Sanitization / LLM)
                              ├──→ SHIELD-5 (Session Management)
                              ├──→ SHIELD-6 (Audit Logging)
                              └──→ SHIELD-33 (security.txt proxy route)

SHIELD-40 (CloudFront SaaS) ──→ SHIELD-13 (WAF rules attach to distribution)
                              ──→ SHIELD-16 (Headers policy attaches to distribution)

SHIELD-38 (Deployment Infra) ──→ SHIELD-25 (DB Proxy needs deployment)

SHIELD-1, SHIELD-2 (Edge) ─────→ Independent (Terraform modules)
SHIELD-8, SHIELD-9 (Infra) ────→ Independent
SHIELD-10, SHIELD-11, SHIELD-12 → Independent (Developer tools)
SHIELD-42 (Cloudflare) ────────→ Independent (Alternative to AWS edge)
```

---

### Mapping from Wrapper Components

| SECURITY_WRAPPER.md Section | Shield AI Epic(s) | Coverage |
|----------------------------|--------------------|----------|
| Component 1A: AWS Infrastructure — WAF | SHIELD-1 (Stories 13, 14, 15) | Full |
| Component 1A: AWS Infrastructure — Security Headers | SHIELD-2 (Story 16) | Full |
| Component 1A: AWS Infrastructure — Secrets | SHIELD-8 (Story 26) | Full |
| Component 1A: AWS Infrastructure — Encryption/KMS | SHIELD-8 (Story 26, task 8.1.4) | Full |
| Component 1B: Cloudflare (Cloud-Agnostic Alternative) | SHIELD-39 (Story 42) | Full |
| Component 1C: CloudFront SaaS Manager (Multi-Tenant) | SHIELD-39 (Stories 40, 41) | Full |
| Component 2: Security Proxy — Application Foundation | SHIELD-34 (Stories 35, 36, 37, 38) | Full |
| Component 2: Security Proxy — Request Pipeline Stage 1 (Session) | SHIELD-5 (Stories 21, 22) | Full |
| Component 2: Security Proxy — Request Pipeline Stage 2 (Sanitizer) | SHIELD-4 (Stories 18, 19, 20) | Full |
| Component 2: Security Proxy — Request Pipeline Stage 3 (Context) | SHIELD-34 (Story 36) | Full |
| Component 2: Security Proxy — Response Pipeline Stage 4 (Sanitizer) | SHIELD-3 (Story 17) | Full |
| Component 2: Security Proxy — Response Pipeline Stage 5 (Audit) | SHIELD-6 (Stories 23, 24) | Full |
| Component 2: Security Proxy — Response Pipeline Stage 6 (Session) | SHIELD-5 (Story 21, task 5.1.3) | Full |
| Component 3: Database Proxy | SHIELD-7 (Story 25) | Full |
| Component 3: Database Proxy — Deployment | SHIELD-34 (Story 38) | Full |
| Component 4: Kubernetes Security — NetworkPolicy | SHIELD-9 (Story 27) | Full |
| Component 4: Kubernetes Security — Pod Security | SHIELD-9 (Story 28) | Full |
| Component 4: Kubernetes Security — Code Validation | SHIELD-9 (Story 29) | Full |
| Component 5: CI/CD Security — Security Scanning | SHIELD-10 (Story 30) | Full |
| Component 5: CI/CD Security — SBOM | SHIELD-11 (Story 31) | Full |
| Using Wrapper for Other Applications — Config for common platforms | SHIELD-34 (Story 37) | Covered by config system |
| Deployment — Container Architecture | SHIELD-34 (Story 38) | Full |
| Environment Configuration — Per-environment settings | SHIELD-34 (Story 38, task 38.5) | Full |

### Mapping from Original CSEC Epics

| Original Epic | Shield AI Epic | Notes |
|---------------|---------------|-------|
| (No original — new) | SHIELD-34 | NEW — Proxy platform foundation, config system, deployment |
| (No original — new) | SHIELD-39 | NEW — Multi-tenant edge platform, Cloudflare, onboarding |
| CSEC Epic 2: Error Handling | SHIELD-3 | Genericized — no Coco file paths |
| CSEC Epic 4: Rate Limiting | SHIELD-1 (Stories 1.2, 1.3) | Expanded to include bot/ATP |
| CSEC Epic 5: Security Headers | SHIELD-2 | Genericized — multi-framework |
| CSEC Epic 6: Audit Logging | SHIELD-6 | Genericized — customer-facing feature |
| CSEC Epic 7: Database RLS | SHIELD-7 | Genericized — any PostgreSQL app |
| CSEC Epic 8: Secrets Management | SHIELD-8 | Genericized — multi-cloud |
| CSEC Epic 9: AI/LLM Security | SHIELD-4 | Genericized — any LLM-backed app |
| CSEC Epic 10: K8s Hardening | SHIELD-9 | Unchanged — already generic |
| CSEC Epic 11: Session Management | SHIELD-5 | Genericized — any auth system |
| CSEC Epic 14: CI/CD Security | SHIELD-10 | Converted to reusable GitHub Action |
| CSEC Epic 15: SBOM | SHIELD-11 | Converted to product feature |
| CSEC Epic 17: Documentation | SHIELD-12 | Converted to template library |
| CSEC Epics 1, 3, 12, 13, 16 | N/A | Coco-specific — see COCO_SECURITY_FIXES.md |

---

*Document created: February 2026*
*Updated: February 2026 — Added SHIELD-34 (Proxy Platform Foundation) and SHIELD-39 (Multi-Tenant Edge Platform) epics to cover all wrapper components. Updated incomplete stories (SHIELD-24, 27, 28, 29, 33) with full descriptions and acceptance criteria. Total effort updated from ~249h to ~327h.*
*Source: Coco TestAI Security Audit, genericized for Shield AI product*
*Jira: [SHIELD project](https://quodroid.atlassian.net/jira/software/projects/SHIELD/boards)*
*See also: [COCO_SECURITY_FIXES.md](./COCO_SECURITY_FIXES.md) for Coco-specific code fixes (CSEC project)*
*See also: [SECURITY_WRAPPER.md](./SECURITY_WRAPPER.md) for full technical architecture*
