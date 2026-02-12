# Shield AI — Product Stories & Tasks

**Product:** ShieldAI Security Wrapper
**Jira Project:** [SHIELD](https://quodroid.atlassian.net/jira/software/projects/SHIELD/boards)
**Date:** February 2026
**Source:** Derived from Coco TestAI Security Audit, genericized for multi-app use
**Total Estimated Effort:** ~249 hours (full product)

---

## How to Read This Document

- **Epics** group related work by product component.
- **Stories** describe a product capability from a customer perspective.
- **Tasks** are specific developer actions to build the feature.
- **Priority** follows product roadmap: P0 (MVP), P1 (Core), P2 (Growth).
- **Effort** is in developer-hours and includes implementation + testing.

---

## Product Architecture

```
Internet → Edge Security (WAF + Headers) → Security Proxy → Customer App → Database Proxy → PostgreSQL
```

| Component | Epics | Purpose |
|-----------|-------|---------|
| Edge Security | SHIELD-1, SHIELD-2 | Block attacks at the edge before they reach any app |
| Security Proxy | SHIELD-3, SHIELD-4, SHIELD-5, SHIELD-6 | Sanitize traffic, manage sessions, log everything |
| Database Proxy | SHIELD-7 | Enforce tenant isolation at database level |
| Infrastructure | SHIELD-8, SHIELD-9 | Secure deployment, secrets management |
| Developer Tools | SHIELD-10, SHIELD-11, SHIELD-12 | CI/CD templates, SBOM, policy templates |

---

## Table of Contents

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

## SHIELD-1: WAF & Threat Protection

**Priority:** P0 — MVP
**Component:** Edge Security Layer
**Source Audit Ref:** Epics 4 (Rate Limiting)

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
| 1.2.2 | Build auto-detection logic in proxy that identifies auth endpoints by URL pattern (`/login`, `/signup`, `/api/auth/*`, `/auth/*`) and applies stricter limits. | `proxy/middleware/rate_limiter.go` | 4h |
| 1.2.3 | Add rate limit response headers to proxy responses. | `proxy/middleware/rate_limiter.go` | 1h |
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
| 2.1.5 | Add CSP builder in proxy that merges customer's app-specific CSP needs (e.g., Google Fonts, analytics scripts) with security defaults. | `proxy/middleware/csp_builder.go` | 3h |
| 2.1.6 | Verify with SecurityHeaders.com and Mozilla Observatory: score should be A or A+. | Testing | 2h |

**Total Effort:** 14 hours

---

## SHIELD-3: Response Sanitization

**Priority:** P0 — MVP
**Component:** Security Proxy
**Source Audit Ref:** Epic 2 (Error Handling & Exception Security)

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
| 3.1.1 | Build `ResponseSanitizer` middleware in the security proxy. On 4xx/5xx responses: parse body, scan for sensitive patterns. Pattern library should detect: Python tracebacks (`Traceback`, `File "..."`), Node.js errors (`at Object.<anonymous>`), Java stack traces, generic patterns (`Exception:`, `Error:`, `psycopg2`, `mysql`, `SQLSTATE`), file paths (`/home/`, `/var/`, `/app/`, `/usr/`), IP addresses, connection strings. | `proxy/middleware/response_sanitizer.go` | 6h |
| 3.1.2 | Build generic error response formatter. For each status code, return a clean JSON response: `{"error": true, "message": "...", "error_id": "a1b2c3d4", "status": 500}`. Status-specific messages: 400 (invalid request), 401 (auth required), 403 (forbidden), 404 (not found), 500 (internal error). | `proxy/middleware/response_sanitizer.go` | 2h |
| 3.1.3 | Log original error body to audit store with the error reference ID, request ID, path, method, timestamp. Enable dashboard search by error_id. | `proxy/middleware/response_sanitizer.go`, audit store | 2h |
| 3.1.4 | Add configurable mode: `passthrough` (no sanitization, for dev), `log_only` (detect but don't replace), `sanitize` (replace). Default: `sanitize`. | `proxy/config/` | 1h |
| 3.1.5 | Strip sensitive response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Debug-*`). | `proxy/middleware/response_sanitizer.go` | 1h |
| 3.1.6 | Test with multiple backend frameworks: Django (Python traceback), Express (Node.js stack), Rails (Ruby error), FastAPI (Pydantic validation). Verify all are sanitized. | Testing | 3h |

**Total Effort:** 15 hours

---

## SHIELD-4: Request Sanitization & LLM Protection

**Priority:** P1 — Core
**Component:** Security Proxy
**Source Audit Ref:** Epic 9 (AI/LLM Security)

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
| 4.1.1 | Build `LLMSanitizer` middleware. For configured LLM endpoint patterns, intercept request body. For each string field, apply sanitization: wrap in `<user_data>` delimiters, escape existing XML-like tags, truncate to configurable max length (default 10,000 chars). | `proxy/middleware/llm_sanitizer.go` | 4h |
| 4.1.2 | Build injection pattern detector: check for common patterns ("ignore previous instructions", "you are now", "reveal your prompt", "system prompt", template injection `{{`, `{%`). Log detection events with request context. Return text unchanged in detect-only mode. | `proxy/middleware/llm_sanitizer.go` | 3h |
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
| 4.2.1 | Build `SSRFValidator` middleware. For configured endpoint patterns, parse JSON body and find URL-like fields. For each URL: resolve hostname to IP, reject if private (10.x, 172.16-31.x, 192.168.x), loopback (127.x, ::1), link-local (169.254.x), or cloud metadata (169.254.169.254). | `proxy/middleware/ssrf_validator.go` | 4h |
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
| 4.3.1 | Build `CallbackVerifier` middleware. Extract signature from configurable header (default: `X-Signature`), extract timestamp from `X-Timestamp`, verify timestamp within 5 minutes, compute HMAC-SHA256 and compare using constant-time comparison. | `proxy/middleware/callback_verifier.go` | 3h |
| 4.3.2 | Build customer configuration for callback endpoints and their signing secrets. | `proxy/config/`, API | 1h |
| 4.3.3 | Test: valid HMAC accepted, invalid rejected, expired timestamp rejected. | Testing | 1h |

**Total Effort:** 5 hours

---

## SHIELD-5: Session Management

**Priority:** P1 — Core
**Component:** Security Proxy
**Source Audit Ref:** Epic 11 (Session Management Hardening)

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
| 5.1.1 | Build `SessionValidator` middleware. On each request: extract session token from cookie or Authorization header, load session from Redis, check `last_activity` against idle timeout threshold, reject with 401 if exceeded, update `last_activity` if valid. | `proxy/middleware/session_validator.go` | 4h |
| 5.1.2 | Build session data model in Redis: `session:{token}` → `{user_id, tenant_id, fingerprint, last_activity, created_at, ip, user_agent}`. | `proxy/session/store.go` | 2h |
| 5.1.3 | Build session lifecycle manager: create session on login response detection, delete on logout response detection, update on every request. Detect login/logout by configurable path patterns and response status codes. | `proxy/middleware/session_updater.go` | 3h |
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
| 5.2.1 | On session creation, compute fingerprint from IP + User-Agent and store in Redis session. On each request, recompute and compare. | `proxy/middleware/session_validator.go` | 2h |
| 5.2.2 | Add configurable binding mode: `off` (no binding), `warn` (log mismatch, allow), `strict` (reject on mismatch). Default: `warn`. | `proxy/config/` | 1h |
| 5.2.3 | Log session binding violations to audit store with details (old IP vs new IP, old UA vs new UA). | `proxy/middleware/session_validator.go`, audit store | 1h |
| 5.2.4 | Test: matching fingerprint passes, changed IP triggers configured action. | Testing | 1h |

**Total Effort:** 5 hours

---

## SHIELD-6: Audit Logging & Compliance

**Priority:** P1 — Core
**Component:** Security Proxy
**Source Audit Ref:** Epic 6 (Structured Audit Logging)

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
| 6.1.1 | Build `AuditLogger` middleware. On every request/response, construct structured audit record with all required fields. Write asynchronously to log pipeline (Kafka or direct to store). | `proxy/middleware/audit_logger.go` | 4h |
| 6.1.2 | Build action detection: map path + method + status patterns to named actions (e.g., `POST /api/auth/login/ 200` → `user.login`, `DELETE /api/*/` → `resource.delete`). Customer-configurable action mappings. | `proxy/middleware/audit_logger.go`, config | 3h |
| 6.1.3 | Build audit storage: ClickHouse schema for high-volume log ingestion. Partitioned by customer_id and timestamp. Retention policy per customer plan. | `infrastructure/clickhouse/schema.sql` | 4h |
| 6.1.4 | Build audit query API: `GET /api/audit-logs/` with filtering by action, user, path, date range, status. Pagination. CSV and JSON export. | API endpoint | 4h |
| 6.1.5 | Build log pipeline: proxy → Kafka → ClickHouse (analytics) + S3 (long-term archive). | `infrastructure/kafka/` | 3h |
| 6.1.6 | Build cleanup job: delete audit records older than retention period per customer plan. | Scheduled job | 1h |
| 6.1.7 | Test: verify audit records created for all request types, verify filtering works, verify export works, verify retention cleanup. | Testing | 3h |

**Total Effort:** 22 hours

---

### Story 6.2: Emit structured JSON logs for observability (SHIELD-24)

**As a** ShieldAI operator, **I want** all proxy application logs in JSON format, **so that** they can be ingested by CloudWatch, Datadog, or ELK.

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

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 9.1.1 | Create Helm chart `shieldai-security-policies` with NetworkPolicy: deny all ingress by default, allow egress only to DNS (port 53), HTTPS (port 443), and callback API. Block egress to internal cluster IPs, cloud metadata (169.254.169.254). | `helm/shieldai-security-policies/` | 3h |
| 9.1.2 | Test: verify pods cannot communicate with each other, can still reach external URLs and callback API. | Testing | 2h |

**Total Effort:** 5 hours

---

### Story 9.2: Enforce pod security standards (SHIELD-28)

**As a** ShieldAI operator, **I want** all customer workload pods running with restricted security contexts, **so that** container escape attacks are mitigated.

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 9.2.1 | Add security context to Helm chart: `runAsNonRoot: true`, `readOnlyRootFilesystem: true` (with writable `/tmp` via emptyDir), `allowPrivilegeEscalation: false`, `capabilities: drop: ["ALL"]`, `seccompProfile: RuntimeDefault`. | `helm/shieldai-security-policies/` | 2h |
| 9.2.2 | Apply PodSecurity label on customer namespaces: `pod-security.kubernetes.io/enforce: restricted`. | Helm chart | 1h |
| 9.2.3 | Test workloads still function with restricted context. Fix permission issues. | Testing | 2h |

**Total Effort:** 5 hours

---

### Story 9.3: Add code validation for AI-generated scripts (SHIELD-29)

**As a** ShieldAI customer running AI-generated code, **I want** generated scripts analyzed for dangerous patterns before execution, **so that** malicious or unsafe code is caught.

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

**Tasks:**

| # | Task | Component | Effort |
|---|------|-----------|--------|
| 12.2.1 | Create `/.well-known/security.txt` template following RFC 9116 with placeholder fields. Auto-serve via proxy for customers who enable it. | `templates/security.txt`, proxy route | 1.5h |
| 12.2.2 | Create vulnerability disclosure policy template. | `templates/policies/vulnerability-disclosure.md` | 2h |

**Total Effort:** 3.5 hours

---

## Effort Summary

### By Epic

| Epic | Priority | Hours | Component |
|------|----------|-------|-----------|
| SHIELD-1: WAF & Threat Protection | P0 | 30 | Edge |
| SHIELD-2: Security Headers | P0 | 14 | Edge |
| SHIELD-3: Response Sanitization | P0 | 15 | Proxy |
| SHIELD-4: Request Sanitization & LLM | P1 | 23 | Proxy |
| SHIELD-5: Session Management | P1 | 17 | Proxy |
| SHIELD-6: Audit Logging | P1 | 26.5 | Proxy |
| SHIELD-7: Database RLS | P1 | 19 | DB Proxy |
| SHIELD-8: Secrets Management | P1 | 15 | Infrastructure |
| SHIELD-9: Container Hardening | P1 | 19 | Infrastructure |
| SHIELD-10: CI/CD Templates | P2 | 16 | Tools |
| SHIELD-11: SBOM | P2 | 8.5 | Tools |
| SHIELD-12: Policy Templates | P2 | 45.5 | Tools |
| **TOTAL** | | **~249 hours** | |

*Note: Effort reduced from 258.5h (original cross-reference) because genericized stories remove Coco-specific tasks (individual file edits) and replace with reusable product features.*

### By Priority

| Priority | Hours | Description |
|----------|-------|-------------|
| **P0 — MVP** | ~59 | Edge security: WAF, headers, response sanitization |
| **P1 — Core** | ~120 | Proxy features: LLM protection, sessions, audit, RLS, secrets, K8s |
| **P2 — Growth** | ~70 | Developer tools: CI/CD, SBOM, policy templates |

### By Component

| Component | Hours | Epics |
|-----------|-------|-------|
| Edge Security | 44 | SHIELD-1, SHIELD-2 |
| Security Proxy | 81.5 | SHIELD-3, SHIELD-4, SHIELD-5, SHIELD-6 |
| Database Proxy | 19 | SHIELD-7 |
| Infrastructure | 34 | SHIELD-8, SHIELD-9 |
| Developer Tools | 70 | SHIELD-10, SHIELD-11, SHIELD-12 |

### Suggested Sprint Plan (2-week sprints, 2 developers)

| Sprint | Epics | Hours | Milestone |
|--------|-------|-------|-----------|
| Sprint 1 | SHIELD-1, SHIELD-2 | ~44 | Edge security live — WAF + headers protect all apps |
| Sprint 2 | SHIELD-3 | ~15 | Response sanitization live — error leaks eliminated |
| Sprint 3 | SHIELD-5, SHIELD-4 (Story 4.1) | ~29 | Session + LLM protection live |
| Sprint 4 | SHIELD-6 | ~26.5 | Audit logging live — compliance ready |
| Sprint 5 | SHIELD-4 (4.2, 4.3), SHIELD-8 | ~26 | SSRF/callback + secrets management |
| Sprint 6 | SHIELD-7 | ~19 | Database RLS live — tenant isolation |
| Sprint 7 | SHIELD-9 | ~19 | K8s hardening live |
| Sprint 8 | SHIELD-10, SHIELD-11 | ~24.5 | CI/CD templates + SBOM launched |
| Sprint 9 | SHIELD-12 | ~45.5 | Policy templates — enterprise feature |

---

### Mapping from Original CSEC Epics

| Original Epic | Shield AI Epic | Notes |
|---------------|---------------|-------|
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
*Updated: February 2026 — Added Jira issue keys (SHIELD-1 through SHIELD-33)*
*Source: Coco TestAI Security Audit, genericized for Shield AI product*
*Jira: [SHIELD project](https://quodroid.atlassian.net/jira/software/projects/SHIELD/boards)*
*See also: [COCO_SECURITY_FIXES.md](./COCO_SECURITY_FIXES.md) for Coco-specific code fixes (CSEC project)*
