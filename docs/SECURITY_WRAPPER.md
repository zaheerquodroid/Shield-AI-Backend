# Security Wrapper Implementation Guide

A comprehensive security layer using a proxy-based architecture that protects any web application without modifying application code.

**Jira Projects:**
- [SHIELD](https://quodroid.atlassian.net/jira/software/projects/SHIELD/boards) — Generic wrapper features (12 epics, 21 stories, ~249h)
- [CSEC](https://quodroid.atlassian.net/jira/software/projects/CSEC/boards/133) — Coco-specific code fixes (5 epics, ~93h)

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Using This Wrapper for Other Applications](#using-this-wrapper-for-other-applications)
4. [Component 1A: AWS Infrastructure (Terraform)](#component-1a-aws-infrastructure-terraform)
5. [Component 1B: Cloudflare (Cloud-Agnostic Alternative)](#component-1b-cloudflare-cloud-agnostic-alternative)
6. [Component 1C: AWS CloudFront SaaS Manager (Multi-Tenant)](#component-1c-aws-cloudfront-saas-manager-multi-tenant)
7. [Component 2: Security Proxy Application](#component-2-security-proxy-application)
7. [Component 3: Database Proxy](#component-3-database-proxy)
8. [Component 4: Kubernetes Security (Helm)](#component-4-kubernetes-security-helm)
9. [Component 5: CI/CD Security (GitHub Actions)](#component-5-cicd-security-github-actions)
10. [Security Audit Coverage](#security-audit-coverage)
11. [Environment Configuration](#environment-configuration)
12. [Deployment](#deployment)
13. [Limitations](#limitations)

---

## Overview

### The Problem

The Security Audit identified 30+ issues. Traditional approaches require either:
- **Modifying Django code** in 50+ locations (high effort, high risk)
- **Adding Django middleware** which still requires changing settings.py and adding models

### The Solution

A **multi-layer security architecture** that combines AWS-native services with a proxy application:

```
Client → CloudFront+WAF (Terraform) → Security Proxy (Container) → Django → DB Proxy → PostgreSQL
```

This allows us to:
- Block attacks at the edge before they reach the application (WAF)
- Inject security headers into all responses (CloudFront)
- Sanitize requests before Django sees them (Proxy)
- Sanitize responses after Django generates them (Proxy)
- Manage sessions externally (Proxy + Redis)
- Enforce database-level security via proxy (DB Proxy)
- **Leave Django code completely unchanged**

### Required Components

**IMPORTANT:** Full protection requires deploying BOTH layers. They serve different purposes:

| Component | Deployment | What It Protects Against |
|-----------|------------|-------------------------|
| **AWS Infrastructure (Terraform)** | `terraform apply` | SQLi, XSS, bots, DDoS, credential stuffing, missing headers |
| **Security Proxy (Container)** | ECS/K8s deployment | Error leaks, LLM injection, session hijacking, SSRF, missing audit logs |
| **Database Proxy (Container)** | ECS/K8s deployment | Cross-tenant data access (RLS) |

**If you only deploy one:**

| Scenario | What You Miss |
|----------|---------------|
| Terraform only, no proxy | Error messages leak stack traces, no session timeout, no LLM sanitization, no audit logs |
| Proxy only, no Terraform | No WAF (SQLi/XSS pass through), no rate limiting, no security headers, no bot protection |

### What This Covers

| Category | Count | Component | Examples |
|----------|-------|-----------|----------|
| **Edge Security** | ~8 | Terraform | WAF (SQLi, XSS, bots), rate limiting, security headers, Secrets Manager, KMS encryption |
| **Application Security** | ~12 | Security Proxy | Error sanitization, LLM input escaping, session security, SSRF blocking, audit logging |
| **Data Security** | ~3 | Database Proxy | Row-Level Security, tenant isolation |
| **CI/CD Security** | ~3 | GitHub Actions | SAST, SCA, SBOM generation |
| **Cannot cover** | ~5 | N/A | Chrome extension, Fernet encryption, code in settings.py |

**Total: ~26 findings addressed without modifying Django code**

---

## Architecture

```
                                    Internet
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AWS EDGE (Terraform)                                 │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  CloudFront + WAF                                                      │  │
│  │  • Rate limiting, Bot control, ATP (credential stuffing)               │  │
│  │  • Managed rules (SQLi, XSS, Known Bad Inputs)                        │  │
│  │  • Security headers (HSTS, CSP, X-Frame-Options)                      │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SECURITY PROXY (Container)                              │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      REQUEST PIPELINE                                │    │
│  │                                                                      │    │
│  │  1. Session Validator                                                │    │
│  │     • Load session from Redis by cookie/token                        │    │
│  │     • Check idle timeout (reject if exceeded)                        │    │
│  │     • Verify IP + User-Agent binding (reject if changed)             │    │
│  │     • Extract tenant_id for downstream                               │    │
│  │                                                                      │    │
│  │  2. Request Sanitizer                                                │    │
│  │     • LLM endpoints: Escape prompt injection patterns in body        │    │
│  │     • Webhook endpoints: Validate URLs against SSRF blocklist        │    │
│  │     • Callback endpoints: Verify HMAC signature                      │    │
│  │     • File uploads: Validate content-type and size                   │    │
│  │                                                                      │    │
│  │  3. Context Injector                                                 │    │
│  │     • Add X-Request-ID header (correlation)                          │    │
│  │     • Add X-Tenant-ID header (for Django and DB proxy)               │    │
│  │     • Add X-User-ID header (authenticated user)                      │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                        │                                     │
│                                        ▼                                     │
│                              ┌─────────────────┐                            │
│                              │  Django Backend  │                            │
│                              │  (Unchanged)     │                            │
│                              └─────────────────┘                            │
│                                        │                                     │
│                                        ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      RESPONSE PIPELINE                               │    │
│  │                                                                      │    │
│  │  4. Response Sanitizer                                               │    │
│  │     • For 4xx/5xx: Replace body with generic error message           │    │
│  │     • Extract and log original error details                         │    │
│  │     • Strip DEBUG information if leaked                              │    │
│  │     • Remove sensitive headers (Server, X-Powered-By)                │    │
│  │                                                                      │    │
│  │  5. Audit Logger                                                     │    │
│  │     • Log request/response metadata                                  │    │
│  │     • Identify security-relevant actions (login, admin, etc.)        │    │
│  │     • Write structured JSON to CloudWatch                            │    │
│  │     • Write to audit database for retention/export                   │    │
│  │                                                                      │    │
│  │  6. Session Updater                                                  │    │
│  │     • Update last_activity timestamp in Redis                        │    │
│  │     • Handle session creation on login response                      │    │
│  │     • Handle session deletion on logout response                     │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                        │                                     │
│                                        ▼                                     │
│                                    Response                                  │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      DATABASE PROXY (Container)                              │
│                                                                              │
│  Django connects here instead of directly to PostgreSQL                      │
│                                                                              │
│  For each query:                                                             │
│  1. Read X-Tenant-ID from connection metadata                                │
│  2. Execute: SET app.current_tenant_id = '{tenant_id}'                       │
│  3. Forward query to PostgreSQL                                              │
│  4. PostgreSQL RLS policies automatically filter by tenant                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      POSTGRESQL (RDS)                                        │
│                                                                              │
│  Row-Level Security enabled on all tenant-scoped tables:                     │
│  • CREATE POLICY tenant_isolation ON {table}                                 │
│      USING (tenant_id = current_setting('app.current_tenant_id')::uuid)      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Using This Wrapper for Other Applications

### The Opportunity

Applications built with AI-assisted tools (Lovable, Bolt, Replit Agent, Cursor, etc.) and low-code platforms typically ship with minimal security. These "vibe-coded" applications often lack:
- Rate limiting and DDoS protection
- Input validation and sanitization
- Error message sanitization (stack traces leak to clients)
- Session security (no idle timeout, no hijacking protection)
- Audit logging
- Security headers

The wrapper architecture is **framework-agnostic** and can protect any HTTP-based application without modifying its code.

### Why This Works for Any Application

The security proxy operates at the HTTP layer, meaning it doesn't care what technology generates the responses:

| Backend Technology | Works? | Notes |
|-------------------|--------|-------|
| Django (Python) | Yes | Original target |
| Flask (Python) | Yes | Same deployment pattern |
| FastAPI (Python) | Yes | Same deployment pattern |
| Express (Node.js) | Yes | Same deployment pattern |
| Next.js | Yes | Works with API routes |
| Rails (Ruby) | Yes | Same deployment pattern |
| Spring Boot (Java) | Yes | Same deployment pattern |
| Lovable / Bolt | Yes | These generate standard backends |
| Bubble / Retool | Partial | Works if self-hosted; SaaS versions need vendor support |
| Supabase Edge Functions | Yes | Proxy sits in front |
| Vercel Functions | Partial | Requires custom deployment |

### Protections That Work Universally

These protections require **zero knowledge** of the backend application:

| Protection | How It Works | Covers |
|------------|--------------|--------|
| **WAF** | Inspects all HTTP requests before they reach the app | SQLi, XSS, known exploits, bot traffic |
| **Rate Limiting** | Counts requests by IP/path at edge | DDoS, brute force, credential stuffing |
| **Security Headers** | Injects headers into all responses | HSTS, CSP, X-Frame-Options, etc. |
| **Error Sanitization** | Replaces 4xx/5xx response bodies with generic messages | Stack trace leaks, debug info leaks |
| **SSRF Validation** | Validates URL fields before forwarding | Internal network attacks |
| **Audit Logging** | Logs all requests with metadata | Compliance, incident response |
| **Session Management** | Manages sessions externally via Redis | Idle timeout, session hijacking |

### Protections That Need Configuration

These require knowing your application's URL patterns:

| Protection | Configuration Needed |
|------------|---------------------|
| **LLM Input Sanitization** | List of endpoints that send user input to LLMs |
| **Callback Signature Verification** | List of webhook endpoints and their HMAC secrets |
| **Path-based Rate Limits** | Identify auth endpoints vs. general endpoints |
| **Audit Action Mapping** | Map paths to action names (login, logout, etc.) |

**Example configuration for a Lovable-generated app:**
```yaml
security_proxy:
  llm_endpoints:
    - /api/chat
    - /api/generate
    - /api/completion

  auth_endpoints:
    - /api/auth/login
    - /api/auth/register
    - /auth/callback

  callback_endpoints:
    - /api/webhooks/stripe
    - /api/webhooks/github
```

### Protections That Don't Apply

Some protections are Coco TestAI-specific:

| Protection | Why Not Universal |
|------------|-------------------|
| Database Proxy (RLS) | Requires PostgreSQL + tenant-based architecture |
| K8s Code Validator | Specific to test runner execution model |
| NetworkPolicy | Specific to Kubernetes test isolation |

### Deployment Models

#### Model 1: Sidecar (Single Application)

Deploy the security proxy alongside a single application:

```
┌─────────────────────────────────────┐
│  Your Cloud Account                 │
│                                     │
│  CloudFront + WAF                   │
│       │                             │
│       ▼                             │
│  Security Proxy (:8080)             │
│       │                             │
│       ▼                             │
│  Your App (Lovable/Bolt/etc)        │
└─────────────────────────────────────┘
```

**Use case:** Protecting a single application you or your team deployed.

#### Model 2: Multi-Tenant Gateway (SaaS)

Run the security proxy as a service protecting multiple applications:

```
┌─────────────────────────────────────────────────┐
│  Security Gateway Service                        │
│                                                  │
│  CloudFront + WAF                                │
│       │                                          │
│       ▼                                          │
│  Security Proxy (multi-tenant)                   │
│       │                                          │
│       ├──→ App A (tenant1.example.com)           │
│       ├──→ App B (tenant2.example.com)           │
│       └──→ App C (tenant3.example.com)           │
└─────────────────────────────────────────────────┘
```

**Use case:** Agency or platform protecting client applications.

#### Model 3: Browser Extension Proxy

A browser extension that routes traffic through your security proxy:

```
Browser Extension → Security Proxy → Original App
```

**Use case:** Protecting third-party hosted applications without modifying deployment.

### Configuration for Common Platforms

#### Lovable / Bolt / GPT Engineer Applications

These typically generate:
- Node.js/Express or Python/Flask backends
- PostgreSQL or Supabase databases
- Standard REST APIs

**Proxy configuration:**
```yaml
error_sanitization: enabled
session_management: enabled
llm_endpoints:
  - /api/ai/*
  - /api/chat/*
  - /api/generate/*
auth_endpoints:
  - /api/auth/*
  - /auth/*
```

#### Supabase-based Applications

Supabase applications use Edge Functions and direct database access.

**Proxy configuration:**
```yaml
error_sanitization: enabled
# Session management handled by Supabase Auth
session_management: disabled
# Supabase has built-in RLS
database_proxy: disabled
# Focus on LLM and webhook protection
llm_endpoints:
  - /functions/v1/ai-*
```

#### Vercel/Netlify Deployed Applications

**Approach:** Use the security proxy as a custom domain origin:
1. Point custom domain to security proxy
2. Security proxy forwards to Vercel/Netlify deployment
3. Configure CORS and host headers appropriately

### Getting Started (Generic Application)

**Choose your edge provider based on your deployment model:**

| Deployment Model | Recommended Edge | Why |
|-----------------|------------------|-----|
| **Multi-tenant SaaS** (protecting customer apps) | AWS CloudFront SaaS Manager | WAF inheritance to all tenants at ~$0.10/tenant, 10-20x cheaper than Cloudflare Enterprise |
| Single AWS app (ECS, EKS, EC2) | AWS WAF + CloudFront | Native integration, single bill |
| Single non-AWS app | Cloudflare Pro | Cloud-agnostic, $20/mo, easy setup |
| Self-hosted / VPS (single domain) | Cloudflare Pro | No AWS account needed |

**IMPORTANT: Multi-Tenant SaaS Pricing Reality**

If you're building a security wrapper SaaS that protects multiple customer applications (each with their own domain), the pricing differs significantly:

| Provider | Multi-Tenant WAF Support | Cost for 100 Customers |
|----------|-------------------------|------------------------|
| **AWS CloudFront SaaS Manager** | Distribution tenants inherit WAF from template | ~$50-100/mo (WAF) + ~$10/mo (tenants) |
| **Cloudflare** | WAF for SaaS requires Enterprise | $3,000+/mo minimum |

Cloudflare's Pro/Business plans only provide SSL and DDoS for custom hostnames - WAF rules do NOT apply to customer domains unless you're on Enterprise.

#### Option A: AWS CloudFront SaaS Manager (Recommended for Multi-Tenant SaaS)

See the dedicated section below: [Component 1C: AWS CloudFront SaaS Manager](#component-1c-aws-cloudfront-saas-manager-multi-tenant)

#### Option B: Cloudflare (Recommended for Single-Domain Non-AWS Apps)

1. **Add domain to Cloudflare:**
   - Sign up at cloudflare.com (free)
   - Add your domain, update nameservers

2. **Deploy edge security (Terraform):**
   ```bash
   cd terraform/cloudflare
   terraform apply -var="zone_id=YOUR_ZONE_ID" -var="environment=prod"
   ```

3. **Deploy Security Proxy (optional but recommended):**
   ```bash
   docker run -e TARGET_URL=https://your-app.vercel.app \
              -e REDIS_URL=redis://... \
              -e CONFIG_FILE=/config/security.yaml \
              coco-security-proxy:latest
   ```

4. **Configure DNS:**
   - With proxy: CNAME your domain to security proxy
   - Without proxy: CNAME to your app origin (Cloudflare still protects)

#### Option B: AWS (For AWS-Hosted Apps)

1. **Deploy AWS Infrastructure:**
   ```bash
   cd terraform/aws
   terraform apply -var="app_origin=your-app.internal.aws"
   ```

2. **Deploy Security Proxy:**
   ```bash
   # As ECS service
   aws ecs update-service --service coco-security-proxy --force-new-deployment
   ```

3. **Configure DNS:**
   - Point your domain to CloudFront distribution
   - CloudFront routes through WAF to security proxy

### Value Proposition

| Without Wrapper | With Wrapper |
|-----------------|--------------|
| Zero rate limiting | 500-2000 req/5min configurable |
| Stack traces exposed | Generic error messages |
| No security headers | Full OWASP recommended headers |
| No audit trail | 90-day structured logs |
| LLM prompts injectable | Input sanitization |
| Sessions never expire | 30-minute idle timeout |
| No breach protection | Credential stuffing detection |

### Cost for Vibe-Coded Apps

| Component | AWS | Cloudflare |
|-----------|-----|------------|
| Edge (WAF + Headers) | $25-50/mo | $0 (Free tier) |
| Security Proxy | $10-30/mo | $10-30/mo |
| Redis (sessions) | $15-30/mo | $15-30/mo |
| **Total** | **$50-110/mo** | **$25-60/mo** |

**Bottom line:** The wrapper provides enterprise-grade security for applications that were built without it, making it ideal for protecting AI-generated applications, MVPs, and internal tools. Use Cloudflare for the cheapest and most portable option.

---

## Component 1A: AWS Infrastructure (Terraform)

### Purpose

Manage AWS-native security resources that protect at the edge. **No application changes required.**

**Use this when:** Your application is hosted on AWS (ECS, EKS, EC2, etc.)

### Module: waf/

Deploys AWS WAF WebACL with:

| Rule | Purpose | Environment |
|------|---------|-------------|
| AWS Managed Rules (CRS) | Block common exploits | All |
| SQL Injection Rules | Block SQLi attempts | All |
| Known Bad Inputs | Block CVE patterns | All |
| Rate Limiting (Auth) | 500 req/5min on /api/auth/* | Prod |
| Rate Limiting (Global) | 2000 req/5min all paths | Prod |
| Bot Control | Detect/challenge bots | Demo, Prod |
| Account Takeover Prevention | Check credentials against breach DB | Demo, Prod |
| CAPTCHA | Challenge suspicious logins | Demo, Prod |

**Logic:**
- Requests pass through WAF before reaching any application component
- In test environment, rules count but don't block (monitoring mode)
- In prod, rules actively block malicious requests

### Module: security-headers/

Deploys CloudFront Response Headers Policy:

| Header | Value |
|--------|-------|
| Strict-Transport-Security | max-age=31536000; includeSubDomains; preload |
| Content-Security-Policy | default-src 'self'; script-src 'self' ... |
| X-Frame-Options | DENY |
| X-Content-Type-Options | nosniff |
| Referrer-Policy | strict-origin-when-cross-origin |
| Permissions-Policy | camera=(), microphone=(), geolocation=() |

### Module: secrets/

Deploys AWS Secrets Manager secrets:

| Secret | Purpose |
|--------|---------|
| django-secret-key | Django SECRET_KEY |
| db-password | PostgreSQL password |
| redis-password | Redis password |
| callback-signing-key | HMAC key for K8s callbacks |

**Logic:**
- Secrets created in Secrets Manager with auto-rotation
- ECS task definition references secrets by ARN
- Secrets injected as environment variables at container start
- Django reads from os.getenv() as normal

### Module: encryption/

Enables KMS encryption:

| Resource | Encryption |
|----------|------------|
| RDS PostgreSQL | KMS-managed key, automatic rotation |
| S3 buckets | KMS-managed key |
| ElastiCache Redis | In-transit + at-rest encryption |

---

## Component 1B: Cloudflare (Cloud-Agnostic Alternative)

### Purpose

Provide the same edge security protections as AWS WAF/CloudFront, but **works with any hosting provider**. This is the recommended option for protecting applications hosted on Vercel, Railway, Render, Fly.io, DigitalOcean, or any non-AWS platform.

**Use this when:** Your application is NOT on AWS, or you want a universal solution that works everywhere.

### Why Cloudflare?

| Consideration | AWS WAF + CloudFront | Cloudflare |
|---------------|---------------------|------------|
| Works with AWS apps | Yes | Yes |
| Works with Vercel/Railway/Render | No (requires complex setup) | Yes (native) |
| Works with self-hosted | No | Yes |
| Terraform support | Yes | Yes |
| Free tier available | No | Yes (generous) |
| Credential stuffing protection | ATP ($10/mo) | Exposed Credentials Check (Enterprise) |
| Bot management | Bot Control ($$$) | Bot Fight Mode (Free) / Bot Management (Enterprise) |

### Architecture with Cloudflare

```
                                    Internet
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CLOUDFLARE EDGE                                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Cloudflare WAF + Workers                                              │  │
│  │  • Managed Rulesets (OWASP, SQLi, XSS)                                │  │
│  │  • Rate Limiting Rules                                                 │  │
│  │  • Bot Fight Mode / Bot Management                                     │  │
│  │  • Transform Rules (Security Headers)                                  │  │
│  │  • Page Rules (caching, redirects)                                     │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SECURITY PROXY (Container)                              │
│                      (Same as AWS deployment)                                │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      TARGET APPLICATION                                      │
│                      (Vercel, Railway, Render, self-hosted, etc.)           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Cloudflare WAF Configuration

#### Managed Rulesets

Enable these managed rulesets in Cloudflare Dashboard or via Terraform:

| Ruleset | Purpose | Action |
|---------|---------|--------|
| Cloudflare Managed Ruleset | Core protection (SQLi, XSS, RCE) | Block |
| Cloudflare OWASP Core Ruleset | OWASP Top 10 coverage | Block |
| Cloudflare Exposed Credentials Check | Detect breached passwords | Challenge |

#### Custom Rate Limiting Rules

| Rule Name | Expression | Rate | Action |
|-----------|------------|------|--------|
| Auth Rate Limit | `http.request.uri.path contains "/api/auth/"` | 20 req/min | Block |
| API Rate Limit | `http.request.uri.path contains "/api/"` | 100 req/min | Block |
| Global Rate Limit | `true` | 500 req/min | Challenge |

#### Transform Rules (Security Headers)

Create a Response Header Modification rule:

| Header | Value |
|--------|-------|
| Strict-Transport-Security | max-age=31536000; includeSubDomains; preload |
| Content-Security-Policy | default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' |
| X-Frame-Options | DENY |
| X-Content-Type-Options | nosniff |
| Referrer-Policy | strict-origin-when-cross-origin |
| Permissions-Policy | camera=(), microphone=(), geolocation=() |
| X-XSS-Protection | 1; mode=block |

### Terraform Configuration (Cloudflare Provider)

**Provider setup:**

```hcl
terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
```

**Variables:**

| Variable | Description |
|----------|-------------|
| cloudflare_api_token | API token with Zone:Edit permissions |
| cloudflare_zone_id | Zone ID for your domain |
| origin_url | URL of your application (e.g., your-app.vercel.app) |
| environment | test, demo, or prod |

**Resources created:**

| Resource | Purpose |
|----------|---------|
| cloudflare_zone_settings_override | Enable SSL, TLS 1.3, HSTS |
| cloudflare_ruleset (WAF) | Managed WAF rulesets |
| cloudflare_ruleset (rate_limit) | Rate limiting rules |
| cloudflare_ruleset (transform) | Security headers |
| cloudflare_record | DNS pointing to security proxy or origin |

### Comparison: AWS vs Cloudflare Coverage

| Protection | AWS (Component 1A) | Cloudflare (Component 1B) |
|------------|-------------------|--------------------------|
| SQLi/XSS blocking | WAF Managed Rules | Managed Ruleset |
| Rate limiting | WAF Rate Rules | Rate Limiting Rules |
| Bot protection | Bot Control | Bot Fight Mode |
| Credential stuffing | ATP | Exposed Credentials Check |
| Security headers | CloudFront Response Headers | Transform Rules |
| DDoS protection | Shield Standard | Always-on DDoS |
| SSL/TLS | ACM + CloudFront | Universal SSL |
| Caching | CloudFront | Cloudflare CDN |

**Key difference:** Cloudflare provides most protections in the free tier, while AWS charges for WAF rules, Bot Control, and ATP separately.

### Deployment Options with Cloudflare

#### Option A: Cloudflare + Security Proxy (Full Protection)

```
User → Cloudflare (WAF/headers) → Security Proxy (your server) → Target App
```

Best for: Maximum protection, self-hosted or cloud VMs

#### Option B: Cloudflare + Direct to App (Edge-Only Protection)

```
User → Cloudflare (WAF/headers) → Target App (Vercel/Railway)
```

Best for: Quick setup, apps on managed platforms where you can't run the proxy

**What you lose without the Security Proxy:**
- Error message sanitization (stack traces may leak)
- LLM input sanitization
- Session idle timeout / hijacking protection
- Audit logging
- SSRF validation

#### Option C: Cloudflare Workers (Proxy at Edge)

Run the security proxy logic as a Cloudflare Worker:

```
User → Cloudflare Worker (WAF + Proxy logic) → Target App
```

Best for: Serverless, global edge deployment, minimal infrastructure

**Benefits:**
- No server to manage
- Runs in 300+ edge locations
- Can implement session management, error sanitization at edge
- Pay per request

### Getting Started with Cloudflare

1. **Add your domain to Cloudflare:**
   - Sign up at cloudflare.com
   - Add your domain and update nameservers
   - Or use Cloudflare for SaaS for customer domains

2. **Enable WAF:**
   ```bash
   cd terraform/cloudflare
   terraform init
   terraform apply -var="zone_id=YOUR_ZONE_ID" -var="environment=prod"
   ```

3. **Point DNS to your security proxy or application:**
   - If using security proxy: CNAME to proxy's load balancer
   - If direct to app: CNAME to vercel/railway/render URL

4. **Verify protection:**
   - Test WAF: `curl "https://yourapp.com/?id=1' OR '1'='1"` (should block)
   - Check headers: `curl -I https://yourapp.com` (should show security headers)
   - Test rate limit: Run 50 requests to /api/auth/login quickly

### Cost Comparison

| Protection Level | AWS Monthly | Cloudflare Monthly |
|-----------------|-------------|-------------------|
| Basic WAF + Headers | ~$25 | $0 (Free tier) |
| + Rate Limiting | ~$30 | $0 (Free tier) |
| + Bot Protection | ~$50 | $0 (Bot Fight Mode) |
| + Credential Stuffing | ~$60 | Enterprise only |
| **Typical Total** | **$50-100** | **$0-25** |

**Recommendation for single-domain vibe-coded apps:** Start with Cloudflare Free tier. It covers 80% of the edge security needs at zero cost.

**For multi-tenant SaaS:** Use AWS CloudFront SaaS Manager instead - see Component 1C below.

---

## Component 1C: AWS CloudFront SaaS Manager (Multi-Tenant)

### Purpose

Provide enterprise-grade edge security for **multi-tenant SaaS applications** where you need to protect multiple customer domains with inherited WAF rules. This is the recommended option for ShieldAI-style security wrapper services.

**Use this when:** You're building a SaaS that protects multiple customer applications, each with their own domain.

### Why CloudFront SaaS Manager Over Cloudflare?

| Consideration | AWS CloudFront SaaS Manager | Cloudflare |
|---------------|---------------------------|------------|
| WAF for custom domains | Inherited from template distribution | Enterprise only ($3,000+/mo) |
| Cost for 100 customers | ~$60-150/mo total | $3,000+/mo |
| SSL for custom domains | Included via distribution tenants | Included (Cloudflare for SaaS) |
| DDoS protection | Shield Standard (free) | Included |
| Setup complexity | Moderate (Terraform) | Low (dashboard) but limited |
| API automation | Full CloudFormation/Terraform | Full API |

### How CloudFront SaaS Manager Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AWS CLOUDFRONT SAAS MANAGER                               │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │              MULTI-TENANT DISTRIBUTION (Template)                    │    │
│  │                                                                      │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │  Shared Configuration:                                       │    │    │
│  │  │  • WAF WebACL (SQLi, XSS, Rate Limiting, Bot Control)       │    │    │
│  │  │  • Response Headers Policy (HSTS, CSP, X-Frame-Options)     │    │    │
│  │  │  • Cache Behaviors                                           │    │    │
│  │  │  • Origin Request Policy                                     │    │    │
│  │  │  • SSL/TLS Settings (TLS 1.2+)                              │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  │                                                                      │    │
│  │  Distribution Tenants (inherit all settings above):                 │    │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                │    │
│  │  │ customer1.com│ │ customer2.com│ │ customer3.com│                │    │
│  │  │ → origin1    │ │ → origin2    │ │ → origin3    │                │    │
│  │  └──────────────┘ └──────────────┘ └──────────────┘                │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SECURITY PROXY (Container)                              │
│                      (Same as other deployments)                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CUSTOMER APPLICATIONS                                   │
│      (Vercel, Railway, Lovable apps, self-hosted, etc.)                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Multi-tenant distribution** | A CloudFront distribution configured as a template; defines shared WAF, headers, cache behaviors |
| **Distribution tenant** | A customer domain that inherits settings from the multi-tenant distribution |
| **WAF WebACL** | Attached to the multi-tenant distribution; automatically protects all tenants |
| **Connection group** | (Optional) Groups tenants for origin routing |

### WAF Coverage for All Tenants

When you attach a WAF WebACL to the multi-tenant distribution, all distribution tenants automatically inherit:

| Protection | How It Works |
|------------|--------------|
| SQL Injection | AWS Managed Rules - SQLi rule group |
| XSS | AWS Managed Rules - XSS rule group |
| Known Exploits | AWS Managed Rules - Known Bad Inputs |
| Rate Limiting | Rate-based rules (e.g., 2000 req/5min) |
| Bot Protection | AWS Bot Control (optional, ~$10/mo) |
| Credential Stuffing | AWS Fraud Control ATP (optional, ~$10/mo) |
| Geo Blocking | Geographic match conditions |

### Response Headers for All Tenants

The Response Headers Policy attached to the multi-tenant distribution applies to all tenant domains:

| Header | Value |
|--------|-------|
| Strict-Transport-Security | max-age=31536000; includeSubDomains; preload |
| Content-Security-Policy | default-src 'self'; script-src 'self' ... |
| X-Frame-Options | DENY |
| X-Content-Type-Options | nosniff |
| Referrer-Policy | strict-origin-when-cross-origin |
| Permissions-Policy | camera=(), microphone=(), geolocation=() |

### Terraform Configuration

**Provider setup:**

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"  # CloudFront requires us-east-1 for WAF
}
```

**Multi-tenant distribution:**

```hcl
resource "aws_cloudfront_distribution" "multi_tenant" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "ShieldAI Multi-Tenant Distribution"
  price_class         = "PriceClass_100"

  # Enable multi-tenant mode
  continuous_deployment_policy_id = null

  # Default origin (security proxy)
  origin {
    domain_name = var.security_proxy_domain
    origin_id   = "security-proxy"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "security-proxy"
    viewer_protocol_policy = "redirect-to-https"

    # Forward all to origin (proxy handles caching)
    forwarded_values {
      query_string = true
      headers      = ["*"]
      cookies {
        forward = "all"
      }
    }

    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }

  # Attach WAF
  web_acl_id = aws_wafv2_web_acl.main.arn

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = false
    acm_certificate_arn            = var.wildcard_cert_arn
    ssl_support_method             = "sni-only"
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  tags = {
    Environment = var.environment
    Purpose     = "multi-tenant-saas"
  }
}
```

**Distribution tenant (per customer):**

```hcl
resource "aws_cloudfront_distribution_tenant" "customer" {
  distribution_id = aws_cloudfront_distribution.multi_tenant.id

  domains {
    domain = var.customer_domain  # e.g., "app.customer.com"
  }

  # Customer-specific origin (their app)
  default_association {
    origin_id = "customer-origin"

    origin {
      domain_name = var.customer_origin  # e.g., "customer-app.vercel.app"
      origin_id   = "customer-origin"

      custom_origin_config {
        http_port              = 80
        https_port             = 443
        origin_protocol_policy = "https-only"
        origin_ssl_protocols   = ["TLSv1.2"]
      }
    }
  }

  # SSL certificate for customer domain
  certificate {
    acm_certificate_arn      = var.customer_cert_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  enabled = true

  tags = {
    Customer    = var.customer_id
    Environment = var.environment
  }
}
```

**WAF WebACL (shared by all tenants):**

```hcl
resource "aws_wafv2_web_acl" "main" {
  name        = "shieldai-waf"
  description = "WAF for all ShieldAI customers"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # AWS Managed Rules - Core Rule Set
  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - SQL Injection
  rule {
    name     = "AWS-AWSManagedRulesSQLiRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rate limiting - Auth endpoints
  rule {
    name     = "RateLimitAuth"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 500
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string         = "/api/auth"
            field_to_match {
              uri_path {}
            }
            positional_constraint = "STARTS_WITH"
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitAuth"
      sampled_requests_enabled   = true
    }
  }

  # Rate limiting - Global
  rule {
    name     = "RateLimitGlobal"
    priority = 4

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitGlobal"
      sampled_requests_enabled   = true
    }
  }

  # Bot Control (optional)
  dynamic "rule" {
    for_each = var.enable_bot_control ? [1] : []
    content {
      name     = "AWS-AWSManagedRulesBotControlRuleSet"
      priority = 5

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesBotControlRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "BotControl"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "ShieldAIWAF"
    sampled_requests_enabled   = true
  }

  tags = {
    Environment = var.environment
  }
}
```

**Response Headers Policy:**

```hcl
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name = "shieldai-security-headers"

  security_headers_config {
    strict_transport_security {
      override                   = true
      include_subdomains         = true
      preload                    = true
      access_control_max_age_sec = 31536000
    }

    content_type_options {
      override = true
    }

    frame_options {
      override     = true
      frame_option = "DENY"
    }

    xss_protection {
      override   = true
      mode_block = true
      protection = true
    }

    referrer_policy {
      override        = true
      referrer_policy = "strict-origin-when-cross-origin"
    }

    content_security_policy {
      override                = true
      content_security_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;"
    }
  }

  custom_headers_config {
    items {
      header   = "Permissions-Policy"
      value    = "camera=(), microphone=(), geolocation=()"
      override = true
    }
  }
}
```

### Customer Onboarding Automation

When a new customer signs up:

1. **Create ACM certificate** for their domain (DNS validation)
2. **Wait for certificate validation** (customer adds CNAME)
3. **Create distribution tenant** pointing to their origin
4. **Customer updates DNS** to point to CloudFront

**Automation script example:**

```python
import boto3

def onboard_customer(customer_domain: str, origin_url: str):
    acm = boto3.client('acm', region_name='us-east-1')
    cloudfront = boto3.client('cloudfront')

    # 1. Request certificate
    cert_response = acm.request_certificate(
        DomainName=customer_domain,
        ValidationMethod='DNS',
        Tags=[{'Key': 'Customer', 'Value': customer_domain}]
    )
    cert_arn = cert_response['CertificateArn']

    # 2. Get validation CNAME (return to customer)
    cert_details = acm.describe_certificate(CertificateArn=cert_arn)
    validation_options = cert_details['Certificate']['DomainValidationOptions']

    # Return validation records to customer
    # Customer adds CNAME, then...

    # 3. Create distribution tenant (after cert validated)
    tenant_response = cloudfront.create_distribution_tenant(
        DistributionId=MULTI_TENANT_DISTRIBUTION_ID,
        DistributionTenantConfig={
            'Domains': {
                'Quantity': 1,
                'Items': [customer_domain]
            },
            'DefaultAssociation': {
                'OriginId': 'customer-origin',
                'Origins': {
                    'Quantity': 1,
                    'Items': [{
                        'Id': 'customer-origin',
                        'DomainName': origin_url,
                        'CustomOriginConfig': {
                            'HTTPPort': 80,
                            'HTTPSPort': 443,
                            'OriginProtocolPolicy': 'https-only',
                            'OriginSslProtocols': {'Quantity': 1, 'Items': ['TLSv1.2']}
                        }
                    }]
                }
            },
            'Certificate': {
                'AcmCertificateArn': cert_arn,
                'SslSupportMethod': 'sni-only',
                'MinimumProtocolVersion': 'TLSv1.2_2021'
            },
            'Enabled': True
        }
    )

    return tenant_response
```

### Cost Breakdown

| Component | Monthly Cost | Notes |
|-----------|--------------|-------|
| WAF WebACL | $5 | Base fee |
| WAF Managed Rules | $1-5/rule group | Core + SQLi = ~$2 |
| WAF Requests | $0.60/million | Typically $5-20 |
| Bot Control | $10 + $1/million | Optional |
| ATP (credential stuffing) | $10 + $1/million | Optional |
| CloudFront Distribution | $0 | No base fee |
| Distribution Tenants | First 200 free, then $0.10/tenant | |
| CloudFront Data Transfer | $0.085/GB | Standard rates |
| ACM Certificates | $0 | Free for public certs |

**Example: 100 customers, 10M requests/month**
- WAF: $5 + $2 (rules) + $6 (requests) = $13
- Bot Control: $10 + $10 = $20 (optional)
- Distribution Tenants: $0 (under 200)
- Data Transfer: ~$50 (varies)
- **Total: ~$50-90/month** (vs $3,000+/month for Cloudflare Enterprise)

### Comparison: CloudFront SaaS Manager vs Cloudflare

| Feature | CloudFront SaaS Manager | Cloudflare Enterprise |
|---------|------------------------|----------------------|
| Multi-tenant WAF | Yes (inherited) | Yes |
| Cost (100 customers) | ~$60-150/mo | $3,000+/mo |
| Setup complexity | Moderate | Low |
| Custom domain SSL | ACM (free, auto-renew) | Included |
| Bot protection | Optional ($10/mo) | Included |
| Credential stuffing | Optional ($10/mo) | Included |
| Global edge locations | 400+ | 300+ |
| API automation | Full | Full |

### Getting Started with CloudFront SaaS Manager

1. **Create multi-tenant distribution:**
   ```bash
   cd terraform/aws-cloudfront-saas
   terraform init
   terraform apply -var="environment=prod"
   ```

2. **Create WAF WebACL and attach:**
   - WebACL is created by Terraform
   - Automatically attached to distribution

3. **Onboard first customer:**
   ```bash
   python scripts/onboard_customer.py \
     --domain app.customer.com \
     --origin customer-app.vercel.app
   ```

4. **Customer adds DNS records:**
   - CNAME for SSL validation
   - CNAME pointing domain to CloudFront

5. **Verify protection:**
   ```bash
   # Test WAF
   curl "https://app.customer.com/?id=1' OR '1'='1"
   # Should return 403

   # Check headers
   curl -I https://app.customer.com
   # Should show security headers
   ```

---

## Component 2: Security Proxy Application

### Purpose

A FastAPI/Starlette application that sits between CloudFront/ALB and Django, intercepting all HTTP traffic to enforce security controls.

### Why a Separate Application?

| Approach | Django Changes | Drawbacks |
|----------|---------------|-----------|
| Django middleware | Must modify settings.py, add to MIDDLEWARE | Couples security to app |
| Security proxy | None | Additional service to deploy |

The proxy approach keeps Django completely unchanged while centralizing all security logic.

### Request Pipeline

#### Stage 1: Session Validator

**Purpose:** Enforce session security without Django session middleware.

**Logic:**
1. Extract session token from cookie or Authorization header
2. Load session data from Redis using token as key
3. **Idle Timeout Check:**
   - Read `last_activity` timestamp from session
   - If `now - last_activity > 30 minutes`, reject with 401
4. **Session Binding Check:**
   - Read `fingerprint` from session (hash of IP + User-Agent)
   - Compute current fingerprint from request
   - If mismatch, log potential hijacking, reject with 401
5. **Extract Context:**
   - Read `tenant_id` and `user_id` from session
   - Store in request context for later stages

**Session Data Structure (Redis):**
```
session:{token} = {
  "user_id": "uuid",
  "tenant_id": "uuid",
  "fingerprint": "sha256-hash",
  "last_activity": "2026-02-09T12:00:00Z",
  "created_at": "2026-02-09T10:00:00Z",
  "ip": "203.0.113.42",
  "user_agent": "Mozilla/5.0..."
}
```

#### Stage 2: Request Sanitizer

**Purpose:** Modify request bodies to neutralize attacks before Django processes them.

##### LLM Endpoint Sanitization

**Protected Paths:**
- `/api/conversations/`
- `/api/test-cases/generate/`
- `/api/artifacts/generate/`
- `/api/acceptance-criteria/`

**Logic:**
1. Parse JSON request body
2. For each string field, apply sanitization:
   - Escape known injection patterns
   - Add delimiter markers around user content
   - Remove or encode control sequences
3. Replace request body with sanitized version
4. Django receives clean input

**Injection Patterns Escaped:**
- `ignore previous instructions` → `[FILTERED: instruction_override]`
- `you are now` → `[FILTERED: role_manipulation]`
- `reveal your prompt` → `[FILTERED: output_extraction]`
- Template injection patterns (`{{`, `{%`) → escaped

**Why This Works:**
The vulnerable code in `artifacts.py` interpolates user input into prompts:
```python
prompt = f"Generate test for: {test_case.description}"
```
By sanitizing `description` before it reaches Django, the interpolation is safe.

##### SSRF Validation

**Protected Paths:**
- `/api/webhooks/`
- `/api/integrations/*/callback/`

**Logic:**
1. Parse JSON body, find URL fields
2. For each URL:
   - Parse and resolve hostname to IP
   - Reject if IP is private (10.x, 172.16-31.x, 192.168.x)
   - Reject if IP is loopback (127.x, ::1)
   - Reject if IP is link-local (169.254.x)
   - Reject if hostname is internal
3. Return 400 if any URL fails validation

##### Callback Signature Verification

**Protected Paths:**
- `/api/test-results/callback/`

**Logic:**
1. Extract signature from `X-Signature` header
2. Extract timestamp from `X-Timestamp` header
3. Verify timestamp within 5 minutes of current time
4. Compute expected signature: `HMAC-SHA256(body + timestamp, secret)`
5. Compare signatures using constant-time comparison
6. Reject with 401 if invalid

#### Stage 3: Context Injector

**Purpose:** Add headers that downstream components use for context.

**Headers Added:**
| Header | Value | Used By |
|--------|-------|---------|
| X-Request-ID | UUID (8 chars) | Logging correlation |
| X-Tenant-ID | From session | Database proxy for RLS |
| X-User-ID | From session | Audit logging |
| X-Forwarded-For | Client IP | Django for logging |

### Response Pipeline

#### Stage 4: Response Sanitizer

**Purpose:** Prevent information leakage through error responses.

**Logic:**
1. Check response status code
2. If 4xx or 5xx:
   - Parse response body
   - Check for sensitive patterns:
     - Stack traces (`Traceback`, `File "..."``)
     - Exception details (`Exception:`, `Error:`)
     - Database errors (`psycopg2`, `relation "..."`)
     - File paths (`/home/`, `/var/`, `/app/`)
   - If found, replace entire body with generic message
   - Log original body to CloudWatch with request ID

**Generic Error Messages:**
| Status | Message |
|--------|---------|
| 400 | The request was invalid or malformed. |
| 401 | Authentication is required. |
| 403 | You do not have permission to perform this action. |
| 404 | The requested resource was not found. |
| 500 | An internal error occurred. Please try again later. |

**Error Response Format:**
```json
{
  "error": true,
  "message": "An internal error occurred. Please try again later.",
  "error_id": "a1b2c3d4",
  "status": 500
}
```

#### Stage 5: Audit Logger

**Purpose:** Create structured audit trail for security-relevant actions.

**Auditable Actions (detected by path + method + status):**
| Path Pattern | Method | Success Status | Action |
|--------------|--------|----------------|--------|
| /api/auth/login/ | POST | 200 | user.login |
| /api/auth/logout/ | POST | 200 | user.logout |
| /api/auth/signup/ | POST | 201 | user.signup |
| /api/auth/password/reset/ | POST | 200 | user.password_reset |
| /api/auth/mfa/enable/ | POST | 200 | user.mfa_enable |
| /api/team/members/ | POST | 201 | admin.member_add |
| /api/team/members/* | DELETE | 200 | admin.member_remove |
| /api/team/members/*/role/ | PUT | 200 | admin.role_change |

**Audit Record:**
```json
{
  "timestamp": "2026-02-09T12:00:00.000Z",
  "request_id": "a1b2c3d4",
  "action": "user.login",
  "user_id": "uuid",
  "tenant_id": "uuid",
  "ip": "203.0.113.42",
  "user_agent": "Mozilla/5.0...",
  "path": "/api/auth/login/",
  "method": "POST",
  "status": 200,
  "success": true
}
```

**Storage:**
- CloudWatch Logs: Real-time streaming, 90-day retention
- PostgreSQL audit table: For customer export API

#### Stage 6: Session Updater

**Purpose:** Manage session lifecycle based on Django responses.

**Logic:**
1. **On successful login response (POST /api/auth/login/, 200):**
   - Extract user info from response body
   - Create session in Redis with tenant_id, user_id
   - Set fingerprint from current IP + User-Agent
   - Set session cookie in response

2. **On logout response (POST /api/auth/logout/, 200):**
   - Delete session from Redis
   - Clear session cookie

3. **On all other successful responses:**
   - Update `last_activity` timestamp in Redis

---

## Component 3: Database Proxy

### Purpose

Enforce PostgreSQL Row-Level Security by automatically setting tenant context on every database connection.

### Why a Database Proxy?

Without proxy, Django would need code changes to execute `SET app.current_tenant_id = ...` on each request. The proxy does this transparently.

### Architecture Options

#### Option A: Custom Proxy (Recommended for Full Control)

A lightweight Go/Python application that:
1. Accepts PostgreSQL connections from Django
2. Reads `application_name` connection parameter (contains tenant_id)
3. On each transaction, executes `SET app.current_tenant_id = '{tenant_id}'`
4. Forwards query to actual PostgreSQL

**Django Configuration:**
```python
DATABASES = {
    'default': {
        'HOST': 'db-proxy',  # Point to proxy, not RDS
        'OPTIONS': {
            'application_name': '{{ tenant_id }}'  # Set by WSGI middleware
        }
    }
}
```

**Note:** This requires minimal Django change - just setting application_name in connection options, which can be done via environment variable or simple middleware.

#### Option B: PgBouncer with Hooks

PgBouncer with `server_connect_query`:
```ini
[pgbouncer]
server_connect_query = SET app.current_tenant_id = '%u'
```

**Limitation:** PgBouncer's variable interpolation is limited. May need custom build.

#### Option C: PostgreSQL Extension (pg_hint_plan style)

Use a PostgreSQL extension that reads a custom parameter and sets session variables.

### RLS Policy Setup

Executed via Terraform or migration script (one-time setup):

**For each tenant-scoped table:**
1. Enable RLS: `ALTER TABLE {table} ENABLE ROW LEVEL SECURITY`
2. Force RLS for owner: `ALTER TABLE {table} FORCE ROW LEVEL SECURITY`
3. Create policy:
```sql
CREATE POLICY tenant_isolation ON {table}
  FOR ALL
  TO application_role
  USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid)
```

**Tables Covered:**
- projects, test_cases, test_runs
- artifacts, documents
- conversations, messages
- team_members, invitations

### Defense in Depth

Even if Django ORM query misses tenant filter, RLS enforces it:

```python
# Django view (potentially buggy - no tenant filter)
TestCase.objects.all()

# Without RLS: Returns ALL test cases (data leak!)
# With RLS: Returns only current tenant's test cases
```

---

## Component 4: Kubernetes Security (Helm)

### Purpose

Secure the Kubernetes environment where test runner jobs execute.

### Chart: coco-security-policies

#### NetworkPolicy

**Purpose:** Prevent test runner pods from attacking each other or internal services.

**Rules:**
- Deny all ingress to `coco-runners` namespace by default
- Allow egress only to:
  - DNS (kube-dns, port 53)
  - HTTPS (port 443) to external URLs
  - Results callback endpoint
- Block egress to:
  - Internal cluster IPs (10.x)
  - Cloud metadata (169.254.169.254)
  - Other namespaces

**Effect:** Compromised test code cannot make lateral movements.

#### Pod Security Standards

**Purpose:** Restrict container capabilities.

**Enforced:**
- `runAsNonRoot: true` - No root containers
- `readOnlyRootFilesystem: true` - No filesystem writes
- `allowPrivilegeEscalation: false` - No privilege escalation
- `capabilities: drop: ["ALL"]` - No Linux capabilities
- `seccompProfile: RuntimeDefault` - Syscall filtering

#### Code Validation Service

**Purpose:** Analyze LLM-generated code before execution.

**Deployment:**
- Runs in `coco-system` namespace
- Receives code from K8s executor before job creation
- Returns pass/fail verdict

**Validation Logic:**
1. Parse Python code into AST
2. Walk AST looking for:
   - Imports of dangerous modules (os, subprocess, socket, shutil)
   - Usage of eval(), exec(), compile()
   - Shell command patterns in strings
3. Return detailed report of findings
4. K8s executor only creates job if validation passes

**Blocked Imports:**
- `os` - Filesystem and process access
- `subprocess` - Shell command execution
- `socket` - Network connections
- `shutil` - File operations
- `ctypes` - C library access
- `importlib` - Dynamic imports

---

## Component 5: CI/CD Security (GitHub Actions)

### Purpose

Automate security scanning in the development workflow.

### Workflow: security-scan.yml

**Triggers:** Push to main, Pull requests, Weekly schedule

**Jobs:**

| Job | Tool | Purpose |
|-----|------|---------|
| Secret Detection | gitleaks | Find committed secrets |
| SAST Python | Bandit, Semgrep | Static analysis |
| SAST JavaScript | ESLint Security | Static analysis |
| SCA Python | pip-audit | Dependency vulnerabilities |
| SCA JavaScript | npm audit | Dependency vulnerabilities |
| Container Scan | Trivy | Image vulnerabilities |

### Workflow: sbom-generate.yml

**Triggers:** Release tags

**Purpose:** Generate Software Bill of Materials for compliance.

**Output:** CycloneDX JSON uploaded to release artifacts.

---

## Security Audit Coverage

**Note:** The findings below require different components. For full coverage, deploy:
1. **Edge security** - Either AWS (Component 1A) OR Cloudflare (Component 1B)
2. **Security Proxy container** (error sanitization, session management, LLM protection)
3. **Database Proxy container** (RLS enforcement) - only if using PostgreSQL multi-tenant
4. **GitHub Actions workflows** (CI/CD scanning)

### Fully Covered (No Django Changes)

#### Edge Security (AWS Terraform OR Cloudflare Required)

| Finding | AWS Solution | Cloudflare Solution |
|---------|--------------|---------------------|
| Rate limiting missing | WAF rate-based rules | Rate Limiting Rules |
| No DDoS protection | WAF + CloudFront | Always-on DDoS |
| Credential stuffing | WAF ATP ($) | Exposed Credentials Check (Enterprise) |
| No account lockout | WAF CAPTCHA | Managed Challenge |
| Missing HSTS | CloudFront headers | Transform Rules |
| Missing CSP | CloudFront headers | Transform Rules |
| Missing security headers (10) | CloudFront headers | Transform Rules |
| Secrets in env vars | Secrets Manager + ECS | N/A (use cloud provider's secret manager) |
| No KMS encryption | RDS/S3 KMS | N/A (use cloud provider's encryption) |
| security.txt missing | S3 static file | Pages / R2 static file |

**Note:** Secrets Manager and KMS encryption are AWS-specific. For non-AWS deployments, use your cloud provider's equivalent (GCP Secret Manager, Azure Key Vault, etc.) or a third-party like HashiCorp Vault.

#### Application Security (Security Proxy Container Required)

| Finding | Solution | Component |
|---------|----------|-----------|
| **44+ str(e) error leaks** | Response sanitizer | Security Proxy |
| **DEBUG info leaked** | Response sanitizer | Security Proxy |
| **LLM prompt injection** | Request sanitizer | Security Proxy |
| **No idle session timeout** | Session validator | Security Proxy |
| **No session binding** | Session validator | Security Proxy |
| **SSRF vulnerability** | Request sanitizer | Security Proxy |
| **No callback signing** | Request sanitizer | Security Proxy |
| **No audit logging** | Audit logger | Security Proxy |
| **No 90-day retention** | CloudWatch + DB | Security Proxy |

#### Kubernetes Security (Helm Required)

| Finding | Solution | Component |
|---------|----------|-----------|
| K8s NetworkPolicy missing | NetworkPolicy | Helm |
| Pod Security missing | Pod Security Standards | Helm |
| No code validation | Code validator service | Helm |

#### CI/CD Security (GitHub Actions Required)

| Finding | Solution | Component |
|---------|----------|-----------|
| No CI/CD scanning | GitHub Actions | Workflows |
| No SBOM | GitHub Actions | Workflows |

### Covered with Minimal Change

| Finding | Solution | Change Required |
|---------|----------|-----------------|
| PostgreSQL RLS | Database proxy | Django: Set application_name in DB connection |

### Cannot Cover (Tracked in CSEC Project)

These require application code changes and are tracked in the [CSEC Jira project](https://quodroid.atlassian.net/jira/software/projects/CSEC/boards/133):

| Finding | CSEC Epic | Reason |
|---------|-----------|--------|
| Chrome extension sender validation | CSEC-12 | Extension JavaScript code |
| Chrome extension encrypted storage | CSEC-12 | Extension JavaScript code |
| Chrome extension tab filtering | CSEC-12 | Extension JavaScript code |
| Fernet → AES-256-GCM | CSEC-3 | Application encryption logic in mfa.py, encryption.py |
| Remove SECRET_KEY fallback | CSEC-1 | Code in settings.py:36 |
| VITE_USER_ID removal | CSEC-13 | Frontend code |
| Console.log stripping | CSEC-13 | Build configuration |
| Client-side file validation | CSEC-13 | Frontend code |

---

## Environment Configuration

### Security Proxy Settings

| Setting | Test | Demo | Prod |
|---------|------|------|------|
| SESSION_IDLE_TIMEOUT | Disabled | 30 min | 30 min |
| SESSION_BINDING_ENABLED | false | true | true |
| ERROR_SANITIZATION | Passthrough | Sanitize | Sanitize |
| LLM_SANITIZATION | Log only | Sanitize | Sanitize |
| SSRF_VALIDATION | Log only | Block | Block |
| AUDIT_LOG_ENABLED | true | true | true |

### WAF Settings

| Setting | Test | Demo | Prod |
|---------|------|------|------|
| BLOCK_MODE | false (count) | true | true |
| RATE_LIMIT_AUTH | 2000/5min | 1000/5min | 500/5min |
| BOT_CONTROL | false | true | true |
| ATP_ENABLED | false | true | true |

### Database Proxy Settings

| Setting | Test | Demo | Prod |
|---------|------|------|------|
| RLS_ENFORCEMENT | false | true | true |

---

## Deployment

### Container Architecture

```
ECS Cluster
├── Service: coco-security-proxy (2-3 replicas)
│   └── Container: security-proxy
│       ├── Port 8080 (receives from ALB)
│       └── Connects to: Django, Redis, CloudWatch
│
├── Service: coco-api (2-3 replicas)
│   └── Container: django
│       ├── Port 8000 (receives from security-proxy)
│       └── Connects to: db-proxy
│
├── Service: coco-db-proxy (2 replicas)
│   └── Container: db-proxy
│       ├── Port 5432 (receives from Django)
│       └── Connects to: RDS PostgreSQL
│
└── Service: coco-redis
    └── Container: redis (or ElastiCache)
```

### Traffic Flow

```
Internet
  → CloudFront
    → WAF
      → ALB
        → Security Proxy (:8080)
          → Django (:8000)
            → DB Proxy (:5432)
              → PostgreSQL (RDS)
```

### Deployment Order

```bash
# 1. Deploy infrastructure (Terraform)
cd terraform
terraform apply -var-file=environments/prod.tfvars

# 2. Deploy RLS policies (one-time)
psql -f sql/enable_rls.sql

# 3. Deploy Kubernetes security (Helm)
helm install coco-security ./helm/coco-security-policies

# 4. Deploy security proxy
aws ecs update-service --service coco-security-proxy --force-new-deployment

# 5. Deploy Django (unchanged)
aws ecs update-service --service coco-api --force-new-deployment

# 6. Deploy database proxy
aws ecs update-service --service coco-db-proxy --force-new-deployment

# 7. Copy GitHub Actions
cp -r github/workflows/ .github/workflows/
```

---

## Limitations

### What the Wrapper Cannot Do

| Issue | Why | Required Fix |
|-------|-----|--------------|
| **Fernet encryption** | Encryption happens inside Django before any proxy | Change mfa.py, encryption.py |
| **SECRET_KEY fallback** | Code exists in settings.py | Delete line 36 |
| **Chrome extension** | Runs in browser, not server | Fix service-worker.js |
| **Frontend issues** | Build-time, not runtime | Fix source code |

### Operational Considerations

| Consideration | Mitigation |
|---------------|------------|
| Added latency | Proxy adds ~5-10ms; use connection pooling |
| Single point of failure | Run 2-3 proxy replicas with health checks |
| Session store dependency | Use ElastiCache Redis with Multi-AZ |
| Complexity | Centralized security logic easier to audit than scattered code |

### False Positive Risks

| Component | Risk | Mitigation |
|-----------|------|------------|
| LLM sanitization | May escape legitimate content | Allowlist known-good patterns |
| SSRF validation | May block valid internal URLs | Explicit allowlist for integrations |
| WAF rules | May block legitimate requests | Start in count mode, tune rules |

---

## Verification Checklist

### Infrastructure
- [ ] WAF WebACL attached to CloudFront
- [ ] Security headers visible in browser dev tools
- [ ] Secrets in Secrets Manager, not in env vars
- [ ] RDS encryption enabled

### Security Proxy
- [ ] Error responses are generic (test with invalid endpoint)
- [ ] Session expires after idle timeout
- [ ] Session rejects after IP change
- [ ] LLM endpoints receive sanitized input (check logs)
- [ ] Audit logs appear in CloudWatch

### Database Proxy
- [ ] RLS policies exist: `SELECT * FROM pg_policies`
- [ ] Cross-tenant query returns empty (test manually)

### Kubernetes
- [ ] NetworkPolicy blocks inter-pod traffic
- [ ] Pods run as non-root
- [ ] Code validator rejects dangerous imports

### CI/CD
- [ ] Security scan runs on PR
- [ ] Vulnerabilities fail the build

---

## Cost Estimation

| Component | Test | Demo | Prod |
|-----------|------|------|------|
| WAF | $5 | $15 | $50 |
| WAF ATP | - | $10 | $10 |
| Security Proxy (Fargate) | $10 | $30 | $60 |
| DB Proxy (Fargate) | $5 | $15 | $30 |
| Redis (ElastiCache) | $15 | $30 | $60 |
| CloudWatch Logs | $2 | $10 | $30 |
| **Total** | **~$37/mo** | **~$110/mo** | **~$240/mo** |

---

## References

- [AWS WAF Documentation](https://docs.aws.amazon.com/waf/)
- [AWS WAF ATP](https://aws.amazon.com/waf/features/fraud-control/)
- [PostgreSQL Row Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [EKS Network Policies](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html)
- [OWASP Proxy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Proxy_Cheat_Sheet.html)

---

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2026-02-10 | 7.0 | Added AWS CloudFront SaaS Manager for multi-tenant SaaS (10-20x cheaper than Cloudflare Enterprise); clarified Cloudflare is for single-domain only |
| 2026-02-09 | 6.0 | Added Cloudflare as cloud-agnostic alternative to AWS WAF |
| 2026-02-09 | 5.1 | Clarified that both Terraform AND proxy containers are required for full coverage |
| 2026-02-09 | 5.0 | Added generic application support (Lovable, Bolt, etc.) |
| 2026-02-09 | 4.0 | Restructured as wrapper application (proxy-based) |
| 2026-02-09 | 3.0 | Split by tool (Terraform, Python, Helm) |
| 2026-02-09 | 2.0 | Added expanded middleware |
| 2026-02-09 | 1.0 | Initial WAF + headers |
