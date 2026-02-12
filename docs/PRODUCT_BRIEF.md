# Security Wrapper Product Brief

## Product Name: ShieldAI (Working Title)

**Tagline:** Enterprise security for AI-generated apps — no code changes required.

**Version:** 1.0 Draft
**Date:** 2026-02-09
**Jira Project:** [SHIELD](https://quodroid.atlassian.net/jira/software/projects/SHIELD/boards) (12 epics, 21 stories)
**Product Stories:** [SHIELD_AI_PRODUCT_STORIES.md](./SHIELD_AI_PRODUCT_STORIES.md)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Problem Statement](#problem-statement)
3. [Solution Overview](#solution-overview)
4. [Target Market](#target-market)
5. [Product Features](#product-features)
6. [Architecture Design](#architecture-design)
7. [User Experience](#user-experience)
8. [Security Coverage](#security-coverage)
9. [Pricing Strategy](#pricing-strategy)
10. [Competitive Landscape](#competitive-landscape)
11. [Go-to-Market Strategy](#go-to-market-strategy)
12. [Success Metrics](#success-metrics)
13. [Roadmap](#roadmap)
14. [Technical Requirements](#technical-requirements)
15. [Risks and Mitigations](#risks-and-mitigations)

---

## Executive Summary

### What We're Building

A security-as-a-service platform that wraps any web application with enterprise-grade security protections, requiring zero code changes to the target application.

### Why Now

The rise of AI coding assistants (Lovable, Bolt, Cursor, Replit Agent, GPT Engineer) has created a new category of "vibe-coded" applications — functional apps built in hours by non-security-experts. These apps ship with virtually no security, creating massive risk for their users and operators.

### The Opportunity

- 10M+ developers using AI coding tools
- Most AI-generated apps lack basic security (no rate limiting, exposed stack traces, missing headers)
- Traditional security solutions require code changes or security expertise
- Gap in market for "plug and play" security for indie developers and startups

### Value Proposition

| For Developers | For Businesses |
|----------------|----------------|
| Add security in 5 minutes | Reduce breach risk by 70%+ |
| No code changes required | Meet compliance requirements faster |
| Understand security posture | Audit-ready logging out of the box |
| Focus on features, not security | Lower security team burden |

---

## Problem Statement

### The Security Gap in AI-Generated Applications

When developers use AI tools to build applications, security is consistently deprioritized:

**What AI coding tools generate:**
- Functional CRUD operations
- Basic authentication (often insecure)
- Database queries (often vulnerable to injection)
- API endpoints (no rate limiting)
- Error handling (exposes stack traces)

**What AI coding tools DON'T generate:**
- Web Application Firewall rules
- Security headers (HSTS, CSP, X-Frame-Options)
- Rate limiting and DDoS protection
- Session security (timeout, hijacking protection)
- Audit logging
- Input sanitization for LLM prompts
- Error message sanitization

### Real-World Impact

| Vulnerability | Consequence | Frequency in Vibe-Coded Apps |
|--------------|-------------|------------------------------|
| Missing rate limiting | Account takeover via brute force | 95%+ |
| Exposed stack traces | Information disclosure | 90%+ |
| No security headers | Clickjacking, XSS amplification | 85%+ |
| No WAF | SQL injection, XSS | 80%+ |
| No audit logging | Cannot investigate breaches | 95%+ |
| Session never expires | Stolen sessions work forever | 90%+ |

### Why Existing Solutions Don't Work

| Solution | Problem |
|----------|---------|
| Manual code fixes | Requires security expertise developers don't have |
| Security consultants | Expensive ($10K+), slow (weeks), one-time |
| Traditional WAF (AWS, Cloudflare) | Requires configuration expertise |
| SAST/DAST tools | Find problems, don't fix them |
| Security middleware | Requires code changes |

---

## Solution Overview

### Core Concept

A transparent security layer that sits between the internet and any web application, providing instant protection without requiring any changes to the application code.

### How It Works (Simple)

```
Before ShieldAI:
    User → Your App (vulnerable)

After ShieldAI:
    User → ShieldAI → Your App (protected)
```

### How It Works (Technical)

```
┌─────────────────────────────────────────────────────────────────┐
│                         ShieldAI Platform                        │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  Edge Layer  │ →  │ Proxy Layer  │ →  │  Your App    │      │
│  │  (CloudFront │    │  (ShieldAI)  │    │  (Unchanged) │      │
│  │  SaaS Mgr)   │    │              │    │              │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│                                                                  │
│  • WAF Rules          • Error Sanitization  • No changes       │
│  • Rate Limiting      • Session Security    • No SDK           │
│  • Security Headers   • Audit Logging       • No integration   │
│  • Bot Protection     • LLM Sanitization                       │
│  • DDoS Mitigation    • SSRF Protection                        │
└─────────────────────────────────────────────────────────────────┘
```

### Key Differentiators

| Feature | ShieldAI | Traditional WAF | Security Middleware |
|---------|----------|-----------------|---------------------|
| Setup time | 5 minutes | Hours/days | Days/weeks |
| Code changes | None | None | Required |
| Error sanitization | Yes | No | Requires code |
| Session security | Yes | No | Requires code |
| Audit logging | Yes | Partial | Requires code |
| LLM protection | Yes | No | No |
| Expertise required | None | Moderate | High |

---

## Target Market

### Primary Segments

#### Segment 1: Indie Hackers & Solo Developers

**Profile:**
- Building MVPs and side projects
- Using AI coding tools (Lovable, Bolt, Cursor)
- Limited security knowledge
- Price-sensitive

**Pain Points:**
- Know their app is insecure but don't know how to fix it
- Can't afford security consultants
- Don't want to spend time on security instead of features

**Value Proposition:** "Launch secure, even if you're not a security expert"

#### Segment 2: Early-Stage Startups

**Profile:**
- Series Seed to Series A
- Small engineering team (2-10)
- Moving fast, shipping often
- Starting to face security questions from customers/investors

**Pain Points:**
- Enterprise customers asking about SOC 2
- No dedicated security person
- Security debt accumulating rapidly

**Value Proposition:** "Enterprise security without an enterprise security team"

#### Segment 3: Agencies Building for Clients

**Profile:**
- Building apps for multiple clients
- Often using low-code/AI tools for speed
- Responsible for security of client apps
- Need consistent security across projects

**Pain Points:**
- Can't manually secure every client app
- Clients expect security but won't pay for it separately
- Liability risk if client apps get breached

**Value Proposition:** "Secure every client app with one platform"

#### Segment 4: Internal Tool Builders

**Profile:**
- Building internal tools quickly
- Using Retool, Lovable, or custom code
- Less scrutiny than external apps
- Still need basic security

**Pain Points:**
- IT/Security team requires basic protections
- Don't want to slow down internal tool development
- Need audit logs for compliance

**Value Proposition:** "Pass security review without slowing down"

### Market Size Estimation

| Segment | Estimated Size | Potential Revenue |
|---------|---------------|-------------------|
| Indie hackers using AI tools | 2M+ | $20M ARR at $10/mo avg |
| Early-stage startups | 500K+ | $150M ARR at $50/mo avg |
| Agencies | 100K+ | $50M ARR at $50/mo avg |
| Enterprise internal tools | 50K+ | $100M ARR at $200/mo avg |

---

## Product Features

### Feature Matrix by Tier

| Feature | Free | Pro ($29/mo) | Business ($99/mo) | Enterprise |
|---------|------|--------------|-------------------|------------|
| **Edge Security** |
| WAF (SQLi, XSS) | ✅ | ✅ | ✅ | ✅ |
| Security Headers | ✅ | ✅ | ✅ | ✅ |
| Rate Limiting | Basic | Advanced | Custom | Custom |
| Bot Protection | Basic | Enhanced | Advanced | Advanced |
| DDoS Protection | ✅ | ✅ | ✅ | ✅ |
| **Proxy Security** |
| Error Sanitization | ❌ | ✅ | ✅ | ✅ |
| Session Security | ❌ | ✅ | ✅ | ✅ |
| LLM Input Sanitization | ❌ | ✅ | ✅ | ✅ |
| SSRF Protection | ❌ | ✅ | ✅ | ✅ |
| **Observability** |
| Security Dashboard | Basic | Full | Full | Full |
| Audit Logs | 7 days | 30 days | 90 days | 1 year |
| Log Export | ❌ | CSV | API + Webhooks | SIEM Integration |
| Alerting | Email | Email + Slack | + PagerDuty | Custom |
| **Support** |
| Documentation | ✅ | ✅ | ✅ | ✅ |
| Email Support | ❌ | ✅ | ✅ | ✅ |
| Priority Support | ❌ | ❌ | ✅ | ✅ |
| Dedicated CSM | ❌ | ❌ | ❌ | ✅ |
| SLA | ❌ | ❌ | 99.9% | 99.99% |
| **Limits** |
| Requests/month | 100K | 1M | 10M | Unlimited |
| Apps | 1 | 5 | 20 | Unlimited |
| Team members | 1 | 3 | 10 | Unlimited |

### Feature Deep Dives

#### Feature 1: One-Click Security Headers

**What:** Automatically inject security headers into all responses

**Headers Included:**
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

**User Experience:**
1. User enables "Security Headers" toggle
2. ShieldAI injects headers into all responses
3. User can test with securityheaders.com
4. Security score goes from F to A+

**Configurability:**
- Preset modes: Strict, Balanced, Permissive
- Custom CSP builder for advanced users
- Report-only mode for testing

#### Feature 2: Intelligent Rate Limiting

**What:** Automatically detect and protect sensitive endpoints

**How It Works:**
1. ShieldAI analyzes URL patterns
2. Automatically identifies auth endpoints (/login, /signup, /api/auth/*)
3. Applies stricter rate limits to sensitive endpoints
4. Global rate limit for all other traffic

**Default Configuration:**
| Endpoint Type | Rate Limit |
|--------------|------------|
| Login/Auth | 10 req/min per IP |
| Password Reset | 3 req/min per IP |
| API General | 100 req/min per IP |
| Global | 1000 req/min per IP |

**User Experience:**
- Auto-detection means zero configuration for most apps
- Dashboard shows rate limit hits
- Alerts when thresholds are frequently triggered
- Easy override for specific endpoints

#### Feature 3: Error Sanitization

**What:** Replace error responses with generic messages, log original errors securely

**Problem Solved:**
```
Before: {"error": "psycopg2.OperationalError: connection to database 'prod_db' at '10.0.1.5:5432' failed"}

After: {"error": "An error occurred. Reference: err_a1b2c3d4"}
```

**How It Works:**
1. Proxy intercepts all responses
2. Detects error responses (4xx, 5xx status codes)
3. Scans body for sensitive patterns (stack traces, file paths, DB errors)
4. Replaces with generic message + error reference ID
5. Logs original error with reference ID for debugging

**User Experience:**
- Developer can search error reference ID in dashboard
- See full original error, stack trace, request context
- Users see clean, professional error messages

#### Feature 4: Session Security

**What:** Add session timeout and hijacking protection without code changes

**Capabilities:**
- Idle timeout (configurable, default 30 min)
- Absolute timeout (configurable, default 24 hours)
- IP binding (optional, alert or block on IP change)
- User-Agent binding (optional)
- Concurrent session limits

**How It Works:**
1. ShieldAI manages sessions in Redis (separate from app sessions)
2. Validates ShieldAI session on each request
3. If invalid, returns 401 before request reaches app
4. Updates session activity timestamp on each request

**User Experience:**
- Enable with one toggle
- Configure timeouts via slider
- View active sessions in dashboard
- Force logout capability for all sessions

#### Feature 5: Audit Logging

**What:** Comprehensive, structured audit logs for all requests

**What's Logged:**
| Field | Description |
|-------|-------------|
| timestamp | ISO 8601 timestamp |
| request_id | Unique request identifier |
| method | HTTP method |
| path | Request path |
| status | Response status code |
| duration_ms | Response time |
| client_ip | Client IP address |
| user_agent | Client user agent |
| country | GeoIP country |
| user_id | User ID (if authenticated) |
| action | Detected action type (login, logout, etc.) |
| blocked | Whether request was blocked |
| block_reason | Why request was blocked |

**User Experience:**
- Search and filter logs in dashboard
- Export to CSV, JSON
- Webhook integration for real-time streaming
- SIEM integration (Splunk, Datadog, etc.) for Enterprise

#### Feature 6: LLM Input Sanitization

**What:** Detect and neutralize prompt injection attempts

**How It Works:**
1. User configures which endpoints accept LLM-bound input
2. ShieldAI scans request bodies for injection patterns
3. Detected patterns are escaped or flagged
4. Clean input passed to application

**Detection Patterns:**
- Instruction override attempts ("ignore previous instructions")
- Role manipulation ("you are now")
- Output extraction ("reveal your system prompt")
- Encoding bypass attempts (base64, unicode)

**User Experience:**
- Configure protected endpoints in dashboard
- View blocked/modified requests
- Tune sensitivity (strict, moderate, permissive)
- Allowlist specific patterns

#### Feature 7: Security Score & Recommendations

**What:** Gamified security posture assessment

**How It Works:**
1. ShieldAI analyzes enabled features and configuration
2. Computes security score (0-100)
3. Provides actionable recommendations to improve score

**Score Components:**
| Category | Max Points |
|----------|------------|
| Edge Security (WAF, headers) | 25 |
| Rate Limiting | 15 |
| Error Handling | 15 |
| Session Security | 15 |
| Audit Logging | 15 |
| Advanced (LLM, SSRF) | 15 |

**User Experience:**
- Dashboard shows current score prominently
- Recommendations sorted by impact
- One-click enable for most recommendations
- Score history over time

---

## Architecture Design

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER'S BROWSER                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ HTTPS
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AWS CLOUDFRONT SAAS MANAGER                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │              Multi-Tenant Distribution + WAF WebACL                  │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │    │
│  │  │  CDN Edge   │  │  WAF Rules  │  │  Response   │                  │    │
│  │  │  (400+ PoPs)│  │  (inherited)│  │  Headers    │                  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                  │    │
│  │                                                                      │    │
│  │  Distribution Tenants: customer1.com, customer2.com, ...            │    │
│  │  Managed by: ShieldAI Terraform/API                                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ HTTPS (origin pull)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SHIELDAI PROXY CLUSTER                               │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    Load Balancer (Regional)                          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                          │              │              │                     │
│                          ▼              ▼              ▼                     │
│                   ┌──────────┐   ┌──────────┐   ┌──────────┐               │
│                   │  Proxy   │   │  Proxy   │   │  Proxy   │               │
│                   │ Instance │   │ Instance │   │ Instance │               │
│                   └──────────┘   └──────────┘   └──────────┘               │
│                          │              │              │                     │
│                          └──────────────┼──────────────┘                     │
│                                         │                                    │
│                                         ▼                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      Shared Services                                 │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │    │
│  │  │    Redis    │  │  PostgreSQL │  │    Kafka    │                  │    │
│  │  │  (Sessions) │  │   (Config)  │  │   (Logs)    │                  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ HTTPS (to customer origin)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CUSTOMER'S APPLICATION                                  │
│                                                                              │
│                    (Vercel, Railway, Render, AWS, etc.)                     │
│                                                                              │
│                           ┌──────────────┐                                  │
│                           │   App Origin │                                  │
│                           │              │                                  │
│                           │  Unchanged   │                                  │
│                           │  No SDK      │                                  │
│                           │  No Config   │                                  │
│                           └──────────────┘                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Details

#### Component: AWS CloudFront SaaS Manager (Edge)

**Responsibilities:**
- CDN and edge caching (400+ PoPs globally)
- TLS termination
- WAF rule enforcement (inherited by all tenants)
- Rate limiting (edge)
- Bot detection (AWS Bot Control)
- DDoS mitigation (AWS Shield Standard)
- Security header injection (Response Headers Policy)

**Configuration:**
- Managed via AWS API/Terraform by ShieldAI control plane
- Multi-tenant distribution defines shared WAF, headers, and behaviors
- Each customer domain is a "distribution tenant" that inherits all protections
- Customer onboarding creates new tenant via API

**Why AWS CloudFront SaaS Manager:**
- **WAF inheritance**: All tenants automatically get WAF protection from template
- **10-20x cheaper** than Cloudflare Enterprise for multi-tenant SaaS (~$100/mo vs $3,000+/mo)
- Global edge network (400+ locations)
- Pay-per-use pricing (first 200 tenants free, then $0.10/tenant)
- Full API automation via AWS SDK/Terraform
- ACM provides free SSL certificates for all customer domains

**Why NOT Cloudflare for Multi-Tenant SaaS:**
- Cloudflare's "WAF for SaaS" (applying WAF to custom hostnames) requires Enterprise tier
- Enterprise starts at $3,000+/month
- Pro/Business plans only provide SSL and DDoS for custom hostnames, NOT WAF rules

#### Component: Security Proxy

**Responsibilities:**
- Request inspection and sanitization
- Response inspection and sanitization
- Session management
- Audit logging
- LLM input filtering
- SSRF validation

**Technology Choices:**
| Aspect | Choice | Rationale |
|--------|--------|-----------|
| Language | Go or Rust | Performance critical, low latency |
| Framework | Custom or Pingora | Reverse proxy optimized |
| Deployment | Kubernetes | Auto-scaling, multi-region |
| Protocol | HTTP/2, HTTP/3 | Performance |

**Scaling Model:**
- Horizontal scaling based on request rate
- Regional deployment (US, EU, APAC initially)
- Automatic failover between regions
- Target: <10ms added latency p99

#### Component: Session Store (Redis)

**Responsibilities:**
- Store active sessions
- Session lookup on every request
- Session invalidation
- Rate limit counters (backup to Cloudflare)

**Architecture:**
- Redis Cluster for HA
- Multi-region replication
- Automatic failover

**Data Model:**
```
session:{customer_id}:{session_token}
├── user_id (string)
├── created_at (timestamp)
├── last_activity (timestamp)
├── ip (string)
├── user_agent (string)
├── fingerprint (hash)
└── TTL: max_session_duration
```

#### Component: Configuration Store (PostgreSQL)

**Responsibilities:**
- Customer configuration
- Feature flags
- Billing state
- Team/user data

**Data Model:**
```
customers
├── id
├── name
├── plan
├── created_at
└── settings (JSONB)

apps
├── id
├── customer_id
├── name
├── origin_url
├── cloudflare_zone_id
├── enabled_features
└── settings (JSONB)

team_members
├── id
├── customer_id
├── email
├── role
└── created_at
```

#### Component: Log Pipeline (Kafka → ClickHouse)

**Responsibilities:**
- Ingest audit logs from all proxy instances
- Buffer for reliability
- Stream to storage and analytics

**Pipeline:**
```
Proxy → Kafka → ClickHouse (analytics)
                     ↓
              → S3 (long-term storage)
                     ↓
              → Customer webhooks (real-time)
```

**Why ClickHouse:**
- Columnar storage ideal for log analytics
- Excellent compression
- Fast aggregation queries
- Cost-effective at scale

### Request Flow

```
1. User makes request to app.customer.com
                    │
2. DNS resolves to CloudFront distribution tenant
                    │
3. CloudFront + WAF applies (inherited from multi-tenant distribution):
   ├── WAF rules (block if malicious)
   ├── Rate limiting (block if exceeded)
   ├── Bot detection (challenge if suspicious)
   └── Pass to origin (ShieldAI proxy)
                    │
4. ShieldAI Proxy - Request Pipeline:
   ├── Parse request
   ├── Lookup customer config
   ├── Validate session (if enabled)
   │   ├── Check session exists
   │   ├── Check idle timeout
   │   └── Check IP/UA binding
   ├── Sanitize request (if configured)
   │   ├── LLM endpoints: escape injection patterns
   │   └── URL fields: validate against SSRF
   ├── Add context headers (X-Request-ID, etc.)
   └── Forward to customer origin
                    │
5. Customer app processes request
                    │
6. Customer app returns response
                    │
7. ShieldAI Proxy - Response Pipeline:
   ├── Check status code
   ├── If error: sanitize response body
   ├── Inject security headers (if not from edge)
   ├── Log request/response metadata
   ├── Update session last_activity
   └── Return response
                    │
8. CloudFront caches (if applicable) and returns to user
```

### Multi-Tenancy Design

**Isolation Model:**
- Logical isolation (shared infrastructure, isolated data)
- Each customer has unique identifiers
- All data tagged with customer_id
- Query filters enforce isolation

**Resource Limits:**
- Rate limits enforced per customer
- Proxy CPU/memory limits via Kubernetes
- Log storage quotas per plan
- Session storage limits

**Security Boundaries:**
- CloudFront distribution tenants are per-customer
- WAF and headers inherited from shared multi-tenant distribution
- Customer configs never cross-reference
- Logs partitioned by customer
- API authentication per customer

### Disaster Recovery

| Component | RPO | RTO | Strategy |
|-----------|-----|-----|----------|
| CloudFront | 0 | 0 | Multi-region by design (400+ PoPs) |
| Proxy | 0 | <1min | K8s auto-restart, multi-region |
| Redis | <1sec | <1min | Cluster replication |
| PostgreSQL | <1min | <5min | Streaming replication |
| ClickHouse | <5min | <15min | Replicated tables |

---

## User Experience

### Onboarding Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     Step 1: Sign Up                             │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                                                          │    │
│  │   Create your ShieldAI account                          │    │
│  │                                                          │    │
│  │   Email:     [________________________]                  │    │
│  │   Password:  [________________________]                  │    │
│  │                                                          │    │
│  │   [  Sign up with Google  ]                             │    │
│  │   [  Sign up with GitHub  ]                             │    │
│  │                                                          │    │
│  │                      [ Continue → ]                      │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Step 2: Add Your App                          │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                                                          │    │
│  │   What's your app's URL?                                │    │
│  │                                                          │    │
│  │   [  https://my-app.vercel.app  ]                       │    │
│  │                                                          │    │
│  │   We'll protect this origin. Your users will access     │    │
│  │   your app through your custom domain.                  │    │
│  │                                                          │    │
│  │                      [ Continue → ]                      │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Step 3: Configure Domain                       │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                                                          │    │
│  │   How do you want to connect?                           │    │
│  │                                                          │    │
│  │   ○ I have a custom domain (app.mycompany.com)          │    │
│  │     → Update your DNS to point to ShieldAI              │    │
│  │                                                          │    │
│  │   ○ Use a ShieldAI subdomain (myapp.shield.ai)          │    │
│  │     → Instant setup, upgrade to custom domain anytime   │    │
│  │                                                          │    │
│  │                      [ Continue → ]                      │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Step 4: DNS Setup                            │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                                                          │    │
│  │   Update your DNS records:                              │    │
│  │                                                          │    │
│  │   ┌───────────────────────────────────────────────┐     │    │
│  │   │ Type   Name              Value                │     │    │
│  │   │ CNAME  app.mycompany.com proxy.shieldai.com  │     │    │
│  │   └───────────────────────────────────────────────┘     │    │
│  │                                                          │    │
│  │   [Copy to clipboard]                                   │    │
│  │                                                          │    │
│  │   Waiting for DNS propagation...  ⏳                    │    │
│  │                                                          │    │
│  │   [ Check DNS ]     [ I'll do this later ]              │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Step 5: Enable Protections                      │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                                                          │    │
│  │   Your app is connected! Enable protections:            │    │
│  │                                                          │    │
│  │   ┌─────────────────────────────────────────────┐       │    │
│  │   │ ☑ WAF (SQL injection, XSS)        [Enabled] │       │    │
│  │   │ ☑ Security Headers                [Enabled] │       │    │
│  │   │ ☑ Rate Limiting                   [Enabled] │       │    │
│  │   │ ☐ Error Sanitization              [Pro]     │       │    │
│  │   │ ☐ Session Security                [Pro]     │       │    │
│  │   │ ☐ Audit Logging                   [Pro]     │       │    │
│  │   └─────────────────────────────────────────────┘       │    │
│  │                                                          │    │
│  │   Security Score: 65/100  ████████░░░                   │    │
│  │                                                          │    │
│  │          [ Go to Dashboard → ]                          │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Dashboard Design

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ShieldAI                                    [Settings] [Docs] [Account ▼] │
├────────────────┬────────────────────────────────────────────────────────────┤
│                │                                                            │
│  📊 Overview   │   MY-APP.COM                                              │
│                │   ─────────────────────────────────────────────────────   │
│  🛡️ Security  │                                                            │
│    ├ WAF       │   SECURITY SCORE                    TRAFFIC (24h)         │
│    ├ Headers   │   ┌─────────────────┐              ┌─────────────────┐    │
│    ├ Rate Limit│   │                 │              │                 │    │
│    └ Sessions  │   │      78/100     │              │   45.2K requests│    │
│                │   │    ████████░░   │              │   ▂▃▅▇▆▅▃▂▃▅   │    │
│  📝 Logs       │   │                 │              │                 │    │
│    ├ Requests  │   │  +12 from last  │              │  +15% from      │    │
│    └ Audit     │   │     week        │              │     yesterday   │    │
│                │   └─────────────────┘              └─────────────────┘    │
│  ⚠️ Alerts     │                                                            │
│                │   BLOCKED THREATS (24h)            TOP RECOMMENDATIONS    │
│  ⚙️ Settings   │   ┌─────────────────┐              ┌─────────────────┐    │
│                │   │ SQLi attempts: 23│              │ ⚡ Enable Error │    │
│  📖 Docs       │   │ XSS attempts: 12 │              │    Sanitization │    │
│                │   │ Rate limited: 156│              │    +15 points   │    │
│                │   │ Bot blocked: 89  │              │                 │    │
│                │   └─────────────────┘              │ ⚡ Enable Session│    │
│                │                                     │    Security     │    │
│                │   RECENT ACTIVITY                   │    +10 points   │    │
│                │   ┌─────────────────────────────┐   └─────────────────┘    │
│                │   │ 2m ago  POST /api/login     │                         │
│                │   │         Rate limited (5th)  │                         │
│                │   │ 5m ago  GET /admin          │                         │
│                │   │         WAF blocked (SQLi)  │                         │
│                │   │ 12m ago POST /api/users     │                         │
│                │   │         200 OK              │                         │
│                │   └─────────────────────────────┘                         │
│                │                                                            │
└────────────────┴────────────────────────────────────────────────────────────┘
```

### Key Screens

1. **Overview Dashboard** - Security score, traffic stats, recent threats
2. **WAF Settings** - Enable/disable rules, view blocked requests
3. **Security Headers** - Configure headers, preview, test
4. **Rate Limiting** - Set limits by endpoint pattern
5. **Session Security** - Configure timeouts, binding options
6. **Audit Logs** - Search, filter, export logs
7. **Alerts** - Configure alert rules, view history
8. **Settings** - Team management, billing, API keys

---

## Security Coverage

### What ShieldAI Protects Against

| Threat | Protection | Layer |
|--------|------------|-------|
| SQL Injection | WAF rules detect and block SQLi patterns | Edge |
| Cross-Site Scripting (XSS) | WAF rules + CSP header | Edge |
| Clickjacking | X-Frame-Options header | Edge |
| MIME Sniffing | X-Content-Type-Options header | Edge |
| Man-in-the-Middle | HSTS header + TLS enforcement | Edge |
| DDoS | Cloudflare DDoS mitigation | Edge |
| Brute Force | Rate limiting on auth endpoints | Edge + Proxy |
| Credential Stuffing | Rate limiting + bot detection | Edge |
| Information Disclosure | Error sanitization | Proxy |
| Session Hijacking | IP/UA binding, timeout | Proxy |
| Session Fixation | Secure session management | Proxy |
| Prompt Injection | LLM input sanitization | Proxy |
| SSRF | URL validation | Proxy |

### What ShieldAI Cannot Protect Against

| Threat | Why | Recommendation |
|--------|-----|----------------|
| Broken Access Control | App-specific authorization logic | Implement proper RBAC in app |
| IDOR | App must verify resource ownership | Add ownership checks in app |
| Business Logic Flaws | App-specific rules | Manual code review |
| Insecure Dependencies | In app's supply chain | Use CI/CD scanning (feature roadmap) |
| Hardcoded Secrets | Already in source code | Use secret scanning tools |
| Weak Passwords | User-chosen passwords | Implement password policies in app |
| Insecure Data Storage | App database design | Encrypt sensitive fields in app |

### OWASP Top 10 Coverage

| # | Category | Coverage | Notes |
|---|----------|----------|-------|
| A01 | Broken Access Control | ❌ Partial | Rate limiting helps, but app must implement authz |
| A02 | Cryptographic Failures | ✅ Partial | HTTPS enforced, HSTS enabled; app handles data encryption |
| A03 | Injection | ✅ Yes | WAF blocks SQLi, XSS, command injection |
| A04 | Insecure Design | ❌ No | Architectural, must be addressed in app |
| A05 | Security Misconfiguration | ✅ Yes | Headers, TLS, defaults secured |
| A06 | Vulnerable Components | ❌ No | App dependency; CI/CD integration planned |
| A07 | Auth Failures | ✅ Partial | Rate limiting, session security; app handles auth logic |
| A08 | Data Integrity Failures | ❌ Partial | SRI headers can help; app handles data validation |
| A09 | Logging Failures | ✅ Yes | Comprehensive audit logging |
| A10 | SSRF | ✅ Yes | URL validation in proxy |

**Overall OWASP Coverage: ~60-70%** of categories have meaningful protection.

---

## Pricing Strategy

### Pricing Philosophy

1. **Free tier must be genuinely useful** - Edge security alone provides significant value
2. **Pro tier for serious side projects** - $29/mo is approachable for indie hackers
3. **Business tier for startups** - $99/mo is negligible vs. security consultant costs
4. **Enterprise for compliance-heavy** - Custom pricing for large deployments

### Price Points

| Tier | Monthly | Annual (20% off) | Target Segment |
|------|---------|------------------|----------------|
| Free | $0 | - | Hobbyists, evaluation |
| Pro | $29 | $279/yr | Indie hackers, serious side projects |
| Business | $99 | $949/yr | Startups, small businesses |
| Enterprise | Custom | Custom | Larger companies, agencies |

### Revenue Model

**Assumptions:**
- 10,000 signups in Year 1
- 5% convert to Pro: 500 × $29 = $14,500/mo
- 2% convert to Business: 200 × $99 = $19,800/mo
- 0.2% convert to Enterprise: 20 × $300 avg = $6,000/mo

**Year 1 MRR Target:** $40,000/mo = $480,000 ARR

### Upsell Triggers

| From | To | Trigger |
|------|-----|---------|
| Free | Pro | Hits request limit, wants error sanitization |
| Pro | Business | Needs more apps, longer log retention, team access |
| Business | Enterprise | Needs SLA, SIEM integration, dedicated support |

---

## Competitive Landscape

### Direct Competitors

| Competitor | Focus | Strengths | Weaknesses |
|------------|-------|-----------|------------|
| Cloudflare | Edge security | Global network, DDoS | No error sanitization, no session security |
| AWS WAF | Edge security | AWS integration | Complex, AWS-only, no proxy features |
| Imperva | Enterprise WAF | Comprehensive | Expensive, complex, enterprise-focused |
| StackHawk | DAST/API security | Good testing | Finds issues, doesn't fix them |
| Snyk | App security | Comprehensive platform | Developer tool, not runtime protection |

### Competitive Positioning

```
                    High Touch / Enterprise
                           │
            Imperva   ●    │
                           │
                           │    ● ShieldAI (Business/Enterprise)
    Expensive ─────────────┼─────────────── Affordable
                           │
         AWS WAF  ●        │    ● ShieldAI (Pro)
                           │
            Cloudflare ●   │    ● ShieldAI (Free)
                           │
                    Self-Service / SMB
```

### Why ShieldAI Wins

| vs. Cloudflare | vs. AWS WAF | vs. Imperva |
|----------------|-------------|-------------|
| +Error sanitization | +Cloud agnostic | +10x cheaper |
| +Session security | +Much simpler | +Self-service |
| +LLM protection | +Better UX | +5 min setup |
| +Opinionated defaults | +Proxy features | +Indie friendly |

---

## Go-to-Market Strategy

### Phase 1: Developer Community (Months 1-6)

**Goals:**
- 10,000 signups
- 500 paying customers
- Establish brand in indie hacker community

**Tactics:**
1. **Content Marketing**
   - "Security checklist for Lovable apps"
   - "Why your AI-generated app is vulnerable"
   - "From F to A+ security score in 5 minutes"

2. **Community Presence**
   - Indie Hackers
   - r/SideProject, r/startups
   - Twitter/X (tech twitter)
   - Hacker News Show HN

3. **Integrations**
   - Lovable partnership/listing
   - Vercel integration
   - Railway integration

4. **Product-Led Growth**
   - Free tier with real value
   - Shareable security score badges
   - "Protected by ShieldAI" footer (optional)

### Phase 2: Startup Market (Months 6-12)

**Goals:**
- 50,000 signups
- 2,000 paying customers
- $50K MRR

**Tactics:**
1. **Case Studies** - "How [Startup] passed SOC 2 faster with ShieldAI"
2. **Compliance Features** - Log export, SIEM integration
3. **Partnerships** - Accelerators, VC portfolio perks
4. **Sales-Assisted** - Outbound for Business/Enterprise

### Phase 3: Scale (Year 2+)

**Goals:**
- $500K MRR
- Enterprise logos
- Platform ecosystem

**Tactics:**
1. **Enterprise Features** - SSO, custom contracts, SLAs
2. **Channel Partnerships** - MSPs, security consultants
3. **API Platform** - Let others build on ShieldAI
4. **Geographic Expansion** - EU, APAC presence

---

## Success Metrics

### North Star Metric

**Protected Requests per Month** - Total requests processed through ShieldAI

Why: Measures real usage and value delivered, regardless of pricing tier.

### Key Metrics by Category

#### Acquisition
| Metric | Target (Month 6) |
|--------|-----------------|
| Monthly signups | 2,000 |
| Activation rate (add 1 app) | 60% |
| Traffic source diversity | No source >40% |

#### Engagement
| Metric | Target (Month 6) |
|--------|-----------------|
| Weekly active customers | 70% |
| Features enabled (avg) | 4+ |
| Dashboard visits/week | 2+ |

#### Revenue
| Metric | Target (Month 6) |
|--------|-----------------|
| MRR | $20,000 |
| Free to Paid conversion | 5% |
| Net Revenue Retention | >100% |

#### Product
| Metric | Target |
|--------|--------|
| Onboarding completion | >80% |
| P99 latency added | <15ms |
| Uptime | 99.9% |

---

## Roadmap

### Phase 1: MVP (Months 1-3)

**Goal:** Validate core value proposition with edge security + basic proxy

| Feature | Priority | Status |
|---------|----------|--------|
| Cloudflare integration | P0 | 🔲 |
| WAF managed rules | P0 | 🔲 |
| Security headers | P0 | 🔲 |
| Basic rate limiting | P0 | 🔲 |
| Error sanitization | P0 | 🔲 |
| Dashboard v1 | P0 | 🔲 |
| User auth (Clerk/Auth0) | P0 | 🔲 |
| Stripe billing | P1 | 🔲 |

### Phase 2: Core Features (Months 4-6)

**Goal:** Complete proxy feature set, launch Pro tier

| Feature | Priority | Status |
|---------|----------|--------|
| Session security | P0 | 🔲 |
| Audit logging | P0 | 🔲 |
| LLM input sanitization | P1 | 🔲 |
| SSRF protection | P1 | 🔲 |
| Advanced rate limiting | P1 | 🔲 |
| Security score | P1 | 🔲 |
| Alert system | P2 | 🔲 |

### Phase 3: Growth Features (Months 7-12)

**Goal:** Enable Business tier, expand market

| Feature | Priority | Status |
|---------|----------|--------|
| Team management | P0 | 🔲 |
| Log export (CSV, API) | P0 | 🔲 |
| Webhook integrations | P1 | 🔲 |
| Custom rules builder | P1 | 🔲 |
| API for automation | P1 | 🔲 |
| Vercel/Railway integrations | P2 | 🔲 |
| SOC 2 report | P2 | 🔲 |

### Phase 4: Enterprise (Year 2)

| Feature | Priority |
|---------|----------|
| SSO (SAML, OIDC) | P0 |
| SIEM integration | P0 |
| Custom domains at scale | P1 |
| SLA dashboard | P1 |
| Advanced bot management | P2 |
| CI/CD security scanning | P2 |

---

## Technical Requirements

### Infrastructure

| Component | Requirement |
|-----------|-------------|
| Proxy servers | Kubernetes cluster, auto-scaling |
| Database | PostgreSQL (managed) |
| Cache | Redis Cluster (managed) |
| Log storage | ClickHouse or similar |
| CDN/WAF | Cloudflare (API access) |
| Monitoring | Prometheus + Grafana |
| Alerting | PagerDuty or similar |

### Performance Requirements

| Metric | Target |
|--------|--------|
| Added latency (p50) | <5ms |
| Added latency (p99) | <15ms |
| Uptime | 99.9% |
| Time to first byte | <100ms |

### Security Requirements

| Requirement | Implementation |
|-------------|----------------|
| Data encryption at rest | AES-256 |
| Data encryption in transit | TLS 1.3 |
| Secret management | HashiCorp Vault or cloud KMS |
| Access control | RBAC + audit logging |
| Penetration testing | Annual third-party pentest |
| SOC 2 Type II | Year 1 goal |

### Compliance

| Standard | Timeline |
|----------|----------|
| SOC 2 Type I | Month 9 |
| SOC 2 Type II | Month 15 |
| GDPR compliance | Launch |
| CCPA compliance | Launch |

---

## Risks and Mitigations

### Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Proxy latency too high | High | Medium | Optimize early, set strict targets, multi-region |
| Cloudflare API limits | High | Low | Negotiate enterprise terms, cache aggressively |
| False positives block legitimate traffic | High | Medium | Start permissive, tune rules, easy bypass |
| Data breach | Critical | Low | Encrypt everything, pentest, SOC 2 |

### Business Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Cloudflare builds same features | High | Medium | Differentiate on UX, proxy features |
| Low conversion rate | High | Medium | Iterate on value prop, pricing |
| Enterprise sales cycle too long | Medium | High | Focus on self-service first |
| AI coding tools add security | High | Low | They haven't yet, we move faster |

### Operational Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Support overwhelm | Medium | Medium | Good docs, community forum, tier support |
| Scaling challenges | High | Medium | Over-provision early, load test |
| Key person dependency | High | Medium | Document everything, cross-train |

---

## Appendix

### Glossary

| Term | Definition |
|------|------------|
| WAF | Web Application Firewall |
| HSTS | HTTP Strict Transport Security |
| CSP | Content Security Policy |
| OWASP | Open Web Application Security Project |
| SQLi | SQL Injection |
| XSS | Cross-Site Scripting |
| SSRF | Server-Side Request Forgery |
| LLM | Large Language Model |
| IDOR | Insecure Direct Object Reference |
| SOC 2 | Service Organization Control 2 |

### References

- OWASP Top 10: https://owasp.org/Top10/
- Cloudflare API: https://developers.cloudflare.com/api/
- Security Headers: https://securityheaders.com/
- SOC 2 Compliance: https://www.aicpa.org/soc2

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.1 | 2026-02-10 | Claude | Changed edge provider from Cloudflare to AWS CloudFront SaaS Manager for multi-tenant support at 10-20x lower cost |
| 1.0 | 2026-02-09 | Claude | Initial draft |
