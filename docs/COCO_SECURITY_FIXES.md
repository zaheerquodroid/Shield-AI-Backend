# Coco TestAI — Application-Specific Security Fixes

**Jira Project:** [CSEC](https://quodroid.atlassian.net/jira/software/projects/CSEC/boards/133) (epics labeled `coco-specific`)
**Jira Filter:** `project = CSEC AND labels = coco-specific`
**Date:** February 2026
**Source:** [SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md)
**Repo:** `coco-testai-with-copilot-engine`, `coco-testai-webapp`, `coco-testai-chrome-extension`
**Total Estimated Effort:** ~93 hours

---

## Context

These are security fixes that **require changes to Coco TestAI application code** and cannot be handled by the Shield AI wrapper product. They were identified in the original security audit alongside wrapper-solvable issues.

For the wrapper-solvable issues (rate limiting, error sanitization, security headers, session management, audit logging, LLM protection, RLS, secrets, K8s hardening, CI/CD, SBOM, and documentation), see **[SHIELD_AI_PRODUCT_STORIES.md](./SHIELD_AI_PRODUCT_STORIES.md)**.

### Why These Require Code Changes

| Category | Reason Wrapper Can't Help |
|----------|--------------------------|
| Secure defaults (Epic 1) | Settings live inside Django's `settings.py` — wrapper mitigates impact but best practice is to fix the source |
| Encryption upgrade (Epic 3) | Encryption happens inside Django before any proxy sees the data |
| Chrome extension (Epic 12) | Runs in the browser, completely outside the HTTP proxy model |
| Frontend hardening (Epic 13) | Build-time code changes to React source |
| GDPR endpoints (Epic 16) | Requires app-specific database queries for data export/deletion |

### Mitigation by Shield AI Wrapper

Even without these fixes, the Shield AI wrapper significantly reduces risk:

| Epic | Risk Without Wrapper | Risk With Wrapper (no code fix) |
|------|---------------------|--------------------------------|
| Epic 1: Secure Defaults | **Critical** — DEBUG=True exposes stack traces, ALLOWED_HOSTS=* allows host header injection | **Low** — Proxy sanitizes errors, edge injects headers, proxy manages sessions |
| Epic 3: Encryption | **High** — Fernet is weaker than AES-256-GCM | **Medium** — Fernet is still functional encryption, just not best practice |
| Epic 12: Chrome Extension | **Medium** — Auth tokens readable by other extensions | **Medium** — Wrapper has no impact on extension security |
| Epic 13: Frontend | **Low** — Console logs and VITE_USER_ID are minor issues | **Low** — Wrapper has no impact on frontend code |
| Epic 16: GDPR | **Medium** — No data export/deletion API | **Low** — Audit logging from wrapper covers most compliance needs |

---

## Table of Contents

- [CSEC-1: Secure Default Configuration](#csec-1-secure-default-configuration)
- [CSEC-3: Encryption Upgrade](#csec-3-encryption-upgrade)
- [CSEC-12: Chrome Extension Security](#csec-12-chrome-extension-security)
- [CSEC-13: Frontend Security Hardening](#csec-13-frontend-security-hardening)
- [CSEC-16: GDPR Data Subject Rights](#csec-16-gdpr-data-subject-rights)
- [Effort Summary](#effort-summary)

---

## CSEC-1: Secure Default Configuration

**Jira:** [CSEC-1](https://quodroid.atlassian.net/browse/CSEC-1) | Labels: `coco-specific`, `mitigated-by-shield`
**Priority:** P0 — Critical (but largely mitigated by wrapper)
**Audit Ref:** Sections 3, 12, A2
**Repo:** `coco-testai-with-copilot-engine`
**Wrapper Mitigation:** High — proxy sanitizes errors regardless of DEBUG, injects headers regardless of Django config

---

### CSEC-18: Remove hardcoded SECRET_KEY fallback

**As a** security engineer, **I want** the application to fail loudly if `SECRET_KEY` is not set via environment variable, **so that** a known insecure key is never used in production.

**Acceptance Criteria:**
- Application raises `ImproperlyConfigured` on startup if `SECRET_KEY` env var is missing.
- No hardcoded key exists anywhere in `settings.py`.
- `.env.example` includes a placeholder with generation instructions.

**Tasks:**

| # | Task | File | Effort |
|---|------|------|--------|
| 1.1.1 | Remove the default value from `SECRET_KEY = os.getenv('SECRET_KEY', '...')` in `settings.py:36`. Replace with: `SECRET_KEY = os.environ['SECRET_KEY']` wrapped in try/except that raises `ImproperlyConfigured`. | `copilot_orchestrator/settings.py:36` | 1h |
| 1.1.2 | Update `.env.example`, `.env.dev.example`, `.env.prod.example` to include `SECRET_KEY=` with generation instructions. | `.env.example` files | 0.5h |
| 1.1.3 | Verify all team members' local `.env` files have `SECRET_KEY` set. | Documentation | 0.5h |

**Total Effort:** 2 hours

---

### CSEC-19: Change DEBUG to default False

**As a** security engineer, **I want** `DEBUG` to default to `False`, **so that** a missing environment variable in production never exposes stack traces.

**Tasks:**

| # | Task | File | Effort |
|---|------|------|--------|
| 1.2.1 | Change `settings.py:39` from `DEBUG = os.getenv('DEBUG', 'True') == 'True'` to `DEBUG = os.getenv('DEBUG', 'False') == 'True'`. | `copilot_orchestrator/settings.py:39` | 0.5h |
| 1.2.2 | Ensure `.env.dev.example` has `DEBUG=True` and `.env.prod.example` has `DEBUG=False`. | `.env` files | 0.5h |
| 1.2.3 | Test startup with and without the `DEBUG` env var. | Manual testing | 0.5h |

**Total Effort:** 1.5 hours

---

### CSEC-20: Change ALLOWED_HOSTS to default empty

**As a** security engineer, **I want** `ALLOWED_HOSTS` to default to an empty list, **so that** a missing environment variable does not allow Host header injection.

**Tasks:**

| # | Task | File | Effort |
|---|------|------|--------|
| 1.3.1 | Change `settings.py:41` from `os.getenv('ALLOWED_HOSTS', '*').split(',')` to `os.getenv('ALLOWED_HOSTS', '').split(',') if os.getenv('ALLOWED_HOSTS') else []`. | `copilot_orchestrator/settings.py:41` | 0.5h |
| 1.3.2 | Update `.env.dev.example` with `ALLOWED_HOSTS=localhost,127.0.0.1,host.minikube.internal`. | `.env.dev.example` | 0.5h |
| 1.3.3 | Test locally with and without `ALLOWED_HOSTS` env var. | Manual testing | 0.5h |

**Total Effort:** 1.5 hours

---

## CSEC-3: Encryption Upgrade

**Jira:** [CSEC-3](https://quodroid.atlassian.net/browse/CSEC-3) | Labels: `coco-specific`, `code-change-required`
**Priority:** P0 — Critical
**Audit Ref:** Section 2
**Repo:** `coco-testai-with-copilot-engine`
**Wrapper Mitigation:** None — encryption is internal to the application

---

### Story 3.1: Upgrade encryption from Fernet to AES-256-GCM

**As a** platform operator, **I want** all data encrypted at rest to use AES-256-GCM, **so that** our implementation matches our published security claims and industry standards.

**Acceptance Criteria:**
- TOTP secrets and OAuth tokens encrypted using AES-256-GCM.
- Data migration re-encrypts all existing Fernet-encrypted values.
- Encryption key sourced from dedicated `ENCRYPTION_KEY` env var (not derived from `SECRET_KEY`).
- Backward compatibility during migration.

**Tasks:**

| # | Task | File | Effort |
|---|------|------|--------|
| 3.1.1 | Implement `AES256GCMCipher` class using `cryptography.hazmat.primitives.ciphers.aead.AESGCM`. 256-bit key from `ENCRYPTION_KEY` env var, random 96-bit nonce prepended to ciphertext. | `interpreter/services/encryption.py` | 4h |
| 3.1.2 | Update `interpreter/auth/mfa.py` to use new cipher. Keep Fernet `decrypt_secret()` as `_legacy_decrypt()` for migration. | `interpreter/auth/mfa.py` | 3h |
| 3.1.3 | Update OAuth token encryption and callers. | `interpreter/services/encryption.py`, callers | 3h |
| 3.1.4 | Write Django data migration: read Fernet-encrypted values, decrypt with legacy key, re-encrypt with AES-256-GCM, save. Include dry-run flag. | `interpreter/migrations/` (new) | 6h |
| 3.1.5 | Add `ENCRYPTION_KEY` to `.env.example` files. Validate at startup. | `settings.py`, `.env.example` | 1h |
| 3.1.6 | Write unit tests for cipher: encrypt/decrypt roundtrip, wrong key fails, tampered ciphertext fails. | `tests/test_encryption.py` | 3h |
| 3.1.7 | Remove legacy Fernet code after migration confirmed in all environments. | `mfa.py`, `encryption.py` | 1h |

**Total Effort:** 21 hours

---

### Story 3.2: Integrate AWS KMS for key management (optional — for HIPAA/enterprise)

**As a** platform operator, **I want** encryption keys managed by AWS KMS with automatic rotation, **so that** we achieve KMS-managed keys for enterprise compliance.

**Tasks:**

| # | Task | File | Effort |
|---|------|------|--------|
| 3.2.1 | Create `KMSEnvelopeEncryption` class using `boto3.client('kms')` for envelope encryption. | `interpreter/services/kms_encryption.py` (new) | 8h |
| 3.2.2 | Add `KMS_KEY_ID` and `AWS_KMS_REGION` to config. | `settings.py`, `.env.example` | 1h |
| 3.2.3 | Create factory function `get_cipher()`: returns KMS-backed cipher if configured, otherwise local AES cipher. | `interpreter/services/encryption.py` | 2h |
| 3.2.4 | Enable automatic annual KMS key rotation. Document procedure. | Infrastructure docs | 2h |
| 3.2.5 | Write integration tests (localstack for CI). | `tests/test_kms_encryption.py` | 4h |

**Total Effort:** 17 hours

---

## CSEC-12: Chrome Extension Security

**Jira:** [CSEC-12](https://quodroid.atlassian.net/browse/CSEC-12) | Labels: `coco-specific`, `code-change-required`, `extension-launch`
**Priority:** P2 — Medium
**Audit Ref:** Section 10, A10
**Repo:** `coco-testai-chrome-extension`
**Wrapper Mitigation:** None — extension runs in the browser

---

### CSEC-42: Add message sender validation

**As a** security engineer, **I want** the Chrome extension service worker to validate message senders, **so that** only messages from our own extension are processed.

**Tasks:**

| # | Task | File | Effort |
|---|------|------|--------|
| 12.1.1 | Add sender validation at top of `chrome.runtime.onMessage.addListener` callback: `if (sender.id !== chrome.runtime.id) { return; }`. | `background/service-worker.js:136` | 1h |
| 12.1.2 | For `chrome.runtime.onMessageExternal`, reject all messages or add strict allowlist. | `background/service-worker.js` | 0.5h |
| 12.1.3 | Test: verify normal operations work, messages from devtools console rejected. | Manual testing | 1h |

**Total Effort:** 2.5 hours

---

### CSEC-43: Encrypt stored auth data

**As a** user, **I want** my authentication data encrypted in extension storage, **so that** other extensions or malware cannot trivially read my credentials.

**Tasks:**

| # | Task | File | Effort |
|---|------|------|--------|
| 12.2.1 | Create `scripts/crypto.js` using Web Crypto API (`crypto.subtle`) for AES-GCM encryption/decryption. Key derived from extension ID + random salt in `chrome.storage.local`. | `scripts/crypto.js` (new) | 4h |
| 12.2.2 | Update `handleSaveAuth()` to encrypt auth/user objects before storing. | `background/service-worker.js:344-353` | 2h |
| 12.2.3 | Update `handleGetAuth()` to decrypt after retrieval. | `background/service-worker.js:327-339` | 1h |
| 12.2.4 | Handle migration: encrypt existing unencrypted data on first access. | `background/service-worker.js` | 1.5h |
| 12.2.5 | Test: verify auth works end-to-end, stored data not readable as plain JSON. | Manual testing | 1.5h |

**Total Effort:** 10 hours

---

### CSEC-44: Filter tab broadcasts and strip console logs

**As a** security engineer, **I want** extension messages sent only to relevant tabs and console logging removed from production, **so that** sensitive data is not exposed.

**Tasks:**

| # | Task | File | Effort |
|---|------|------|--------|
| 12.3.1 | Replace `chrome.tabs.query({}, ...)` with filtered query matching configured API URL origin only. | `background/service-worker.js:164` | 2h |
| 12.3.2 | Remove or wrap all `console.log`/`console.error` in a `DEBUG` flag that is `false` in production builds. | Throughout extension | 3h |
| 12.3.3 | Test: notifications work on relevant pages, not on unrelated tabs. | Manual testing | 1h |

**Total Effort:** 6 hours

---

### CSEC-45: Add explicit CSP and tighten permissions

**Tasks:**

| # | Task | File | Effort |
|---|------|------|--------|
| 12.4.1 | Add `content_security_policy` to `manifest.json`: `"extension_pages": "script-src 'self'; object-src 'self'"`. | `manifest.json` | 0.5h |
| 12.4.2 | Review and restrict `web_accessible_resources` via `matches` pattern. | `manifest.json` | 1h |
| 12.4.3 | Add URL protocol validation in `popup.js:45` — reject non-http/https URLs. | `popup/popup.js` | 1h |
| 12.4.4 | Test extension still functions with tightened CSP. | Manual testing | 1h |

**Total Effort:** 3.5 hours

---

## CSEC-13: Frontend Security Hardening

**Jira:** [CSEC-13](https://quodroid.atlassian.net/browse/CSEC-13) | Labels: `coco-specific`, `code-change-required`
**Priority:** P2 — Medium
**Audit Ref:** Section 11
**Repo:** `coco-testai-webapp`
**Wrapper Mitigation:** Partial — proxy can validate file uploads server-side, but client-side fixes are still needed

---

### Story 13.1: Remove VITE_USER_ID and add client-side upload validation

**Tasks:**

| # | Task | File | Effort |
|---|------|------|--------|
| 13.1.1 | Remove `VITE_USER_ID` from `.env`. Replace any usage with authenticated user context from `AppContext`. | `.env`, `src/` files | 2h |
| 13.1.2 | Add client-side file validation in upload flow: check file type against allowlist (`.pdf`, `.doc`, `.docx`, `.txt`, `.md`, `.csv`), check file size (max 50MB), display error if invalid. | `src/services/api.js`, upload component | 3h |
| 13.1.3 | Add Vite plugin to strip `console.log` and `console.error` in production builds. | `vite.config.js` | 1.5h |
| 13.1.4 | Test uploads with valid and invalid file types/sizes. | Manual testing | 1h |

**Total Effort:** 7.5 hours

---

## CSEC-16: GDPR Data Subject Rights

**Jira:** [CSEC-16](https://quodroid.atlassian.net/browse/CSEC-16) | Labels: `coco-specific`, `code-change-required`
**Priority:** P2 — Medium
**Audit Ref:** Section 15, Certification Roadmap
**Repo:** `coco-testai-with-copilot-engine`
**Wrapper Mitigation:** Partial — audit logging from wrapper covers compliance logging, but data export/deletion require app code

---

### Story 16.1: Build user data export endpoint (Right of Access)

**As a** user, **I want** to export all my personal data in a machine-readable format, **so that** my GDPR right of access is satisfied.

**Tasks:**

| # | Task | File | Effort |
|---|------|------|--------|
| 16.1.1 | Create endpoint `GET /api/auth/my-data/export/` that collects all user data: profile, projects, test cases, test executions, conversations, audit logs, session history. Return as JSON. | `interpreter/auth/views.py` or `views_gdpr.py` (new) | 6h |
| 16.1.2 | Add CSV export option via `?format=csv`. | Same view | 2h |
| 16.1.3 | Rate-limit the endpoint to 1 request per hour per user. | Throttle class | 0.5h |
| 16.1.4 | Test: verify all data categories included, other user's data excluded, rate limiting works. | Tests | 3h |

**Total Effort:** 11.5 hours

---

### Story 16.2: Verify cascade deletion covers all user data (Right to Erasure)

**As a** user who deletes their account, **I want** all my data completely removed, **so that** my GDPR right to erasure is satisfied.

**Tasks:**

| # | Task | File | Effort |
|---|------|------|--------|
| 16.2.1 | Audit all user-related models: conversations, AI interactions, test executions, scripts, audit logs, sessions, OAuth connections. Verify `CASCADE` or explicit cleanup. | `interpreter/models.py` | 3h |
| 16.2.2 | If any models use `SET_NULL` instead of `CASCADE`, add explicit deletion logic. | `interpreter/auth/views.py` | 2h |
| 16.2.3 | Document log file retention (text logs may retain data; note as exception or implement scrubbing). | Documentation | 1h |
| 16.2.4 | Write integration test: create user with data across all models, delete account, verify zero records remain. | Tests | 3h |

**Total Effort:** 9 hours

---

## Effort Summary

### By Epic

| Jira Key | Epic | Priority | Hours | Repo |
|----------|------|----------|-------|------|
| CSEC-1 | Secure Default Configuration | P0 | 5 | Backend |
| CSEC-3 | Encryption Upgrade | P0 | 38 | Backend |
| CSEC-12 | Chrome Extension Security | P2 | 22 | Extension |
| CSEC-13 | Frontend Security Hardening | P2 | 7.5 | Frontend |
| CSEC-16 | GDPR Data Subject Rights | P2 | 20.5 | Backend |
| | **TOTAL** | | **~93 hours** | |

*Note: Total is slightly higher than the 88h estimate because CSEC-1 (5h) is included even though the wrapper mitigates most of its risk.*

### By Priority

| Priority | Hours | Description |
|----------|-------|-------------|
| **P0 — Critical** | 43h | Secure defaults + encryption upgrade |
| **P2 — Medium** | 50h | Extension security, frontend, GDPR |

### By Repository

| Repository | Hours |
|------------|-------|
| `coco-testai-with-copilot-engine` (Backend) | ~63.5h |
| `coco-testai-webapp` (Frontend) | ~7.5h |
| `coco-testai-chrome-extension` (Extension) | ~22h |

### Suggested Sprint Plan (2-week sprints, 1-2 developers)

| Sprint | Epics | Hours | Notes |
|--------|-------|-------|-------|
| Sprint 1 | CSEC-1 (Secure Defaults) | 5h | Quick wins, largely mitigated by wrapper |
| Sprint 2 | CSEC-3 Story 3.1 (AES-256-GCM) | 21h | Critical encryption upgrade |
| Sprint 3 | CSEC-12 (Chrome Extension) | 22h | Required for extension public launch |
| Sprint 4 | CSEC-16 (GDPR) | 20.5h | Required for EU compliance |
| Sprint 5 | CSEC-13 (Frontend) + CSEC-3 Story 3.2 (KMS) | 24.5h | Hardening + enterprise encryption |

---

### Relationship to Shield AI Wrapper

| This Doc (Code Fixes) | Shield AI Product (Wrapper) |
|-----------------------|---------------------------|
| 5 epics, ~93 hours | 12 epics, ~249 hours |
| Coco-specific file paths and line numbers | Generic, multi-app product features |
| Fix the source code | Protect from outside |
| Must be done per-app | Built once, protects all apps |
| Reduces risk at the source | Reduces risk at the perimeter |

**Recommendation:** Deploy the Shield AI wrapper first for immediate protection across all layers, then work through these code fixes to eliminate remaining risk at the source.

---

*Document created: February 2026*
*Updated: February 2026 — Added Jira issue keys (CSEC-1, CSEC-3, CSEC-12, CSEC-13, CSEC-16)*
*Source: Coco TestAI Security Audit (application-specific fixes)*
*Jira: [CSEC project](https://quodroid.atlassian.net/jira/software/projects/CSEC/boards/133) — filter by label `coco-specific`*
*See also: [SHIELD_AI_PRODUCT_STORIES.md](./SHIELD_AI_PRODUCT_STORIES.md) for wrapper features (SHIELD project)*
