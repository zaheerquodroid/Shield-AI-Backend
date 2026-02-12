# Chrome Extension Launch - Security Requirements

**Total Effort:** ~74.5 hours
**Jira Filter:** `project = CSEC AND labels = extension-launch`
**Scrum Board:** https://quodroid.atlassian.net/jira/software/projects/CSEC/boards/133

---

## Summary

These security fixes must be completed before the Chrome extension can be publicly launched as part of the PLG (Product-Led Growth) strategy. The extension is the zero-friction entry point where users install and generate tests without an account.

---

## Stories

### Epic 1: Secure Default Configuration (5h)

| Key | Story | Hours |
|-----|-------|-------|
| CSEC-18 | Remove hardcoded SECRET_KEY fallback | 2h |
| CSEC-19 | Change DEBUG to default False | 1.5h |
| CSEC-20 | Change ALLOWED_HOSTS to default empty | 1.5h |

### Epic 2: Error Handling & Exception Security (21h)

| Key | Story | Hours |
|-----|-------|-------|
| CSEC-21 | Sanitize API error responses (views) | 13.5h |
| CSEC-22 | Sanitize WebSocket error messages | 3h |
| CSEC-23 | Fix bare except clauses and add global exception handler | 4.5h |

### Epic 4: Rate Limiting & Brute Force Protection (21.5h)

| Key | Story | Hours |
|-----|-------|-------|
| CSEC-26 | Add DRF throttling to authentication endpoints | 13.5h |
| CSEC-27 | Add breached-password checking | 8h |

### Epic 5: Security Headers (15h)

| Key | Story | Hours |
|-----|-------|-------|
| CSEC-28 | Configure Django security headers for production | 3.5h |
| CSEC-29 | Add Content-Security-Policy header | 9.5h |
| CSEC-30 | Add Permissions-Policy header | 2h |

### Epic 12: Chrome Extension Security (22h)

| Key | Story | Hours |
|-----|-------|-------|
| CSEC-42 | Add message sender validation | 2.5h |
| CSEC-43 | Encrypt stored auth data | 10h |
| CSEC-44 | Filter tab broadcasts and strip console logs | 6h |
| CSEC-45 | Add explicit CSP and tighten permissions | 3.5h |

---

## Recommended Sprint Plan

| Week | Focus | Stories | Hours |
|------|-------|---------|-------|
| Week 1-2 | Secure defaults + Extension security | CSEC-18, 19, 20, 42, 43, 44, 45 | 27h |
| Week 3-4 | Rate limiting + Security headers | CSEC-26, 27, 28, 29, 30 | 36.5h |
| Week 5-6 | Error handling | CSEC-21, 22, 23 | 21h |

---

## Why These Are Required

| Category | Risk if Not Fixed |
|----------|-------------------|
| **Chrome Extension** | Auth tokens readable by other extensions; messages broadcast to all tabs |
| **Rate Limiting** | Brute force attacks on login; credential stuffing |
| **Error Handling** | Internal paths, stack traces exposed to users |
| **Security Headers** | XSS, clickjacking, protocol downgrade attacks |
| **Secure Defaults** | Production runs in DEBUG mode; accepts any Host header |

---

*Created: February 2026*
*Source: SECURITY_AUDIT_REPORT.md, PLG Marketing Strategy*
