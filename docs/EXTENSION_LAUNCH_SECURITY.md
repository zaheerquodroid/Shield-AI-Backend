# Chrome Extension Launch - Security Requirements

**Jira Filter:** `project = CSEC AND labels = extension-launch` + `project = SHIELD AND priority = P0`
**CSEC Board:** https://quodroid.atlassian.net/jira/software/projects/CSEC/boards/133
**SHIELD Board:** https://quodroid.atlassian.net/jira/software/projects/SHIELD/boards

---

## Summary

These security fixes must be completed before the Chrome extension can be publicly launched as part of the PLG (Product-Led Growth) strategy. The extension is the zero-friction entry point where users install and generate tests without an account.

Following the Jira restructure, launch requirements are now split across two projects:

| Project | What It Covers | Effort |
|---------|---------------|--------|
| **SHIELD** (wrapper) | Edge security that protects the API automatically — WAF, rate limiting, security headers, error sanitization | ~59h (P0 epics) |
| **CSEC** (code fixes) | Application-specific fixes requiring code changes — secure defaults, Chrome extension hardening | ~27h |
| **Total** | | **~86h** |

---

## SHIELD Project — Wrapper Protections (Deploy Once)

These are handled by deploying the Shield AI security wrapper in front of the Coco API. No application code changes needed.

### SHIELD-1: WAF & Threat Protection (30h)

| Key | Story | Hours |
|-----|-------|-------|
| SHIELD-13 | Deploy edge WAF with managed rulesets | 10h |
| SHIELD-14 | Add rate limiting rules | 13h |
| SHIELD-15 | Add bot protection and credential stuffing detection | 7h |

*Replaces: CSEC-4 (Rate Limiting), CSEC-26 (DRF throttling), CSEC-27 (breached-password checking)*

### SHIELD-2: Security Headers (14h)

| Key | Story | Hours |
|-----|-------|-------|
| SHIELD-16 | Inject security headers into all responses | 14h |

*Replaces: CSEC-5, CSEC-28 (Django security headers), CSEC-29 (CSP), CSEC-30 (Permissions-Policy)*

### SHIELD-3: Response Sanitization (15h)

| Key | Story | Hours |
|-----|-------|-------|
| SHIELD-17 | Sanitize error responses to prevent information leakage | 15h |

*Replaces: CSEC-2, CSEC-21 (API error sanitization), CSEC-22 (WebSocket errors), CSEC-23 (bare except clauses)*

---

## CSEC Project — Code Changes Required

### CSEC-1: Secure Default Configuration (5h)

| Key | Story | Hours |
|-----|-------|-------|
| CSEC-18 | Remove hardcoded SECRET_KEY fallback | 2h |
| CSEC-19 | Change DEBUG to default False | 1.5h |
| CSEC-20 | Change ALLOWED_HOSTS to default empty | 1.5h |

*Note: SHIELD-2 (security headers) and SHIELD-3 (error sanitization) mitigate most risks from these defaults, but fixing the source code is still best practice.*

### CSEC-12: Chrome Extension Security (22h)

| Key | Story | Hours |
|-----|-------|-------|
| CSEC-42 | Add message sender validation | 2.5h |
| CSEC-43 | Encrypt stored auth data | 10h |
| CSEC-44 | Filter tab broadcasts and strip console logs | 6h |
| CSEC-45 | Add explicit CSP and tighten permissions | 3.5h |

*These cannot be handled by the wrapper — the extension runs in the browser.*

---

## Recommended Launch Sequence

| Phase | Focus | Stories | Hours |
|-------|-------|---------|-------|
| Phase 1 | Deploy SHIELD wrapper (instant protection) | SHIELD-1, SHIELD-2, SHIELD-3 | ~59h |
| Phase 2 | Fix secure defaults | CSEC-18, 19, 20 | 5h |
| Phase 3 | Harden Chrome extension | CSEC-42, 43, 44, 45 | 22h |

**Recommendation:** Deploy the SHIELD wrapper first. This immediately covers rate limiting, security headers, and error sanitization — the three highest-risk categories — without any Coco code changes. Then work through the CSEC code fixes in parallel.

---

## Why These Are Required

| Category | Project | Risk if Not Fixed |
|----------|---------|-------------------|
| **WAF & Rate Limiting** | SHIELD-1 | Brute force attacks on login; credential stuffing; no DDoS protection |
| **Security Headers** | SHIELD-2 | XSS, clickjacking, protocol downgrade attacks |
| **Error Handling** | SHIELD-3 | Internal paths, stack traces exposed to users |
| **Secure Defaults** | CSEC-1 | Production runs in DEBUG mode; accepts any Host header |
| **Chrome Extension** | CSEC-12 | Auth tokens readable by other extensions; messages broadcast to all tabs |

---

## What Changed (Feb 2026 Restructure)

The original version of this document listed 5 CSEC epics totaling ~74.5h. Following the Jira restructure:

- **Epics 2, 4, 5** (Error Handling, Rate Limiting, Security Headers) moved to the **SHIELD** project as generic wrapper features
- **Epics 1, 12** remain in **CSEC** as application-specific code fixes
- Total effort is now ~86h across both projects (was ~74.5h in CSEC alone)
- The wrapper approach means ~59h of that effort protects **all** apps, not just Coco

---

*Updated: February 2026*
*Source: SECURITY_AUDIT_REPORT.md, PLG Marketing Strategy, Jira CSEC/SHIELD restructure*
