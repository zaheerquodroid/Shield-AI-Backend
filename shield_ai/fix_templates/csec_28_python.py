"""
CSEC-28: Django Security Headers Configuration Fix Template

This module provides fix templates for configuring Django security headers
in an environment-aware manner (production vs development).

Jira: CSEC-28
Epic: CSEC-5 (Security Configuration)
"""

# Security Headers Configuration Block Template
SECURITY_HEADERS_TEMPLATE = '''
# ==============================================================================
# Shield AI: CSEC-28 - Security Headers Configuration
# ==============================================================================
# Added: {timestamp}
# Jira: CSEC-28
# Purpose: Configure Django security headers for production while allowing
#          easier development locally.
#
# References:
# - OWASP Secure Headers: https://owasp.org/www-project-secure-headers/
# - Mozilla Observatory: https://observatory.mozilla.org/
# - Django Security Middleware: https://docs.djangoproject.com/en/stable/ref/middleware/#module-django.middleware.security
# ==============================================================================

import os

# Detect environment (set DJANGO_ENV=production in production)
DJANGO_ENV = os.environ.get('DJANGO_ENV', 'development')

if DJANGO_ENV == 'production':
    # ===========================================================================
    # PRODUCTION SECURITY HEADERS (OWASP Recommended)
    # ===========================================================================

    # HTTP Strict Transport Security (HSTS)
    # Prevents protocol downgrade attacks and cookie hijacking
    SECURE_HSTS_SECONDS = 31536000  # 1 year (OWASP recommended)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True  # Apply to all subdomains
    SECURE_HSTS_PRELOAD = True  # Allow browser HSTS preloading

    # SSL/HTTPS Configuration
    # Redirect all HTTP requests to HTTPS
    SECURE_SSL_REDIRECT = True

    # Content-Type Security
    # Prevent MIME-sniffing attacks
    SECURE_CONTENT_TYPE_NOSNIFF = True

    # Referrer Policy
    # Control referrer information leakage
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

    # Clickjacking Protection
    # Prevent embedding in iframes
    X_FRAME_OPTIONS = 'DENY'  # Most secure (use 'SAMEORIGIN' if needed)

    # Secure Cookies
    # Mark cookies as secure (HTTPS only)
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access
    CSRF_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'  # CSRF protection
    CSRF_COOKIE_SAMESITE = 'Strict'

else:
    # ===========================================================================
    # DEVELOPMENT SECURITY HEADERS (Relaxed for Local Testing)
    # ===========================================================================

    # HSTS disabled (allows HTTP locally)
    SECURE_HSTS_SECONDS = 0
    SECURE_HSTS_INCLUDE_SUBDOMAINS = False
    SECURE_HSTS_PRELOAD = False

    # SSL redirect disabled (allows http://localhost)
    SECURE_SSL_REDIRECT = False

    # Content-Type nosniff enabled (doesn't break local dev)
    SECURE_CONTENT_TYPE_NOSNIFF = True

    # Referrer policy relaxed
    SECURE_REFERRER_POLICY = 'same-origin'

    # X-Frame-Options relaxed (allows embedding for debugging)
    X_FRAME_OPTIONS = 'SAMEORIGIN'

    # Cookies not marked secure (allows HTTP cookies locally)
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    CSRF_COOKIE_SAMESITE = 'Lax'

# ==============================================================================
# End Shield AI CSEC-28 Configuration
# ==============================================================================
'''

# .env.example Template
ENV_EXAMPLE_TEMPLATE = '''
# ==============================================================================
# Shield AI: CSEC-28 - Environment Configuration
# ==============================================================================
# Copy this file to .env and set values for your environment
# ==============================================================================

# Django Environment (production or development)
# Set to 'production' to enable security headers
# Set to 'development' for local testing with relaxed headers
DJANGO_ENV=development

# In production deployment (Heroku, AWS, etc.), set:
# DJANGO_ENV=production

# ==============================================================================
# Verification:
# ==============================================================================
# After deploying to production, verify headers are set:
#   curl -I https://your-production-domain.com
#
# Expected headers:
#   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
#   X-Content-Type-Options: nosniff
#   X-Frame-Options: DENY
#   Referrer-Policy: strict-origin-when-cross-origin
#
# For comprehensive analysis:
#   https://observatory.mozilla.org/
#   https://securityheaders.com/
# ==============================================================================
'''

# Documentation Template
DOCUMENTATION_TEMPLATE = '''
# CSEC-28: Django Security Headers Configuration

## Changes Made

Shield AI has added environment-aware security headers configuration to your Django settings.

### Files Modified
- `{settings_file}` - Added security headers configuration block
- `.env.example` - Created with DJANGO_ENV variable (if not exists)

### Backup Created
- `{settings_file}.shield_ai_backup` - Original file backup

## Security Headers Configured

### Production (DJANGO_ENV=production)

| Header | Value | Purpose |
|--------|-------|---------|
| `SECURE_HSTS_SECONDS` | 31536000 (1 year) | Force HTTPS for 1 year |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | True | Apply HSTS to subdomains |
| `SECURE_HSTS_PRELOAD` | True | Allow browser preloading |
| `SECURE_SSL_REDIRECT` | True | Redirect HTTP to HTTPS |
| `SECURE_CONTENT_TYPE_NOSNIFF` | True | Prevent MIME sniffing |
| `SECURE_REFERRER_POLICY` | strict-origin-when-cross-origin | Limit referrer leakage |
| `X_FRAME_OPTIONS` | DENY | Prevent clickjacking |
| `SESSION_COOKIE_SECURE` | True | HTTPS-only session cookies |
| `CSRF_COOKIE_SECURE` | True | HTTPS-only CSRF cookies |
| `SESSION_COOKIE_HTTPONLY` | True | Prevent JavaScript access |
| `CSRF_COOKIE_HTTPONLY` | True | Prevent JavaScript access |
| `SESSION_COOKIE_SAMESITE` | Strict | CSRF protection |
| `CSRF_COOKIE_SAMESITE` | Strict | CSRF protection |

### Development (DJANGO_ENV=development)

All headers are disabled or relaxed to allow local HTTP testing.

## Deployment Instructions

### 1. Set Environment Variable

**Heroku:**
```bash
heroku config:set DJANGO_ENV=production
```

**AWS Elastic Beanstalk:**
```bash
eb setenv DJANGO_ENV=production
```

**Docker:**
```dockerfile
ENV DJANGO_ENV=production
```

**Manual/.env file:**
```bash
echo "DJANGO_ENV=production" > .env
```

### 2. Verify Deployment

**Check HTTP headers:**
```bash
curl -I https://your-production-domain.com
```

**Expected output:**
```
HTTP/2 200
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
```

### 3. Run Security Scans

**Mozilla Observatory (Target: A+):**
```
https://observatory.mozilla.org/analyze/your-domain.com
```

**Security Headers (Target: A):**
```
https://securityheaders.com/?q=your-domain.com
```

## Security Benefits

### Vulnerabilities Prevented

1. **Clickjacking** (X-Frame-Options: DENY)
   - Prevents attackers from embedding your site in iframes
   - Protects against UI redressing attacks

2. **MIME Sniffing** (Content-Type nosniff)
   - Prevents browsers from executing malicious content
   - Blocks MIME confusion attacks

3. **Protocol Downgrade** (HSTS)
   - Forces HTTPS for all connections
   - Prevents man-in-the-middle attacks
   - Protects against SSL stripping

4. **Man-in-the-Middle** (SSL Redirect)
   - Redirects HTTP to HTTPS automatically
   - Prevents initial request interception

5. **Cookie Theft** (Secure Cookies)
   - Cookies only sent over HTTPS
   - Prevents session hijacking

6. **XSS Cookie Access** (HttpOnly Cookies)
   - JavaScript cannot read cookies
   - Limits XSS attack impact

7. **CSRF Attacks** (SameSite Cookies)
   - Cookies not sent cross-site
   - Prevents CSRF exploitation

## Compliance

### Standards Met

- **OWASP Top 10 A5:2021** - Security Misconfiguration
- **OWASP ASVS V14.4** - HTTP Security Headers
- **Mozilla Web Security Guidelines** - Security Headers
- **NIST 800-53 SC-8** - Transmission Confidentiality

## Testing

### Local Development

No changes needed - headers are automatically disabled when `DJANGO_ENV != production`.

```bash
# Run locally (uses development headers)
python manage.py runserver
```

### Production Testing

```bash
# Test production headers locally
DJANGO_ENV=production python manage.py runserver
```

**Note:** SSL redirect will fail locally. Test on actual HTTPS deployment.

## Troubleshooting

### Issue: "This site can't provide a secure connection"

**Cause:** `SECURE_SSL_REDIRECT = True` in development without HTTPS

**Fix:**
```bash
# Ensure DJANGO_ENV is not set to production locally
unset DJANGO_ENV
# Or explicitly set to development
export DJANGO_ENV=development
```

### Issue: "Cookies not working locally"

**Cause:** Secure cookies require HTTPS

**Fix:** Same as above - ensure `DJANGO_ENV=development`

### Issue: "HSTS errors in browser"

**Cause:** Browser cached HSTS policy from testing

**Fix:**
1. Chrome: chrome://net-internals/#hsts → Delete domain
2. Firefox: Clear site data for localhost

## Rollback

If needed, restore original settings:

```bash
# Restore backup
cp {settings_file}.shield_ai_backup {settings_file}

# Or manually remove the Shield AI CSEC-28 configuration block
# (Lines between the "Shield AI: CSEC-28" markers)
```

## References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Django Security Middleware](https://docs.djangoproject.com/en/stable/ref/middleware/#module-django.middleware.security)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [Security Headers Checker](https://securityheaders.com/)
- [HSTS Preload](https://hstspreload.org/)

## Support

**Jira Ticket:** CSEC-28
**Epic:** CSEC-5 - Security Configuration
**Implementation Date:** {timestamp}
'''

# Combined template with metadata
FULL_DOCUMENTATION = '''# Shield AI Security Updates - CSEC-28

## Summary
Shield AI has configured Django security headers to protect against common web vulnerabilities including clickjacking, MIME sniffing, protocol downgrade attacks, and session hijacking.

{documentation}

---
Generated by Shield AI Backend
Pattern: csec_28_security_headers
Date: {timestamp}
'''


def get_fix_template(finding: dict, framework: str = 'django') -> dict:
    """
    Get the fix template for CSEC-28 security headers misconfiguration.

    Args:
        finding: The security finding from scanner
        framework: Target framework (django, flask, fastapi)

    Returns:
        Dictionary with fix template and metadata
    """
    if framework.lower() != 'django':
        return {
            'status': 'error',
            'message': f'CSEC-28 only supports Django framework, got: {framework}'
        }

    import datetime
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    settings_file = finding.get('file_path', 'settings.py')

    return {
        'status': 'success',
        'fix_type': 'configuration_addition',
        'breaking_change': False,
        'templates': {
            'security_headers': SECURITY_HEADERS_TEMPLATE.format(timestamp=timestamp),
            'env_example': ENV_EXAMPLE_TEMPLATE,
            'documentation': DOCUMENTATION_TEMPLATE.format(
                settings_file=settings_file,
                timestamp=timestamp
            )
        },
        'files_to_create': [
            {
                'path': '.env.example',
                'content': ENV_EXAMPLE_TEMPLATE,
                'overwrite': False  # Don't overwrite existing .env.example
            }
        ],
        'files_to_modify': [
            {
                'path': settings_file,
                'action': 'append',  # Append security headers block
                'content': SECURITY_HEADERS_TEMPLATE.format(timestamp=timestamp),
                'location': 'end'  # Add at end of file
            }
        ],
        'documentation': FULL_DOCUMENTATION.format(
            documentation=DOCUMENTATION_TEMPLATE.format(
                settings_file=settings_file,
                timestamp=timestamp
            ),
            timestamp=timestamp
        ),
        'verification_commands': [
            'curl -I https://your-production-domain.com',
            'Check for: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy'
        ],
        'deployment_steps': [
            'Set environment variable: DJANGO_ENV=production',
            'Deploy application to production',
            'Verify headers with: curl -I https://your-domain.com',
            'Run Mozilla Observatory scan: https://observatory.mozilla.org/',
            'Target grade: A+ (Mozilla Observatory)',
            'Target grade: A (securityheaders.com)'
        ],
        'compliance': [
            'OWASP Top 10 A5:2021 - Security Misconfiguration',
            'OWASP ASVS V14.4 - HTTP Security Headers',
            'Mozilla Web Security Guidelines - Security Headers',
            'NIST 800-53 SC-8 - Transmission Confidentiality'
        ]
    }
