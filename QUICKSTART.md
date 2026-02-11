# Shield AI Backend - Quick Start Guide

## Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Verify installation:**
   ```bash
   python -m shield_ai --help
   ```

## Usage Examples

### 1. Scan a Codebase (Coco TestAI)

```bash
# Scan entire codebase
python -m shield_ai scan /path/to/coco-testai

# Scan for specific pattern (CSEC-22: WebSocket Error Sanitization)
python -m shield_ai scan /path/to/coco-testai --pattern csec_22_websocket_errors

# Scan for CSEC-23 (Bare except and DRF exception handler)
python -m shield_ai scan /path/to/coco-testai --pattern csec_23_bare_except

# Scan for CSEC-27 (Missing breached password validation)
python -m shield_ai scan /path/to/coco-testai --pattern csec_27_missing_pwned_check

# Scan for CSEC-28 (Missing security headers)
python -m shield_ai scan /path/to/coco-testai --pattern csec_28_security_headers

# Save findings to JSON
python -m shield_ai scan /path/to/coco-testai --output findings.json
```

### 2. Preview Fixes (Dry Run)

```bash
# Preview what changes will be made WITHOUT actually changing files
python -m shield_ai fix /path/to/coco-testai --dry-run
```

### 3. Apply Fixes

```bash
# Apply fixes for CSEC-22 (WebSocket errors)
python -m shield_ai fix /path/to/coco-testai --pattern csec_22_websocket_errors --framework django

# Apply fixes for CSEC-23 (Bare except)
python -m shield_ai fix /path/to/coco-testai --pattern csec_23_bare_except --framework django

# Apply fixes for CSEC-27 (Breached password validation)
python -m shield_ai fix /path/to/coco-testai --pattern csec_27_missing_pwned_check --framework django

# Apply fixes for CSEC-28 (Security headers)
python -m shield_ai fix /path/to/coco-testai --pattern csec_28_security_headers --framework django
```

**What happens:**
- ✅ Wraps vulnerable code with error handling utilities
- ✅ Adds configuration for missing security features
- ✅ Generates helper functions and utilities
- ✅ Creates `SECURITY_UPDATES.md` documentation
- ✅ Creates backups of modified files (*.shield_ai_backup)

### 4. Generate Reports

```bash
# Text report
python -m shield_ai report /path/to/coco-testai

# Markdown report
python -m shield_ai report /path/to/coco-testai --format markdown --output SECURITY_REPORT.md

# JSON report
python -m shield_ai report /path/to/coco-testai --format json --output report.json
```

## Workflow for CSEC-22 (WebSocket Error Sanitization)

### Step 1: Scan
```bash
python -m shield_ai scan ../coco-testai --pattern csec_22_websocket_errors
```

**Expected output:**
```
🔍 Scanning ../coco-testai...
📋 Patterns to check: 1

  [!] Found X issues for csec_22_websocket_errors

📊 SCAN RESULTS
Total findings: X

1. Unsanitized WebSocket Error Message (csec_22_websocket_errors)
   File: ../coco-testai/interpreter/consumers.py:45
   Severity: CRITICAL
   Code: await self.send(text_data=json.dumps({'error': str(e)}))...
```

### Step 2: Preview Fixes
```bash
python -m shield_ai fix ../coco-testai --pattern csec_22_websocket_errors --dry-run
```

### Step 3: Apply Fix

```bash
# Apply the fix (creates wrapper utility and sanitizes errors)
python -m shield_ai fix ../coco-testai --pattern csec_22_websocket_errors --framework django
```

**Files modified:**
- WebSocket consumer files - Error handling wrapped
- `interpreter/utils/websocket_errors.py` - Created with sanitization utility
- `SECURITY_UPDATES.md` - Documentation
- Backup files created (*.shield_ai_backup)

---

## Workflow for CSEC-23 (Bare Except & DRF Exception Handler)

### Step 1: Scan
```bash
python -m shield_ai scan ../coco-testai --pattern csec_23_bare_except
```

### Step 2: Preview Fixes
```bash
python -m shield_ai fix ../coco-testai --pattern csec_23_bare_except --dry-run
```

### Step 3: Apply Fix

```bash
# Apply fixes (context-aware exception type suggestions)
python -m shield_ai fix ../coco-testai --pattern csec_23_bare_except --framework django
```

**What Shield AI does:**
- Analyzes try block context (file operations, JSON parsing, etc.)
- Suggests specific exception types (e.g., JSONDecodeError, IOError)
- Replaces `except:` with appropriate exception type
- Adds custom DRF exception handler if missing

---

## Workflow for CSEC-27 (Breached Password Validation)

### Step 1: Scan
```bash
python -m shield_ai scan ../coco-testai --pattern csec_27_missing_pwned_check
```

**Expected output:**
```
Scanning ../coco-testai...

  [!] Found 1 issues for csec_27_missing_pwned_check

1. Missing Breached Password Validation (csec_27_missing_pwned_check)
   File: ../coco-testai/coco_backend/settings.py:85
   Severity: HIGH
   Description: AUTH_PASSWORD_VALIDATORS without breach password checking
```

### Step 2: Preview Fixes
```bash
python -m shield_ai fix ../coco-testai --pattern csec_27_missing_pwned_check --dry-run
```

### Step 3: Apply Fix
```bash
# Add breached password checking (non-breaking addition)
python -m shield_ai fix ../coco-testai --pattern csec_27_missing_pwned_check --framework django
```

**What Shield AI adds:**

**Option 1: django-pwned-passwords (Recommended)**
```python
# Added to settings.py AUTH_PASSWORD_VALIDATORS:
{
    'NAME': 'pwned_passwords_django.validators.PwnedPasswordsValidator',
    'OPTIONS': {
        'error_message': 'This password has appeared in a data breach.',
        'help_text': 'Your password will be checked against known breaches.',
    }
},

# Configuration:
PWNED_PASSWORDS_API_TIMEOUT = 1.0
PWNED_PASSWORDS_FAIL_SAFE = True
```

**Option 2: Custom Validator (No Dependencies)**
```python
# Creates utils/validators.py with BreachedPasswordValidator
# Uses Have I Been Pwned API with k-anonymity
# Full control, no external dependencies
```

**Files created/modified:**
- `coco_backend/settings.py` - AUTH_PASSWORD_VALIDATORS updated
- `utils/validators.py` - Custom validator (if option 2)
- `requirements.txt` - Add django-pwned-passwords or requests
- `SECURITY_UPDATES.md` - Documentation
- Backup files created

### Step 4: Install Dependencies
```bash
# If using django-pwned-passwords (Option 1):
pip install django-pwned-passwords

# If using custom validator (Option 2):
pip install requests
```

### Step 5: Test
```bash
# Test with known breached password
python manage.py shell
>>> from django.contrib.auth.password_validation import validate_password
>>> validate_password("password123")
ValidationError: This password has appeared 37,000 times in data breaches.

# Test with strong password
>>> validate_password("G9$mKp2#xL@vNq4R")
# No error - password is secure!
```

### How It Works

**k-Anonymity for Privacy:**
1. Password hashed with SHA-1 locally: `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`
2. Only first 5 chars sent to HIBP: `5BAA6`
3. API returns all hashes starting with `5BAA6` (~800 hashes)
4. Local matching determines if password is breached
5. User sees warning if password is compromised

**Privacy protected:** Actual password never leaves your server!

### Security Benefits

**Prevents:**
- ✅ Credential stuffing attacks
- ✅ Password reuse exploitation
- ✅ Brute force with known passwords
- ✅ Account takeover via leaked credentials

**Statistics:**
- HIBP database: 613 million+ breached passwords
- "password123" appears 2.3 million times
- "123456" (most common): 37 million times

### Compliance

**Meets security standards:**
- ✅ NIST 800-63B Section 5.1.1.2 - Check against breach databases
- ✅ OWASP ASVS V2.1.7 - Verify passwords against breached lists
- ✅ PCI DSS - Password security best practices

---

## Workflow for CSEC-28 (Django Security Headers)

### Step 1: Scan
```bash
python -m shield_ai scan ../coco-testai --pattern csec_28_security_headers
```

**Expected output:**
```
Scanning ../coco-testai...

  [!] Found 1-7 issues for csec_28_security_headers

1. Missing or Insecure Django Security Headers (csec_28_security_headers)
   File: ../coco-testai/coco_backend/settings.py:45
   Severity: HIGH
   Description: SECURE_HSTS_SECONDS = 0 (HSTS disabled)
```

### Step 2: Preview Fixes
```bash
python -m shield_ai fix ../coco-testai --pattern csec_28_security_headers --dry-run
```

### Step 3: Apply Fix
```bash
# Add environment-aware security headers configuration
python -m shield_ai fix ../coco-testai --pattern csec_28_security_headers --framework django
```

**What Shield AI adds:**

**Environment-Aware Security Headers Block:**
```python
# Added to settings.py:
import os

DJANGO_ENV = os.environ.get('DJANGO_ENV', 'development')

if DJANGO_ENV == 'production':
    # Production - All security headers enabled
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_SSL_REDIRECT = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
    X_FRAME_OPTIONS = 'DENY'
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    CSRF_COOKIE_SAMESITE = 'Strict'
else:
    # Development - Headers disabled for easier local testing
    SECURE_HSTS_SECONDS = 0
    SECURE_SSL_REDIRECT = False
    # ... (relaxed settings)
```

**.env.example Created:**
```bash
# Django Environment (production or development)
DJANGO_ENV=development

# In production deployment, set:
# DJANGO_ENV=production
```

**Files created/modified:**
- `coco_backend/settings.py` - Security headers configuration added
- `.env.example` - Environment variable template
- `SECURITY_UPDATES.md` - Documentation
- Backup files created

### Step 4: Deploy to Production

```bash
# Set environment variable in your deployment platform
# Heroku:
heroku config:set DJANGO_ENV=production

# AWS:
eb setenv DJANGO_ENV=production

# Docker:
# Add to Dockerfile: ENV DJANGO_ENV=production

# Manual/.env:
echo "DJANGO_ENV=production" > .env
```

### Step 5: Verify Headers

```bash
# Test production deployment
curl -I https://your-production-domain.com

# Expected headers:
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Referrer-Policy: strict-origin-when-cross-origin
```

### Step 6: Run Security Scans

**Mozilla Observatory (Target: A+):**
```
https://observatory.mozilla.org/analyze/your-domain.com
```

**Security Headers (Target: A):**
```
https://securityheaders.com/?q=your-domain.com
```

### How It Works

**Environment Detection:**
1. Checks `DJANGO_ENV` environment variable
2. If `production`: Enables all security headers (OWASP recommended)
3. If `development`: Disables headers for easier local testing
4. No changes needed to local development workflow

**Privacy protected:** All traffic forced to HTTPS in production!

### Security Benefits

**Prevents:**
- ✅ Clickjacking attacks (X-Frame-Options: DENY)
- ✅ MIME sniffing attacks (Content-Type nosniff)
- ✅ Protocol downgrade attacks (HSTS)
- ✅ Man-in-the-middle attacks (SSL redirect)
- ✅ Session hijacking (Secure cookies)
- ✅ XSS cookie theft (HttpOnly cookies)
- ✅ CSRF attacks (SameSite cookies)

### Compliance

**Meets security standards:**
- ✅ OWASP Top 10 A5:2021 - Security Misconfiguration
- ✅ OWASP ASVS V14.4 - HTTP Security Headers
- ✅ Mozilla Web Security Guidelines - Security Headers
- ✅ NIST 800-53 SC-8 - Transmission Confidentiality

---

## File Structure After Running Shield AI

```
coco-testai/
├── SECURITY_UPDATES.md                       # ✨ Generated by Shield AI
├── interpreter/
│   ├── consumers.py                          # ✅ Fixed by Shield AI
│   ├── consumers.py.shield_ai_backup         # 💾 Backup created
│   ├── views.py                              # ✅ Fixed by Shield AI
│   ├── views.py.shield_ai_backup             # 💾 Backup created
│   └── utils/
│       └── websocket_errors.py               # ✨ Created by Shield AI
└── ... (rest of codebase)
```

## Rollback

If something goes wrong:

```bash
# Restore from backup
cp interpreter/consumers.py.shield_ai_backup interpreter/consumers.py
cp interpreter/views.py.shield_ai_backup interpreter/views.py
```

## Testing After Fix

```bash
# Test the application
cd ../coco-testai
python manage.py check

# Run tests
python manage.py test
```

## Support

For issues or questions:
- GitHub: https://github.com/zaheerquodroid/Shield-AI-Backend
- Jira:
  - CSEC-22 (WebSocket Error Sanitization)
  - CSEC-23 (Bare Except & DRF Exception Handler)
  - CSEC-27 (Breached Password Validation)
  - CSEC-28 (Django Security Headers)
