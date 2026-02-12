"""
Fix templates for CSEC-29: Missing Content-Security-Policy Header (Python/Django)
"""

# ============================================================================
# OPTION 1: django-csp Library (Recommended)
# ============================================================================

# Template for django-csp configuration (Strict Policy)
DJANGO_CSP_STRICT_CONFIG = '''
# Shield AI: Content-Security-Policy Configuration (Strict)
# Provides maximum XSS protection with strict CSP directives

# CSP Directives - Strict Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)  # No inline scripts allowed
CSP_STYLE_SRC = ("'self'",)   # No inline styles allowed
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'", "data:")
CSP_CONNECT_SRC = ("'self'",)
CSP_MEDIA_SRC = ("'self'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_FRAME_ANCESTORS = ("'none'",)  # Prevent clickjacking
CSP_BASE_URI = ("'self'",)
CSP_FORM_ACTION = ("'self'",)
CSP_FRAME_SRC = ("'none'",)
CSP_MANIFEST_SRC = ("'self'",)
CSP_WORKER_SRC = ("'self'",)

# Upgrade insecure requests
CSP_UPGRADE_INSECURE_REQUESTS = True

# Report violations
CSP_REPORT_URI = None  # Set to your CSP reporting endpoint
# CSP_REPORT_URI = '/api/csp-report/'  # Example endpoint

# Include nonce for inline scripts (optional)
CSP_INCLUDE_NONCE_IN = ['script-src']
'''

# Template for django-csp configuration (Moderate Policy)
DJANGO_CSP_MODERATE_CONFIG = '''
# Shield AI: Content-Security-Policy Configuration (Moderate)
# Allows some inline scripts/styles for compatibility

# CSP Directives - Moderate Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")  # Allow inline scripts
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")   # Allow inline styles
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'", "data:")
CSP_CONNECT_SRC = ("'self'",)
CSP_MEDIA_SRC = ("'self'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_FRAME_ANCESTORS = ("'self'",)
CSP_BASE_URI = ("'self'",)
CSP_FORM_ACTION = ("'self'",)
CSP_FRAME_SRC = ("'self'",)

# Upgrade insecure requests
CSP_UPGRADE_INSECURE_REQUESTS = True

# Report violations
CSP_REPORT_URI = None  # Set to your CSP reporting endpoint
'''

# Template for django-csp configuration (Report-Only Mode - Phase 1)
DJANGO_CSP_REPORT_ONLY_CONFIG = '''
# Shield AI: Content-Security-Policy Report-Only Mode (Phase 1)
# Monitor CSP violations without blocking - safe for testing

# Enable report-only mode (doesn't block, only reports violations)
CSP_REPORT_ONLY = True

# CSP Directives - Same as enforcement policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'", "data:")
CSP_CONNECT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)

# REQUIRED: Report URI for violations
CSP_REPORT_URI = '/api/csp-report/'  # Configure your reporting endpoint

# After monitoring and fixing violations, set CSP_REPORT_ONLY = False
'''

# Middleware addition template
ADD_CSP_MIDDLEWARE = '''    # Shield AI: Add CSP middleware
    'csp.middleware.CSPMiddleware','''

# Full middleware example
MIDDLEWARE_WITH_CSP = '''
# Shield AI: MIDDLEWARE with CSP
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'csp.middleware.CSPMiddleware',  # Shield AI: CSP protection
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
'''

# ============================================================================
# OPTION 2: Custom CSP Middleware (No Dependencies)
# ============================================================================

CUSTOM_CSP_MIDDLEWARE = '''
# Shield AI: Custom Content-Security-Policy Middleware
# File: utils/middleware.py

import logging

logger = logging.getLogger(__name__)


class ContentSecurityPolicyMiddleware:
    """
    Adds Content-Security-Policy header to all HTTP responses.

    Provides XSS protection by restricting which resources can be loaded
    and executed in the browser.
    """

    # CSP Policy Configuration
    CSP_DIRECTIVES = {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'img-src': ["'self'", "data:", "https:"],
        'font-src': ["'self'", "data:"],
        'connect-src': ["'self'"],
        'media-src': ["'self'"],
        'object-src': ["'none'"],
        'frame-ancestors': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'frame-src': ["'none'"],
    }

    def __init__(self, get_response):
        """Initialize middleware."""
        self.get_response = get_response
        self.csp_header = self._build_csp_header()

    def __call__(self, request):
        """Process request and add CSP header to response."""
        response = self.get_response(request)

        # Add CSP header to response
        if not response.has_header('Content-Security-Policy'):
            response['Content-Security-Policy'] = self.csp_header

        return response

    def _build_csp_header(self):
        """
        Build CSP header string from directives.

        Returns:
            str: Complete CSP header value
        """
        directives = []

        for directive, values in self.CSP_DIRECTIVES.items():
            value_str = ' '.join(values)
            directives.append(f"{directive} {value_str}")

        # Add upgrade-insecure-requests
        directives.append("upgrade-insecure-requests")

        return '; '.join(directives)


class ContentSecurityPolicyReportOnlyMiddleware:
    """
    Adds Content-Security-Policy-Report-Only header for testing.

    Use this in Phase 1 to monitor CSP violations without blocking.
    Switch to ContentSecurityPolicyMiddleware in Phase 2.
    """

    # Same directives as enforcement policy
    CSP_DIRECTIVES = {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'"],  # Allow inline for compatibility
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:", "https:"],
        'font-src': ["'self'", "data:"],
        'connect-src': ["'self'"],
        'frame-ancestors': ["'none'"],
    }

    REPORT_URI = '/api/csp-report/'  # Configure your reporting endpoint

    def __init__(self, get_response):
        """Initialize middleware."""
        self.get_response = get_response
        self.csp_header = self._build_csp_header()

    def __call__(self, request):
        """Process request and add CSP-Report-Only header."""
        response = self.get_response(request)

        # Add CSP-Report-Only header (doesn't block, only reports)
        if not response.has_header('Content-Security-Policy-Report-Only'):
            response['Content-Security-Policy-Report-Only'] = self.csp_header

        return response

    def _build_csp_header(self):
        """Build CSP header string with report-uri."""
        directives = []

        for directive, values in self.CSP_DIRECTIVES.items():
            value_str = ' '.join(values)
            directives.append(f"{directive} {value_str}")

        # Add report-uri
        if self.REPORT_URI:
            directives.append(f"report-uri {self.REPORT_URI}")

        return '; '.join(directives)
'''

# Custom middleware settings configuration
CUSTOM_MIDDLEWARE_SETTINGS = '''
# Shield AI: Add custom CSP middleware to settings
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'utils.middleware.ContentSecurityPolicyMiddleware',  # Shield AI: CSP
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
'''

# ============================================================================
# CSP VIOLATION REPORTING ENDPOINT
# ============================================================================

CSP_REPORT_VIEW = '''
# Shield AI: CSP Violation Reporting View
# File: views.py or api/views.py

import json
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

logger = logging.getLogger('csp.violations')


@csrf_exempt  # CSP reports come from browser, not user forms
@require_POST
def csp_report(request):
    """
    Receive and log CSP violation reports.

    Browser sends POST requests when CSP is violated.
    Log these for analysis and fixing.
    """
    try:
        # Parse CSP report
        report = json.loads(request.body)
        csp_report = report.get('csp-report', {})

        # Log violation details
        logger.warning(
            f"CSP Violation: "
            f"blocked-uri={csp_report.get('blocked-uri')} "
            f"violated-directive={csp_report.get('violated-directive')} "
            f"document-uri={csp_report.get('document-uri')} "
            f"source-file={csp_report.get('source-file')} "
            f"line-number={csp_report.get('line-number')}"
        )

        # Optionally store in database for analysis
        # CSPViolation.objects.create(
        #     blocked_uri=csp_report.get('blocked-uri'),
        #     violated_directive=csp_report.get('violated-directive'),
        #     ...
        # )

        return JsonResponse({'status': 'ok'})

    except Exception as e:
        logger.error(f"Error processing CSP report: {e}")
        return JsonResponse({'status': 'error'}, status=400)
'''

# URL configuration for CSP reporting
CSP_REPORT_URL = '''
# Shield AI: CSP Reporting URL
# Add to urls.py

from django.urls import path
from . import views

urlpatterns = [
    # ... other urls ...

    # Shield AI: CSP violation reporting endpoint
    path('api/csp-report/', views.csp_report, name='csp_report'),
]
'''

# ============================================================================
# REQUIREMENTS & DEPENDENCIES
# ============================================================================

REQUIREMENTS_ENTRY = '''# Shield AI: Content-Security-Policy
django-csp>=3.7  # CSP header middleware
'''

REQUIREMENTS_ENTRY_CUSTOM = '''# Shield AI: No additional dependencies for custom CSP middleware
# Custom implementation in utils/middleware.py
'''

# ============================================================================
# DOCUMENTATION TEMPLATE
# ============================================================================

DOCUMENTATION_TEMPLATE = '''## Content-Security-Policy (CSP) Added

Shield AI has added Content-Security-Policy headers to protect against
Cross-Site Scripting (XSS) attacks.

### What Was Added?

**CSP Headers:**
- Content-Security-Policy header on all HTTP responses
- Restricts which resources (scripts, styles, images, etc.) can be loaded
- Prevents execution of malicious injected scripts
- Browser-level XSS protection (defense-in-depth)

### How It Works

**When browser loads a page:**

1. **Server sends CSP header** with allowed resource origins
2. **Browser enforces policy** - blocks resources not matching policy
3. **XSS attempts blocked** - injected scripts can't execute
4. **Violations reported** - logged for monitoring and fixes

**Example CSP Header:**
```
Content-Security-Policy: default-src 'self'; script-src 'self';
style-src 'self'; img-src 'self' data: https:; frame-ancestors 'none'
```

### Implementation Options

**Option 1: django-csp (Recommended)**
```bash
# Install dependency
pip install django-csp

# Already added to settings.py:
MIDDLEWARE = [
    'csp.middleware.CSPMiddleware',  # CSP protection
    # ... other middleware ...
]

CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
# ... other directives ...
```

**Option 2: Custom CSP Middleware (No Dependencies)**
```python
# Custom middleware created in utils/middleware.py
# Adds CSP header to all responses
# Full control over CSP policy
```

### Phased Implementation

**Phase 1: Report-Only Mode (Current)**
```python
# Monitor violations without blocking
CSP_REPORT_ONLY = True
CSP_REPORT_URI = '/api/csp-report/'

# Violations logged but not blocked
# Safe for testing in production
```

**Phase 2: Enforcement Mode (After Validation)**
```python
# Enable enforcement after fixing violations
CSP_REPORT_ONLY = False  # or remove this line

# CSP now blocks violating resources
# Full XSS protection active
```

### CSP Policy Levels

**Strict Policy (Maximum Security):**
- No inline scripts: `script-src 'self'`
- No inline styles: `style-src 'self'`
- External resources must be HTTPS
- Best for new applications

**Moderate Policy (Compatibility):**
- Allow inline scripts: `script-src 'self' 'unsafe-inline'`
- Allow inline styles: `style-src 'self' 'unsafe-inline'`
- Good for existing applications during migration

### Configuration

**CSP Directives Configured:**

| Directive | Value | Purpose |
|-----------|-------|---------|
| default-src | 'self' | Default policy for all resources |
| script-src | 'self' | Only load scripts from same origin |
| style-src | 'self' | Only load styles from same origin |
| img-src | 'self' data: https: | Images from same origin, data URIs, HTTPS |
| font-src | 'self' data: | Fonts from same origin, data URIs |
| connect-src | 'self' | AJAX requests only to same origin |
| frame-ancestors | 'none' | Prevent clickjacking (no framing) |
| form-action | 'self' | Forms submit only to same origin |

### Violation Reporting

**CSP Violation Endpoint:**
```python
# Endpoint: /api/csp-report/
# Receives POST requests from browser when CSP violated
# Logs violations for analysis and fixes
```

**Example Violation Log:**
```
CSP Violation: blocked-uri=https://evil.com/script.js
violated-directive=script-src document-uri=https://yourapp.com/page
```

### Security Benefits

**Prevents:**
- XSS attacks via injected scripts
- Malicious external resource loading
- Clickjacking attacks
- Data exfiltration via unauthorized requests
- Session hijacking via XSS

**Defense-in-Depth:**
- Works even if input sanitization fails
- Browser-level enforcement
- No code changes required for protection
- Automatic blocking of violations

### Browser Support

**Coverage:**
- Chrome/Edge: Full support
- Firefox: Full support
- Safari: Full support
- Mobile browsers: 97%+ support
- Legacy browsers: Gracefully ignored (no errors)

### Testing CSP

**Check CSP header:**
```bash
# Verify CSP header in responses
curl -I https://yourapp.com | grep -i content-security-policy

# Expected output:
# Content-Security-Policy: default-src 'self'; script-src 'self'; ...
```

**Test violations:**
```javascript
// Try inline script (should be blocked in strict mode)
<script>alert('test')</script>

// Check browser console for CSP violation messages
```

**CSP Evaluator:**
- Use https://csp-evaluator.withgoogle.com/
- Paste your CSP policy for security analysis
- Get recommendations for improvements

### Common CSP Issues

**Issue 1: Inline scripts blocked**
```
Solution: Move scripts to external .js files
OR use nonces: <script nonce="{{request.csp_nonce}}">
```

**Issue 2: Third-party resources blocked**
```
Solution: Add trusted domains to CSP
CSP_SCRIPT_SRC = ("'self'", "https://trusted-cdn.com")
```

**Issue 3: Styles not loading**
```
Solution: Move inline styles to external .css files
OR allow unsafe-inline temporarily: CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
```

### Migration Strategy

**Step 1: Enable Report-Only Mode**
```python
CSP_REPORT_ONLY = True
CSP_REPORT_URI = '/api/csp-report/'
```

**Step 2: Monitor Violations**
- Review logs for violations
- Identify blocked resources
- Update CSP or fix violations

**Step 3: Fix Violations**
- Move inline scripts/styles to external files
- Add trusted domains to CSP
- Use nonces for dynamic content

**Step 4: Enable Enforcement**
```python
CSP_REPORT_ONLY = False  # Full protection active
```

### Compliance

**Meets security standards:**
- OWASP Top 10 2021 - A03:2021 Injection (XSS mitigation)
- OWASP ASVS V14.4 - HTTP Security Headers
- Mozilla Observatory - Required for A+ rating
- PCI DSS 6.5.7 - XSS prevention

### References

- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [django-csp Documentation](https://django-csp.readthedocs.io/)
- [CSP Quick Reference](https://content-security-policy.com/)
- [OWASP CSP Cheat Sheet](https://owasp.org/www-community/controls/Content_Security_Policy)
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)

**Pattern:** CSEC-29 - Missing Content-Security-Policy Header
**Severity:** High
**Status:** Fixed

For more information, see: [Shield AI Documentation](https://github.com/zaheerquodroid/Shield-AI-Backend)
'''


def get_csp_option(option='library', policy='moderate'):
    """
    Get the appropriate CSP configuration based on option and policy.

    Args:
        option: 'library' for django-csp or 'custom' for custom middleware
        policy: 'strict', 'moderate', or 'report-only'

    Returns:
        dict: Configuration details
    """
    if option == 'library':
        if policy == 'strict':
            config = DJANGO_CSP_STRICT_CONFIG
        elif policy == 'report-only':
            config = DJANGO_CSP_REPORT_ONLY_CONFIG
        else:  # moderate
            config = DJANGO_CSP_MODERATE_CONFIG

        return {
            'config': config,
            'middleware_addition': ADD_CSP_MIDDLEWARE,
            'requirements': REQUIREMENTS_ENTRY,
            'middleware_class': 'csp.middleware.CSPMiddleware',
        }
    else:  # custom
        return {
            'middleware_code': CUSTOM_CSP_MIDDLEWARE,
            'middleware_settings': CUSTOM_MIDDLEWARE_SETTINGS,
            'requirements': REQUIREMENTS_ENTRY_CUSTOM,
            'middleware_class': 'utils.middleware.ContentSecurityPolicyMiddleware',
            'report_view': CSP_REPORT_VIEW,
            'report_url': CSP_REPORT_URL,
        }


def format_template(template, **kwargs):
    """
    Format a template with given variables.

    Args:
        template: Template string
        **kwargs: Variables to substitute

    Returns:
        str: Formatted template
    """
    return template.format(**kwargs)
