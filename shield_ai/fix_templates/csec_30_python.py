"""
Fix templates for CSEC-30: Missing Permissions-Policy Header (Python/Django)
"""

# =============================================================================
# PART 1: PERMISSIONS-POLICY MIDDLEWARE
# =============================================================================

PERMISSIONS_POLICY_MIDDLEWARE_TEMPLATE = '''"""
Permissions-Policy Middleware - CSEC-30
Controls which browser features and APIs can be used

Created by Shield AI Backend
"""


class PermissionsPolicyMiddleware:
    """
    Django middleware that adds Permissions-Policy and Feature-Policy headers
    to restrict browser feature access.

    Permissions-Policy is the modern header (Chrome 88+)
    Feature-Policy is the legacy header (older browsers, Firefox)

    Both headers are included for maximum browser compatibility.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Add Permissions-Policy header (modern browsers)
        response['Permissions-Policy'] = self.get_permissions_policy()

        # Add Feature-Policy header (legacy browsers, Firefox)
        response['Feature-Policy'] = self.get_feature_policy()

        return response

    def get_permissions_policy(self):
        """
        Generate Permissions-Policy header value

        Syntax: directive=(allowlist)
        - () = Disabled for all origins
        - (self) = Allowed for same origin only
        - (self "https://example.com") = Allowed for self and specific origins
        - * = Allowed for all origins (not recommended)

        Returns:
            str: Permissions-Policy header value
        """
        policies = [
            # Highly sensitive features - deny by default
            'camera=()',                    # No camera access
            'microphone=()',                # No microphone access
            'geolocation=()',               # No geolocation access
            'payment=()',                   # No payment APIs
            'usb=()',                       # No USB device access
            'magnetometer=()',              # No magnetometer access
            'gyroscope=()',                 # No gyroscope access
            'accelerometer=()',             # No accelerometer access

            # Less sensitive - allow for same origin
            'fullscreen=(self)',            # Allow fullscreen for same origin
            'picture-in-picture=(self)',    # Allow PiP for same origin
            'display-capture=(self)',       # Allow screen sharing for same origin

            # Clipboard access (same origin only)
            'clipboard-read=(self)',        # Allow clipboard read for same origin
            'clipboard-write=(self)',       # Allow clipboard write for same origin

            # Media features
            'autoplay=(self)',              # Control media autoplay

            # Deprecated/restricted features
            'sync-xhr=()',                  # Disable synchronous XHR (slow, deprecated)
        ]

        return ', '.join(policies)

    def get_feature_policy(self):
        """
        Generate Feature-Policy header value (legacy format)

        Syntax: directive 'allowlist'
        - 'none' = Disabled for all origins
        - 'self' = Allowed for same origin only
        - 'self' https://example.com = Allowed for self and specific origins
        - * = Allowed for all origins (not recommended)

        Returns:
            str: Feature-Policy header value
        """
        policies = [
            # Highly sensitive features - deny by default
            "camera 'none'",
            "microphone 'none'",
            "geolocation 'none'",
            "payment 'none'",
            "usb 'none'",
            "magnetometer 'none'",
            "gyroscope 'none'",
            "accelerometer 'none'",

            # Less sensitive - allow for same origin
            "fullscreen 'self'",
            "picture-in-picture 'self'",
            "display-capture 'self'",

            # Clipboard access
            "clipboard-read 'self'",
            "clipboard-write 'self'",

            # Media features
            "autoplay 'self'",

            # Deprecated features
            "sync-xhr 'none'",
        ]

        return '; '.join(policies)
'''


# =============================================================================
# PART 2: CUSTOMIZABLE PERMISSIONS-POLICY MIDDLEWARE
# =============================================================================

CUSTOMIZABLE_MIDDLEWARE_TEMPLATE = '''"""
Customizable Permissions-Policy Middleware - CSEC-30
Allows configuration via Django settings

Created by Shield AI Backend
"""
from django.conf import settings


class PermissionsPolicyMiddleware:
    """
    Configurable Permissions-Policy middleware

    Configure in settings.py:
        PERMISSIONS_POLICY = {{
            'camera': [],              # Deny all
            'microphone': [],          # Deny all
            'geolocation': [],         # Deny all
            'fullscreen': ['self'],    # Allow same origin
        }}
    """

    # Default policy (restrictive)
    DEFAULT_POLICY = {{
        'camera': [],
        'microphone': [],
        'geolocation': [],
        'payment': [],
        'usb': [],
        'magnetometer': [],
        'gyroscope': [],
        'accelerometer': [],
        'fullscreen': ['self'],
        'picture-in-picture': ['self'],
        'display-capture': ['self'],
        'clipboard-read': ['self'],
        'clipboard-write': ['self'],
        'autoplay': ['self'],
        'sync-xhr': [],
    }}

    def __init__(self, get_response):
        self.get_response = get_response
        self.policy = getattr(settings, 'PERMISSIONS_POLICY', self.DEFAULT_POLICY)

    def __call__(self, request):
        response = self.get_response(request)

        response['Permissions-Policy'] = self._build_permissions_policy()
        response['Feature-Policy'] = self._build_feature_policy()

        return response

    def _build_permissions_policy(self):
        """Build Permissions-Policy header from configuration"""
        policies = []

        for directive, allowlist in self.policy.items():
            if not allowlist:
                # Empty list = deny all
                policies.append(f'{{directive}}=()')
            else:
                # Format allowlist
                formatted = ' '.join(
                    f'"{{origin}}"' if origin != 'self' else origin
                    for origin in allowlist
                )
                policies.append(f'{{directive}}=({{formatted}})')

        return ', '.join(policies)

    def _build_feature_policy(self):
        """Build Feature-Policy header from configuration (legacy format)"""
        policies = []

        for directive, allowlist in self.policy.items():
            if not allowlist:
                # Empty list = 'none'
                policies.append(f"{{directive}} 'none'")
            else:
                # Format allowlist
                formatted = ' '.join(
                    f"'{{origin}}'" if origin == 'self' else origin
                    for origin in allowlist
                )
                policies.append(f"{{directive}} {{formatted}}")

        return '; '.join(policies)
'''


# =============================================================================
# PART 3: SETTINGS CONFIGURATION
# =============================================================================

SETTINGS_MIDDLEWARE_ADDITION = '''
# Shield AI: CSEC-30 - Permissions-Policy Header
# Add to MIDDLEWARE list (after SecurityMiddleware)

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'middleware.permissions_policy.PermissionsPolicyMiddleware',  # Add this line
    'django.contrib.sessions.middleware.SessionMiddleware',
    # ... rest of middleware
]
'''

SETTINGS_CUSTOM_POLICY_CONFIG = '''
# Shield AI: CSEC-30 - Custom Permissions-Policy Configuration
# Optional: Customize which features are allowed

PERMISSIONS_POLICY = {{
    # Highly sensitive features - deny by default
    'camera': [],                      # No camera access
    'microphone': [],                  # No microphone access
    'geolocation': [],                 # No geolocation access
    'payment': [],                     # No payment APIs
    'usb': [],                         # No USB access

    # Less sensitive - allow for same origin
    'fullscreen': ['self'],            # Allow fullscreen
    'picture-in-picture': ['self'],    # Allow PiP
    'clipboard-read': ['self'],        # Allow clipboard read
    'clipboard-write': ['self'],       # Allow clipboard write

    # Media autoplay
    'autoplay': ['self'],              # Allow autoplay from same origin

    # If you need to allow specific external origins:
    # 'camera': ['self', 'https://trusted-video-service.com'],
}}
'''


# =============================================================================
# PART 4: TESTING UTILITIES
# =============================================================================

TEST_PERMISSIONS_POLICY_SCRIPT = '''"""
Test script to verify Permissions-Policy header

Usage:
    python test_permissions_policy.py
"""
import requests


def test_permissions_policy(url='http://localhost:8000'):
    """Test if Permissions-Policy header is present"""

    print(f"Testing Permissions-Policy header on {{url}}")
    print("=" * 60)

    try:
        response = requests.get(url)

        # Check for Permissions-Policy header
        permissions_policy = response.headers.get('Permissions-Policy')
        feature_policy = response.headers.get('Feature-Policy')

        if permissions_policy:
            print("[OK] Permissions-Policy header found!")
            print(f"Value: {{permissions_policy}}")
        else:
            print("[FAIL] Permissions-Policy header NOT found!")

        print()

        if feature_policy:
            print("[OK] Feature-Policy header found!")
            print(f"Value: {{feature_policy}}")
        else:
            print("[WARN] Feature-Policy header NOT found (optional)")

        print()
        print("=" * 60)

        # Verify specific directives
        if permissions_policy:
            print("Checking specific directives:")
            print()

            checks = [
                ('camera=()', 'Camera disabled'),
                ('microphone=()', 'Microphone disabled'),
                ('geolocation=()', 'Geolocation disabled'),
                ('fullscreen=(self)', 'Fullscreen allowed for same origin'),
            ]

            for directive, description in checks:
                if directive in permissions_policy:
                    print(f"[OK] {{description}}")
                else:
                    print(f"[WARN] {{description}} - not found")

    except requests.RequestException as e:
        print(f"[ERROR] Failed to connect: {{e}}")


if __name__ == '__main__':
    test_permissions_policy()
'''


# =============================================================================
# PART 5: DOCUMENTATION TEMPLATE
# =============================================================================

DOCUMENTATION_TEMPLATE = '''## Security Fix: Permissions-Policy Header (CSEC-30)

Shield AI has added Permissions-Policy header to control browser feature access.

### What Changed

**Before (VULNERABLE):**
- No Permissions-Policy header
- Browser features unrestricted
- Embedded content can access camera/microphone
- Geolocation tracking possible without explicit permission

**After (PROTECTED):**
- Permissions-Policy header added to all responses
- Camera and microphone access denied by default
- Geolocation tracking prevented
- Payment APIs restricted
- Other sensitive features controlled

### Why This Matters

Without Permissions-Policy, malicious embedded content can:
- 🔴 Access camera/microphone without user knowledge
- 🔴 Track user location via geolocation
- 🔴 Autoplay media draining battery/bandwidth
- 🔴 Trigger payment requests
- 🔴 Access USB devices
- 🔴 Collect sensor data (accelerometer, gyroscope)

### Header Details

**Permissions-Policy (Modern):**
```
Permissions-Policy: camera=(), microphone=(), geolocation=(),
payment=(), fullscreen=(self), picture-in-picture=(self)
```

**Feature-Policy (Legacy):**
```
Feature-Policy: camera 'none'; microphone 'none'; geolocation 'none';
payment 'none'; fullscreen 'self'; picture-in-picture 'self'
```

### Browser Feature Controls

| Feature | Policy | Description |
|---------|--------|-------------|
| camera | () | Deny camera access to all origins |
| microphone | () | Deny microphone access to all origins |
| geolocation | () | Deny geolocation access to all origins |
| payment | () | Deny payment API access |
| usb | () | Deny USB device access |
| fullscreen | (self) | Allow fullscreen for same origin only |
| picture-in-picture | (self) | Allow PiP for same origin only |
| clipboard-read | (self) | Allow clipboard read for same origin |
| clipboard-write | (self) | Allow clipboard write for same origin |

### Policy Syntax

**Permissions-Policy:**
- `()` = Disabled for all origins
- `(self)` = Allowed for same origin only
- `(self "https://trusted.com")` = Allow for self and specific origin
- `*` = Allowed for all origins (not recommended)

**Feature-Policy:**
- `'none'` = Disabled for all origins
- `'self'` = Allowed for same origin only
- `'self' https://trusted.com` = Allow for self and specific origin
- `*` = Allowed for all origins (not recommended)

### Files Created/Modified

- `middleware/permissions_policy.py` - Custom middleware
- `settings.py` - Middleware added to MIDDLEWARE list
- `SECURITY_UPDATES.md` - Documentation

### Verification

**Method 1: Browser DevTools**
1. Open your site in Chrome/Edge
2. Open DevTools (F12)
3. Go to Network tab
4. Refresh page
5. Click on any request
6. Check Response Headers for `Permissions-Policy`

**Method 2: curl**
```bash
curl -I http://localhost:8000 | grep -i "permissions-policy\\|feature-policy"

# Expected output:
# Permissions-Policy: camera=(), microphone=(), ...
# Feature-Policy: camera 'none'; microphone 'none'; ...
```

**Method 3: Test Script**
```bash
python test_permissions_policy.py
```

### Customization

To allow specific features, edit `settings.py`:

```python
# Example: Allow camera for trusted video service
PERMISSIONS_POLICY = {{
    'camera': ['self', 'https://video.trusted.com'],
    'microphone': ['self', 'https://video.trusted.com'],
    'geolocation': [],  # Still deny geolocation
    # ... other features
}}
```

### Browser Compatibility

| Browser | Support | Notes |
|---------|---------|-------|
| Chrome 88+ | ✅ Full | Permissions-Policy |
| Edge 88+ | ✅ Full | Permissions-Policy |
| Opera 74+ | ✅ Full | Permissions-Policy |
| Safari | ⚠️ Partial | Uses Feature-Policy |
| Firefox | ⚠️ Partial | Uses Feature-Policy |

Both headers are included for maximum compatibility.

### Security Benefits

**Prevents:**
- ✅ Unauthorized camera/microphone access
- ✅ Geolocation tracking without consent
- ✅ Malicious iframe feature abuse
- ✅ Clickjacking via fullscreen API
- ✅ USB device access attacks
- ✅ Sensor data leakage

### Compliance

**Meets security standards:**
- ✅ OWASP ASVS V14.4 - HTTP Security Headers
- ✅ Mozilla Web Security Guidelines
- ✅ GDPR Privacy Requirements (feature restrictions)

### Troubleshooting

**Feature not working:**
1. Check if feature is in PERMISSIONS_POLICY
2. Verify middleware is in MIDDLEWARE list
3. Ensure middleware is loaded (check response headers)
4. Clear browser cache

**Need to allow feature:**
1. Add to PERMISSIONS_POLICY in settings.py
2. Use `(self)` for same-origin access
3. Specify exact origins for third-party access
4. Restart Django server

---
**Pattern:** CSEC-30
**Severity:** Medium (P1-High)
**Status:** Implemented ✅
'''


# =============================================================================
# PART 6: HELPER FUNCTIONS
# =============================================================================

def get_middleware_template(customizable=False):
    """
    Get middleware template

    Args:
        customizable: If True, returns configurable version

    Returns:
        str: Middleware template code
    """
    if customizable:
        return CUSTOMIZABLE_MIDDLEWARE_TEMPLATE
    else:
        return PERMISSIONS_POLICY_MIDDLEWARE_TEMPLATE


def get_settings_update():
    """Get settings.py update template"""
    return SETTINGS_MIDDLEWARE_ADDITION


def get_custom_policy_config():
    """Get custom policy configuration template"""
    return SETTINGS_CUSTOM_POLICY_CONFIG


def get_test_script():
    """Get test script template"""
    return TEST_PERMISSIONS_POLICY_SCRIPT


def generate_documentation():
    """Generate complete CSEC-30 documentation"""
    return DOCUMENTATION_TEMPLATE


def format_template(template, **kwargs):
    """Format a template with given variables"""
    return template.format(**kwargs)
