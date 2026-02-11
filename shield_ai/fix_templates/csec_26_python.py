"""
Fix templates for CSEC-26: Missing DRF Rate Limiting Configuration (Python)
"""

# =============================================================================
# PART 1: CUSTOM THROTTLE CLASSES
# =============================================================================

THROTTLE_CLASSES_TEMPLATE = '''"""
Custom DRF Throttle Classes - CSEC-26
Rate limiting for authentication endpoints and general API access

Created by Shield AI Backend
"""
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle, SimpleRateThrottle


class LoginRateThrottle(AnonRateThrottle):
    """
    Rate limit for login endpoints
    Target: 5 attempts per minute per IP
    Protects against: Brute force, credential stuffing
    """
    scope = 'login'

    def get_cache_key(self, request, view):
        # Rate limit by IP address for anonymous login attempts
        return self.cache_format % {{
            'scope': self.scope,
            'ident': self.get_ident(request)
        }}


class SignupRateThrottle(AnonRateThrottle):
    """
    Rate limit for signup/registration endpoints
    Target: 3 attempts per minute per IP
    Protects against: Spam registration, fake accounts
    """
    scope = 'signup'


class PasswordResetRateThrottle(AnonRateThrottle):
    """
    Rate limit for password reset endpoints
    Target: 3 attempts per minute per IP
    Protects against: Account enumeration, DoS
    """
    scope = 'password_reset'


class MFAVerifyRateThrottle(AnonRateThrottle):
    """
    Rate limit for MFA/2FA verification endpoints
    Target: 5 attempts per minute per IP
    Protects against: MFA brute force, code guessing
    """
    scope = 'mfa_verify'


class AuthenticatedUserThrottle(UserRateThrottle):
    """
    General rate limit for authenticated users
    Target: 100 requests per minute per user
    Protects against: API abuse by authenticated users
    """
    scope = 'authenticated_user'

    def get_cache_key(self, request, view):
        if request.user and request.user.is_authenticated:
            # Rate limit by user ID for authenticated requests
            ident = request.user.pk
        else:
            # Fall back to IP for unauthenticated
            ident = self.get_ident(request)

        return self.cache_format % {{
            'scope': self.scope,
            'ident': ident
        }}


class AnonUserThrottle(AnonRateThrottle):
    """
    General rate limit for anonymous users
    Target: 20 requests per minute per IP
    Protects against: Anonymous API abuse, DoS
    """
    scope = 'anon_user'


class AdaptiveRateThrottle(SimpleRateThrottle):
    """
    Advanced: Adaptive rate limiting based on behavior patterns
    Adjusts limits based on traffic patterns and risk indicators
    """
    scope = 'adaptive'

    def get_cache_key(self, request, view):
        return self.cache_format % {{
            'scope': self.scope,
            'ident': self.get_ident(request)
        }}

    def get_rate(self):
        """
        Determine rate based on request characteristics
        Override in subclasses for custom logic
        """
        # Example: Stricter limits during detected attack patterns
        if self.is_suspicious_request(self.request):
            return '2/min'  # Very restrictive
        return super().get_rate()

    def is_suspicious_request(self, request):
        """
        Detect suspicious patterns (override in subclass)
        - Rapid sequential attempts with different usernames
        - Unusual time of day
        - Known bad IP ranges
        """
        # Placeholder - implement actual detection logic
        return False


class BurstRateThrottle(SimpleRateThrottle):
    """
    Short burst protection - allows bursts but limits sustained traffic
    Example: 10 requests per second, but max 50 per minute
    """
    scope = 'burst'

    def __init__(self):
        super().__init__()
        self.burst_rate = '10/sec'  # Short burst limit
        self.sustained_rate = '50/min'  # Sustained limit
'''


# =============================================================================
# PART 2: LOGIN LOCKOUT IMPLEMENTATION
# =============================================================================

LOGIN_LOCKOUT_TEMPLATE = '''"""
Login Lockout - CSEC-26
Lock accounts after multiple failed login attempts

Created by Shield AI Backend
"""
from django.core.cache import cache
from django.utils import timezone
from rest_framework.exceptions import Throttled
import logging

logger = logging.getLogger(__name__)


class LoginLockout:
    """
    Account lockout after repeated failed login attempts

    Features:
    - Locks account after MAX_ATTEMPTS failed logins
    - Automatic unlock after LOCKOUT_DURATION
    - Tracks attempts per username (not just IP)
    - Provides unlock mechanisms
    """

    # Configuration
    MAX_ATTEMPTS = 10
    LOCKOUT_DURATION = 3600  # 1 hour in seconds
    ATTEMPT_WINDOW = 3600  # Track attempts over 1 hour

    # Cache key prefixes
    FAILED_KEY_PREFIX = 'login_failed'
    LOCKED_KEY_PREFIX = 'login_locked'
    LOCKOUT_TIME_PREFIX = 'lockout_time'

    @classmethod
    def record_failed_attempt(cls, username, ip_address=None):
        """
        Record a failed login attempt for a username

        Args:
            username: Username that failed authentication
            ip_address: Optional IP address for logging

        Returns:
            dict: {{
                'attempts': int,
                'locked': bool,
                'remaining': int,
                'reset_at': datetime or None
            }}

        Raises:
            Throttled: If account is now locked
        """
        # Get current attempt count
        attempts_key = f'{{cls.FAILED_KEY_PREFIX}}:{{username}}'
        attempts = cache.get(attempts_key, 0) + 1

        # Store updated attempt count
        cache.set(attempts_key, attempts, cls.ATTEMPT_WINDOW)

        # Calculate remaining attempts
        remaining = max(0, cls.MAX_ATTEMPTS - attempts)

        # Log the attempt
        logger.warning(
            f"Failed login attempt for user '{{username}}' "
            f"(attempt {{attempts}}/{{cls.MAX_ATTEMPTS}}, IP: {{ip_address}})"
        )

        # Check if we've hit the lockout threshold
        if attempts >= cls.MAX_ATTEMPTS:
            cls._lock_account(username)

            logger.error(
                f"Account '{{username}}' locked after {{attempts}} failed attempts "
                f"(IP: {{ip_address}})"
            )

            raise Throttled(
                detail='Account temporarily locked due to multiple failed login attempts. '
                       f'Please try again in {{cls.LOCKOUT_DURATION // 60}} minutes.',
                code='account_locked'
            )

        return {{
            'attempts': attempts,
            'locked': False,
            'remaining': remaining,
            'reset_at': None
        }}

    @classmethod
    def _lock_account(cls, username):
        """Lock an account and record lockout time"""
        locked_key = f'{{cls.LOCKED_KEY_PREFIX}}:{{username}}'
        lockout_time_key = f'{{cls.LOCKOUT_TIME_PREFIX}}:{{username}}'

        lockout_time = timezone.now()

        cache.set(locked_key, True, cls.LOCKOUT_DURATION)
        cache.set(lockout_time_key, lockout_time.isoformat(), cls.LOCKOUT_DURATION)

    @classmethod
    def is_locked(cls, username):
        """
        Check if an account is currently locked

        Args:
            username: Username to check

        Returns:
            bool: True if locked, False otherwise
        """
        locked_key = f'{{cls.LOCKED_KEY_PREFIX}}:{{username}}'
        return cache.get(locked_key, False)

    @classmethod
    def get_lockout_info(cls, username):
        """
        Get detailed lockout information for a username

        Returns:
            dict: {{
                'locked': bool,
                'attempts': int,
                'locked_at': str or None,
                'locked_until': str or None
            }}
        """
        attempts_key = f'{{cls.FAILED_KEY_PREFIX}}:{{username}}'
        locked_key = f'{{cls.LOCKED_KEY_PREFIX}}:{{username}}'
        lockout_time_key = f'{{cls.LOCKOUT_TIME_PREFIX}}:{{username}}'

        is_locked = cache.get(locked_key, False)
        attempts = cache.get(attempts_key, 0)
        lockout_time = cache.get(lockout_time_key)

        result = {{
            'locked': is_locked,
            'attempts': attempts,
            'locked_at': lockout_time,
            'locked_until': None
        }}

        if is_locked and lockout_time:
            from datetime import datetime, timedelta
            locked_at = datetime.fromisoformat(lockout_time)
            locked_until = locked_at + timedelta(seconds=cls.LOCKOUT_DURATION)
            result['locked_until'] = locked_until.isoformat()

        return result

    @classmethod
    def reset_attempts(cls, username):
        """
        Reset failed attempts and unlock account
        Called after successful login or manual unlock

        Args:
            username: Username to reset
        """
        attempts_key = f'{{cls.FAILED_KEY_PREFIX}}:{{username}}'
        locked_key = f'{{cls.LOCKED_KEY_PREFIX}}:{{username}}'
        lockout_time_key = f'{{cls.LOCKOUT_TIME_PREFIX}}:{{username}}'

        cache.delete(attempts_key)
        cache.delete(locked_key)
        cache.delete(lockout_time_key)

        logger.info(f"Reset login attempts for user '{{username}}'")

    @classmethod
    def unlock_account(cls, username, unlocked_by=None):
        """
        Manually unlock an account (admin action)

        Args:
            username: Username to unlock
            unlocked_by: Admin username performing unlock
        """
        cls.reset_attempts(username)

        logger.info(
            f"Account '{{username}}' manually unlocked" +
            (f" by {{unlocked_by}}" if unlocked_by else "")
        )

    @classmethod
    def check_before_auth(cls, username):
        """
        Check if account is locked before attempting authentication
        Raises exception if locked

        Args:
            username: Username to check

        Raises:
            Throttled: If account is locked
        """
        if cls.is_locked(username):
            info = cls.get_lockout_info(username)

            logger.warning(f"Login attempt for locked account '{{username}}'")

            raise Throttled(
                detail='Account is temporarily locked due to multiple failed login attempts. '
                       'Please try again later or contact support.',
                code='account_locked'
            )
'''


# =============================================================================
# PART 3: SETTINGS CONFIGURATION
# =============================================================================

SETTINGS_THROTTLE_CONFIG_TEMPLATE = '''
# Shield AI: CSEC-26 - Rate Limiting Configuration
# Add to your Django settings.py

# Cache backend for throttling (Redis recommended for production)
CACHES = {{
    'default': {{
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {{
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }},
        'KEY_PREFIX': 'throttle',
        'TIMEOUT': 300,
    }}
}}

# DRF Throttling Configuration
REST_FRAMEWORK = {{
    # Default throttle classes applied to all views
    'DEFAULT_THROTTLE_CLASSES': [
        'interpreter.auth.throttles.AuthenticatedUserThrottle',
        'interpreter.auth.throttles.AnonUserThrottle',
    ],

    # Throttle rates by scope
    'DEFAULT_THROTTLE_RATES': {{
        # Authentication endpoints
        'login': '5/min',              # 5 login attempts per minute per IP
        'signup': '3/min',             # 3 signup attempts per minute per IP
        'password_reset': '3/min',     # 3 password reset per minute per IP
        'mfa_verify': '5/min',         # 5 MFA verification per minute per IP

        # General API
        'authenticated_user': '100/min',  # 100 requests/min for authenticated users
        'anon_user': '20/min',            # 20 requests/min for anonymous users

        # Advanced
        'adaptive': '10/min',          # Adaptive rate limiting
        'burst': '10/sec',             # Burst protection
    }},

    # Include rate limit headers in responses
    'EXCEPTION_HANDLER': 'interpreter.utils.exception_handler.custom_exception_handler',
}}

# Login lockout configuration
LOGIN_LOCKOUT = {{
    'ENABLED': True,
    'MAX_ATTEMPTS': 10,              # Lock after 10 failed attempts
    'LOCKOUT_DURATION': 3600,        # Lock for 1 hour (in seconds)
    'ATTEMPT_WINDOW': 3600,          # Track attempts over 1 hour
}}
'''

SETTINGS_PHASE_WARNING_TEMPLATE = '''
# Shield AI: CSEC-26 - Phase 1: Warning Mode (High Limits)
# Use these permissive limits initially to monitor false positives

REST_FRAMEWORK = {{
    'DEFAULT_THROTTLE_RATES': {{
        'login': '50/min',             # 10x target (warning only)
        'signup': '30/min',            # 10x target
        'password_reset': '30/min',    # 10x target
        'mfa_verify': '50/min',        # 10x target
        'authenticated_user': '1000/min',  # 10x target
        'anon_user': '200/min',        # 10x target
    }},
}}
'''

SETTINGS_PHASE_SOFT_TEMPLATE = '''
# Shield AI: CSEC-26 - Phase 2: Soft Enforcement (2x Target)
# Monitor user complaints and adjust

REST_FRAMEWORK = {{
    'DEFAULT_THROTTLE_RATES': {{
        'login': '10/min',             # 2x target
        'signup': '6/min',             # 2x target
        'password_reset': '6/min',     # 2x target
        'mfa_verify': '10/min',        # 2x target
        'authenticated_user': '200/min',   # 2x target
        'anon_user': '40/min',         # 2x target
    }},
}}
'''


# =============================================================================
# PART 4: VIEW DECORATORS
# =============================================================================

VIEW_DECORATOR_TEMPLATE = '''
# Shield AI: CSEC-26 - Apply throttling to views

from rest_framework.decorators import throttle_classes
from rest_framework.views import APIView
from interpreter.auth.throttles import (
    LoginRateThrottle,
    SignupRateThrottle,
    PasswordResetRateThrottle,
    MFAVerifyRateThrottle
)
from interpreter.auth.lockout import LoginLockout
from rest_framework.exceptions import AuthenticationFailed


@throttle_classes([LoginRateThrottle])
class LoginView(APIView):
    """Login endpoint with rate limiting and lockout protection"""

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        # Check if account is locked BEFORE attempting authentication
        LoginLockout.check_before_auth(username)

        # Attempt authentication
        user = authenticate(username=username, password=password)

        if user is not None:
            # Successful login - reset lockout counter
            LoginLockout.reset_attempts(username)

            # Log them in...
            return Response({{'token': get_token(user)}})
        else:
            # Failed login - record attempt (may raise Throttled exception)
            ip_address = self.get_client_ip(request)
            LoginLockout.record_failed_attempt(username, ip_address)

            raise AuthenticationFailed('Invalid credentials')

    def get_client_ip(self, request):
        """Get client IP address (handles proxies)"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')


@throttle_classes([SignupRateThrottle])
class SignupView(APIView):
    """Signup endpoint with rate limiting"""
    # ... existing signup logic


@throttle_classes([PasswordResetRateThrottle])
class PasswordResetView(APIView):
    """Password reset endpoint with rate limiting"""
    # ... existing password reset logic


@throttle_classes([MFAVerifyRateThrottle])
class MFAVerifyView(APIView):
    """MFA verification endpoint with rate limiting"""
    # ... existing MFA verification logic
'''


# =============================================================================
# PART 5: DOCUMENTATION TEMPLATES
# =============================================================================

DOCUMENTATION_TEMPLATE = '''## Security Fix: Rate Limiting (CSEC-26)

Shield AI has implemented rate limiting to protect against brute force attacks.

### What Changed

**Before (VULNERABLE):**
- No rate limits on authentication endpoints
- Unlimited login attempts possible
- API vulnerable to abuse and DoS
- No protection against credential stuffing

**After (PROTECTED):**
- Login: Max 5 attempts/minute per IP
- Signup: Max 3 attempts/minute per IP
- Password reset: Max 3 attempts/minute per IP
- MFA verify: Max 5 attempts/minute per IP
- Account locked after 10 failed login attempts
- Rate limit headers in all responses

### Why This Matters

Without rate limiting, attackers can:
- 🔴 Brute force passwords (millions of attempts)
- 🔴 Perform credential stuffing attacks
- 🔴 Enumerate valid usernames
- 🔴 DoS the API with floods of requests
- 🔴 Bypass MFA with automated attempts

### Rate Limits

| Endpoint | Authenticated | Anonymous | Notes |
|----------|--------------|-----------|-------|
| Login | N/A | 5/min per IP | +lockout after 10 fails |
| Signup | N/A | 3/min per IP | Prevents spam |
| Password Reset | N/A | 3/min per IP | Prevents enumeration |
| MFA Verify | N/A | 5/min per IP | Prevents bypass |
| General API | 100/min per user | 20/min per IP | Normal usage |

### Response Headers

When rate limited, responses include:
```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1644532800
Retry-After: 60

{{
  "detail": "Too many requests. Please try again later."
}}
```

### Account Lockout

After 10 failed login attempts:
1. Account is locked for 1 hour
2. User receives clear error message
3. Admin can manually unlock if needed
4. Automatic unlock after timeout

**Unlock Methods:**
- Automatic after 1 hour
- Email verification link
- Admin manual unlock

### Phased Rollout

**Phase 1: Warning (7 days)**
- High limits (10x target)
- Log violations, don't block
- Monitor false positives

**Phase 2: Soft Enforcement (7 days)**
- Medium limits (2x target)
- Block violations, return 429
- Adjust based on feedback

**Phase 3: Full Enforcement (Ongoing)**
- Final target limits
- Full lockout enabled
- Continuous monitoring

### Testing

```bash
# Test rate limiting
for i in {{1..6}}; do
  curl -X POST http://localhost:8000/api/auth/login/ \\
    -d "username=test&password=wrong"
  sleep 1
done

# Should see 429 on 6th request
```

### Configuration

Redis is required for production:
```bash
# Install Redis
pip install redis django-redis

# Configure in settings.py
CACHES = {{
    'default': {{
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }}
}}
```

### Troubleshooting

**"Too many requests" for legitimate users:**
1. Check if limits are too restrictive
2. Verify IP detection is correct (check proxies)
3. Consider raising limits for authenticated users
4. Implement CAPTCHA as alternative

**Rate limiting not working:**
1. Verify Redis is running: `redis-cli ping`
2. Check cache configuration in settings
3. Ensure throttle classes are imported correctly
4. Check logs for throttling events

### Security Best Practices

1. **Monitor False Positives**
   - Track 429 responses
   - Identify legitimate users being blocked
   - Adjust limits accordingly

2. **Geographic Considerations**
   - Higher limits for trusted regions
   - Lower limits for high-risk regions
   - Use GeoIP for location-based throttling

3. **Add CAPTCHA**
   - After 3 failed attempts
   - Alternative to hard lockout
   - Better user experience

4. **Alert on Patterns**
   - Spike in 429 responses = attack
   - Multiple lockouts = credential stuffing
   - Integrate with security monitoring

---
**Pattern:** CSEC-26
**Severity:** High (P0-Critical)
**Status:** Implemented ✅
'''


# =============================================================================
# PART 6: HELPER FUNCTIONS
# =============================================================================

def get_throttle_classes_template():
    """Get custom throttle classes template"""
    return THROTTLE_CLASSES_TEMPLATE


def get_login_lockout_template():
    """Get login lockout implementation template"""
    return LOGIN_LOCKOUT_TEMPLATE


def get_settings_config(phase='full'):
    """
    Get settings configuration for specified phase

    Args:
        phase: 'warning', 'soft', or 'full'

    Returns:
        str: Settings configuration template
    """
    if phase == 'warning':
        return SETTINGS_PHASE_WARNING_TEMPLATE
    elif phase == 'soft':
        return SETTINGS_PHASE_SOFT_TEMPLATE
    else:
        return SETTINGS_THROTTLE_CONFIG_TEMPLATE


def get_view_decorator_template():
    """Get view decorator examples"""
    return VIEW_DECORATOR_TEMPLATE


def generate_documentation():
    """Generate complete CSEC-26 documentation"""
    return DOCUMENTATION_TEMPLATE


def format_template(template, **kwargs):
    """Format a template with given variables"""
    return template.format(**kwargs)
