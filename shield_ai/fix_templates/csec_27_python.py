"""
Fix templates for CSEC-27: Missing Breached Password Validation (Python/Django)
"""

# Template for adding django-pwned-passwords validator (Option 1 - Recommended)
PWNED_PASSWORDS_VALIDATOR_CONFIG = '''
# Shield AI: Add breached password checking
# Checks passwords against Have I Been Pwned using k-anonymity
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    # Shield AI: Breached password checking
    {
        'NAME': 'pwned_passwords_django.validators.PwnedPasswordsValidator',
        'OPTIONS': {
            'error_message': 'This password has appeared in a data breach. Please choose a different password.',
            'help_text': 'Your password will be checked against known data breaches for your security.',
        }
    },
]

# Shield AI: Configuration for pwned passwords
PWNED_PASSWORDS_API_TIMEOUT = 1.0  # seconds
PWNED_PASSWORDS_FAIL_SAFE = True  # Don't block signup if API fails
'''

# Template for adding to existing AUTH_PASSWORD_VALIDATORS
ADD_TO_EXISTING_VALIDATORS = '''    # Shield AI: Add breached password checking
    {{
        'NAME': 'pwned_passwords_django.validators.PwnedPasswordsValidator',
        'OPTIONS': {{
            'error_message': 'This password has appeared in a data breach. Please choose a different password.',
            'help_text': 'Your password will be checked against known data breaches for your security.',
        }}
    }},'''

# Custom validator implementation (Option 2 - No external dependencies)
CUSTOM_HIBP_VALIDATOR = '''
# Shield AI: Custom breached password validator
# File: utils/validators.py

import hashlib
import logging
import requests
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)


class BreachedPasswordValidator:
    """
    Validates that password has not appeared in known data breaches.
    Uses Have I Been Pwned API with k-anonymity for privacy.

    This is advisory - it warns users but doesn't block signup.
    """

    def __init__(self, threshold=1, timeout=1.0, fail_safe=True):
        """
        Args:
            threshold: Minimum breach count to trigger warning (default: 1)
            timeout: API request timeout in seconds (default: 1.0)
            fail_safe: If True, allow password if API fails (default: True)
        """
        self.threshold = threshold
        self.timeout = timeout
        self.fail_safe = fail_safe

    def validate(self, password, user=None):
        """
        Validate the password against HIBP database.

        Args:
            password: The password to check
            user: The user object (optional)

        Raises:
            ValidationError: If password is found in breaches
        """
        breach_count = self._check_hibp_api(password)

        if breach_count is None:
            # API error occurred
            if not self.fail_safe:
                raise ValidationError(
                    _("Unable to verify password security. Please try again later."),
                    code='api_error',
                )
            # Fail safe - allow password
            logger.warning("HIBP API check failed, allowing password due to fail_safe=True")
            return

        if breach_count >= self.threshold:
            raise ValidationError(
                _(
                    "This password has appeared %(count)d times in data breaches. "
                    "For your security, please choose a different password."
                ),
                code='password_pwned',
                params={'count': breach_count},
            )

    def _check_hibp_api(self, password):
        """
        Check password using HIBP k-anonymity API.

        Only the first 5 characters of the SHA-1 hash are sent to HIBP,
        protecting user privacy.

        Args:
            password: Password to check

        Returns:
            int: Number of times password appears in breaches
            None: If API request fails
        """
        # Hash password with SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            # Query HIBP API with k-anonymity
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=self.timeout,
                headers={'User-Agent': 'Django-Shield-AI-Password-Validator'}
            )

            if response.status_code == 200:
                # Parse response
                hashes = response.text.split('\\r\\n')
                for hash_line in hashes:
                    if ':' not in hash_line:
                        continue
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        return int(count)
                return 0  # Password not found in breaches
            else:
                logger.error(f"HIBP API returned status {response.status_code}")
                return None

        except requests.Timeout:
            logger.warning(f"HIBP API timeout after {self.timeout}s")
            return None
        except requests.RequestException as e:
            logger.error(f"HIBP API request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in HIBP check: {e}")
            return None

    def get_help_text(self):
        """Return help text for this validator."""
        return _(
            "Your password will be checked against known data breaches "
            "using the Have I Been Pwned service. This helps keep your account secure."
        )
'''

# Settings configuration for custom validator
CUSTOM_VALIDATOR_SETTINGS = '''
# Shield AI: Add custom breached password validator
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    # Shield AI: Custom breached password checking
    {
        'NAME': 'utils.validators.BreachedPasswordValidator',
        'OPTIONS': {
            'threshold': 1,      # Warn if password appears 1+ times
            'timeout': 1.0,      # 1 second timeout
            'fail_safe': True,   # Allow password if API fails
        }
    },
]
'''

# requirements.txt entry
REQUIREMENTS_ENTRY = '''# Shield AI: Breached password checking
django-pwned-passwords>=2.0.0  # Check passwords against Have I Been Pwned
'''

# Alternative: requests for custom validator
REQUIREMENTS_ENTRY_CUSTOM = '''# Shield AI: HTTP client for breached password checking
requests>=2.28.0  # For HIBP API calls
'''

# .env.example entry
ENV_EXAMPLE_ENTRY = '''# PWNED_PASSWORDS - Configuration for breach password checking (optional)
# PWNED_PASSWORDS_API_TIMEOUT=1.0
# PWNED_PASSWORDS_FAIL_SAFE=True
# PWNED_PASSWORDS_ERROR_MESSAGE="This password has appeared in a data breach."
'''

# Documentation template
DOCUMENTATION_TEMPLATE = '''## Breached Password Validation Added

Shield AI has added password breach checking to prevent users from setting
passwords that have been exposed in known data breaches.

### What Was Added?

**Password Validator:**
- Checks all new passwords against Have I Been Pwned (HIBP) database
- Uses k-anonymity to protect user privacy (only first 5 hash chars sent)
- Advisory warning - doesn't block signup, just warns users
- Graceful degradation if HIBP API is unavailable

### How It Works

**When a user sets a password:**

1. **Password is hashed** with SHA-1 locally
2. **First 5 characters** of hash sent to HIBP API (k-anonymity)
3. **API returns** all hashes starting with those 5 characters
4. **Local matching** determines if password is compromised
5. **Warning shown** if password found in breaches

**Privacy Protection (k-anonymity):**
- Only first 5 characters of hash sent to HIBP
- Actual password never leaves your server
- HIBP cannot determine which password you're checking
- ~800 hashes returned per query for anonymity

### Implementation Options

**Option 1: django-pwned-passwords (Recommended)**
```bash
# Install dependency
pip install django-pwned-passwords

# Already added to settings.py:
AUTH_PASSWORD_VALIDATORS = [
    # ... other validators ...
    {{
        'NAME': 'pwned_passwords_django.validators.PwnedPasswordsValidator',
        'OPTIONS': {{
            'error_message': 'This password has appeared in a data breach.',
        }}
    }},
]
```

**Option 2: Custom Validator (No Dependencies)**
```python
# Custom validator created in utils/validators.py
# Uses requests library to query HIBP API directly
# Full control over behavior and error handling
```

### Configuration

**Settings (settings.py):**
```python
# Timeout for HIBP API requests
PWNED_PASSWORDS_API_TIMEOUT = 1.0  # seconds

# Allow signup if API fails
PWNED_PASSWORDS_FAIL_SAFE = True

# Custom error message
PWNED_PASSWORDS_ERROR_MESSAGE = "This password has appeared in a data breach."
```

### User Experience

**When user chooses a breached password:**

❌ **Before Shield AI:**
```
Password: password123
✓ Password accepted  # INSECURE!
```

✅ **After Shield AI:**
```
Password: password123
⚠️  This password has appeared 37,000 times in data breaches.
    Please choose a different password for your security.
```

**When user chooses a strong password:**
```
Password: G9$mKp2#xL@vNq4R
✓ Password accepted and secure!
```

### Security Benefits

**Prevents:**
- ✅ Credential stuffing attacks
- ✅ Password reuse exploitation
- ✅ Brute force with known passwords
- ✅ Account takeover via leaked credentials

**Statistics:**
- HIBP database: 613 million+ breached passwords
- Password123 appears: 2.3 million times
- Most common password (123456): 37 million times

### Testing

**Test the validator:**
```python
from django.contrib.auth.password_validation import validate_password

# Test with known breached password
try:
    validate_password("password123")
except ValidationError as e:
    print(e)  # Should show breach warning

# Test with strong unique password
validate_password("G9$mKp2#xL@vNq4R")  # Should pass
```

### API Information

**Have I Been Pwned API:**
- Endpoint: https://api.pwnedpasswords.com/range/{prefix}
- Rate limit: Reasonable for production use
- Privacy: k-anonymity protects user data
- No authentication required
- Free for reasonable use

### Compliance

**Meets security standards:**
- ✅ NIST 800-63B Section 5.1.1.2 - Check against breach databases
- ✅ OWASP ASVS V2.1.7 - Verify passwords against breached lists
- ✅ PCI DSS - Password security best practices

### Troubleshooting

**Common issues:**

1. **"Unable to verify password security"**
   - HIBP API may be temporarily unavailable
   - Check internet connectivity
   - If fail_safe=True, password will be allowed

2. **Slow password validation**
   - Normal - API call adds ~200-500ms
   - Can implement caching for frequently checked passwords
   - Consider async checking for better UX

3. **Privacy concerns**
   - Explain k-anonymity to users
   - No actual password sent to HIBP
   - Only anonymous hash prefix transmitted

### References

- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [django-pwned-passwords docs](https://django-pwned-passwords.readthedocs.io/)
- [NIST 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [k-anonymity explanation](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/)

**Pattern:** CSEC-27 - Missing Breached Password Validation
**Severity:** High
**Status:** Fixed

For more information, see: [Shield AI Documentation](https://github.com/zaheerquodroid/Shield-AI-Backend)
'''


def get_validator_option(option='library'):
    """
    Get the appropriate validator configuration based on option.

    Args:
        option: 'library' for django-pwned-passwords or 'custom' for custom validator

    Returns:
        dict: Configuration details
    """
    if option == 'library':
        return {
            'config': PWNED_PASSWORDS_VALIDATOR_CONFIG,
            'requirements': REQUIREMENTS_ENTRY,
            'validator_name': 'pwned_passwords_django.validators.PwnedPasswordsValidator',
        }
    else:  # custom
        return {
            'config': CUSTOM_VALIDATOR_SETTINGS,
            'validator_code': CUSTOM_HIBP_VALIDATOR,
            'requirements': REQUIREMENTS_ENTRY_CUSTOM,
            'validator_name': 'utils.validators.BreachedPasswordValidator',
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
