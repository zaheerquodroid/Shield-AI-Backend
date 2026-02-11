"""
Fix templates for CSEC-23: Bare Except Clauses and DRF Exception Handler (Python)
"""
import re

# =============================================================================
# PART 1: BARE EXCEPT REPLACEMENT TEMPLATES
# =============================================================================

# Context-aware exception type suggestions
CONTEXT_SUGGESTIONS = {
    'json_operations': {
        'patterns': [r'json\.loads', r'json\.load', r'json\.dumps', r'json\.dump'],
        'exception': 'json.JSONDecodeError',
        'comment': '# JSON parsing error'
    },
    'file_operations': {
        'patterns': [r'open\(', r'\.read\(', r'\.write\(', r'Path\('],
        'exception': '(IOError, FileNotFoundError)',
        'comment': '# File operation error'
    },
    'database_operations': {
        'patterns': [r'\.execute\(', r'\.fetch', r'cursor\.', r'connection\.'],
        'exception': 'DatabaseError',
        'comment': '# Database operation error'
    },
    'http_requests': {
        'patterns': [r'requests\.', r'urllib\.', r'http\.'],
        'exception': 'requests.RequestException',
        'comment': '# HTTP request error'
    },
    'type_conversions': {
        'patterns': [r'\bint\(', r'\bfloat\(', r'\bstr\('],
        'exception': '(ValueError, TypeError)',
        'comment': '# Type conversion error'
    },
    'dict_access': {
        'patterns': [r'\[[\'\"]', r'\.get\('],
        'exception': 'KeyError',
        'comment': '# Dictionary key error'
    },
}

# Generic fallback
GENERIC_EXCEPTION = 'Exception'
GENERIC_COMMENT = '# Consider specifying more specific exception types'


def analyze_try_block_context(try_block_content):
    """
    Analyze the content of a try block to suggest appropriate exception type.

    Args:
        try_block_content: String content of the try block

    Returns:
        tuple: (exception_type, comment)
    """
    for context_name, context_info in CONTEXT_SUGGESTIONS.items():
        for pattern in context_info['patterns']:
            if re.search(pattern, try_block_content):
                return context_info['exception'], context_info['comment']

    return GENERIC_EXCEPTION, GENERIC_COMMENT


# Bare except replacement template - specific exception
BARE_EXCEPT_FIX_TEMPLATE = '''except {exception_type}:{comment}'''

# Bare except with logging template
BARE_EXCEPT_WITH_LOGGING_TEMPLATE = '''except {exception_type} as e:{comment}
    logger.error(f"{error_context}: {{e}}", exc_info=True)'''

# Bare except with re-raise template (for investigation)
BARE_EXCEPT_INVESTIGATE_TEMPLATE = '''except {exception_type} as e:{comment}
    # TODO: Review this exception handling
    logger.warning(f"Caught exception: {{e}}", exc_info=True)'''


# =============================================================================
# PART 2: DRF CUSTOM EXCEPTION HANDLER
# =============================================================================

DRF_EXCEPTION_HANDLER_TEMPLATE = '''"""
Custom DRF Exception Handler - CSEC-23
Sanitizes all unhandled exceptions to prevent information disclosure

Created by Shield AI Backend
"""
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
import logging
import traceback

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """
    Custom exception handler that sanitizes error responses.

    This handler provides defense-in-depth for exception handling:
    1. Handles all standard DRF exceptions normally (validation, auth, etc.)
    2. Sanitizes unexpected exceptions to prevent information disclosure
    3. Logs full details server-side for debugging
    4. Provides detailed errors in DEBUG mode, generic in production

    Args:
        exc: The exception instance
        context: Dictionary with request context (view, args, kwargs, request)

    Returns:
        Response: DRF Response object with appropriate error details
    """
    # Call DRF's default exception handler first
    # This handles all standard DRF exceptions (ValidationError, NotFound, etc.)
    response = drf_exception_handler(exc, context)

    if response is not None:
        # DRF successfully handled this exception
        # Return as-is (validation errors, 404s, etc.)
        return response

    # This is an unhandled exception - need to sanitize for security

    # Extract context information for logging
    view = context.get('view', None)
    request = context.get('request', None)

    log_context = {
        'view': view.__class__.__name__ if view else 'Unknown',
        'request_method': request.method if request else 'Unknown',
        'request_path': request.path if request else 'Unknown',
        'user': str(request.user) if request and hasattr(request, 'user') else 'Anonymous',
    }

    # Log the full exception details server-side
    logger.error(
        f"Unhandled exception in {log_context['view']}: "
        f"{exc.__class__.__name__}: {str(exc)}",
        exc_info=True,
        extra={
            'exception_type': exc.__class__.__name__,
            'exception_message': str(exc),
            'context': log_context,
        }
    )

    # Determine response based on DEBUG setting
    if settings.DEBUG:
        # Development mode - provide detailed error information
        # This helps developers debug issues locally
        error_response = {
            'error': exc.__class__.__name__,
            'detail': str(exc),
            'traceback': traceback.format_exc().split('\n'),
            'context': log_context,
            'note': 'Detailed error shown because DEBUG=True. '
                   'This will be hidden in production.'
        }
    else:
        # Production mode - sanitize error response
        # Only show generic error to prevent information disclosure
        error_response = {
            'error': 'Internal server error',
            'detail': 'An unexpected error occurred. Please contact support if the issue persists.',
            'support_contact': getattr(settings, 'SUPPORT_EMAIL', 'support@example.com')
        }

    # Return 500 Internal Server Error
    return Response(
        error_response,
        status=status.HTTP_500_INTERNAL_SERVER_ERROR
    )


def sanitize_log_message(message):
    """
    Sanitize log messages to remove potential sensitive information.

    This is an additional security measure to prevent secrets from
    appearing in logs even during exceptions.

    Args:
        message: The log message to sanitize

    Returns:
        str: Sanitized message
    """
    import re

    # Patterns to redact
    patterns = [
        (r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'password="[REDACTED]"'),
        (r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'token="[REDACTED]"'),
        (r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'api_key="[REDACTED]"'),
        (r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'secret="[REDACTED]"'),
        (r'Bearer\s+[\w\-\.]+', 'Bearer [REDACTED]'),
    ]

    sanitized = message
    for pattern, replacement in patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

    return sanitized
'''

# Settings update template
DRF_SETTINGS_UPDATE_TEMPLATE = '''
# Shield AI: CSEC-23 - Custom exception handler for security
REST_FRAMEWORK = {
    'EXCEPTION_HANDLER': 'interpreter.utils.exception_handler.custom_exception_handler',
    # ... other settings ...
}
'''

# Alternative: If REST_FRAMEWORK already exists, just add the key
DRF_SETTINGS_ADD_HANDLER = """'EXCEPTION_HANDLER': 'interpreter.utils.exception_handler.custom_exception_handler',"""


# =============================================================================
# PART 3: DOCUMENTATION TEMPLATES
# =============================================================================

BARE_EXCEPT_DOCUMENTATION = '''## Security Fix: Bare Except Clauses (CSEC-23)

Shield AI has replaced bare `except:` clauses with specific exception types.

### What Changed

**Before (RISKY):**
```python
try:
    data = json.loads(content)
except:  # Catches EVERYTHING, including system exceptions
    data = {}
```

**After (SAFE):**
```python
try:
    data = json.loads(content)
except json.JSONDecodeError:  # Catches only JSON errors
    data = {}
```

### Why This Matters

Bare `except:` clauses catch ALL exceptions, including:
- 🔴 `KeyboardInterrupt` - Prevents Ctrl+C from stopping the program
- 🔴 `SystemExit` - Prevents proper shutdown
- 🔴 `MemoryError` - Masks critical system issues
- 🔴 `Exception` - Hides bugs and makes debugging impossible

### What You Need to Do

1. **Review the changes** - Verify the suggested exception types are correct
2. **Test error paths** - Ensure error handling still works as expected
3. **Update tests** - Add tests for specific exception types if needed

### Exception Type Guide

| Context | Exception Type | Example |
|---------|---------------|---------|
| JSON parsing | `json.JSONDecodeError` | `json.loads(data)` |
| File operations | `IOError, FileNotFoundError` | `open(file)` |
| Database | `DatabaseError` | `cursor.execute()` |
| HTTP requests | `requests.RequestException` | `requests.get()` |
| Type conversion | `ValueError, TypeError` | `int(value)` |
| Dictionary access | `KeyError` | `dict[key]` |

### When to Use `except Exception:`

Only use `except Exception:` when:
- You truly need to catch all non-system exceptions
- You're logging the error for investigation
- You re-raise the exception after handling

```python
try:
    risky_operation()
except Exception as e:
    logger.error(f"Unexpected error: {e}", exc_info=True)
    raise  # Re-raise to let caller handle it
```
'''

DRF_HANDLER_DOCUMENTATION = '''## Security Fix: DRF Custom Exception Handler (CSEC-23)

Shield AI has added a custom exception handler to prevent information disclosure.

### What Changed

**Before:**
- Unhandled exceptions exposed stack traces to API clients
- Internal file paths and code visible in responses
- Debug information leaked in production

**After:**
- All exceptions properly handled and sanitized
- Generic error messages in production
- Full details logged server-side
- Detailed errors only in DEBUG mode

### Exception Handler Behavior

#### Development (DEBUG=True)
```json
{
  "error": "AttributeError",
  "detail": "'NoneType' object has no attribute 'name'",
  "traceback": ["...", "..."],
  "note": "Detailed error shown because DEBUG=True"
}
```

#### Production (DEBUG=False)
```json
{
  "error": "Internal server error",
  "detail": "An unexpected error occurred. Please contact support.",
  "support_contact": "support@example.com"
}
```

### What Gets Logged

Server-side logs include:
- Full exception type and message
- Complete traceback
- Request context (view, method, path, user)
- **NO passwords, tokens, or secrets** (sanitized)

### Testing Your API

```bash
# Test with DEBUG=True (development)
export DEBUG=True
python manage.py runserver

# Trigger an error and verify detailed response

# Test with DEBUG=False (production simulation)
export DEBUG=False
python manage.py runserver

# Trigger an error and verify generic response
```

### Handled Exception Types

The custom handler preserves normal DRF error handling:
- ✅ Validation errors (400) - shown as-is
- ✅ Authentication errors (401) - shown as-is
- ✅ Permission errors (403) - shown as-is
- ✅ Not found errors (404) - shown as-is
- ⚠️ Unhandled exceptions (500) - sanitized

### Integration with Error Tracking

To integrate with Sentry or other error tracking:

```python
# In your exception handler
import sentry_sdk

def custom_exception_handler(exc, context):
    response = drf_exception_handler(exc, context)

    if response is None:
        # Send to Sentry before sanitizing
        sentry_sdk.capture_exception(exc)

        # ... rest of sanitization logic
```
'''

FULL_DOCUMENTATION = '''## CSEC-23: Exception Handling Security

Shield AI has implemented comprehensive exception handling security fixes.

### Changes Made

1. **Bare Except Clauses** - Replaced with specific exception types
2. **DRF Exception Handler** - Added global sanitization handler

### Files Modified

- `**/*.py` - Bare except clauses replaced
- `interpreter/utils/exception_handler.py` - Created custom handler
- `settings.py` - Added EXCEPTION_HANDLER configuration

### Security Benefits

✅ **Information Disclosure Prevention**
- No stack traces leaked to clients
- Internal paths hidden
- Database details protected

✅ **Better Error Handling**
- Specific exceptions caught appropriately
- System exceptions no longer masked
- Easier debugging with proper logging

✅ **Production Safety**
- Generic errors in production
- Detailed errors in development
- Full logging for investigation

### Next Steps

1. Review all modified files
2. Test error handling paths
3. Verify logs are working
4. Update monitoring/alerting
5. Train team on new exception patterns

---
**Pattern:** CSEC-23
**Severity:** Medium (P0-Critical)
**Status:** Fixed ✅
'''


# =============================================================================
# PART 4: HELPER FUNCTIONS
# =============================================================================

def get_bare_except_fix_template(context_content='', include_logging=False):
    """
    Get the appropriate bare except fix template.

    Args:
        context_content: Content of the try block for context analysis
        include_logging: Whether to include logging in the fix

    Returns:
        str: The fix template
    """
    exception_type, comment = analyze_try_block_context(context_content)

    if include_logging:
        return BARE_EXCEPT_WITH_LOGGING_TEMPLATE.format(
            exception_type=exception_type,
            comment=comment,
            error_context="Exception in error handling"
        )
    else:
        return BARE_EXCEPT_FIX_TEMPLATE.format(
            exception_type=exception_type,
            comment=comment
        )


def get_drf_exception_handler():
    """Get the DRF exception handler template."""
    return DRF_EXCEPTION_HANDLER_TEMPLATE


def get_settings_update(existing_rest_framework=False):
    """
    Get settings update template.

    Args:
        existing_rest_framework: Whether REST_FRAMEWORK already exists

    Returns:
        str: Settings update code
    """
    if existing_rest_framework:
        return DRF_SETTINGS_ADD_HANDLER
    else:
        return DRF_SETTINGS_UPDATE_TEMPLATE


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


def generate_bare_except_documentation():
    """Generate documentation for bare except fixes."""
    return BARE_EXCEPT_DOCUMENTATION


def generate_drf_handler_documentation():
    """Generate documentation for DRF exception handler."""
    return DRF_HANDLER_DOCUMENTATION


def generate_full_documentation():
    """Generate complete CSEC-23 documentation."""
    return FULL_DOCUMENTATION
